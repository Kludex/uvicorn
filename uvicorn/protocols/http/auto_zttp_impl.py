from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from uvicorn.config import Config
from uvicorn.protocols.http.zttp_h2_impl import ZttpH2Protocol
from uvicorn.protocols.http.zttp_impl import ZttpProtocol
from uvicorn.protocols.utils import is_ssl
from uvicorn.server import ServerState

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


class AutoZttpProtocol(asyncio.Protocol):
    """Dispatches each new connection to the HTTP/1.1 or HTTP/2 zttp protocol.

    Over TLS the choice is made from the ALPN result as soon as the connection
    is made. On cleartext connections the first bytes are sniffed for the
    HTTP/2 preface (prior-knowledge h2c); anything else is HTTP/1.1.
    """

    alpn_protocols: ClassVar[list[str]] = ["h2", "http/1.1"]

    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if not config.loaded:
            config.load()

        self.config = config
        self.server_state = server_state
        self.app_state = app_state
        self.loop = _loop or asyncio.get_event_loop()
        self.connections = server_state.connections
        self.transport: asyncio.Transport = None  # type: ignore[assignment]
        self.timeout_task: asyncio.TimerHandle | None = None
        self.buffer = b""

    def connection_made(  # type: ignore[override]
        self, transport: asyncio.Transport
    ) -> None:
        self.transport = transport
        if is_ssl(transport):
            ssl_object = transport.get_extra_info("ssl_object")
            alpn = ssl_object.selected_alpn_protocol() if ssl_object is not None else None
            self._switch(http2=alpn == "h2")
            return
        self.connections.add(self)
        self.timeout_task = self.loop.call_later(self.config.timeout_keep_alive, self.transport.close)

    def connection_lost(self, exc: Exception | None) -> None:
        self.connections.discard(self)
        if self.timeout_task is not None:
            self.timeout_task.cancel()
            self.timeout_task = None

    def eof_received(self) -> None:
        pass

    def shutdown(self) -> None:
        self.transport.close()

    def data_received(self, data: bytes) -> None:
        self.buffer += data
        if len(self.buffer) < len(HTTP2_PREFACE) and HTTP2_PREFACE.startswith(self.buffer):
            return
        self.connections.discard(self)
        if self.timeout_task is not None:
            self.timeout_task.cancel()
            self.timeout_task = None
        self._switch(http2=self.buffer.startswith(HTTP2_PREFACE), initial_data=self.buffer)

    def _switch(self, http2: bool, initial_data: bytes = b"") -> None:
        protocol_class: type[asyncio.Protocol] = ZttpH2Protocol if http2 else ZttpProtocol
        protocol = protocol_class(  # type: ignore[call-arg]
            config=self.config,
            server_state=self.server_state,
            app_state=self.app_state,
            _loop=self.loop,
        )
        self.transport.set_protocol(protocol)
        protocol.connection_made(self.transport)
        if initial_data:
            protocol.data_received(initial_data)

from __future__ import annotations

import asyncio
from collections.abc import Generator
from typing import TYPE_CHECKING, Any

import zttp
from wsproto import ConnectionType, events
from wsproto.connection import Connection, ConnectionState
from wsproto.events import Event
from wsproto.handshake import server_extensions_handshake
from wsproto.utilities import LocalProtocolError, RemoteProtocolError, split_comma_header

from uvicorn.protocols.websockets.wsproto_impl import WSProtocol

if TYPE_CHECKING:
    from uvicorn.protocols.http.zttp_h2_impl import ZttpH2Protocol


class H2WebSocketConnection:
    def __init__(self, stream: zttp.Stream, request: events.Request) -> None:
        self.stream = stream
        self.request = request
        self.connection: Connection | None = None
        self.response_started = False

    @property
    def state(self) -> ConnectionState:
        return self.connection.state if self.connection is not None else ConnectionState.CONNECTING

    def receive_data(self, data: bytes | None) -> None:
        if self.connection is None:
            raise RemoteProtocolError("WebSocket data received before acceptance", event_hint=events.RejectConnection())
        self.connection.receive_data(data)

    def events(self) -> Generator[Event]:
        if self.connection is not None:
            yield from self.connection.events()

    def send(self, event: Event) -> bytes:
        if isinstance(event, events.AcceptConnection):
            headers = list(event.extra_headers)
            if event.subprotocol is not None:
                if event.subprotocol not in self.request.subprotocols:
                    raise LocalProtocolError(f"Unexpected subprotocol {event.subprotocol}")
                headers.append((b"sec-websocket-protocol", event.subprotocol.encode("ascii")))
            offers = [str(offer) for offer in self.request.extensions]
            extensions = server_extensions_handshake(offers, event.extensions)
            if extensions:
                headers.append((b"sec-websocket-extensions", extensions))
            self.send_response(200, headers)
            self.connection = Connection(ConnectionType.SERVER, event.extensions)
            return b""
        if isinstance(event, events.RejectConnection):
            if not 300 <= event.status_code < 600:
                raise LocalProtocolError("A WebSocket denial must use a 3xx, 4xx, or 5xx status")
            self.send_response(event.status_code, list(event.headers))
            return b""
        if isinstance(event, events.RejectData):
            return event.data
        assert self.connection is not None
        return self.connection.send(event)

    def send_response(self, status: int, headers: list[tuple[bytes, bytes]]) -> None:
        from uvicorn.protocols.http.zttp_h2_impl import FORBIDDEN_HEADERS

        forbidden = FORBIDDEN_HEADERS | {b"sec-websocket-accept", b"sec-websocket-key", b"te"}
        if status == 200:
            forbidden = forbidden | {b"content-length"}
        headers = [(name.lower(), value) for name, value in headers if name.lower() not in forbidden]
        self.stream.send_response(status, headers)
        self.response_started = True


class H2WebSocketTransport(asyncio.Transport):
    def __init__(self, parent: ZttpH2Protocol, event: zttp.Request, headers: list[tuple[bytes, bytes]]) -> None:
        self.parent = parent
        self.stream = parent.conn.stream(event.stream_id)
        self.closed = False
        subprotocols: list[str] = []
        extensions: list[str] = []
        host = ""
        for name, value in headers:
            if name == b"host":
                host = value.decode("ascii")
            elif name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
            elif name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
        request = events.Request(
            host=host,
            target=event.target.decode("ascii"),
            subprotocols=subprotocols,
            extensions=extensions,
            extra_headers=[(name, value) for name, value in headers if name != b"host"],
        )
        self.connection = H2WebSocketConnection(self.stream, request)
        self.protocol = WSProtocol(parent.config, parent.server_state, parent.app_state, parent.loop)
        self.protocol.conn = self.connection
        self.protocol.http_version = "2"
        self.protocol.connection_made(self)
        # Only the parent TCP connection belongs in the server's connection registry.
        self.protocol.connections.discard(self.protocol)
        self.request = request

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return self.parent.transport.get_extra_info(name) or default

    def is_closing(self) -> bool:
        return self.closed or self.parent.transport.is_closing()

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self.is_closing():
            return
        if data:
            self.stream.send_data(bytes(data))
        self.parent.flush()

    def data_received(self, data: bytes | None) -> None:
        self.protocol.data_received(data)
        if not self.closed and self.protocol.queue.qsize() > self.parent.config.ws_max_queue:
            while not self.protocol.queue.empty():
                self.protocol.queue.get_nowait()
            self.protocol.queue.put_nowait({"type": "websocket.disconnect", "code": 1013})
            self.write(self.connection.send(events.CloseConnection(code=1013, reason="Receive queue is full")))
            self.close()

    def pause_reading(self) -> None:
        # Keep reading WINDOW_UPDATE and sibling streams; bound this stream's queue instead.
        pass

    def resume_reading(self) -> None:
        pass

    def close(self) -> None:
        if self.closed:
            return
        if not self.parent.transport.is_closing():
            if self.connection.response_started:
                self.stream.end_message()
            else:
                self.stream.reset()
        self.closed = True
        self.protocol.connection_lost(None)
        self.parent.flush()
        self.parent.on_stream_closed()

    def disconnect(self) -> None:
        if not self.closed:
            self.protocol.queue.put_nowait({"type": "websocket.disconnect", "code": 1006})
            self.closed = True
            self.protocol.connection_lost(None)
        self.parent.websockets.pop(self.stream.stream_id, None)

    def update_writable(self) -> None:
        if self.closed:
            if not self.stream.pending_bytes:
                self.parent.websockets.pop(self.stream.stream_id, None)
                self.parent.on_stream_closed()
            return
        if self.parent.flow.write_paused or self.stream.pending_bytes:
            self.protocol.pause_writing()
        else:
            self.protocol.resume_writing()

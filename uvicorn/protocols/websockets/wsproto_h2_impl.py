from __future__ import annotations

import asyncio
import contextvars
from typing import TYPE_CHECKING, Any

import zttp
from wsproto import events
from wsproto.utilities import split_comma_header

from uvicorn.protocols.websockets.wsproto_connection import H2WebSocketConnection
from uvicorn.protocols.websockets.wsproto_impl import WSProtocol
from uvicorn.server import ServerState

if TYPE_CHECKING:
    from uvicorn.protocols.http.zttp_h2_impl import ZttpH2Protocol


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
        # Keep stream registrations local, but track application tasks on the server.
        state = ServerState()
        state.tasks = parent.server_state.tasks
        state.default_headers = parent.server_state.default_headers
        self.protocol = WSProtocol(parent.config, state, parent.app_state, parent.loop)
        self.protocol.conn = self.connection
        self.protocol.http_version = "2"
        self.protocol.connection_made(self)

    @classmethod
    def start(cls, parent: ZttpH2Protocol, event: zttp.Request, headers: list[tuple[bytes, bytes]]) -> None:
        versions = [value for name, value in headers if name == b"sec-websocket-version"]
        status = 0
        if event.end_stream or len(versions) != 1:
            status = 400
        elif versions != [b"13"]:
            status = 426
        if not status:
            try:
                websocket = cls(parent, event, headers)
            except UnicodeDecodeError:
                status = 400
            else:
                parent.websockets[event.stream_id] = websocket
                websocket.update_writable()
                if parent.config.reset_contextvars:
                    contextvars.Context().run(websocket.protocol.handle_connect, websocket.connection.request)
                else:
                    websocket.protocol.handle_connect(websocket.connection.request)
                return
        stream = parent.conn.stream(event.stream_id)
        stream.send_response(status, [(b"sec-websocket-version", b"13")] if status == 426 else [])
        stream.end_message()

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
        if self.closed or self.protocol.response_started:
            return
        self.protocol.data_received(data)
        if (
            not self.closed
            and not self.protocol.close_sent
            and self.protocol.queue.qsize() > self.parent.config.ws_max_queue
        ):
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

    def disconnect(self) -> None:
        if not self.closed:
            self.protocol.queue.put_nowait({"type": "websocket.disconnect", "code": 1006})
            self.closed = True
            self.protocol.connection_lost(None)
        self.parent.websockets.pop(self.stream.stream_id, None)

    def shutdown(self) -> None:
        # A denial is an HTTP response; let its body finish during shutdown.
        if not self.closed and not self.protocol.response_started:
            self.protocol.shutdown()

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

from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING

from wsproto import ConnectionType, events
from wsproto.connection import Connection, ConnectionState
from wsproto.events import Event
from wsproto.handshake import server_extensions_handshake
from wsproto.utilities import LocalProtocolError, RemoteProtocolError

if TYPE_CHECKING:
    import zttp
    from typing_extensions import Protocol

    class WebSocketConnection(Protocol):
        @property
        def state(self) -> ConnectionState: ...

        def receive_data(self, data: bytes | None) -> None: ...

        def events(self) -> Generator[Event]: ...

        def send(self, event: Event) -> bytes: ...


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

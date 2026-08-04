from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeAlias

from tests.benchmarks.http import MockLoop, MockTransport
from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.server import ServerState

if TYPE_CHECKING:
    from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol
    from uvicorn.protocols.websockets.wsproto_impl import WSProtocol

    WSProtocolClass: TypeAlias = type[WSProtocol] | type[WebSocketsSansIOProtocol]

WS_UPGRADE = (
    b"GET / HTTP/1.1\r\n"
    b"Host: example.org\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: YmVuY2htYXJra2V5MTIzNA==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"\r\n"
)

# Masked text frame: "Hello, world!" (13 bytes) with zero mask key
WS_TEXT_FRAME = b"\x81\x8d\x00\x00\x00\x00Hello, world!"

# Masked close frame: code 1000 with zero mask key
WS_CLOSE_FRAME = b"\x88\x82\x00\x00\x00\x00\x03\xe8"


def get_connected_ws_protocol(config: Config, ws_protocol_cls: WSProtocolClass) -> Any:
    loop = MockLoop()
    transport = MockTransport()
    lifespan = LifespanOff(config)
    server_state = ServerState()
    protocol = ws_protocol_cls(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)  # type: ignore[arg-type]
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol

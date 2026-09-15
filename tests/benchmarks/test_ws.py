from __future__ import annotations

import importlib.util
from typing import TYPE_CHECKING

import pytest

from tests.benchmarks.http import make_config
from tests.benchmarks.ws import WS_UPGRADE, get_connected_ws_protocol
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope

if TYPE_CHECKING:
    from tests.benchmarks.ws import WSProtocolClass

pytestmark = [pytest.mark.anyio, pytest.mark.benchmark]


@pytest.fixture(
    params=[
        pytest.param(
            "wsproto",
            marks=pytest.mark.skipif(not importlib.util.find_spec("wsproto"), reason="wsproto not installed."),
            id="wsproto",
        ),
        pytest.param("websockets-sansio", id="websockets-sansio"),
    ]
)
def ws_cls(request: pytest.FixtureRequest) -> WSProtocolClass:
    if request.param == "wsproto":
        from uvicorn.protocols.websockets.wsproto_impl import WSProtocol

        return WSProtocol
    from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol

    return WebSocketsSansIOProtocol


async def _ws_accept_close_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    await receive()
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.close", "code": 1000})


async def _ws_send_text_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    await receive()
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.send", "text": "Hello, world!"})
    await send({"type": "websocket.close", "code": 1000})


_ws_accept_close_config = make_config(_ws_accept_close_app, access_log=False)
_ws_send_text_config = make_config(_ws_send_text_app, access_log=False)


async def test_bench_ws_handshake(ws_cls: WSProtocolClass) -> None:
    protocol = get_connected_ws_protocol(_ws_accept_close_config, ws_cls)
    protocol.data_received(WS_UPGRADE)
    await protocol.loop.run_one()


async def test_bench_ws_send_text(ws_cls: WSProtocolClass) -> None:
    protocol = get_connected_ws_protocol(_ws_send_text_config, ws_cls)
    protocol.data_received(WS_UPGRADE)
    await protocol.loop.run_one()

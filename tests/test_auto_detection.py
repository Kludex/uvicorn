import asyncio
import contextlib
import importlib

import pytest

from uvicorn.config import Config
from uvicorn.loops.auto import auto_loop_factory
from uvicorn.protocols.http.auto import AutoHTTPProtocol
from uvicorn.protocols.websockets.auto import AutoWebSocketsProtocol
from uvicorn.server import ServerState

try:
    importlib.import_module("uvloop")
    expected_loop = "uvloop"  # pragma: py-win32
except ImportError:  # pragma: py-not-win32
    expected_loop = "asyncio"

try:
    importlib.import_module("httptools")
    expected_http = "HttpToolsProtocol"
except ImportError:  # pragma: no cover
    expected_http = "H11Protocol"

try:
    importlib.import_module("websockets")
    expected_websockets = "WebSocketProtocol"
except ImportError:  # pragma: no cover
    expected_websockets = "WSProtocol"


async def app(scope, receive, send):
    pass  # pragma: no cover


def test_loop_auto():
    loop_factory = auto_loop_factory(use_subprocess=True)
    with contextlib.closing(loop_factory()) as loop:
        assert isinstance(loop, asyncio.AbstractEventLoop)
        assert type(loop).__module__.startswith(expected_loop)


@pytest.mark.anyio
async def test_http_auto():
    config = Config(app=app)
    server_state = ServerState()
    protocol = AutoHTTPProtocol(  # type: ignore[call-arg]
        config=config, server_state=server_state, app_state={}
    )
    assert type(protocol).__name__ == expected_http


@pytest.mark.anyio
async def test_websocket_auto():
    config = Config(app=app)
    server_state = ServerState()

    assert AutoWebSocketsProtocol is not None
    protocol = AutoWebSocketsProtocol(config=config, server_state=server_state, app_state={})
    assert type(protocol).__name__ == expected_websockets

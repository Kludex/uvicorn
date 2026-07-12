from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast

import httpx
import pytest

from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol, _is_ws_upgrade
from uvicorn.server import ServerState

if TYPE_CHECKING:
    from uvicorn._types import HTTPScope

pytestmark = pytest.mark.anyio

# httpunk drives its own async serve loop over a real transport, so — unlike the
# h11/httptools protocols — it can't be exercised through the synchronous
# MockTransport/MockLoop harness in `test_http.py`. These tests run a real server and
# hit it with an httpx client instead. HTTP/1 alone covers every line of the ASGI
# bridge (the h2-specific branches are single-line expressions shared with the h1 path).


class _RecordingHandler(logging.Handler):
    """Captures every emitted record in a list for later assertions."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


async def _run(app: object, port: int, *, log_level: str = "warning", **config_kwargs: object):
    config = Config(app=app, loop="asyncio", port=port, http="httpunk1", log_level=log_level, **config_kwargs)  # type: ignore[arg-type]
    return run_server(config)


async def test_get_request(unused_tcp_port: int):
    """Fast path: a single-body response goes out in one respond() call."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"Hello, world"})

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 200
    assert response.text == "Hello, world"


async def test_post_request_body(unused_tcp_port: int):
    """The request body is streamed to the app through `receive()`."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            assert message["type"] == "http.request"
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.post(f"http://127.0.0.1:{unused_tcp_port}/", content=b"request-payload")
    assert response.status_code == 200
    assert response.text == "request-payload"


async def test_streaming_response(unused_tcp_port: int):
    """A multi-part body (more_body=True) switches to the concurrent streaming path."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"chunk-1", "more_body": True})
        await send({"type": "http.response.body", "body": b"chunk-2", "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 200
    assert response.text == "chunk-1chunk-2"


async def test_start_only_response(unused_tcp_port: int):
    """An app that starts a response but never sends a body still flushes an empty one."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 204
    assert response.text == ""


async def test_app_exception(unused_tcp_port: int):
    """An exception before the response starts yields a 500."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        raise RuntimeError("boom")

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 500
    assert response.text == "Internal Server Error"


async def test_no_response_returned(unused_tcp_port: int):
    """An app that returns without starting a response yields a 500."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        return

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 500


async def test_root_path(unused_tcp_port: int):
    """`root_path` is prepended to the ASGI `path` and reported in the scope."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        http_scope = cast("HTTPScope", scope)
        body = f"{http_scope['root_path']}|{http_scope['path']}".encode()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    async with await _run(app, unused_tcp_port, root_path="/api"):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/items")
    assert response.text == "/api|/api/items"


async def test_access_log(unused_tcp_port: int):
    """With the access log enabled, each request is logged."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    # Attach our own handler directly to the access logger so that `hasHandlers()` is true
    # (the bridge enables access logging from that) and so we capture the emitted record.
    # `log_level="info"` lets the server's logging setup raise the access logger to INFO.
    handler = _RecordingHandler()
    access_logger = logging.getLogger("uvicorn.access")
    access_logger.addHandler(handler)
    try:
        async with await _run(app, unused_tcp_port, access_log=True, log_level="info", log_config=None):
            async with httpx.AsyncClient() as client:
                response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    finally:
        access_logger.removeHandler(handler)
    assert response.status_code == 200
    assert any('"GET / HTTP/1.1" 200' in record.getMessage() for record in handler.records)


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"connection": b"Upgrade", "upgrade": b"websocket"}, True),
        ({"connection": b"keep-alive, Upgrade", "upgrade": b"WebSocket"}, True),
        ({"connection": b"keep-alive"}, False),
        ({"connection": b"Upgrade", "upgrade": b"h2c"}, False),
    ],
)
def test_is_ws_upgrade(headers: dict[str, bytes], expected: bool):
    class _Headers:
        def __init__(self, data: dict[str, bytes]) -> None:
            self._data = data

        def items(self):
            return self._data.items()

    class _Request:
        def __init__(self, data: dict[str, bytes]) -> None:
            self.headers = _Headers(data)

    assert _is_ws_upgrade(_Request(headers)) is expected


async def test_init_loads_config():
    """Constructing a protocol with an unloaded config loads it (config.load())."""

    async def app(
        scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None: ...  # pragma: no cover - never invoked, just a valid ASGI target

    config = Config(app=app)
    assert not config.loaded
    protocol = HTTPunkH1Protocol(config=config, server_state=ServerState(), app_state={})
    assert config.loaded
    assert protocol.app is not None

from __future__ import annotations

import asyncio
import contextvars
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, cast

import httpx
import pytest
from httpunk.asyncio import H2ClientProtocol

from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol, _BodyHandoff, _is_ws_upgrade, _StreamAborted
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


async def _run(app: object, port: int, *, http: str = "httpunk1", log_level: str = "warning", **config_kwargs: object):
    config = Config(app=app, loop="asyncio", port=port, http=http, log_level=log_level, **config_kwargs)  # type: ignore[arg-type]
    return run_server(config)


async def _ok_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    """A minimal 200 "ok" app, shared by tests where the response body itself doesn't matter."""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


@asynccontextmanager
async def _h2_connection(port: int) -> AsyncIterator[Any]:
    """Open a plaintext (h2c prior-knowledge) HTTP/2 connection using httpunk's own client;
    yields the connection facade to send requests on. `httpx`'s http2 needs the `h2` package,
    which isn't a dependency, so the in-repo httpunk client is used instead."""
    loop = asyncio.get_event_loop()
    _transport, proto = await loop.create_connection(
        lambda: H2ClientProtocol(authority=f"127.0.0.1:{port}", scheme="http"), "127.0.0.1", port
    )
    try:
        yield await proto.ready()
    finally:
        await proto.aclose()


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


async def test_destreamed_response(unused_tcp_port: int):
    """A multi-part body completed within one loop tick never commits to streaming: it
    collapses into a single Content-Length respond() instead of a chunked response."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"part-1;", "more_body": True})
        await send({"type": "http.response.body", "body": b"part-2", "more_body": False})

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 200
    assert response.text == "part-1;part-2"
    assert response.headers.get("content-length") == "13"
    assert "transfer-encoding" not in response.headers


async def test_streaming_response_flushes_between_awaits(unused_tcp_port: int):
    """A streamer that suspends between chunks commits on the next loop tick (via the
    deferred call_soon) — the response stays chunked, the first chunk isn't held back."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"tick;", "more_body": True})
        await asyncio.sleep(0.05)
        await send({"type": "http.response.body", "body": b"tock", "more_body": False})

    async with await _run(app, unused_tcp_port):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 200
    assert response.text == "tick;tock"
    assert response.headers.get("transfer-encoding") == "chunked"


async def test_body_handoff_abort_releases_parked_consumer():
    """abort() wakes a consumer parked in __anext__, which then raises _StreamAborted
    (truncating the wire response); later puts from the producer are silent no-ops."""
    handoff = _BodyHandoff(asyncio.get_event_loop())
    consumer = asyncio.ensure_future(handoff.__anext__())
    await asyncio.sleep(0)  # let the consumer park in its get-waiter
    handoff.abort()
    with pytest.raises(_StreamAborted):
        await consumer
    await handoff.put(b"late", True)  # producer outlives the abort: dropped, no park


async def test_body_handoff_abort_releases_parked_producer():
    """A non-empty chunk behind an unconsumed one parks the producer (backpressure);
    abort() releases it without delivering the chunk. Empty non-final puts are no-ops."""
    handoff = _BodyHandoff(asyncio.get_event_loop())
    await handoff.put(b"first", True)  # slot free: returns without parking
    await handoff.put(b"", True)  # empty non-final chunk: nothing to hand over
    producer = asyncio.ensure_future(handoff.put(b"second", True))
    await asyncio.sleep(0)  # let the producer park on the occupied slot
    assert not producer.done()
    handoff.abort()
    await producer  # released by the abort, the parked chunk is dropped


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
    # The 500 must still carry the configured default headers (e.g. the Server header).
    assert response.headers.get("server") == "uvicorn"


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


async def test_total_requests_counted(unused_tcp_port: int):
    """Each completed request is counted in `server_state.total_requests` (what drives
    `--limit-max-requests`)."""
    async with await _run(_ok_app, unused_tcp_port) as server:
        async with httpx.AsyncClient() as client:
            await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
            await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    # Checked after shutdown has drained the connection, so every request has finished counting.
    assert server.server_state.total_requests == 2


async def test_limit_concurrency(unused_tcp_port: int):
    """Over the concurrency limit, the app is replaced by uvicorn's 503 response."""
    # limit=1 with the single open connection already at the limit -> 503, matching h11/httptools.
    async with await _run(_ok_app, unused_tcp_port, limit_concurrency=1):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 503
    assert response.text == "Service Unavailable"


async def test_h2_request(unused_tcp_port: int):
    """A basic HTTP/2 request is served, with the request seen as http_version '2'."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        http_scope = cast("HTTPScope", scope)
        body = f"{http_scope['type']}/{http_scope['http_version']}".encode()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    async with await _run(app, unused_tcp_port, http="httpunk2"):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 200
    assert body == b"http/2"
    assert dict(response.headers.items()).get("server") == b"uvicorn"


async def test_h2_concurrent_streams(unused_tcp_port: int):
    """Many requests multiplexed on a single HTTP/2 connection are each handled independently."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        http_scope = cast("HTTPScope", scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": http_scope["path"].encode()})

    async with await _run(app, unused_tcp_port, http="httpunk2") as server:
        async with _h2_connection(unused_tcp_port) as conn:

            async def one(i: int) -> bytes:
                response = await conn.request("GET", f"/{i}", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
                return await response.read()

            results = await asyncio.gather(*(one(i) for i in range(6)))
    assert results == [f"/{i}".encode() for i in range(6)]
    assert server.server_state.total_requests == 6


async def test_reset_contextvars(unused_tcp_port: int):
    """With `reset_contextvars=True`, the app runs in a fresh context, so a ContextVar set on the
    serve task is not visible inside it."""
    var: contextvars.ContextVar[str] = contextvars.ContextVar("test_httpunk_ctx", default="default")
    var.set("outer")
    seen: dict[str, str] = {}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        seen["value"] = var.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async with await _run(app, unused_tcp_port, reset_contextvars=True):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 200
    assert seen["value"] == "default"  # the outer "outer" value did not leak into the fresh context


async def test_h2_limit_concurrency(unused_tcp_port: int):
    """The 503 path works over HTTP/2: `service_unavailable`'s `connection: close` header —
    illegal in HTTP/2 — is stripped instead of resetting the stream."""

    async with await _run(_ok_app, unused_tcp_port, http="httpunk2", limit_concurrency=1):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 503
    assert body == b"Service Unavailable"

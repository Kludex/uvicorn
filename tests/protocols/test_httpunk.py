from __future__ import annotations

import asyncio
import contextlib
import contextvars
import importlib.util
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, cast

import httpx2
import pytest

from tests.response import Response
from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.server import ServerState

if TYPE_CHECKING:
    from uvicorn._types import HTTPScope

try:
    import zttp

    skip_if_no_zttp_h2 = pytest.mark.skipif(
        not hasattr(zttp, "HTTP2"), reason="zttp with HTTP/2 support is not installed"
    )
except ModuleNotFoundError:  # pragma: no cover
    skip_if_no_zttp_h2 = pytest.mark.skipif(True, reason="zttp is not installed")

skip_if_no_httpunk = pytest.mark.skipif(not importlib.util.find_spec("httpunk"), reason="httpunk not installed.")

pytestmark = pytest.mark.anyio


# --- HTTP/2 behavior ------------------------------------------------------------


class WireH2Client:
    """A raw HTTP/2 client over a real connection, driven by zttp's sans-io engine.
    Complements httpunk's high-level client below for tests that must observe or
    inject individual frames (RST_STREAM, mid-request closes)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.conn = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)

    @classmethod
    @asynccontextmanager
    async def connect(cls, port: int) -> AsyncIterator[WireH2Client]:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            yield cls(reader, writer)
        finally:
            writer.close()

    def flush(self) -> None:
        data = self.conn.data_to_send()
        if data:
            self.writer.write(data)

    def request(self, method: bytes = b"GET", target: bytes = b"/", end: bool = True) -> zttp.Stream:
        stream = self.conn.send_request(method, target, b"2", [(b"host", b"example.org")])
        if end:
            stream.end_message()
        self.flush()
        return stream

    def send_frame(self, ftype: int, flags: int, stream_id: int, payload: bytes) -> None:
        header = len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + stream_id.to_bytes(4, "big")
        self.writer.write(header + payload)

    def rst_stream(self, stream_id: int) -> None:
        self.send_frame(0x03, 0, stream_id, (0x8).to_bytes(4, "big"))  # CANCEL

    async def drain_events(self, timeout: float = 0.5) -> list[Any]:
        """Read frames until the peer goes quiet, the connection closes, or
        `timeout` elapses between reads."""
        events: list[Any] = []
        with contextlib.suppress(asyncio.TimeoutError):
            while data := await asyncio.wait_for(self.reader.read(65536), timeout):
                self.conn.receive_data(data)
                while (event := self.conn.next_event()) is not zttp.NEED_DATA:
                    events.append(event)
        return events

    async def read_response(self, stream_id: int) -> tuple[int | None, bytes, bool]:
        """Collect status, body, and whether the stream ended cleanly (False on RST or close)."""
        status: int | None = None
        body = b""
        for event in await self.drain_events():
            if isinstance(event, zttp.Response) and event.stream_id == stream_id:
                status = event.status_code
            elif isinstance(event, zttp.Data) and event.stream_id == stream_id:
                body += event.data
            elif isinstance(event, zttp.EndOfMessage) and event.stream_id == stream_id:
                return status, body, True
            elif isinstance(event, zttp.RstStream) and event.stream_id == stream_id:
                break
        return status, body, False


@asynccontextmanager
async def _h2_connection(port: int) -> AsyncIterator[Any]:
    from httpunk.asyncio import H2ClientProtocol

    loop = asyncio.get_event_loop()
    _transport, proto = await loop.create_connection(
        lambda: H2ClientProtocol(authority=f"127.0.0.1:{port}", scheme="http"), "127.0.0.1", port
    )
    try:
        yield await proto.ready()
    finally:
        await proto.aclose()


@skip_if_no_httpunk
async def test_get_request(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"Hello, world"})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 200
    assert body == b"Hello, world"
    assert dict(response.headers.items()).get("server") == b"uvicorn"


@skip_if_no_httpunk
async def test_request_scope(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        http_scope = cast("HTTPScope", scope)
        body = "|".join(
            [
                http_scope["http_version"],
                http_scope["method"],
                http_scope["root_path"],
                http_scope["path"],
                http_scope["query_string"].decode(),
            ]
        ).encode()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    config = Config(
        app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning", root_path="/api"
    )
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/items?a=1&b=2", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 200
    assert body == b"2|GET|/api|/api/items|a=1&b=2"


@skip_if_no_httpunk
async def test_post_request_body(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
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

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request(
                "POST", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"}, body=b"request-payload"
            )
            body = await response.read()
    assert response.status == 200
    assert body == b"request-payload"


@skip_if_no_httpunk
async def test_streaming_response(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"chunk-1", "more_body": True})
        await asyncio.sleep(0.01)
        await send({"type": "http.response.body", "body": b"chunk-2", "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 200
    assert body == b"chunk-1chunk-2"


@skip_if_no_httpunk
async def test_destreamed_response(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    """A multi-part body completed without suspending may collapse into a single response."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"part-1;", "more_body": True})
        await send({"type": "http.response.body", "body": b"part-2", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 200
    assert body == b"part-1;part-2"


@skip_if_no_httpunk
async def test_streaming_response_backpressure(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    """Several chunks emitted within one loop tick, then more after suspending."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"a" * 1024, "more_body": True})
        await send({"type": "http.response.body", "body": b"b" * 1024, "more_body": True})
        await send({"type": "http.response.body", "body": b"c" * 1024, "more_body": True})
        await asyncio.sleep(0.01)
        await send({"type": "http.response.body", "body": b"d" * 1024, "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 200
    assert body == b"a" * 1024 + b"b" * 1024 + b"c" * 1024 + b"d" * 1024


@skip_if_no_httpunk
async def test_client_disconnect_mid_stream(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    """A client vanishing mid-streaming-response must not take the server down."""
    sending = asyncio.Event()
    gone = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"x" * 1024, "more_body": True})
        sending.set()
        await gone.wait()
        await send({"type": "http.response.body", "body": b"y" * 1024, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        loop = asyncio.get_event_loop()
        from httpunk.asyncio import H2ClientProtocol

        transport, proto = await loop.create_connection(
            lambda: H2ClientProtocol(authority=f"127.0.0.1:{unused_tcp_port}", scheme="http"),
            "127.0.0.1",
            unused_tcp_port,
        )
        conn = await proto.ready()
        request = conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
        task = asyncio.ensure_future(request)
        await sending.wait()
        transport.abort()
        gone.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, OSError):
            await task
        await asyncio.sleep(0.05)

        async with _h2_connection(unused_tcp_port) as conn2:
            response = await conn2.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            sending.clear()
            gone.set()
            body = await response.read()
    assert response.status == 200
    assert body == b"x" * 1024 + b"y" * 1024


@skip_if_no_httpunk
async def test_concurrent_streams(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        http_scope = cast("HTTPScope", scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": http_scope["path"].encode()})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config) as server:
        async with _h2_connection(unused_tcp_port) as conn:

            async def one(i: int) -> bytes:
                response = await conn.request("GET", f"/{i}", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
                return await response.read()

            results = await asyncio.gather(*(one(i) for i in range(6)))
    assert results == [f"/{i}".encode() for i in range(6)]
    assert server.server_state.total_requests == 6


@skip_if_no_httpunk
async def test_app_exception_returns_500(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        raise RuntimeError("boom")

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 500
    assert body == b"Internal Server Error"
    assert dict(response.headers.items()).get("server") == b"uvicorn"


@skip_if_no_httpunk
async def test_no_response_returns_500(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        return

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            await response.read()
    assert response.status == 500


@skip_if_no_httpunk
async def test_app_exception_after_start_before_body(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    """A crash between `http.response.start` and the body (here: ASGI misuse, a second
    start) must not take the connection down: the stream fails alone, siblings work."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        if cast("HTTPScope", scope)["path"] == "/boom":
            await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="critical")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            with contextlib.suppress(Exception):  # zttp resets the stream; httpunk answers 500
                response = await conn.request("GET", "/boom", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
                assert response.status == 500
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert (response.status, body) == (200, b"ok")


@skip_if_no_httpunk
async def test_app_exception_mid_stream_fails_only_its_stream(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        if cast("HTTPScope", scope)["path"] == "/boom":
            await send({"type": "http.response.body", "body": b"partial", "more_body": True})
            await asyncio.sleep(0.05)  # genuinely streaming: the first chunk is on the wire
            raise RuntimeError("boom")
        await send({"type": "http.response.body", "body": b"ok"})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="critical")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/boom", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            assert response.status == 200
            with pytest.raises(Exception):  # truncated by RST_STREAM  # noqa: B017
                await response.read()
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert (response.status, body) == (200, b"ok")


@skip_if_no_httpunk
async def test_client_disconnect_mid_upload_disconnects_the_app(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    disconnected = asyncio.Event()
    uploading = asyncio.Event()
    gone = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected.set()
                return
            uploading.set()

    async def body() -> AsyncIterator[bytes]:
        yield b"x" * 1024
        yield b"x" * 1024  # httpunk's sender holds one chunk back: the first is flushed by the second
        await gone.wait()

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        from httpunk.asyncio import H2ClientProtocol

        loop = asyncio.get_event_loop()
        transport, proto = await loop.create_connection(
            lambda: H2ClientProtocol(authority=f"127.0.0.1:{unused_tcp_port}", scheme="http"),
            "127.0.0.1",
            unused_tcp_port,
        )
        conn = await proto.ready()
        task = asyncio.ensure_future(conn.request("POST", "/", headers={"host": "x"}, body=body()))
        await uploading.wait()
        transport.abort()
        gone.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
        await asyncio.wait_for(disconnected.wait(), 2)


@skip_if_no_httpunk
async def test_keep_alive_timeout_closes_idle_h2_connection(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    app = Response("Hello, world", media_type="text/plain")
    config = Config(
        app=app,
        loop="asyncio",
        port=unused_tcp_port,
        http=http2_protocol_cls,
        log_level="warning",
        timeout_keep_alive=1,
    )
    async with run_server(config):
        from httpunk.asyncio import H2ClientProtocol

        loop = asyncio.get_event_loop()
        transport, proto = await loop.create_connection(
            lambda: H2ClientProtocol(authority=f"127.0.0.1:{unused_tcp_port}", scheme="http"),
            "127.0.0.1",
            unused_tcp_port,
        )
        conn = await proto.ready()
        response = await conn.request("GET", "/", headers={"host": "x"})
        assert await response.read() == b"Hello, world"
        # Idle now: the server must GOAWAY + close by itself within the timeout; the
        # client marks the connection `closed` on either.
        for _ in range(60):
            if conn.closed:
                break
            await asyncio.sleep(0.05)
        assert conn.closed
        await proto.aclose()


@skip_if_no_httpunk
async def test_connection_specific_response_headers_are_stripped(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"Connection", b"close"),
                    (b"Keep-Alive", b"timeout=5"),
                    (b"TE", b"gzip"),
                    (b"X-Custom", b"kept"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            await response.read()
    headers = dict(response.headers.items())
    assert response.status == 200
    assert "connection" not in headers
    assert "keep-alive" not in headers
    assert headers.get("x-custom") == b"kept"
    assert "te" not in headers


@skip_if_no_httpunk
async def test_limit_concurrency_returns_503(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:  # pragma: no cover
        # Never invoked: the concurrency limit replaces the app with uvicorn's own 503 response.
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    config = Config(
        app=app,
        loop="asyncio",
        port=unused_tcp_port,
        http=http2_protocol_cls,
        log_level="warning",
        limit_concurrency=1,
    )
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await response.read()
    assert response.status == 503
    assert body == b"Service Unavailable"


@skip_if_no_httpunk
async def test_reset_contextvars(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    var: contextvars.ContextVar[str] = contextvars.ContextVar("test_http2_ctx", default="default")
    var.set("outer")
    seen: dict[str, str] = {}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        seen["value"] = var.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    config = Config(
        app=app,
        loop="asyncio",
        port=unused_tcp_port,
        http=http2_protocol_cls,
        log_level="warning",
        reset_contextvars=True,
    )
    async with run_server(config):
        async with _h2_connection(unused_tcp_port) as conn:
            response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            await response.read()
    assert response.status == 200
    assert seen["value"] == "default"


@skip_if_no_zttp_h2
async def test_head_request_has_no_body(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"Hello, world", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request(b"HEAD")
            status, body, _ = await wire.read_response(stream.stream_id)
    assert status == 200
    assert body == b""


@skip_if_no_zttp_h2
async def test_204_response_has_no_body(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request()
            status, body, ended = await wire.read_response(stream.stream_id)
    assert status == 204
    assert body == b""
    assert ended


@skip_if_no_zttp_h2
async def test_partial_response_resets_stream(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request()
            _, _, ended = await wire.read_response(stream.stream_id)
    assert not ended  # RST_STREAM, not a falsely-complete response


@skip_if_no_zttp_h2
async def test_unexpected_message_after_start_affects_only_its_stream(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    """ASGI misuse on one stream (a second `http.response.start`) must not take the
    whole connection down: the stream fails, sibling streams keep working."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        if cast("HTTPScope", scope)["path"] == "/boom":
            await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="critical")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            bad = wire.request(target=b"/boom")
            status, _, ended = await wire.read_response(bad.stream_id)
            assert not (status == 200 and ended)  # a reset or a 500 — never a clean 200
            good = wire.request(target=b"/")
            status, body, ended = await wire.read_response(good.stream_id)
    assert (status, body, ended) == (200, b"ok", True)


@skip_if_no_zttp_h2
async def test_app_exception_mid_stream_resets_only_its_stream(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        if cast("HTTPScope", scope)["path"] == "/boom":
            await send({"type": "http.response.body", "body": b"partial", "more_body": True})
            await asyncio.sleep(0.05)  # genuinely streaming: the first chunk is on the wire
            raise RuntimeError("boom")
        await send({"type": "http.response.body", "body": b"ok"})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="critical")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            bad = wire.request(target=b"/boom")
            status, _, ended = await wire.read_response(bad.stream_id)
            assert status == 200 and not ended  # truncated by RST_STREAM
            good = wire.request(target=b"/")
            status, body, ended = await wire.read_response(good.stream_id)
    assert (status, body, ended) == (200, b"ok", True)


@skip_if_no_zttp_h2
async def test_response_shorter_than_content_length_resets_stream(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"10")]})
        await send({"type": "http.response.body", "body": b"short", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request()
            _, _, ended = await wire.read_response(stream.stream_id)
    assert not ended


@skip_if_no_zttp_h2
async def test_response_longer_than_content_length_resets_stream(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"too long", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request()
            _, _, ended = await wire.read_response(stream.stream_id)
    assert not ended


@skip_if_no_zttp_h2
async def test_response_body_before_start_returns_500(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.body", "body": b"oops", "more_body": False})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request()
            status, body, _ = await wire.read_response(stream.stream_id)
    assert status == 500
    assert body == b"Internal Server Error"


@skip_if_no_zttp_h2
async def test_rst_stream_disconnects_the_app(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    disconnected = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        message = await receive()
        if message["type"] == "http.disconnect":
            disconnected.set()

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            # RST_STREAM with CANCEL aborts the stream before the request body arrived.
            stream = wire.request(b"POST", end=False)
            await wire.drain_events(timeout=0.1)
            wire.rst_stream(stream.stream_id)
            await asyncio.wait_for(disconnected.wait(), 2)


@skip_if_no_zttp_h2
async def test_connection_lost_disconnects_the_app(http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int):
    disconnected = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        message = await receive()
        if message["type"] == "http.disconnect":
            disconnected.set()

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            wire.request(b"POST", end=False)
            await wire.drain_events(timeout=0.1)
            wire.writer.close()
            await asyncio.wait_for(disconnected.wait(), 2)


async def _read_eof(reader: asyncio.StreamReader, conn: Any, timeout: float) -> list[Any]:
    """Read until the peer closes, returning the parsed events; fails on `timeout`."""
    events: list[Any] = []

    async def read() -> None:
        while data := await reader.read(65536):
            conn.receive_data(data)
            while (event := conn.next_event()) is not zttp.NEED_DATA:
                events.append(event)

    await asyncio.wait_for(read(), timeout)
    return events


@skip_if_no_zttp_h2
async def test_client_goaway_closes_idle_connection_on_the_wire(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    """A client GOAWAY on an idle connection: the server acknowledges with its own
    GOAWAY and then actually closes the socket, rather than lingering."""
    app = Response("Hello, world", media_type="text/plain")
    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=http2_protocol_cls, log_level="warning")
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request()
            status, _, ended = await wire.read_response(stream.stream_id)
            assert (status, ended) == (200, True)
            wire.send_frame(0x07, 0, 0, (0).to_bytes(4, "big") + (0).to_bytes(4, "big"))  # GOAWAY(0, NO_ERROR)
            events = await _read_eof(wire.reader, wire.conn, timeout=2)
            assert any(isinstance(event, zttp.GoAway) for event in events)


@skip_if_no_zttp_h2
async def test_keep_alive_timeout_closes_idle_connection_on_the_wire(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    app = Response("Hello, world", media_type="text/plain")
    config = Config(
        app=app,
        loop="asyncio",
        port=unused_tcp_port,
        http=http2_protocol_cls,
        log_level="warning",
        timeout_keep_alive=1,
    )
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            stream = wire.request()
            status, _, ended = await wire.read_response(stream.stream_id)
            assert (status, ended) == (200, True)
            # Idle now: the server must GOAWAY and close by itself within the timeout.
            events = await _read_eof(wire.reader, wire.conn, timeout=3)
            assert any(isinstance(event, zttp.GoAway) for event in events)


@skip_if_no_zttp_h2
async def test_keep_alive_timeout_waits_for_in_flight_streams(
    http2_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):
    """The timer only runs while NO stream is in flight: a slow stream outliving the
    timeout must not get its connection closed under it."""
    release = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if cast("HTTPScope", scope)["path"] == "/slow":
            await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    config = Config(
        app=app,
        loop="asyncio",
        port=unused_tcp_port,
        http=http2_protocol_cls,
        log_level="warning",
        timeout_keep_alive=1,
    )
    async with run_server(config):
        async with WireH2Client.connect(unused_tcp_port) as wire:
            slow = wire.request(target=b"/slow")
            await asyncio.sleep(1.5)  # longer than the keep-alive timeout
            fast = wire.request(target=b"/")
            status, body, ended = await wire.read_response(fast.stream_id)
            assert (status, body, ended) == (200, b"ok", True)  # connection still alive
            release.set()
            status, body, ended = await wire.read_response(slow.stream_id)
            assert (status, body, ended) == (200, b"ok", True)


# --- Configuration -------------------------------------------------------------


@skip_if_no_httpunk
async def test_config_httpunk_loads_http1_protocol():
    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

    config = Config(app=Response("ok"), http="httpunk")
    config.load()
    assert config.http_protocol_class is HTTPunkH1Protocol


@skip_if_no_httpunk
async def test_config_http2_loads_httpunk_negotiator():
    from uvicorn.protocols.http.httpunk_impl import HTTPunkAutoProtocol

    config = Config(app=Response("ok"), http="httpunk", http2=True)
    config.load()
    assert config.http_protocol_class is HTTPunkAutoProtocol
    assert config.http_protocol_class.alpn_protocols == ["h2", "http/1.1"]


# --- HTTP/1 and protocol internals ------------------------------------------------
@skip_if_no_httpunk
async def test_start_only_response(unused_tcp_port: int):
    """An app that starts a response but never completes it truncates the connection,
    matching h11's behaviour on an incomplete response."""
    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})

    config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=HTTPunkH1Protocol, log_level="critical")
    async with run_server(config):
        with pytest.raises(httpx2.RemoteProtocolError):
            async with httpx2.AsyncClient() as client:
                await client.get(f"http://127.0.0.1:{unused_tcp_port}/")


@skip_if_no_httpunk
async def test_body_handoff_abort_releases_parked_consumer():
    """abort() wakes a consumer parked in __anext__, which then raises _StreamAborted
    (truncating the wire response); later puts from the producer are silent no-ops."""
    from uvicorn.protocols.http.httpunk_impl import _BodyHandoff, _StreamAborted

    handoff = _BodyHandoff(asyncio.get_event_loop())
    consumer = asyncio.ensure_future(handoff.__anext__())
    await asyncio.sleep(0)  # let the consumer park in its get-waiter
    handoff.abort()
    with pytest.raises(_StreamAborted):
        await consumer
    await handoff.put(b"late", True)  # producer outlives the abort: dropped, no park


@skip_if_no_httpunk
async def test_body_handoff_abort_releases_parked_producer():
    """A non-empty chunk behind an unconsumed one parks the producer (backpressure);
    abort() releases it without delivering the chunk. Empty non-final puts are no-ops."""
    from uvicorn.protocols.http.httpunk_impl import _BodyHandoff

    handoff = _BodyHandoff(asyncio.get_event_loop())
    await handoff.put(b"first", True)  # slot free: returns without parking
    await handoff.put(b"", True)  # empty non-final chunk: nothing to hand over
    producer = asyncio.ensure_future(handoff.put(b"second", True))
    await asyncio.sleep(0)  # let the producer park on the occupied slot
    assert not producer.done()
    handoff.abort()
    await producer  # released by the abort, the parked chunk is dropped


@skip_if_no_httpunk
@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"connection": b"Upgrade", "upgrade": b"websocket"}, True),
        ({"connection": b"keep-alive, Upgrade", "upgrade": b"WebSocket"}, True),
        ({"connection": b"keep-alive"}, False),
        ({"connection": b"Upgrade", "upgrade": b"h2c"}, False),
    ],
)
@skip_if_no_httpunk
def test_is_ws_upgrade(headers: dict[str, bytes], expected: bool):
    from uvicorn.protocols.http.httpunk_impl import _is_ws_upgrade

    class _Headers:
        def __init__(self, data: dict[str, bytes]) -> None:
            self._data = data

        def items(self):
            return self._data.items()

    class _Request:
        def __init__(self, data: dict[str, bytes]) -> None:
            self.headers = _Headers(data)

    assert _is_ws_upgrade(_Request(headers)) is expected


@skip_if_no_httpunk
async def test_init_loads_config():
    """Constructing a protocol with an unloaded config loads it (config.load())."""
    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

    async def app(
        scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None: ...  # pragma: no cover - never invoked, just a valid ASGI target

    config = Config(app=app)
    assert not config.loaded
    protocol = HTTPunkH1Protocol(config=config, server_state=ServerState(), app_state={})
    assert config.loaded
    assert protocol.app is not None


@skip_if_no_httpunk
async def test_access_log(unused_tcp_port: int):
    """With the access log enabled, each request is logged."""
    import logging

    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    records: list[logging.LogRecord] = []

    class _RecordingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _RecordingHandler()
    access_logger = logging.getLogger("uvicorn.access")
    access_logger.addHandler(handler)
    config: Config = Config(
        app=app,
        loop="asyncio",
        port=unused_tcp_port,
        http=HTTPunkH1Protocol,
        access_log=True,
        log_level="info",
        log_config=None,
    )
    try:
        async with run_server(config):
            async with httpx2.AsyncClient() as client:
                response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    finally:
        access_logger.removeHandler(handler)
    assert response.status_code == 200
    assert any('"GET / HTTP/1.1" 200' in record.getMessage() for record in records)


@skip_if_no_httpunk
async def test_keepalive_and_total_requests(unused_tcp_port: int):
    """Sequential requests reuse the connection and are counted in `total_requests`."""
    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    config: Config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=HTTPunkH1Protocol, log_level="warning")
    async with run_server(config) as server:
        async with httpx2.AsyncClient() as client:
            await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
            await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert server.server_state.total_requests == 2


@skip_if_no_httpunk
async def test_h1_post_request_body(unused_tcp_port: int):
    """httpunk drives its own serve loop over a real transport, so it can't run through
    `test_http.py`'s synchronous MockTransport harness; exercise its HTTP/1 body path here."""
    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

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

    config: Config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=HTTPunkH1Protocol, log_level="warning")
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.post(f"http://127.0.0.1:{unused_tcp_port}/", content=b"request-payload")
    assert response.status_code == 200
    assert response.text == "request-payload"


@skip_if_no_httpunk
async def test_h1_streaming_response(unused_tcp_port: int):
    """The HTTP/1 chunked streaming path over a real transport."""
    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"tick;", "more_body": True})
        await asyncio.sleep(0.05)
        await send({"type": "http.response.body", "body": b"tock", "more_body": False})

    config: Config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=HTTPunkH1Protocol, log_level="warning")
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 200
    assert response.text == "tick;tock"
    assert response.headers.get("transfer-encoding") == "chunked"


@skip_if_no_httpunk
async def test_h1_app_exception_returns_500(unused_tcp_port: int):
    from uvicorn.protocols.http.httpunk_impl import HTTPunkH1Protocol

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        raise RuntimeError("boom")

    config: Config = Config(app=app, loop="asyncio", port=unused_tcp_port, http=HTTPunkH1Protocol, log_level="warning")
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert response.headers.get("server") == "uvicorn"


@skip_if_no_httpunk
async def test_auto_protocol_serves_h1_and_h2(unused_tcp_port: int):
    """`--http httpunk` sniffs the protocol per connection: an HTTP/1 request and an
    h2c prior-knowledge HTTP/2 request are both served on the same port."""
    from httpunk.asyncio import H2ClientProtocol

    from uvicorn.protocols.http.httpunk_impl import HTTPunkAutoProtocol

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        version: Any = scope.get("http_version")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": f"http/{version}".encode()})

    config: Config = Config(
        app=app, loop="asyncio", port=unused_tcp_port, http=HTTPunkAutoProtocol, log_level="warning"
    )
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
        assert response.text == "http/1.1"

        loop = asyncio.get_event_loop()
        _transport, proto = await loop.create_connection(
            lambda: H2ClientProtocol(authority=f"127.0.0.1:{unused_tcp_port}", scheme="http"),
            "127.0.0.1",
            unused_tcp_port,
        )
        try:
            conn = await proto.ready()
            h2_response = await conn.request("GET", "/", headers={"host": f"127.0.0.1:{unused_tcp_port}"})
            body = await h2_response.read()
        finally:
            await proto.aclose()
    assert body == b"http/2"

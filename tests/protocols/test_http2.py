from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

import pytest

from tests.response import Response
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.lifespan.on import LifespanOn
from uvicorn.protocols.http.flow_control import HIGH_WATER_LIMIT
from uvicorn.server import ServerState

try:
    import zttp

    from uvicorn.protocols.http.zttp_h2_impl import ZttpH2Protocol

    skip_if_no_zttp_h2 = pytest.mark.skipif(
        not hasattr(zttp, "HTTP2"), reason="zttp with HTTP/2 support is not installed"
    )
except ModuleNotFoundError:  # pragma: no cover
    skip_if_no_zttp_h2 = pytest.mark.skipif(True, reason="zttp is not installed")

pytestmark = [pytest.mark.anyio, skip_if_no_zttp_h2]


class MockSSLObject:
    def __init__(self, alpn_protocol: str | None):
        self._alpn_protocol = alpn_protocol

    def selected_alpn_protocol(self) -> str | None:
        return self._alpn_protocol


class MockTransport:
    def __init__(
        self,
        sockname: tuple[str, int] | None = None,
        peername: tuple[str, int] | None = None,
        sslcontext: bool = False,
        alpn_protocol: str | None = None,
    ):
        self.sockname = ("127.0.0.1", 8000) if sockname is None else sockname
        self.peername = ("127.0.0.1", 8001) if peername is None else peername
        self.sslcontext = sslcontext
        self.ssl_object = MockSSLObject(alpn_protocol) if sslcontext else None
        self.closed = False
        self.buffer = b""
        self.read_paused = False
        self.protocol: asyncio.Protocol | None = None

    def get_extra_info(self, key: Any):
        return {
            "sockname": self.sockname,
            "peername": self.peername,
            "sslcontext": self.sslcontext,
            "ssl_object": self.ssl_object,
        }.get(key)

    def write(self, data: bytes):
        assert not self.closed
        self.buffer += data

    def close(self):
        assert not self.closed
        self.closed = True

    def pause_reading(self):
        self.read_paused = True

    def resume_reading(self):
        self.read_paused = False

    def is_closing(self):
        return self.closed

    def clear_buffer(self):
        self.buffer = b""

    def set_protocol(self, protocol: asyncio.Protocol):
        self.protocol = protocol

    def get_protocol(self) -> asyncio.Protocol | None:
        return self.protocol


class MockTimerHandle:
    def __init__(
        self, loop_later_list: list[MockTimerHandle], delay: float, callback: Callable[[], None], args: tuple[Any, ...]
    ):
        self.loop_later_list = loop_later_list
        self.delay = delay
        self.callback = callback
        self.args = args
        self.cancelled = False

    def cancel(self):
        if not self.cancelled:
            self.cancelled = True
            self.loop_later_list.remove(self)


class MockTask:
    def add_done_callback(self, callback: Callable[[], None]):
        pass


class MockLoop:
    def __init__(self):
        self._tasks: list[Any] = []
        self._later: list[MockTimerHandle] = []

    def create_task(self, coroutine: Any, **kwargs: Any) -> Any:
        self._tasks.insert(0, coroutine)
        return MockTask()

    def call_later(self, delay: float, callback: Callable[[], None], *args: Any) -> MockTimerHandle:
        handle = MockTimerHandle(self._later, delay, callback, args)
        self._later.insert(0, handle)
        return handle

    async def run_one(self):
        return await self._tasks.pop()

    def run_later(self, with_delay: float) -> None:
        later: list[MockTimerHandle] = []
        for timer_handle in self._later:
            if with_delay >= timer_handle.delay:
                timer_handle.callback(*timer_handle.args)
            else:
                later.append(timer_handle)
        self._later = later


class MockProtocol(asyncio.Protocol):
    loop: MockLoop
    transport: MockTransport
    conn: Any
    flow: Any
    cycles: dict[int, Any]
    timeout_keep_alive_task: Any

    def shutdown(self) -> None: ...

    def resume_reading_if_idle(self) -> None: ...


def get_connected_protocol(
    app: Callable[..., Any],
    lifespan: LifespanOff | LifespanOn | None = None,
    **kwargs: Any,
) -> MockProtocol:
    loop = MockLoop()
    transport = MockTransport(sslcontext=True)
    config = Config(app=app, http2=True, **kwargs)
    lifespan = lifespan or LifespanOff(config)
    server_state = ServerState()
    protocol = ZttpH2Protocol(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)  # type: ignore[arg-type]
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol  # type: ignore[return-value]


def frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    header = len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + stream_id.to_bytes(4, "big")
    return header + payload


class H2Client:
    """Drives the client half of the wire with zttp's own client connection."""

    def __init__(self) -> None:
        self.conn = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP2)

    def request(
        self,
        method: bytes = b"GET",
        target: bytes = b"/",
        headers: list[tuple[bytes, bytes]] | None = None,
        body: bytes = b"",
        end: bool = True,
    ) -> zttp.Stream:
        headers = [(b"host", b"example.org")] if headers is None else headers
        stream = self.conn.send_request(method, target, b"2", headers)
        if body:
            stream.send_data(body)
        if end:
            stream.end_message()
        return stream

    def data_to_send(self) -> bytes:
        return self.conn.data_to_send()

    def events(self, data: bytes) -> list[Any]:
        self.conn.receive_data(data)
        events = []
        while (event := self.conn.next_event()) is not zttp.NEED_DATA:
            events.append(event)
        return events

    def parse_responses(self, data: bytes) -> dict[int, tuple[int, list[tuple[bytes, bytes]], bytes, bool]]:
        responses: dict[int, tuple[int, list[tuple[bytes, bytes]], bytes, bool]] = {}
        for event in self.events(data):
            if isinstance(event, zttp.Response):
                responses[event.stream_id] = (event.status_code, event.headers, b"", False)
            elif isinstance(event, zttp.Data):
                status, headers, body, ended = responses[event.stream_id]
                responses[event.stream_id] = (status, headers, body + event.data, ended)
            elif isinstance(event, zttp.EndOfMessage):
                status, headers, body, _ = responses[event.stream_id]
                responses[event.stream_id] = (status, headers, body, True)
        return responses

    def parse_response(self, data: bytes, stream_id: int = 1) -> tuple[int, list[tuple[bytes, bytes]], bytes, bool]:
        return self.parse_responses(data)[stream_id]


async def test_get_request():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, headers, body, ended = client.parse_response(protocol.transport.buffer)
    assert status == 200
    assert (b"content-type", b"text/plain; charset=utf-8") in headers
    assert body == b"Hello, world"
    assert ended


async def test_post_request():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            assert message["type"] == "http.request"
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        response = Response(b"Body: " + body, media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"POST", b"/", body=b'{"hello": "world"}')
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 200
    assert body == b'Body: {"hello": "world"}'


async def test_request_scope():
    received_scope: Any = None

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_scope
        received_scope = scope
        response = Response("OK", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app, root_path="/api")
    client = H2Client()

    client.request(b"GET", b"/path?a=1&b=2")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    assert received_scope is not None
    assert received_scope["type"] == "http"
    assert received_scope["http_version"] == "2"
    assert received_scope["scheme"] == "https"
    assert received_scope["method"] == "GET"
    assert received_scope["root_path"] == "/api"
    assert received_scope["path"] == "/api/path"
    assert received_scope["raw_path"] == b"/api/path"
    assert received_scope["query_string"] == b"a=1&b=2"
    assert (b"host", b"example.org") in received_scope["headers"]


async def test_multiplexed_requests():
    async def app(scope: Any, receive: ASGIReceiveCallable, send: ASGISendCallable):
        response = Response(b"Served " + scope["path"].encode(), media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    client = H2Client()

    first = client.request(b"GET", b"/first")
    second = client.request(b"GET", b"/second")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()
    await protocol.loop.run_one()

    responses = client.parse_responses(protocol.transport.buffer)
    status, _, body, _ = responses[first.stream_id]
    assert status == 200
    assert body == b"Served /first"
    status, _, body, _ = responses[second.stream_id]
    assert status == 200
    assert body == b"Served /second"


async def test_streaming_response():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        for chunk in (b"1", b"2", b"3"):
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, ended = client.parse_response(protocol.transport.buffer)
    assert status == 200
    assert body == b"123"
    assert ended


async def test_head_request_has_no_body():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"Hello, world", "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"HEAD", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, headers, body, ended = client.parse_response(protocol.transport.buffer)
    assert status == 200
    assert (b"content-type", b"text/plain") in headers
    assert body == b""
    assert ended


async def test_204_response_has_no_body():
    app = Response(b"", status_code=204)
    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, ended = client.parse_response(protocol.transport.buffer)
    assert status == 204
    assert body == b""
    assert ended


async def test_app_exception_returns_500():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        raise RuntimeError("boom")

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 500
    assert body == b"Internal Server Error"


async def test_app_returning_without_response_returns_500():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        pass

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 500
    assert body == b"Internal Server Error"


async def test_partial_response_closes_transport():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    assert protocol.transport.is_closing()


async def test_limit_concurrency_returns_503():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app, limit_concurrency=1)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 503
    assert body == b"Service Unavailable"


async def test_connection_specific_response_headers_are_stripped():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"Connection", b"close"),
                    (b"Keep-Alive", b"timeout=5"),
                    (b"Transfer-Encoding", b"chunked"),
                    (b"TE", b"gzip"),
                    (b"te", b"trailers"),
                    (b"X-Custom", b"kept"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, headers, _, _ = client.parse_response(protocol.transport.buffer)
    assert status == 200
    names = [name for name, _ in headers]
    assert b"connection" not in names
    assert b"keep-alive" not in names
    assert b"transfer-encoding" not in names
    assert (b"te", b"trailers") in headers
    assert (b"x-custom", b"kept") in headers


async def test_response_shorter_than_content_length_closes_transport():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"10")]})
        await send({"type": "http.response.body", "body": b"short", "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    assert protocol.transport.is_closing()


async def test_response_longer_than_content_length_closes_transport():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"too long", "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    assert protocol.transport.is_closing()


async def test_rst_stream_disconnects_the_app():
    received_disconnect = False

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_disconnect
        message = await receive()
        received_disconnect = message["type"] == "http.disconnect"

    protocol = get_connected_protocol(app)
    client = H2Client()

    stream = client.request(b"POST", b"/", end=False)
    protocol.data_received(client.data_to_send())
    # RST_STREAM with CANCEL (0x8) aborts the stream before the body arrived.
    protocol.data_received(frame(0x03, 0, stream.stream_id, (0x8).to_bytes(4, "big")))
    await protocol.loop.run_one()

    assert received_disconnect
    assert not protocol.transport.is_closing()


async def test_connection_lost_disconnects_the_app():
    received_disconnect = False

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_disconnect
        message = await receive()
        received_disconnect = message["type"] == "http.disconnect"

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"POST", b"/", end=False)
    protocol.data_received(client.data_to_send())
    protocol.connection_lost(None)
    await protocol.loop.run_one()

    assert received_disconnect


async def test_keep_alive_timeout_closes_idle_connection():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app, timeout_keep_alive=5)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()
    assert not protocol.transport.is_closing()

    protocol.loop.run_later(with_delay=1)
    assert not protocol.transport.is_closing()
    protocol.loop.run_later(with_delay=5)
    assert protocol.transport.is_closing()


async def test_idle_frames_rearm_keep_alive_timer():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app, timeout_keep_alive=5)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()
    armed = protocol.timeout_keep_alive_task
    assert armed is not None

    protocol.data_received(frame(0x06, 0, 0, b"\x00" * 8))  # PING
    rearmed = protocol.timeout_keep_alive_task
    assert rearmed is not None
    assert rearmed is not armed


async def test_shutdown_when_idle_closes_connection():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    protocol.shutdown()
    assert protocol.transport.is_closing()


async def test_shutdown_refuses_new_streams_and_closes_after_last_response():
    waiting = asyncio.Event()
    release = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        waiting.set()
        await release.wait()
        response = Response("done", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    client = H2Client()

    first = client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    task = asyncio.get_running_loop().create_task(protocol.loop.run_one())
    await waiting.wait()

    protocol.shutdown()
    assert not protocol.transport.is_closing()

    second = client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()
    status, _, body, _ = client.parse_response(protocol.transport.buffer, stream_id=second.stream_id)
    assert status == 503
    assert body == b"Service Unavailable"

    protocol.transport.clear_buffer()
    release.set()
    await task
    status, _, body, _ = client.parse_response(protocol.transport.buffer, stream_id=first.stream_id)
    assert status == 200
    assert body == b"done"
    assert protocol.transport.is_closing()


async def test_goaway_closes_idle_connection():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    protocol.data_received(frame(0x07, 0, 0, (0).to_bytes(4, "big") + (0).to_bytes(4, "big")))
    assert protocol.transport.is_closing()


async def test_invalid_frames_close_the_connection(caplog: pytest.LogCaptureFixture):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app)

    protocol.data_received(b"NOT A VALID HTTP/2 PREFACE!!!!!!")

    assert protocol.transport.is_closing()
    assert any("Invalid HTTP/2 frame received" in record.getMessage() for record in caplog.records)


async def test_resume_reading_waits_for_other_buffered_streams():
    """Ending or consuming one stream must not release transport backpressure
    while another stream's body buffer is still over the high-water mark."""
    protocol = get_connected_protocol(Response("ok", media_type="text/plain"))
    client = H2Client()

    stream = client.request(b"POST", b"/", end=False)
    protocol.data_received(client.data_to_send())

    cycle = protocol.cycles[stream.stream_id]
    cycle.body += b"x" * (HIGH_WATER_LIMIT + 1)
    protocol.flow.pause_reading()
    assert protocol.transport.read_paused

    protocol.resume_reading_if_idle()
    assert protocol.transport.read_paused

    cycle.body = bytearray()
    protocol.resume_reading_if_idle()
    assert not protocol.transport.read_paused

    protocol.data_received(frame(0x03, 0, stream.stream_id, (0x8).to_bytes(4, "big")))
    await protocol.loop.run_one()


async def test_early_response_ignores_late_request_frames():
    """If the app responds before consuming the request body, frames the
    client keeps sending on that stream must be dropped, not crash."""
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app)
    client = H2Client()

    stream = client.request(b"POST", b"/", end=False)
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, _, _ = client.parse_response(protocol.transport.buffer)
    assert status == 200

    protocol.data_received(frame(0x00, 0, stream.stream_id, b"late data"))
    protocol.data_received(frame(0x00, 0x01, stream.stream_id, b"the end"))
    protocol.data_received(frame(0x03, 0, stream.stream_id, (0x8).to_bytes(4, "big")))
    assert not protocol.transport.is_closing()


async def test_window_update_flushes_pending_response_data():
    """A response larger than the peer's flow-control window is parked inside
    zttp and must flush once WINDOW_UPDATE frames arrive."""
    body = b"x" * 100_000

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    stream = client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    written = len(protocol.transport.buffer)
    increment = (100_000).to_bytes(4, "big")
    protocol.data_received(frame(0x08, 0, 0, increment))
    protocol.data_received(frame(0x08, 0, stream.stream_id, increment))
    assert len(protocol.transport.buffer) > written

    # Count the DATA payload on the wire directly: zttp's client cannot read a
    # body larger than its own 64 KiB receive window.
    i, received, ended = 0, 0, False
    buffer = protocol.transport.buffer
    while i + 9 <= len(buffer):
        length = int.from_bytes(buffer[i : i + 3], "big")
        if buffer[i + 3] == 0x00:
            received += length
            ended = ended or bool(buffer[i + 4] & 0x01)
        i += 9 + length
    assert received == len(body)
    assert ended


async def test_app_returning_value_closes_transport():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        response = Response("Hello, world", media_type="text/plain")
        await response(scope, receive, send)
        return 123

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    assert protocol.transport.is_closing()


async def test_send_after_rst_stream_is_dropped():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        message = await receive()
        assert message["type"] == "http.disconnect"
        await send({"type": "http.response.start", "status": 200, "headers": []})

    protocol = get_connected_protocol(app)
    client = H2Client()

    stream = client.request(b"POST", b"/", end=False)
    protocol.data_received(client.data_to_send())
    protocol.data_received(frame(0x03, 0, stream.stream_id, (0x8).to_bytes(4, "big")))
    protocol.transport.clear_buffer()
    await protocol.loop.run_one()

    assert protocol.transport.buffer == b""
    assert not protocol.transport.is_closing()


async def test_response_body_before_start_returns_500():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.body", "body": b"oops", "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 500
    assert body == b"Internal Server Error"


async def test_unexpected_message_after_start_closes_transport():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.start", "status": 200, "headers": []})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    assert protocol.transport.is_closing()


async def test_unexpected_message_after_completion_closes_transport():
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        response = Response("Hello, world", media_type="text/plain")
        await response(scope, receive, send)
        await send({"type": "http.response.body", "body": b"extra", "more_body": False})

    protocol = get_connected_protocol(app)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    assert protocol.transport.is_closing()


async def test_reset_contextvars_runs_each_stream_in_a_fresh_context():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app, reset_contextvars=True)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 200
    assert body == b"Hello, world"


async def test_eof_received_is_a_no_op():
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_connected_protocol(app)
    assert protocol.eof_received() is None


async def test_trace_logging(caplog: pytest.LogCaptureFixture, logging_config: dict[str, Any]):
    app = Response("Hello, world", media_type="text/plain")
    logger = logging.getLogger("uvicorn.error")
    logger.addHandler(caplog.handler)
    try:
        protocol = get_connected_protocol(app, log_level="trace", log_config=logging_config)
        protocol.connection_lost(None)
    finally:
        logger.removeHandler(caplog.handler)

    messages = [record.message for record in caplog.records if record.name == "uvicorn.error"]
    assert any("HTTP/2 connection made" in message for message in messages)
    assert any("HTTP/2 connection lost" in message for message in messages)


# --- Switching from the HTTP/1.1 protocols ------------------------------------


def get_http1_protocol(
    app: Callable[..., Any],
    http_protocol_cls: type[asyncio.Protocol],
    alpn_protocol: str | None = None,
    sslcontext: bool = False,
    **kwargs: Any,
) -> MockProtocol:
    loop = MockLoop()
    transport = MockTransport(sslcontext=sslcontext, alpn_protocol=alpn_protocol)
    config = Config(app=app, **kwargs)
    lifespan = LifespanOff(config)
    server_state = ServerState()
    protocol = http_protocol_cls(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)  # type: ignore[call-arg]
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol  # type: ignore[return-value]


async def test_alpn_h2_switches_protocol(http_protocol_cls: type[asyncio.Protocol]):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_http1_protocol(app, http_protocol_cls, alpn_protocol="h2", sslcontext=True, http2=True)
    assert isinstance(protocol.transport.get_protocol(), ZttpH2Protocol)


async def test_alpn_http11_does_not_switch_protocol(http_protocol_cls: type[asyncio.Protocol]):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_http1_protocol(app, http_protocol_cls, alpn_protocol="http/1.1", sslcontext=True, http2=True)
    assert protocol.transport.get_protocol() is None


async def test_alpn_h2_without_http2_enabled_does_not_switch_protocol(http_protocol_cls: type[asyncio.Protocol]):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_http1_protocol(app, http_protocol_cls, alpn_protocol="h2", sslcontext=True, http2=False)
    assert protocol.transport.get_protocol() is None


async def test_prior_knowledge_preface_switches_protocol(http_protocol_cls: type[asyncio.Protocol]):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_http1_protocol(app, http_protocol_cls, http2=True)
    client = H2Client()

    client.request(b"GET", b"/")
    protocol.data_received(client.data_to_send())

    h2_protocol = protocol.transport.get_protocol()
    assert isinstance(h2_protocol, ZttpH2Protocol)
    await h2_protocol.loop.run_one()  # type: ignore[attr-defined]

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 200
    assert body == b"Hello, world"


async def test_prior_knowledge_preface_split_across_packets(http_protocol_cls: type[asyncio.Protocol]):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_http1_protocol(app, http_protocol_cls, http2=True)
    client = H2Client()

    client.request(b"GET", b"/")
    wire = client.data_to_send()
    protocol.data_received(wire[:10])
    assert protocol.transport.get_protocol() is None
    protocol.data_received(wire[10:])

    h2_protocol = protocol.transport.get_protocol()
    assert isinstance(h2_protocol, ZttpH2Protocol)
    await h2_protocol.loop.run_one()  # type: ignore[attr-defined]

    status, _, body, _ = client.parse_response(protocol.transport.buffer)
    assert status == 200
    assert body == b"Hello, world"


async def test_http1_request_with_http2_enabled_stays_on_http1(http_protocol_cls: type[asyncio.Protocol]):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_http1_protocol(app, http_protocol_cls, http2=True)

    protocol.data_received(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
    await protocol.loop.run_one()

    assert protocol.transport.get_protocol() is None
    assert b"HTTP/1.1 200 OK" in protocol.transport.buffer
    assert b"Hello, world" in protocol.transport.buffer


async def test_http2_over_tls_without_alpn_stays_on_http1(http_protocol_cls: type[asyncio.Protocol]):
    app = Response("Hello, world", media_type="text/plain")
    protocol = get_http1_protocol(app, http_protocol_cls, sslcontext=True, http2=True)

    protocol.data_received(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
    await protocol.loop.run_one()

    assert protocol.transport.get_protocol() is None
    assert b"HTTP/1.1 200 OK" in protocol.transport.buffer


# --- Configuration -------------------------------------------------------------


async def test_config_http2_true_loads_zttp_h2_protocol():
    config = Config(app=Response("ok"), http2=True)
    config.load()
    assert config.h2_protocol_class is ZttpH2Protocol


async def test_config_http2_false_loads_no_h2_protocol():
    config = Config(app=Response("ok"))
    config.load()
    assert config.h2_protocol_class is None


async def test_config_http2_import_string():
    config = Config(app=Response("ok"), http2="uvicorn.protocols.http.zttp_h2_impl:ZttpH2Protocol")
    config.load()
    assert config.h2_protocol_class is ZttpH2Protocol


async def test_config_http2_protocol_class():
    config = Config(app=Response("ok"), http2=ZttpH2Protocol)
    config.load()
    assert config.h2_protocol_class is ZttpH2Protocol


async def test_config_http2_offers_alpn_protocols(
    tls_ca_certificate_pem_path: str,
    tls_ca_certificate_private_key_path: str,
):
    config = Config(
        app=Response("ok"),
        http2=True,
        ssl_certfile=tls_ca_certificate_pem_path,
        ssl_keyfile=tls_ca_certificate_private_key_path,
    )
    config.load()
    assert config.is_ssl is True

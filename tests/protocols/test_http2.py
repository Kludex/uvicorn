from __future__ import annotations

import asyncio
from collections.abc import Callable
from ssl import SSLObject
from typing import TYPE_CHECKING, Any, cast

import pytest

from tests.response import Response
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope, WWWScope
from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.lifespan.on import LifespanOn
from uvicorn.server import ServerState

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.errors import ErrorCodes

    from uvicorn.protocols.http.h2_impl import H2Protocol

    skip_if_no_h2 = pytest.mark.skipif(False, reason="h2 is installed")
except ModuleNotFoundError:  # pragma: no cover
    skip_if_no_h2 = pytest.mark.skipif(True, reason="h2 is not installed")

if TYPE_CHECKING:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.errors import ErrorCodes


pytestmark = [pytest.mark.anyio, skip_if_no_h2]


class MockTransport:
    def __init__(
        self,
        sockname: tuple[str, int] | None = None,
        peername: tuple[str, int] | None = None,
        sslcontext: bool = True,
        ssl_object: SSLObject | None = None,
    ):
        self.sockname = ("127.0.0.1", 8000) if sockname is None else sockname
        self.peername = ("127.0.0.1", 8001) if peername is None else peername
        self.sslcontext = sslcontext
        self._ssl_object = ssl_object
        self.closed = False
        self.buffer = b""
        self.read_paused = False

    def get_extra_info(self, key: Any):
        return {
            "sockname": self.sockname,
            "peername": self.peername,
            "sslcontext": self.sslcontext,
            "ssl_object": self._ssl_object,
        }.get(key)

    def write(self, data: bytes):
        assert not self.closed
        self.buffer += data

    def close(self):
        assert not self.closed
        self.closed = True

    def pause_reading(self):  # pragma: no cover
        self.read_paused = True

    def resume_reading(self):
        self.read_paused = False

    def is_closing(self):
        return self.closed

    def clear_buffer(self):
        self.buffer = b""

    def set_protocol(self, protocol: asyncio.Protocol): ...


class MockTimerHandle:
    def __init__(
        self,
        loop_later_list: list[MockTimerHandle],
        delay: float,
        callback: Callable[[], None],
        args: tuple[Any, ...],
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


class MockLoop(asyncio.AbstractEventLoop):
    def __init__(self) -> None:
        self._tasks: list[asyncio.Task[Any]] = []
        self._later: list[MockTimerHandle] = []

    def create_task(self, coroutine: Any) -> MockTask:  # type: ignore[override]
        self._tasks.insert(0, coroutine)
        return MockTask()

    def call_later(self, delay: float, callback: Callable[[], None], *args: Any) -> MockTimerHandle:  # type: ignore[override]
        handle = MockTimerHandle(self._later, delay, callback, args)
        self._later.insert(0, handle)
        return handle

    async def run_one(self) -> Any:
        return await self._tasks.pop()

    def run_later(self, with_delay: float) -> None:
        later: list[MockTimerHandle] = []
        for timer_handle in self._later:
            if with_delay >= timer_handle.delay:
                timer_handle.callback(*timer_handle.args)
            else:  # pragma: no cover
                later.append(timer_handle)
        self._later = later


class MockTask:
    def add_done_callback(self, callback: Callable[[], None]):
        pass


class MockProtocol(asyncio.Protocol):
    """Type stub for protocol with mock transport and loop."""

    loop: MockLoop
    transport: MockTransport
    scope: Scope
    connections: set[Any]

    def shutdown(self) -> None: ...


def get_connected_protocol(
    app: Callable[..., Any],
    lifespan: LifespanOff | LifespanOn | None = None,
    **kwargs: Any,
) -> MockProtocol:
    loop = MockLoop()  # type: ignore[abstract]
    transport = MockTransport()
    config = Config(app=app, **kwargs)
    lifespan = lifespan or LifespanOff(config)
    server_state = ServerState()
    protocol = H2Protocol(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol  # type: ignore[return-value]


def create_h2_request(
    method: str = "GET",
    path: str = "/",
    headers: list[tuple[str, str]] | None = None,
    body: bytes | None = None,
) -> bytes:
    """Create an HTTP/2 request using h2 library."""
    config = H2Configuration(client_side=True, header_encoding="utf-8")
    conn = H2Connection(config=config)
    conn.initiate_connection()

    # Build headers
    request_headers = [
        (":method", method),
        (":path", path),
        (":scheme", "https"),
        (":authority", "example.org"),
    ]
    if headers:
        request_headers.extend(headers)

    # Determine if we're ending the stream with headers
    end_stream = body is None or len(body) == 0

    # Send headers
    conn.send_headers(1, request_headers, end_stream=end_stream)

    # Send body if provided (chunked to respect max frame size)
    if body:
        max_frame_size = conn.max_outbound_frame_size
        offset = 0
        while offset < len(body):
            chunk = body[offset : offset + max_frame_size]
            offset += len(chunk)
            is_last = offset >= len(body)
            conn.send_data(1, chunk, end_stream=is_last)

    return conn.data_to_send()


def parse_h2_response(data: bytes) -> tuple[int, dict[str, str], bytes]:
    """Parse HTTP/2 response data and return (status, headers, body)."""
    from h2.events import DataReceived, ResponseReceived

    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    # Simulate that we sent a request on stream 1
    request_headers = [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "localhost")]
    conn.send_headers(1, request_headers, end_stream=True)
    conn.clear_outbound_data_buffer()

    # Now parse the response
    events = conn.receive_data(data)

    status = 0
    headers: dict[str, str] = {}
    body = b""

    for event in events:
        if isinstance(event, ResponseReceived):
            for name, value in event.headers:
                if name == b":status":
                    status = int(value)
                else:
                    headers[name.decode("utf-8")] = value.decode("utf-8")
        elif isinstance(event, DataReceived):
            body += event.data

    return status, headers, body


async def test_get_request():
    app = Response("Hello, world", media_type="text/plain")

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    status, headers, body = parse_h2_response(protocol.transport.buffer)
    assert status == 200
    assert headers["content-type"] == "text/plain; charset=utf-8"
    assert body == b"Hello, world"


async def test_post_request():
    received_body = b""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_body
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            assert message["type"] == "http.request"
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        received_body = body
        response = Response(b"Body: " + body, media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    # Send HTTP/2 POST request with body
    request_data = create_h2_request(
        "POST",
        "/",
        headers=[("content-type", "application/json")],
        body=b'{"hello": "world"}',
    )
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    assert received_body == b'{"hello": "world"}'


async def test_scope_http_version():
    received_scope = None

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_scope
        received_scope = scope
        response = Response("OK", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    assert received_scope is not None
    assert received_scope["http_version"] == "2"
    assert received_scope["type"] == "http"


async def test_scope_path_and_query_string():
    received_scope = None

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_scope
        received_scope = scope
        response = Response("OK", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/test/path?foo=bar&baz=qux")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    assert received_scope is not None
    assert received_scope["path"] == "/test/path"
    assert received_scope["query_string"] == b"foo=bar&baz=qux"


async def test_head_request():
    app = Response("Hello, world", media_type="text/plain")

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("HEAD", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    status, headers, body = parse_h2_response(protocol.transport.buffer)
    assert status == 200
    assert headers["content-type"] == "text/plain; charset=utf-8"
    assert not body


async def test_app_exception():
    async def app(_scope: Scope, _receive: ASGIReceiveCallable, _send: ASGISendCallable):
        raise Exception("Test exception")

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    status, _, body = parse_h2_response(protocol.transport.buffer)
    assert status == 500
    assert body == b"Internal Server Error"


async def test_no_response_returned():
    async def app(_scope: Scope, _receive: ASGIReceiveCallable, _send: ASGISendCallable):
        pass  # App returns without sending response

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    status, _, body = parse_h2_response(protocol.transport.buffer)
    assert status == 500
    assert body == b"Internal Server Error"


async def test_max_concurrency():
    app = Response("Hello, world", media_type="text/plain")

    protocol = get_connected_protocol(app, limit_concurrency=1)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    status, _, body = parse_h2_response(protocol.transport.buffer)
    assert status == 503
    assert body == b"Service Unavailable"


async def test_shutdown_during_idle():
    app = Response("Hello, world", media_type="text/plain")

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    protocol.shutdown()
    assert protocol.transport.is_closing()


async def test_root_path() -> None:
    received_scope: WWWScope | None = None

    async def app(scope: WWWScope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_scope
        received_scope = scope
        response = Response("OK", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app, root_path="/api")
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/test")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    assert received_scope is not None
    assert received_scope["root_path"] == "/api"
    assert received_scope["path"] == "/api/test"


async def test_lifespan_state() -> None:
    expected_state = {"key": "value"}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        assert "state" in scope
        assert scope["state"]["key"] == "value"
        return await Response("Hi!")(scope, receive, send)

    lifespan = LifespanOn(config=Config(app=app))
    lifespan.state.update(expected_state)

    protocol = get_connected_protocol(app, lifespan=lifespan)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    status, _, body = parse_h2_response(protocol.transport.buffer)
    assert status == 200
    assert body == b"Hi!"


async def test_scope_extensions() -> None:
    """Test that HTTP/2 scope includes http.response.push extension."""
    received_scope: WWWScope | None = None

    async def app(scope: WWWScope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_scope
        received_scope = scope
        response = Response("OK", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    assert received_scope is not None
    assert "extensions" in received_scope
    assert "http.response.push" in received_scope["extensions"]


async def test_host_header_from_authority() -> None:
    """Test that :authority pseudo-header is converted to host header."""
    host_header: bytes | None = None

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        nonlocal host_header
        assert scope["type"] == "http"
        headers: dict[bytes, bytes] = dict(scope["headers"])
        host_header = headers.get(b"host")
        response = Response("OK", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    assert host_header == b"example.org"


async def test_server_push():
    """Test HTTP/2 server push via http.response.push."""
    push_received = False
    push_request_received = False

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal push_received, push_request_received
        if scope["type"] == "http" and scope["path"] == "/pushed.js":
            # This is the pushed request
            push_request_received = True
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"pushed content"})
            return

        # Send a push promise for the main request
        await send(
            {
                "type": "http.response.push",
                "path": "/pushed.js",
                "headers": [(b"content-type", b"application/javascript")],
            }
        )
        push_received = True
        # Then send the main response
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/html")],
            }
        )
        await send({"type": "http.response.body", "body": b"<html>Hello</html>"})

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    # Run the pushed request task as well
    await protocol.loop.run_one()

    assert push_received
    assert push_request_received

    status, headers, body = parse_h2_response(protocol.transport.buffer)
    assert status == 200
    assert headers["content-type"] == "text/html"
    assert body == b"<html>Hello</html>pushed content"


async def test_large_body():
    """Test handling of large request body with flow control."""
    received_body = b""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_body
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            assert message["type"] == "http.request"
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        received_body = body
        response = Response(f"Received {len(body)} bytes", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    # Create a large body (within default flow control window of 65535)
    large_body = b"x" * 32768  # 32KB
    request_data = create_h2_request(
        "POST",
        "/",
        headers=[("content-type", "application/octet-stream")],
        body=large_body,
    )
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    assert received_body == large_body


async def test_large_response_exceeding_flow_control_window():
    """Test that response body larger than the flow control window is fully sent.

    The default HTTP/2 flow control window is 65535 bytes. When the server sends
    more data than that, it must buffer the excess and flush it when the client
    sends WINDOW_UPDATE frames. Without proper buffering, the excess data is
    silently dropped and the response is truncated.
    """
    from h2.events import DataReceived

    large_body = b"x" * 100_000

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/octet-stream"),
                    (b"content-length", str(len(large_body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": large_body, "more_body": False})

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    # Set up a client-side h2 connection to simulate the round-trip
    client_config = H2Configuration(client_side=True, header_encoding="utf-8")
    client_conn = H2Connection(config=client_config)
    client_conn.initiate_connection()
    client_conn.send_headers(
        1,
        [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "example.org")],
        end_stream=True,
    )
    # Feed client preface + request to server
    protocol.data_received(client_conn.data_to_send())
    await protocol.loop.run_one()

    # Server has sent data up to the flow control window limit.
    received_body = b""
    server_data = protocol.transport.buffer
    protocol.transport.clear_buffer()

    events = client_conn.receive_data(server_data)
    for event in events:
        if isinstance(event, DataReceived):
            received_body += event.data

    # Send stream-level and connection-level WINDOW_UPDATEs separately so that
    # both branches in handle_window_updated are covered. If sent together, h2
    # opens both windows before returning events, and the first handler's flush
    # sends all data, leaving nothing for the second.
    client_conn.increment_flow_control_window(65535, stream_id=1)
    protocol.data_received(client_conn.data_to_send())

    client_conn.increment_flow_control_window(65535)
    protocol.data_received(client_conn.data_to_send())

    # Collect the remaining data the server flushed after the window updates
    if protocol.transport.buffer:
        events = client_conn.receive_data(protocol.transport.buffer)
        for event in events:
            if isinstance(event, DataReceived):
                received_body += event.data

    assert len(received_body) == 100_000
    assert received_body == large_body


async def test_multiple_requests_sequential() -> None:
    """Test multiple sequential requests on same connection."""
    request_count = 0
    paths_received: list[str] = []

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        nonlocal request_count
        request_count += 1
        if scope["type"] == "http":
            paths_received.append(scope["path"])
        response = Response(f"Request {request_count}", media_type="text/plain")
        await response(scope, receive, send)

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    # Create a client connection that sends two requests
    config = H2Configuration(client_side=True, header_encoding="utf-8")
    conn = H2Connection(config=config)
    conn.initiate_connection()

    # First request on stream 1
    conn.send_headers(
        1,
        [
            (":method", "GET"),
            (":path", "/first"),
            (":scheme", "https"),
            (":authority", "example.org"),
        ],
        end_stream=True,
    )
    protocol.data_received(conn.data_to_send())
    await protocol.loop.run_one()

    assert request_count == 1
    assert "/first" in paths_received

    # Second request on stream 3 (next client-initiated stream)
    conn.send_headers(
        3,
        [
            (":method", "GET"),
            (":path", "/second"),
            (":scheme", "https"),
            (":authority", "example.org"),
        ],
        end_stream=True,
    )
    protocol.data_received(conn.data_to_send())
    await protocol.loop.run_one()

    assert request_count == 2
    assert "/second" in paths_received


async def test_keepalive_timeout():
    """Test keep-alive timeout handler."""
    app = Response("Hello", media_type="text/plain")

    protocol = get_connected_protocol(app, timeout_keep_alive=1)
    protocol.transport.clear_buffer()

    # Process a request
    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    await protocol.loop.run_one()

    # Transport should not be closed yet
    assert not protocol.transport.is_closing()

    # Simulate keep-alive timeout
    protocol.loop.run_later(with_delay=1.0)

    # Now transport should be closed
    assert protocol.transport.is_closing()


async def test_connection_lost():
    """Test connection lost handling."""
    app = Response("Hello", media_type="text/plain")

    protocol = get_connected_protocol(app)
    protocol.connection_lost(None)
    assert protocol not in protocol.connections


async def test_stream_reset():
    """Test handling of client-initiated stream reset (RST_STREAM)."""
    disconnect_received = False
    app_completed = False

    async def app(_scope: Scope, receive: ASGIReceiveCallable, _send: ASGISendCallable):
        nonlocal disconnect_received, app_completed
        # Wait for a message - this will receive disconnect when stream is reset
        message = await receive()
        if message["type"] == "http.disconnect":
            disconnect_received = True
        app_completed = True

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    # Create a client connection
    config = H2Configuration(client_side=True, header_encoding="utf-8")
    conn = H2Connection(config=config)
    conn.initiate_connection()

    # Send request headers (but don't end the stream - simulating a request with body)
    conn.send_headers(
        1,
        [
            (":method", "POST"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", "example.org"),
        ],
        end_stream=False,  # Keep stream open
    )
    protocol.data_received(conn.data_to_send())

    # Now send RST_STREAM to cancel the request
    conn.reset_stream(1, error_code=ErrorCodes.CANCEL)
    protocol.data_received(conn.data_to_send())

    # Run the app task
    await protocol.loop.run_one()

    # App should have received disconnect due to stream reset
    assert disconnect_received
    assert app_completed
    # Stream should be removed from protocol
    h2_protocol = cast(H2Protocol, protocol)
    assert 1 not in h2_protocol.streams

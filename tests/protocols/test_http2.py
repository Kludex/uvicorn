from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

import pytest

from tests.protocols.http_utils import MockLoop, MockTransport
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
    from h2.events import DataReceived, ResponseReceived, StreamEnded

    from uvicorn.protocols.http.h2_impl import H2Protocol

    skip_if_no_h2 = pytest.mark.skipif(False, reason="h2 is installed")
except ModuleNotFoundError:  # pragma: no cover
    skip_if_no_h2 = pytest.mark.skipif(True, reason="h2 is not installed")

if TYPE_CHECKING:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.errors import ErrorCodes
    from h2.events import DataReceived, ResponseReceived, StreamEnded


pytestmark = [pytest.mark.anyio, skip_if_no_h2]


class MockProtocol(asyncio.Protocol):
    """Type stub for protocol with mock transport and loop."""

    loop: MockLoop
    transport: MockTransport
    scope: Scope
    connections: set[Any]
    flow: Any

    def shutdown(self) -> None: ...


def get_connected_protocol(
    app: Callable[..., Any],
    lifespan: LifespanOff | LifespanOn | None = None,
    **kwargs: Any,
) -> MockProtocol:
    loop = MockLoop()
    transport = MockTransport(sslcontext=True)
    config = Config(app=app, **kwargs)
    lifespan = lifespan or LifespanOff(config)
    server_state = ServerState()
    protocol = H2Protocol(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)  # type: ignore[arg-type]
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
    status, headers, body, _ = parse_h2_response_full(data)
    return status, headers, body


def parse_h2_response_full(data: bytes, request_method: str = "GET") -> tuple[int, dict[str, str], bytes, bool]:
    """Parse HTTP/2 response and return (status, headers, body, end_stream_seen)."""
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    request_headers = [
        (":method", request_method),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", "localhost"),
    ]
    conn.send_headers(1, request_headers, end_stream=True)
    conn.clear_outbound_data_buffer()

    events = conn.receive_data(data)

    status = 0
    headers: dict[str, str] = {}
    body = b""
    end_stream_seen = False

    for event in events:
        if isinstance(event, ResponseReceived):
            for name, value in event.headers:
                if name == b":status":
                    status = int(value)
                else:
                    headers[name.decode("utf-8")] = value.decode("utf-8")
        elif isinstance(event, DataReceived):
            body += event.data
        elif isinstance(event, StreamEnded):
            end_stream_seen = True

    return status, headers, body, end_stream_seen


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

    status, headers, body, end_stream = parse_h2_response_full(protocol.transport.buffer, "HEAD")
    assert status == 200
    assert headers["content-type"] == "text/plain; charset=utf-8"
    assert not body
    assert end_stream


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


async def test_authority_replaces_host_header() -> None:
    """When both `:authority` and a duplicate `Host` header arrive, the ASGI
    scope should carry exactly one host entry sourced from `:authority`."""
    received_scope: dict[str, Any] | None = None

    async def app(scope: Any, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal received_scope
        received_scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()
    client_config = H2Configuration(client_side=True, header_encoding=None)
    client_conn = H2Connection(config=client_config)
    client_conn.initiate_connection()
    client_conn.send_headers(
        1,
        [
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"primary.example.org"),
            (b"host", b"primary.example.org"),
        ],
        end_stream=True,
    )
    protocol.data_received(client_conn.data_to_send())
    await protocol.loop.run_one()

    assert received_scope is not None
    host_headers = [value for name, value in received_scope["headers"] if name == b"host"]
    assert host_headers == [b"primary.example.org"]


async def test_early_response_drops_remaining_request_body() -> None:
    """If the app sends a complete response before consuming the body, the
    client may still ship the remaining DATA frames. The server must drop them
    rather than reset a stream hyper-h2 already considers closed."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"too big", "more_body": False})

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    client_config = H2Configuration(client_side=True, header_encoding="utf-8")
    client_conn = H2Connection(config=client_config)
    client_conn.initiate_connection()
    client_conn.send_headers(
        1,
        [(":method", "POST"), (":path", "/"), (":scheme", "https"), (":authority", "localhost")],
        end_stream=False,
    )
    protocol.data_received(client_conn.data_to_send())
    await protocol.loop.run_one()

    # The app already finished, so the stream is closed on the server side.
    h2_protocol = cast(H2Protocol, protocol)
    assert 1 not in h2_protocol.streams

    # The client now sends the remainder of the body (it didn't see the
    # response yet). This must not raise a protocol error.
    client_conn.send_data(1, b"x" * 1000, end_stream=True)
    protocol.data_received(client_conn.data_to_send())


async def test_non_ascii_response_header_bytes_are_preserved() -> None:
    """ASGI lets headers be raw bytes. The HTTP/2 path must not Latin-1-decode
    them and let h2 re-encode as UTF-8, which would corrupt the wire bytes."""
    raw_value = b"\xff-\xc4\x80"

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"x-binary", raw_value)],
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()
    protocol.data_received(create_h2_request("GET", "/"))
    await protocol.loop.run_one()

    client_config = H2Configuration(client_side=True, header_encoding=None)
    client_conn = H2Connection(config=client_config)
    client_conn.initiate_connection()
    client_conn.send_headers(
        1,
        [(b":method", b"GET"), (b":path", b"/"), (b":scheme", b"https"), (b":authority", b"localhost")],
        end_stream=True,
    )
    client_conn.clear_outbound_data_buffer()
    events = client_conn.receive_data(protocol.transport.buffer)
    received: dict[bytes, bytes] = {}
    for event in events:
        if isinstance(event, ResponseReceived):
            for name, value in event.headers:
                received[name] = value
    assert received[b"x-binary"] == raw_value


async def test_send_data_pauses_writer_when_buffer_grows() -> None:
    """When the peer withholds WINDOW_UPDATE, the per-stream buffer grows.
    `send_data` must engage the cycle's flow control so the ASGI app awaits
    `flow.drain()` instead of letting the buffer grow unbounded."""
    response_started = asyncio.Event()
    write_paused_observed = False

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        nonlocal write_paused_observed
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/octet-stream")],
            }
        )
        response_started.set()
        # The default initial window is 65 535 bytes; a 200 KiB chunk forces
        # well over the high water mark of 64 KiB into the pending buffer.
        await send({"type": "http.response.body", "body": b"y" * 200_000, "more_body": True})
        # If backpressure is wired up, the cycle's flow control flag is now set.
        write_paused_observed = protocol.flow.write_paused
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()
    protocol.data_received(create_h2_request("GET", "/"))
    task = asyncio.create_task(protocol.loop.run_one())
    await response_started.wait()
    # Yield a couple of times so the body chunk is processed.
    for _ in range(3):
        await asyncio.sleep(0)

    assert write_paused_observed
    assert protocol.flow.write_paused

    # Open the windows so the rest of the buffer can flush.
    client_config = H2Configuration(client_side=True, header_encoding="utf-8")
    client_conn = H2Connection(config=client_config)
    client_conn.initiate_connection()
    client_conn.send_headers(
        1,
        [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "localhost")],
        end_stream=True,
    )
    client_conn.clear_outbound_data_buffer()
    client_conn.increment_flow_control_window(1_000_000, stream_id=1)
    client_conn.increment_flow_control_window(1_000_000)
    protocol.data_received(client_conn.data_to_send())
    await task

    assert not protocol.flow.write_paused


async def test_shutdown_during_active_stream_closes_after_response():
    """Shutdown during an in-flight stream must close the connection
    once the last response completes, not hold it open until keep-alive expires."""
    response_event = asyncio.Event()
    finish_response = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        response_event.set()
        await finish_response.wait()
        await send({"type": "http.response.body", "body": b"done"})

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()

    request_data = create_h2_request("GET", "/")
    protocol.data_received(request_data)
    task = asyncio.create_task(protocol.loop.run_one())
    await response_event.wait()

    h2_protocol = cast(H2Protocol, protocol)
    assert h2_protocol.streams, "stream should be active before shutdown"
    protocol.shutdown()
    # Connection must stay open while the stream is still in flight.
    assert not protocol.transport.is_closing()

    finish_response.set()
    await task

    # Once the response completes the connection should be closed and the
    # keep-alive timer must not have been scheduled.
    assert protocol.transport.is_closing()
    assert h2_protocol.timeout_keep_alive_task is None


async def test_shutdown_during_flow_controlled_stream_closes_after_flush() -> None:
    """When the response body exceeds the flow-control window the stream cleanup
    is deferred until WINDOW_UPDATE arrives. Shutdown must still close the
    connection once the deferred cleanup happens."""
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

    client_config = H2Configuration(client_side=True, header_encoding="utf-8")
    client_conn = H2Connection(config=client_config)
    client_conn.initiate_connection()
    client_conn.send_headers(
        1,
        [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "example.org")],
        end_stream=True,
    )
    protocol.data_received(client_conn.data_to_send())
    await protocol.loop.run_one()

    h2_protocol = cast(H2Protocol, protocol)
    # The stream stayed in ``streams`` because cleanup is deferred until the
    # flow-control window opens up.
    assert 1 in h2_protocol.streams
    assert h2_protocol.streams[1]._cleanup_pending

    # Shutdown is requested while the stream is still pending data. The TCP
    # transport must NOT close yet.
    protocol.shutdown()
    assert not protocol.transport.is_closing()

    # The peer eventually opens the window and the server flushes the rest.
    client_conn.increment_flow_control_window(65535, stream_id=1)
    client_conn.increment_flow_control_window(65535)
    protocol.data_received(client_conn.data_to_send())

    # Once the buffer drains the connection should close.
    assert protocol.transport.is_closing()
    assert h2_protocol.timeout_keep_alive_task is None


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


async def test_stream_reset_clears_buffered_pending_bytes() -> None:
    """A RST_STREAM while data is queued behind a closed window must release
    the connection-wide backpressure and pending byte counter."""
    response_started = asyncio.Event()
    finish_response = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/octet-stream")],
            }
        )
        response_started.set()
        await send({"type": "http.response.body", "body": b"y" * 200_000, "more_body": True})
        await finish_response.wait()

    protocol = get_connected_protocol(app)
    protocol.transport.clear_buffer()
    protocol.data_received(create_h2_request("GET", "/"))
    task = asyncio.create_task(protocol.loop.run_one())
    await response_started.wait()
    for _ in range(3):
        await asyncio.sleep(0)

    h2_protocol = cast(H2Protocol, protocol)
    assert h2_protocol.pending_bytes > 0
    assert protocol.flow.write_paused

    # Client resets the stream; the buffered data should be discarded and
    # the connection-wide pending byte counter must drop.
    client_config = H2Configuration(client_side=True, header_encoding="utf-8")
    client_conn = H2Connection(config=client_config)
    client_conn.initiate_connection()
    client_conn.send_headers(
        1,
        [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "localhost")],
        end_stream=True,
    )
    client_conn.clear_outbound_data_buffer()
    client_conn.reset_stream(1, error_code=ErrorCodes.CANCEL)
    protocol.data_received(client_conn.data_to_send())

    assert h2_protocol.pending_bytes == 0
    assert not protocol.flow.write_paused
    finish_response.set()
    await task


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

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import signal
import socket
import sys
from collections.abc import AsyncIterator, Callable, Generator
from contextlib import AbstractContextManager

import httpx2
import pytest

from tests.protocols.test_http import SIMPLE_GET_REQUEST
from tests.utils import run_server
from uvicorn._types import ASGIApplication, ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import STARTUP_FAILURE, Config
from uvicorn.protocols.http.flow_control import HIGH_WATER_LIMIT
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
from uvicorn.server import Server, WriteStallMonitor

pytestmark = pytest.mark.anyio


# asyncio does NOT allow raising in signal handlers, so to detect
# raised signals raised a mutable `witness` receives the signal
@contextlib.contextmanager
def capture_signal_sync(sig: signal.Signals) -> Generator[list[int], None, None]:
    """Replace `sig` handling with a normal exception via `signal"""
    witness: list[int] = []
    original_handler = signal.signal(sig, lambda signum, frame: witness.append(signum))
    yield witness
    signal.signal(sig, original_handler)


@contextlib.contextmanager
def capture_signal_async(sig: signal.Signals) -> Generator[list[int], None, None]:  # pragma: py-win32
    """Replace `sig` handling with a normal exception via `asyncio"""
    witness: list[int] = []
    original_handler = signal.getsignal(sig)
    asyncio.get_running_loop().add_signal_handler(sig, witness.append, sig)
    yield witness
    signal.signal(sig, original_handler)


async def dummy_app(scope, receive, send):  # pragma: py-win32
    pass


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    assert scope["type"] == "http"
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


if sys.platform == "win32":  # pragma: py-not-win32
    signals = [signal.SIGBREAK]
    signal_captures = [capture_signal_sync]
else:  # pragma: py-win32
    signals = [signal.SIGTERM, signal.SIGINT]
    signal_captures = [capture_signal_sync, capture_signal_async]


@pytest.mark.parametrize("exception_signal", signals)
@pytest.mark.parametrize("capture_signal", signal_captures)
async def test_server_interrupt(
    exception_signal: signal.Signals,
    capture_signal: Callable[[signal.Signals], AbstractContextManager[None]],
    unused_tcp_port: int,
):  # pragma: py-win32
    """Test interrupting a Server that is run explicitly inside asyncio"""

    async def interrupt_running(srv: Server):
        while not srv.started:
            await asyncio.sleep(0.01)
        signal.raise_signal(exception_signal)

    server = Server(Config(app=dummy_app, loop="asyncio", port=unused_tcp_port))
    asyncio.create_task(interrupt_running(server))
    with capture_signal(exception_signal) as witness:
        await server.serve()
    assert witness
    # set by the server's graceful exit handler
    assert server.should_exit


async def test_shutdown_on_early_exit_during_startup(unused_tcp_port: int):
    """Test that lifespan.shutdown is called even when should_exit is set during startup."""
    startup_complete = False
    shutdown_complete = False

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        nonlocal startup_complete, shutdown_complete
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await asyncio.sleep(0.5)
                    await send({"type": "lifespan.startup.complete"})
                    startup_complete = True
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    shutdown_complete = True
                    return

    config = Config(app=app, lifespan="on", port=unused_tcp_port)
    server = Server(config=config)

    # Simulate a reload signal arriving during startup:
    # set should_exit before the 0.5s startup sleep finishes.
    async def set_exit():
        await asyncio.sleep(0.2)
        server.should_exit = True

    asyncio.create_task(set_exit())
    await server.serve()

    assert startup_complete
    assert shutdown_complete, "lifespan.shutdown was not called despite startup completing"


def test_run_exits_with_startup_failure_on_unloadable_app() -> None:
    """A server exits with the dedicated startup-failure code when the app can't load.

    The multiprocess supervisor relies on `STARTUP_FAILURE` to tell a worker that
    can never boot apart from a worker crashing at runtime, and stops instead of
    restarting it forever. Regression for https://github.com/encode/uvicorn/discussions/2440.
    """
    config = Config(app="tests.test_server:does_not_exist")
    server = Server(config=config)

    with pytest.raises(SystemExit) as exc_info:
        server.run()
    assert exc_info.value.code == STARTUP_FAILURE


async def test_request_than_limit_max_requests_warn_log(
    unused_tcp_port: int, http_protocol_cls: type[H11Protocol | HttpToolsProtocol], caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.INFO, logger="uvicorn.error")
    config = Config(app=app, limit_max_requests=1, port=unused_tcp_port, http=http_protocol_cls)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            tasks = [client.get(f"http://127.0.0.1:{unused_tcp_port}") for _ in range(2)]
            responses = await asyncio.gather(*tasks)
            assert len(responses) == 2
    assert "Maximum request limit of 1 exceeded. Terminating process." in caplog.text


async def test_limit_max_requests_jitter(
    unused_tcp_port: int, http_protocol_cls: type[H11Protocol | HttpToolsProtocol], caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.INFO, logger="uvicorn.error")
    config = Config(
        app=app, limit_max_requests=1, limit_max_requests_jitter=2, port=unused_tcp_port, http=http_protocol_cls
    )
    async with run_server(config) as server:
        limit = server.limit_max_requests
        assert limit is not None
        assert 1 <= limit <= 3
        async with httpx2.AsyncClient() as client:
            tasks = [client.get(f"http://127.0.0.1:{unused_tcp_port}") for _ in range(limit + 1)]
            await asyncio.gather(*tasks)
    assert f"Maximum request limit of {limit} exceeded. Terminating process." in caplog.text


@contextlib.asynccontextmanager
async def _raw_server(
    *,
    app: ASGIApplication,
    port: int,
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol],
    reset_contextvars: bool = False,
):
    config = Config(app=app, port=port, loop="asyncio", http=http_protocol_cls, reset_contextvars=reset_contextvars)
    server = Server(config=config)
    task = asyncio.create_task(server.serve())

    while not server.started:
        await asyncio.sleep(0.01)

    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    async def extract_json_body(request: bytes):
        writer.write(request)
        await writer.drain()

        status, *headers = (await reader.readuntil(b"\r\n\r\n")).split(b"\r\n")[:-2]
        assert status == b"HTTP/1.1 200 OK"

        content_length = next(int(h.split(b":", 1)[1]) for h in headers if h.lower().startswith(b"content-length:"))
        return json.loads(await reader.readexactly(content_length))

    try:
        yield extract_json_body
    finally:
        writer.close()
        await writer.wait_closed()
        server.should_exit = True
        await task


async def test_contextvars_preserved_by_default(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
):
    """By default, context set outside the ASGI task is visible inside it."""
    ctx: contextvars.ContextVar[str] = contextvars.ContextVar("ctx")
    ctx.set("outer-value")

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        assert scope["type"] == "http"
        while True:
            message = await receive()
            assert message["type"] == "http.request"
            if not message["more_body"]:
                break
        body = json.dumps({"ctx": ctx.get("MISSING")}).encode("utf-8")
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("utf-8"))]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async with _raw_server(app=app, http_protocol_cls=http_protocol_cls, port=unused_tcp_port) as extract_json_body:
        assert await extract_json_body(SIMPLE_GET_REQUEST) == {"ctx": "outer-value"}


async def test_reset_contextvars_asyncio(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
):
    """With reset_contextvars=True, each ASGI run starts with a fresh context.

    Non-regression test for https://github.com/encode/uvicorn/issues/2167.
    """
    default_contextvars = {c.name for c in contextvars.copy_context().keys()}
    ctx: contextvars.ContextVar[str] = contextvars.ContextVar("ctx")

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        assert scope["type"] == "http"

        # initial context should be empty
        initial_context = {
            n: v for c, v in contextvars.copy_context().items() if (n := c.name) not in default_contextvars
        }
        # set any contextvar before the body is read
        ctx.set(scope["path"])

        while True:
            message = await receive()
            assert message["type"] == "http.request"
            if not message["more_body"]:
                break

        body = json.dumps(initial_context).encode("utf-8")
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("utf-8"))]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    # body larger than HIGH_WATER_LIMIT forces a reading pause on the main thread
    # and a resumption inside the ASGI task, which is where the original pollution showed up.
    large_body = b"a" * (HIGH_WATER_LIMIT + 1)
    large_request = b"\r\n".join(
        [
            b"POST /large-body HTTP/1.1",
            b"Host: example.org",
            b"Content-Type: application/octet-stream",
            f"Content-Length: {len(large_body)}".encode(),
            b"",
            large_body,
        ]
    )

    async with _raw_server(
        app=app, http_protocol_cls=http_protocol_cls, port=unused_tcp_port, reset_contextvars=True
    ) as extract_json_body:
        assert await extract_json_body(large_request) == {}
        assert await extract_json_body(SIMPLE_GET_REQUEST) == {}


LARGE_BODY = b"x" * (8 * 1024 * 1024)


def body_app(body: bytes) -> ASGIApplication:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        headers = [(b"content-length", str(len(body)).encode())]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    return app


STREAMED_BYTES = 64 * 1024 * 1024
WEBSOCKET_UPGRADE_REQUEST = b"\r\n".join(
    [
        b"GET / HTTP/1.1",
        b"Host: example.org",
        b"Upgrade: websocket",
        b"Connection: Upgrade",
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        b"Sec-WebSocket-Version: 13",
        b"",
        b"",
    ]
)


async def streaming_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    assert scope["type"] == "http"
    await send({"type": "http.response.start", "status": 200, "headers": []})
    chunk = b"x" * HIGH_WATER_LIMIT
    for _ in range(STREAMED_BYTES // len(chunk)):
        await send({"type": "http.response.body", "body": chunk, "more_body": True})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


@contextlib.asynccontextmanager
async def slow_client(
    port: int, receive_buffer_size: int | None = None, request: bytes = SIMPLE_GET_REQUEST
) -> AsyncIterator[socket.socket]:
    loop = asyncio.get_running_loop()
    with socket.socket() as client:
        if receive_buffer_size is not None:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer_size)
        client.setblocking(False)
        await loop.sock_connect(client, ("127.0.0.1", port))
        await loop.sock_sendall(client, request)
        yield client


async def read_until_closed(client: socket.socket) -> int:  # pragma: py-win32
    loop = asyncio.get_running_loop()
    received = 0
    with contextlib.suppress(ConnectionResetError):
        async with asyncio.timeout(5):
            while chunk := await loop.sock_recv(client, 65536):
                received += len(chunk)
    return received


@pytest.mark.skipif(sys.platform == "win32", reason="The write timeout is disabled on ProactorEventLoop")
async def test_timeout_write_closes_connection_when_client_stops_reading(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
):  # pragma: py-win32
    config = Config(app=streaming_app, port=unused_tcp_port, http=http_protocol_cls, lifespan="off", timeout_write=1)
    async with run_server(config):
        async with slow_client(unused_tcp_port, receive_buffer_size=4096) as client:
            await asyncio.sleep(3.5)
            assert await read_until_closed(client) < STREAMED_BYTES


async def websocket_streaming_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    assert scope["type"] == "websocket"
    await receive()
    await send({"type": "websocket.accept"})
    chunk = b"x" * HIGH_WATER_LIMIT
    with contextlib.suppress(OSError):
        for _ in range(STREAMED_BYTES // len(chunk)):
            await send({"type": "websocket.send", "bytes": chunk})


@pytest.mark.skipif(sys.platform == "win32", reason="The write timeout is disabled on ProactorEventLoop")
async def test_timeout_write_closes_websocket_when_client_stops_reading(
    ws_protocol_cls: type[asyncio.Protocol], unused_tcp_port: int
):  # pragma: py-win32
    config = Config(
        app=websocket_streaming_app, port=unused_tcp_port, ws=ws_protocol_cls, lifespan="off", timeout_write=1
    )
    async with run_server(config):
        async with slow_client(unused_tcp_port, receive_buffer_size=4096, request=WEBSOCKET_UPGRADE_REQUEST) as client:
            await asyncio.sleep(3.5)
            assert await read_until_closed(client) < STREAMED_BYTES


async def test_timeout_write_keeps_connection_while_client_reads_slowly(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
):
    config = Config(
        app=body_app(LARGE_BODY), port=unused_tcp_port, http=http_protocol_cls, lifespan="off", timeout_write=1
    )
    async with run_server(config):
        async with slow_client(unused_tcp_port) as client:
            loop = asyncio.get_running_loop()
            response = bytearray()
            slow_until = loop.time() + 2.5
            while loop.time() < slow_until:
                response += await loop.sock_recv(client, 65536)
                await asyncio.sleep(0.03)
            head, _, body = bytes(response).partition(b"\r\n\r\n")
            received = len(body)
            async with asyncio.timeout(10):
                while received < len(LARGE_BODY):
                    chunk = await loop.sock_recv(client, 1024 * 1024)
                    assert chunk, "connection closed while the client was still reading"
                    received += len(chunk)
    assert head.startswith(b"HTTP/1.1 200 OK")
    assert received == len(LARGE_BODY)


class StalledTransport:
    def __init__(self, unsent: int) -> None:
        self.unsent = unsent
        self.aborted = False

    def get_write_buffer_size(self) -> int:
        return self.unsent

    def abort(self) -> None:
        self.aborted = True


class StalledConnection:
    def __init__(self, unsent: int) -> None:
        self.transport = StalledTransport(unsent)


async def test_write_stall_monitor_aborts_connection_without_progress():
    monitor = WriteStallMonitor(timeout=1)
    stalled, idle = StalledConnection(unsent=1024), StalledConnection(unsent=0)

    await monitor.check([stalled, idle], now=0)
    await monitor.check([stalled, idle], now=0.9)
    assert not stalled.transport.aborted

    await monitor.check([stalled, idle], now=1)
    assert stalled.transport.aborted
    assert not idle.transport.aborted


async def test_write_stall_monitor_restarts_while_data_drains():
    monitor = WriteStallMonitor(timeout=1)
    connection = StalledConnection(unsent=1024)

    await monitor.check([connection], now=0)
    connection.transport.unsent = 512
    await monitor.check([connection], now=0.6)
    await monitor.check([connection], now=1.5)
    assert not connection.transport.aborted

    await monitor.check([connection], now=1.6)
    assert connection.transport.aborted


async def test_write_stall_monitor_checks_every_connection_across_chunks():
    monitor = WriteStallMonitor(timeout=1)
    connections = [StalledConnection(unsent=1024) for _ in range(3000)]

    await monitor.check(connections, now=0)
    await monitor.check(connections, now=1)

    assert all(connection.transport.aborted for connection in connections)

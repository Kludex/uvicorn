from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import signal
import sys
from collections.abc import Generator
from contextlib import AbstractContextManager
from typing import Callable

import httpx
import pytest

from tests.protocols.test_http import SIMPLE_GET_REQUEST
from tests.utils import run_server
from uvicorn import Server
from uvicorn._types import ASGIApplication, ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.protocols.http.flow_control import HIGH_WATER_LIMIT
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

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


async def test_request_than_limit_max_requests_warn_log(
    unused_tcp_port: int, http_protocol_cls: type[H11Protocol | HttpToolsProtocol], caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.WARNING, logger="uvicorn.error")
    config = Config(app=app, limit_max_requests=1, port=unused_tcp_port, http=http_protocol_cls)
    async with run_server(config):
        async with httpx.AsyncClient() as client:
            tasks = [client.get(f"http://127.0.0.1:{unused_tcp_port}") for _ in range(2)]
            responses = await asyncio.gather(*tasks)
            assert len(responses) == 2
    assert "Maximum request limit of 1 exceeded. Terminating process." in caplog.text


@contextlib.asynccontextmanager
async def server(*, app: ASGIApplication, port: int, http_protocol_cls: type[H11Protocol | HttpToolsProtocol]):
    config = Config(app=app, port=port, loop="asyncio", http=http_protocol_cls)
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


async def test_no_contextvars_pollution_asyncio(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
):
    """Non-regression test for https://github.com/encode/uvicorn/issues/2167."""
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

        # return the initial context for empty assertion
        body = json.dumps(initial_context).encode("utf-8")
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("utf-8"))]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    # body has to be larger than HIGH_WATER_LIMIT to trigger a reading pause on the main thread
    # and a resumption inside the ASGI task
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

    async with server(app=app, http_protocol_cls=http_protocol_cls, port=unused_tcp_port) as extract_json_body:
        assert await extract_json_body(large_request) == {}
        assert await extract_json_body(SIMPLE_GET_REQUEST) == {}

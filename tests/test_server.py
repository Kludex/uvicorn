from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from collections.abc import Generator
from contextlib import AbstractContextManager
from typing import Callable

import httpx
import pytest

from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
from uvicorn.server import Server

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


async def test_max_requests_jitter_warn_log(
    unused_tcp_port: int, http_protocol_cls: type[H11Protocol | HttpToolsProtocol], caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.WARNING, logger="uvicorn.error")
    config = Config(app=app, limit_max_requests=1, max_requests_jitter=2, port=unused_tcp_port, http=http_protocol_cls)
    async with run_server(config) as server:
        assert server.jittered_limit_max_requests is not None
        assert 1 <= server.jittered_limit_max_requests <= 3
        async with httpx.AsyncClient() as client:
            tasks = [
                client.get(f"http://127.0.0.1:{unused_tcp_port}") for _ in range(server.jittered_limit_max_requests + 1)
            ]
            responses = await asyncio.gather(*tasks)
            assert len(responses) == server.jittered_limit_max_requests + 1
    assert (
        "Maximum request limit of 1" in caplog.text
        or "Maximum request limit of 2" in caplog.text
        or "Maximum request limit of 3" in caplog.text
    )

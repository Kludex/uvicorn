from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from socket import socket

from uvicorn import Config, Server


@asynccontextmanager
async def run_server(config: Config, sockets: list[socket] | None = None) -> AsyncIterator[Server]:
    server = Server(config=config)
    task = asyncio.create_task(server.serve(sockets=sockets))
    await asyncio.sleep(0.1)
    try:
        yield server
    finally:
        await server.shutdown()
        task.cancel()


@contextmanager
def assert_signal(sig: signal.Signals):
    """Check that a signal was received and handled in a block"""
    seen: set[int] = set()
    prev_handler = signal.signal(sig, lambda num, frame: seen.add(num))
    try:
        yield
        assert sig in seen, f"process signal {signal.Signals(sig)!r} was not received or handled"
    finally:
        signal.signal(sig, prev_handler)


@contextmanager
def as_cwd(path: Path):
    """Changes working directory and returns to previous on exit."""
    prev_cwd = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev_cwd)


def get_asyncio_default_loop_per_os() -> type[asyncio.AbstractEventLoop]:
    """Get the default asyncio loop per OS."""
    if sys.platform == "win32":
        return asyncio.ProactorEventLoop  # type: ignore  # pragma: nocover
    else:
        return asyncio.SelectorEventLoop  # pragma: nocover

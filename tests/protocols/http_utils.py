from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any


class MockSSLObject:
    def __init__(self, alpn_protocol: str | None = None):
        self._alpn_protocol = alpn_protocol

    def selected_alpn_protocol(self) -> str | None:
        return self._alpn_protocol


class MockTransport:
    def __init__(
        self,
        sockname: tuple[str, int] | None = None,
        peername: tuple[str, int] | None = None,
        sslcontext: bool = False,
        ssl_object: Any = None,
    ):
        self.sockname = ("127.0.0.1", 8000) if sockname is None else sockname
        self.peername = ("127.0.0.1", 8001) if peername is None else peername
        self.sslcontext = sslcontext
        self._ssl_object = ssl_object
        self.closed = False
        self.buffer = b""
        self.read_paused = False
        self._protocol: asyncio.Protocol | None = None

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

    def pause_reading(self):
        self.read_paused = True

    def resume_reading(self):
        self.read_paused = False

    def is_closing(self):
        return self.closed

    def clear_buffer(self):
        self.buffer = b""

    def set_protocol(self, protocol: asyncio.Protocol):
        self._protocol = protocol

    def get_protocol(self) -> asyncio.Protocol | None:
        return self._protocol


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


class MockTask:
    def add_done_callback(self, callback: Callable[[], None]):
        pass


class MockLoop:
    def __init__(self) -> None:
        self._tasks: list[asyncio.Task[Any]] = []
        self._later: list[MockTimerHandle] = []

    def create_task(self, coroutine: Any, **kwargs: Any) -> Any:
        self._tasks.insert(0, coroutine)
        return MockTask()

    def call_later(self, delay: float, callback: Callable[[], None], *args: Any) -> MockTimerHandle:
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
            else:
                later.append(timer_handle)
        self._later = later


H2C_UPGRADE_REQUEST = b"\r\n".join(
    [
        b"GET / HTTP/1.1",
        b"Host: example.org",
        b"Connection: Upgrade, HTTP2-Settings",
        b"Upgrade: h2c",
        b"HTTP2-Settings: AAMAAABkAAQBAAAAAAIAAAAA",
        b"",
        b"",
    ]
)


def h2c_upgrade_request(
    *,
    method: bytes = b"GET",
    connection: bytes | None = b"Upgrade, HTTP2-Settings",
    upgrade: bytes | None = b"h2c",
    settings: bytes | None = b"AAMAAABkAAQBAAAAAAIAAAAA",
    extra_settings: bytes | None = None,
    content_length: bytes | None = None,
    transfer_encoding: bytes | None = None,
    body: bytes = b"",
) -> bytes:
    """Build an h2c upgrade request, optionally with malformed pieces.

    Set any keyword to None to omit that header. `extra_settings` adds a second
    HTTP2-Settings header (used to assert duplicate-header rejection).
    `content_length` / `transfer_encoding` / `body` build a request that
    carries a body so tests can assert the upgrade is refused.
    """
    lines = [method + b" / HTTP/1.1", b"Host: example.org"]
    if connection is not None:
        lines.append(b"Connection: " + connection)
    if upgrade is not None:
        lines.append(b"Upgrade: " + upgrade)
    if settings is not None:
        lines.append(b"HTTP2-Settings: " + settings)
    if extra_settings is not None:
        lines.append(b"HTTP2-Settings: " + extra_settings)
    if content_length is not None:
        lines.append(b"Content-Length: " + content_length)
    if transfer_encoding is not None:
        lines.append(b"Transfer-Encoding: " + transfer_encoding)
    lines.extend([b"", body])
    return b"\r\n".join(lines)

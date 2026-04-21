from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeAlias

from uvicorn._types import ASGIApplication, Scope
from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

if TYPE_CHECKING:
    from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
    from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
    from uvicorn.protocols.websockets.wsproto_impl import WSProtocol as _WSProtocol

    WSProtocol: TypeAlias = WebSocketProtocol | _WSProtocol
    HTTPProtocol: TypeAlias = H11Protocol | HttpToolsProtocol


SIMPLE_GET_REQUEST = b"\r\n".join([b"GET / HTTP/1.1", b"Host: example.org", b"", b""])

SIMPLE_POST_REQUEST = b"\r\n".join(
    [
        b"POST / HTTP/1.1",
        b"Host: example.org",
        b"Content-Type: application/json",
        b"Content-Length: 18",
        b"",
        b'{"hello": "world"}',
    ]
)

LARGE_POST_REQUEST = b"\r\n".join(
    [
        b"POST / HTTP/1.1",
        b"Host: example.org",
        b"Content-Type: text/plain",
        b"Content-Length: 100000",
        b"",
        b"x" * 100000,
    ]
)

HTTP10_GET_REQUEST = b"\r\n".join([b"GET / HTTP/1.0", b"Host: example.org", b"", b""])

CONNECTION_CLOSE_REQUEST = b"\r\n".join([b"GET / HTTP/1.1", b"Host: example.org", b"Connection: close", b"", b""])

START_POST_REQUEST = b"\r\n".join(
    [
        b"POST / HTTP/1.1",
        b"Host: example.org",
        b"Content-Type: application/json",
        b"Content-Length: 18",
        b"",
        b"",
    ]
)

FINISH_POST_REQUEST = b'{"hello": "world"}'

BODY_CHUNK_SIZE = 256
FRAGMENTED_BODY_SIZE = 100_000
FRAGMENTED_POST_HEADERS = b"\r\n".join(
    [
        b"POST / HTTP/1.1",
        b"Host: example.org",
        b"Content-Type: application/octet-stream",
        b"Content-Length: " + str(FRAGMENTED_BODY_SIZE).encode(),
        b"",
        b"",
    ]
)
FRAGMENTED_BODY_CHUNKS = [b"x" * BODY_CHUNK_SIZE] * (FRAGMENTED_BODY_SIZE // BODY_CHUNK_SIZE)


class MockTransport:
    def __init__(self) -> None:
        self.buffer = b""
        self.closed = False
        self.read_paused = False

    def get_extra_info(self, key: Any) -> Any:
        return {
            "sockname": ("127.0.0.1", 8000),
            "peername": ("127.0.0.1", 8001),
            "sslcontext": False,
        }.get(key)

    def write(self, data: bytes) -> None:
        self.buffer += data

    def close(self) -> None:
        self.closed = True

    def pause_reading(self) -> None:
        self.read_paused = True

    def resume_reading(self) -> None:
        self.read_paused = False

    def is_closing(self) -> bool:
        return self.closed

    def clear_buffer(self) -> None:
        self.buffer = b""

    def set_protocol(self, protocol: asyncio.Protocol) -> None:
        pass


class MockTimerHandle:
    def __init__(
        self, loop_later_list: list[MockTimerHandle], delay: float, callback: Callable[[], None], args: tuple[Any, ...]
    ) -> None:
        self.loop_later_list = loop_later_list
        self.delay = delay
        self.callback = callback
        self.args = args
        self.cancelled = False

    def cancel(self) -> None:
        if not self.cancelled:
            self.cancelled = True
            self.loop_later_list.remove(self)


class MockLoop:
    def __init__(self) -> None:
        self._tasks: list[asyncio.Task[Any]] = []
        self._later: list[MockTimerHandle] = []

    def create_task(self, coroutine: Any) -> Any:
        self._tasks.insert(0, coroutine)
        return MockTask()

    def call_later(self, delay: float, callback: Callable[[], None], *args: Any) -> MockTimerHandle:
        handle = MockTimerHandle(self._later, delay, callback, args)
        self._later.insert(0, handle)
        return handle

    async def run_one(self) -> Any:
        return await self._tasks.pop()


class MockTask:
    def add_done_callback(self, callback: Callable[[], None]) -> None:
        pass


class MockProtocol(asyncio.Protocol):
    loop: MockLoop
    transport: MockTransport
    timeout_keep_alive_task: asyncio.TimerHandle | None
    ws_protocol_class: type[WSProtocol] | None
    scope: Scope


def make_config(app: ASGIApplication, **kwargs: Any) -> Config:
    return Config(app=app, **kwargs)


def get_connected_protocol(
    config: Config,
    http_protocol_cls: type[HTTPProtocol],
) -> MockProtocol:
    loop = MockLoop()
    transport = MockTransport()
    lifespan = LifespanOff(config)
    server_state = ServerState()
    protocol = http_protocol_cls(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)  # type: ignore
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol  # type: ignore[return-value]

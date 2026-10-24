import asyncio
import sys

from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope

CLOSE_HEADER = (b"connection", b"close")

HIGH_WATER_LIMIT = 65536


class FlowControl:
    def __init__(
        self, transport: asyncio.Transport, loop: asyncio.AbstractEventLoop, timeout_write: float | None = None
    ) -> None:
        self._transport = transport
        self._loop = loop
        if sys.platform == "win32" and isinstance(loop, asyncio.ProactorEventLoop):  # pragma: py-not-win32
            # Proactor only reports a send's progress once all of it completes, so a slow reader would look stalled.
            timeout_write = None
        self._timeout_write = timeout_write
        self._write_timer: asyncio.TimerHandle | None = None
        self._write_buffer_size = 0
        self.read_paused = False
        self.write_paused = False
        self._is_writable_event = asyncio.Event()
        self._is_writable_event.set()

    async def drain(self) -> None:
        await self._is_writable_event.wait()  # pragma: full coverage

    def pause_reading(self) -> None:
        if not self.read_paused:
            self.read_paused = True
            self._transport.pause_reading()

    def resume_reading(self) -> None:
        if self.read_paused:
            self.read_paused = False
            self._transport.resume_reading()

    def pause_writing(self) -> None:
        if not self.write_paused:  # pragma: full coverage
            self.write_paused = True
            self._is_writable_event.clear()
            if self._timeout_write is not None:
                self._arm_write_timer()

    def resume_writing(self) -> None:
        if self.write_paused:  # pragma: full coverage
            self.write_paused = False
            self._is_writable_event.set()
            if self._write_timer is not None:
                self._write_timer.cancel()
                self._write_timer = None

    def close_transport(self) -> None:
        # `close()` waits for the write buffer to drain, which never happens if the client stopped reading.
        self._transport.close()
        if self._timeout_write is not None and self._write_timer is None and self._transport.get_write_buffer_size():
            self._arm_write_timer()

    def connection_lost(self) -> None:
        self.resume_writing()
        if self._write_timer is not None:
            self._write_timer.cancel()
            self._write_timer = None

    def _arm_write_timer(self) -> None:
        assert self._timeout_write is not None
        self._write_buffer_size = self._transport.get_write_buffer_size()
        self._write_timer = self._loop.call_later(self._timeout_write, self._check_write_progress)

    def _check_write_progress(self) -> None:
        # The client is still reading, just slowly: give it another window.
        if self._transport.get_write_buffer_size() < self._write_buffer_size:
            self._arm_write_timer()
        else:
            self._write_timer = None
            self._transport.abort()


async def service_unavailable(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", b"19"),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b"Service Unavailable", "more_body": False})

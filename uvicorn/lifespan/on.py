from __future__ import annotations

import asyncio
import logging
from asyncio import Queue
from typing import Any

from uvicorn import Config
from uvicorn._types import (
    LifespanScope,
    LifespanShutdownCompleteEvent,
    LifespanShutdownEvent,
    LifespanShutdownFailedEvent,
    LifespanStartupCompleteEvent,
    LifespanStartupEvent,
    LifespanStartupFailedEvent,
)

LifespanReceiveMessage = LifespanStartupEvent | LifespanShutdownEvent
LifespanSendMessage = (
    LifespanStartupFailedEvent
    | LifespanShutdownFailedEvent
    | LifespanStartupCompleteEvent
    | LifespanShutdownCompleteEvent
)


STATE_TRANSITION_ERROR = "Got invalid state transition on lifespan protocol."


class LifespanOn:
    def __init__(self, config: Config) -> None:
        if not config.loaded:
            config.load()

        self.config = config
        self.logger = logging.getLogger("uvicorn.error")
        self.startup_event = asyncio.Event()
        self.shutdown_event = asyncio.Event()
        self.receive_queue: Queue[LifespanReceiveMessage] = asyncio.Queue()
        self.error_occurred = False
        self.startup_failed = False
        self.shutdown_failed = False
        self.should_exit = False
        self.state: dict[str, Any] = {}
        self.main_lifespan_task: asyncio.Task[None] | None = None

    async def startup(self) -> None:
        self.logger.info("Waiting for application startup.")

        loop = asyncio.get_event_loop()
        # Keep a hard reference to prevent garbage collection, and so it can be
        # cancelled (e.g. if the application never yields back control while
        # handling the startup event).
        # See https://github.com/Kludex/uvicorn/pull/972
        self.main_lifespan_task = loop.create_task(self.main())
        startup_event: LifespanStartupEvent = {"type": "lifespan.startup"}
        await self.receive_queue.put(startup_event)
        await self.startup_event.wait()

        if self.startup_failed or (self.error_occurred and self.config.lifespan == "on"):
            self.logger.error("Application startup failed. Exiting.")
            self.should_exit = True
        else:
            self.logger.info("Application startup complete.")

    def cancel(self) -> None:
        """
        Cancel the lifespan task if the application is still processing the
        startup event, e.g. because it never yields control back to uvicorn.

        This allows a shutdown signal (e.g. Ctrl+C) received while frozen in
        startup to unblock `startup()` instead of hanging forever, since
        nothing else would otherwise interrupt the pending
        ``await self.startup_event.wait()``.
        """
        if self.startup_event.is_set() or self.main_lifespan_task is None:
            return
        self.main_lifespan_task.cancel()
        # If the task is cancelled before its coroutine ever gets a chance to
        # run, `main()`'s try/finally never executes, so nothing would set the
        # events and `startup()` would wait forever. Cover that window here.
        self.main_lifespan_task.add_done_callback(self._on_cancelled_task_done)

    def _on_cancelled_task_done(self, task: asyncio.Task[None]) -> None:
        if self.startup_event.is_set():
            return
        self.error_occurred = True
        self.startup_failed = True
        self.logger.info("Application startup interrupted.")
        self.startup_event.set()
        self.shutdown_event.set()

    async def shutdown(self) -> None:
        if self.error_occurred:
            return
        self.logger.info("Waiting for application shutdown.")
        shutdown_event: LifespanShutdownEvent = {"type": "lifespan.shutdown"}
        await self.receive_queue.put(shutdown_event)
        await self.shutdown_event.wait()

        if self.shutdown_failed or (self.error_occurred and self.config.lifespan == "on"):
            self.logger.error("Application shutdown failed. Exiting.")
            self.should_exit = True
        else:
            self.logger.info("Application shutdown complete.")

    async def main(self) -> None:
        try:
            app = self.config.loaded_app
            scope: LifespanScope = {
                "type": "lifespan",
                "asgi": {"version": self.config.asgi_version, "spec_version": "2.0"},
                "state": self.state,
            }
            await app(scope, self.receive, self.send)
        except asyncio.CancelledError:
            # The task was cancelled (e.g. Ctrl+C while the app was frozen in
            # startup). This is a user-initiated abort, not evidence that the
            # app lacks lifespan support, so report it honestly regardless of
            # the configured lifespan mode.
            self.asgi = None
            self.error_occurred = True
            self.startup_failed = True
            self.logger.info("Application startup interrupted.")
        except BaseException as exc:
            self.asgi = None
            self.error_occurred = True
            if self.startup_failed or self.shutdown_failed:
                return
            if self.config.lifespan == "auto":
                msg = "ASGI 'lifespan' protocol appears unsupported."
                self.logger.info(msg)
            else:
                msg = "Exception in 'lifespan' protocol\n"
                self.logger.error(msg, exc_info=exc)
        finally:
            self.startup_event.set()
            self.shutdown_event.set()

    async def send(self, message: LifespanSendMessage) -> None:
        assert message["type"] in (
            "lifespan.startup.complete",
            "lifespan.startup.failed",
            "lifespan.shutdown.complete",
            "lifespan.shutdown.failed",
        )

        if message["type"] == "lifespan.startup.complete":
            assert not self.startup_event.is_set(), STATE_TRANSITION_ERROR
            assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR
            self.startup_event.set()

        elif message["type"] == "lifespan.startup.failed":
            assert not self.startup_event.is_set(), STATE_TRANSITION_ERROR
            assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR
            self.startup_event.set()
            self.startup_failed = True
            if message.get("message"):
                self.logger.error(message["message"])

        elif message["type"] == "lifespan.shutdown.complete":
            assert self.startup_event.is_set(), STATE_TRANSITION_ERROR
            assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR
            self.shutdown_event.set()

        elif message["type"] == "lifespan.shutdown.failed":
            assert self.startup_event.is_set(), STATE_TRANSITION_ERROR
            assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR
            self.shutdown_event.set()
            self.shutdown_failed = True
            if message.get("message"):
                self.logger.error(message["message"])

    async def receive(self) -> LifespanReceiveMessage:
        return await self.receive_queue.get()

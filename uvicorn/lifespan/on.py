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

    async def startup(self) -> None:
        self.logger.info("Waiting for application startup.")
        if getattr(self.config, "app_context", None) is not None:
            try:
                self.config.loaded_app = await self.config.app_context.__aenter__()
                self.config.setup_app()
            except Exception:
                self.logger.error("Error starting app context manager factory", exc_info=True)
                self.startup_failed = True
                self.error_occurred = True
                self.logger.error("Application startup failed. Exiting.")
                self.should_exit = True
                return

        loop = asyncio.get_event_loop()
        main_lifespan_task = loop.create_task(self.main())  # noqa: F841
        # Keep a hard reference to prevent garbage collection
        # See https://github.com/Kludex/uvicorn/pull/972
        startup_event: LifespanStartupEvent = {"type": "lifespan.startup"}
        await self.receive_queue.put(startup_event)
        await self.startup_event.wait()

        if self.startup_failed or (self.error_occurred and self.config.lifespan == "on"):
            self.logger.error("Application startup failed. Exiting.")
            self.should_exit = True
        else:
            self.logger.info("Application startup complete.")

    async def shutdown(self) -> None:
        if self.error_occurred:
            return
        self.logger.info("Waiting for application shutdown.")
        try:
            shutdown_event: LifespanShutdownEvent = {"type": "lifespan.shutdown"}
            await self.receive_queue.put(shutdown_event)
            await self.shutdown_event.wait()
        finally:
            if getattr(self.config, "app_context", None) is not None:
                try:
                    await self.config.app_context.__aexit__(None, None, None)
                except Exception:
                    self.shutdown_failed = True
                    self.logger.error("Error shutting down app context manager factory", exc_info=True)

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
                "asgi": {"version": "3.0", "spec_version": "2.0"},
                "state": self.state,
            }
            await app(scope, self.receive, self.send)
        except BaseException:
            self.error_occurred = True
            if self.startup_failed or self.shutdown_failed:
                return
            if not self.startup_event.is_set():
                self.logger.exception("Exception in 'lifespan' protocol")
                self.startup_event.set()
            elif not self.shutdown_event.is_set():
                self.logger.exception("Exception in 'lifespan' protocol")
                self.shutdown_event.set()

    async def send(self, message: LifespanSendMessage) -> None:
        message_type = message["type"]

        if not self.startup_event.is_set():
            if message_type == "lifespan.startup.complete":
                self.startup_event.set()
            elif message_type == "lifespan.startup.failed":
                self.startup_failed = True
                self.startup_event.set()
            else:
                self.logger.error(STATE_TRANSITION_ERROR)
                self.error_occurred = True
                self.startup_event.set()

        elif not self.shutdown_event.is_set():
            if message_type == "lifespan.shutdown.complete":
                self.shutdown_event.set()
            elif message_type == "lifespan.shutdown.failed":
                self.shutdown_failed = True
                self.shutdown_event.set()
            else:
                self.logger.error(STATE_TRANSITION_ERROR)
                self.error_occurred = True
                self.shutdown_event.set()

        else:
            self.logger.error(STATE_TRANSITION_ERROR)
            self.error_occurred = True

    async def receive(self) -> LifespanReceiveMessage:
        return await self.receive_queue.get()

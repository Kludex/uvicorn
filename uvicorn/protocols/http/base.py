from __future__ import annotations as _annotations

import asyncio
import logging
from typing import Any

from uvicorn._types import HTTPScope
from uvicorn.config import Config
from uvicorn.protocols.http.flow_control import FlowControl
from uvicorn.server import ServerState


class HTTPProtocol(asyncio.Protocol):
    __slots__ = (
        "config",
        "app",
        "loop",
        "logger",
        "access_logger",
        "access_log",
        "ws_protocol_class",
        "root_path",
        "limit_concurrency",
        "app_state",
        # Timeouts
        "timeout_keep_alive_task",
        "timeout_keep_alive",
        # Global state
        "server_state",
        "connections",
        "tasks",
        # Per-connection state
        "transport",
        "flow",
        "server",
        "client",
        # Per-request state
        "scope",
        "headers",
    )

    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if not config.loaded:
            config.load()

        self.config = config
        self.app = config.loaded_app
        self.loop = _loop or asyncio.get_event_loop()

        self.logger = logging.getLogger("uvicorn.error")
        self.access_logger = logging.getLogger("uvicorn.access")
        self.access_log = self.access_logger.hasHandlers()

        self.ws_protocol_class = config.ws_protocol_class
        self.root_path = config.root_path
        self.limit_concurrency = config.limit_concurrency
        self.app_state = app_state

        # Timeouts
        self.timeout_keep_alive_task: asyncio.TimerHandle | None = None
        self.timeout_keep_alive = config.timeout_keep_alive

        # Global state
        self.server_state = server_state
        self.connections = server_state.connections
        self.tasks = server_state.tasks

        # Per-connection state
        self.transport: asyncio.Transport = None  # type: ignore[assignment]
        self.flow: FlowControl = None  # type: ignore[assignment]
        self.server: tuple[str, int] | None = None
        self.client: tuple[str, int] | None = None

        # Per-request state
        self.scope: HTTPScope = None  # type: ignore[assignment]
        self.headers: list[tuple[bytes, bytes]] = None  # type: ignore[assignment]

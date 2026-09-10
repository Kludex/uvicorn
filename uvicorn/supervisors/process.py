from __future__ import annotations

import functools
import logging
import pickle
import threading
import time
from collections.abc import Callable
from multiprocessing import Pipe
from socket import socket
from typing import TYPE_CHECKING

from uvicorn._subprocess import get_subprocess
from uvicorn.config import Config
from uvicorn.server import Server

PING = b"ping"
SHUTDOWN = b"shutdown"

logger = logging.getLogger("uvicorn.error")

if TYPE_CHECKING:
    from multiprocessing.connection import Connection


def _listen(child_conn: Connection, server: Server) -> None:
    while True:
        try:
            command = child_conn.recv()
            if command == PING:
                child_conn.send(server.started)
            elif command == SHUTDOWN:
                server.should_exit = True
        except (OSError, EOFError):
            server.should_exit = True
            return


def _run(
    sockets: list[socket] | None,
    config: Config,
    target: Callable[[list[socket] | None], None] | None,
    parent_conn: Connection,
    child_conn: Connection,
) -> None:
    parent_conn.close()
    if target is not None:
        target(sockets)
        return

    server = Server(config=config)
    threading.Thread(target=_listen, args=(child_conn, server), daemon=True).start()
    server.run(sockets)


class Process:
    def __init__(
        self,
        config: Config,
        sockets: list[socket],
        target: Callable[[list[socket] | None], None] | None = None,
    ) -> None:
        self.config = config
        self.target = target
        self.parent_conn, self.child_conn = Pipe()
        self._close_lock = threading.Lock()
        self._parent_conn_closed = False
        target_with_control = functools.partial(
            _run,
            config=config,
            target=target,
            parent_conn=self.parent_conn,
            child_conn=self.child_conn,
        )
        self.process = get_subprocess(config, target_with_control, sockets)

    def _healthcheck(self, timeout: float) -> bool | None:
        try:
            self.parent_conn.send(PING)
            if self.parent_conn.poll(timeout):
                started: bool = self.parent_conn.recv()
                return started
            return None
        except (OSError, EOFError, pickle.UnpicklingError):
            return None

    def ping(self, timeout: float = 5) -> bool:
        return self._healthcheck(timeout) is not None

    def is_ready(self, timeout: float = 5) -> bool:
        return self._healthcheck(timeout) is True

    def is_alive(self, timeout: float = 5) -> bool:
        if not self.process.is_alive():
            return False  # pragma: full coverage
        return self.ping(timeout)

    def wait_until_ready(self, timeout: float, should_exit: threading.Event | None = None) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if should_exit is not None and should_exit.is_set():
                return False
            if not self.process.is_alive():
                return False
            if self.is_ready(timeout=min(1, remaining)):
                return True
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))

    def start(self) -> None:
        self.process.start()
        self.child_conn.close()

    def terminate(self) -> None:
        if self.process.exitcode is not None or self.process.pid is None:
            return
        try:
            if self.target is None:
                self.parent_conn.send(SHUTDOWN)
            else:
                self.process.terminate()
        except (OSError, EOFError):
            return
        logger.info(f"Terminated child process [{self.process.pid}]")

    def _close_parent_conn(self) -> None:
        with self._close_lock:
            if not self._parent_conn_closed:
                self.parent_conn.close()
                self._parent_conn_closed = True

    def kill(self) -> None:
        self.process.kill()
        self._close_parent_conn()

    def join(self, timeout: float | None = None) -> None:
        logger.info(f"Waiting for child process [{self.process.pid}]")
        self.process.join(timeout)
        if not self.process.is_alive():
            self._close_parent_conn()

    @property
    def pid(self) -> int | None:
        return self.process.pid

    @property
    def exitcode(self) -> int | None:
        return self.process.exitcode

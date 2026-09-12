from __future__ import annotations

import logging
import os
import signal
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from socket import socket
from types import FrameType

from uvicorn._ansi import style
from uvicorn.config import Config
from uvicorn.supervisors.process import Process

HANDLED_SIGNALS = (
    signal.SIGINT,  # Unix signal 2. Sent by Ctrl+C.
    signal.SIGTERM,  # Unix signal 15. Sent by `kill <pid>`.
)

logger = logging.getLogger("uvicorn.error")


class BaseReload:
    def __init__(
        self,
        config: Config,
        target: Callable[[list[socket] | None], None] | None,
        sockets: list[socket],
    ) -> None:
        self.config = config
        self.target = target
        self.sockets = sockets
        self.should_exit = threading.Event()
        self.pid = os.getpid()
        self.reloader_name: str | None = None

    def signal_handler(self, sig: int, frame: FrameType | None) -> None:  # pragma: full coverage
        """
        A signal handler that is registered with the parent process.
        """
        self.should_exit.set()

    def run(self) -> None:
        self.startup()
        for changes in self:
            if changes:
                logger.warning(
                    "%s detected changes in %s. Reloading...",
                    self.reloader_name,
                    ", ".join(map(_display_path, changes)),
                )
                self.restart()

        self.shutdown()

    def pause(self) -> None:
        if self.should_exit.wait(self.config.reload_delay):
            raise StopIteration()

    def __iter__(self) -> Iterator[list[Path] | None]:
        return self

    def __next__(self) -> list[Path] | None:
        return self.should_restart()

    def startup(self) -> None:
        message = f"Started reloader process [{self.pid}] using {self.reloader_name}"
        color_message = "Started reloader process [{}] using {}".format(
            style(str(self.pid), fg="cyan", bold=True),
            style(str(self.reloader_name), fg="cyan", bold=True),
        )
        logger.info(message, extra={"color_message": color_message})

        for sig in HANDLED_SIGNALS:
            signal.signal(sig, self.signal_handler)

        self.process = Process(config=self.config, target=self.target, sockets=self.sockets)
        self.process.start()

    def restart(self) -> None:
        self.process.terminate()
        self.process.join()

        self.process = Process(config=self.config, target=self.target, sockets=self.sockets)
        self.process.start()

    def shutdown(self) -> None:
        self.process.terminate()
        self.process.join()

        for sock in self.sockets:
            sock.close()

        message = f"Stopping reloader process [{str(self.pid)}]"
        color_message = "Stopping reloader process [{}]".format(style(str(self.pid), fg="cyan", bold=True))
        logger.info(message, extra={"color_message": color_message})

    def should_restart(self) -> list[Path] | None:
        raise NotImplementedError("Reload strategies should override should_restart()")


def _display_path(path: Path) -> str:
    try:
        return f"'{path.relative_to(Path.cwd())}'"
    except ValueError:
        return f"'{path}'"

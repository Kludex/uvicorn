from __future__ import annotations

import copy
import inspect
import logging
import os
import signal
import threading
import time
from collections.abc import Callable
from socket import socket
from typing import Any

import click

from uvicorn.config import Config
from uvicorn.server import Server
from uvicorn.supervisors.multiprocess import SIGNALS

logger = logging.getLogger("uvicorn.error")


class ThreadServer(Server):
    def __init__(self, config: Config, worker_thread: Thread) -> None:
        super().__init__(config)
        self.worker_thread = worker_thread

    async def on_tick(self, counter: int) -> bool:
        if counter % 10 == 0:
            self.worker_thread.record_heartbeat()
        return await super().on_tick(counter)


class Thread:
    def __init__(
        self,
        config: Config,
        target: Callable[[list[socket] | None], None],
        sockets: list[socket],
    ) -> None:
        self.config = copy.copy(config)
        self.real_target = target
        self.sockets = sockets
        self.server: Server | None = None
        self.last_heartbeat = time.monotonic()
        self.thread = threading.Thread(target=self.target, daemon=True)

    def _get_target(self) -> Callable[[list[socket] | None], None]:
        if inspect.ismethod(self.real_target) and isinstance(self.real_target.__self__, Server):
            self.server = ThreadServer(config=self.config, worker_thread=self)
            return self.server.run
        return self.real_target

    def record_heartbeat(self) -> None:
        self.last_heartbeat = time.monotonic()

    def target(self, sockets: list[socket] | None = None) -> Any:
        sockets = [sock.dup() for sock in self.sockets]
        try:
            return self._get_target()(sockets)
        finally:
            for sock in sockets:
                if sock.fileno() != -1:
                    sock.close()

    def is_alive(self) -> bool:
        return self.thread.is_alive()

    def start(self) -> None:
        self.thread.start()

    def terminate(self) -> None:
        if self.server is not None:
            self.server.should_exit = True

    def join(self, timeout: float | None = None) -> bool:
        self.thread.join(timeout=timeout)
        return not self.is_alive()

    def is_healthy(self, timeout: float) -> bool:
        return time.monotonic() - self.last_heartbeat <= timeout


class Multithread:
    def __init__(
        self,
        config: Config,
        target: Callable[[list[socket] | None], None],
        sockets: list[socket],
    ) -> None:
        self.config = config
        self.target = target
        self.sockets = sockets

        self.threads_num = config.workers
        self.threads: list[Thread] = []
        self.stale_threads: list[Thread] = []

        self.should_exit = threading.Event()

        self.signal_queue: list[int] = []
        for sig in SIGNALS:
            signal.signal(sig, lambda sig, frame: self.signal_queue.append(sig))

    def init_threads(self) -> None:
        for _ in range(self.threads_num):
            self.threads.append(self._start_thread())

    def terminate_all(self) -> None:
        for thread in self._all_threads():
            thread.terminate()

    def join_all(self) -> None:
        timeout = self._thread_shutdown_timeout
        for thread in self._all_threads():
            joined = thread.join(timeout=timeout)
            if not joined:
                logger.warning("Worker thread did not exit within %.2f seconds.", timeout)

    def restart_all(self) -> None:
        for idx, thread in enumerate(self.threads):
            self._replace_thread(idx, thread, reason="Worker thread restarted")

    def run(self) -> None:
        message = f"Started parent process [{os.getpid()}]"
        color_message = "Started parent process [{}]".format(click.style(str(os.getpid()), fg="cyan", bold=True))
        logger.info(message, extra={"color_message": color_message})

        self.init_threads()

        while not self.should_exit.wait(0.5):
            self.handle_signals()
            self.keep_subthread_alive()

        self.terminate_all()
        self.join_all()

        message = f"Stopping parent process [{os.getpid()}]"
        color_message = "Stopping parent process [{}]".format(click.style(str(os.getpid()), fg="cyan", bold=True))
        logger.info(message, extra={"color_message": color_message})

    def keep_subthread_alive(self) -> None:
        if self.should_exit.is_set():
            return

        for idx, thread in enumerate(self.threads):
            if self.should_exit.is_set():  # pragma: no cover
                return

            if not thread.is_alive():
                self._replace_thread(idx, thread, reason="Child thread died")
                continue

            if not thread.is_healthy(timeout=self.config.timeout_worker_healthcheck):
                self._replace_thread(idx, thread, reason="Worker thread failed healthcheck")

    def handle_signals(self) -> None:
        for sig in tuple(self.signal_queue):
            self.signal_queue.remove(sig)
            sig_name = SIGNALS[sig]
            sig_handler = getattr(self, f"handle_{sig_name.lower()}", None)
            if sig_handler is not None:
                sig_handler()
            else:  # pragma: no cover
                logger.debug(f"Received signal {sig_name}, but no handler is defined for it.")

    def handle_int(self) -> None:
        logger.info("Received SIGINT, exiting.")
        self.should_exit.set()

    def handle_term(self) -> None:
        logger.info("Received SIGTERM, exiting.")
        self.should_exit.set()

    def handle_break(self) -> None:  # pragma: py-not-win32
        logger.info("Received SIGBREAK, exiting.")
        self.should_exit.set()

    def handle_hup(self) -> None:  # pragma: py-win32
        logger.info("Received SIGHUP, restarting threads.")
        self.restart_all()

    def handle_ttin(self) -> None:  # pragma: py-win32
        logger.info("Received SIGTTIN, increasing the number of threads.")
        self.threads_num += 1
        self.threads.append(self._start_thread())

    def handle_ttou(self) -> None:  # pragma: py-win32
        logger.info("Received SIGTTOU, decreasing number of threads.")
        if self.threads_num <= 1:
            logger.info("Already reached one thread, cannot decrease the number of threads anymore.")
            return
        self.threads_num -= 1
        thread = self.threads.pop()
        thread.terminate()
        if not thread.join(timeout=self._thread_shutdown_timeout):
            logger.warning("Worker thread did not exit within %.2f seconds.", self._thread_shutdown_timeout)
            self.stale_threads.append(thread)

    @property
    def _thread_shutdown_timeout(self) -> float:
        if self.config.timeout_graceful_shutdown is not None:
            return float(self.config.timeout_graceful_shutdown)
        return float(self.config.timeout_worker_healthcheck)

    def _start_thread(self) -> Thread:
        thread = Thread(self.config, self.target, self.sockets)
        thread.start()
        return thread

    def _replace_thread(self, idx: int, thread: Thread, *, reason: str) -> None:
        thread.terminate()
        if not thread.join(timeout=self._thread_shutdown_timeout):
            logger.warning("%s; starting a replacement thread while the previous thread is still running.", reason)
            self.stale_threads.append(thread)
        else:
            logger.info(reason)
        self.threads[idx] = self._start_thread()

    def _all_threads(self) -> list[Thread]:
        threads = list(self.threads)
        for thread in self.stale_threads:
            if thread not in threads:
                threads.append(thread)
        return threads

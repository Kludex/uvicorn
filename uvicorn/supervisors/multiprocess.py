from __future__ import annotations

import logging
import os
import pickle
import signal
import threading
import time
from multiprocessing import Pipe
from socket import socket

from uvicorn._ansi import style
from uvicorn._subprocess import get_subprocess
from uvicorn.config import STARTUP_FAILURE, Config
from uvicorn.server import Server

SIGNALS = {
    getattr(signal, f"SIG{x}"): x
    for x in "INT TERM BREAK HUP QUIT TTIN TTOU USR1 USR2 WINCH".split()
    if hasattr(signal, f"SIG{x}")
}

logger = logging.getLogger("uvicorn.error")


class Process:
    def __init__(
        self,
        config: Config,
        sockets: list[socket],
    ) -> None:
        self.config = config
        self._server: Server | None = None

        self.parent_conn, self.child_conn = Pipe()
        self.process = get_subprocess(config, self.target, sockets)

    def _healthcheck(self, timeout: float) -> bool | None:
        """Receives a timeout and returns the worker's startup flag, or None if it does not answer in time."""
        try:
            self.parent_conn.send(b"ping")
            if self.parent_conn.poll(timeout):
                started: bool = self.parent_conn.recv()
                return started
            return None
        except (OSError, EOFError, pickle.UnpicklingError):
            return None

    def ping(self, timeout: float = 5) -> bool:
        """Receives a timeout and returns True if the worker answers a healthcheck in time."""
        return self._healthcheck(timeout) is not None

    def is_ready(self, timeout: float = 5) -> bool:
        """Receives a timeout and returns True if the worker answers and its server has finished startup."""
        return self._healthcheck(timeout) is True

    def pong(self) -> None:
        """Receives one healthcheck ping and replies with whether the server has finished startup."""
        self.child_conn.recv()
        self.child_conn.send(self.server.started)

    def always_pong(self) -> None:
        while True:
            self.pong()

    def target(self, sockets: list[socket] | None = None) -> None:  # pragma: no cover
        if os.name == "nt":  # pragma: py-not-win32
            # Windows doesn't support SIGTERM, so we use SIGBREAK instead.
            # And then we raise SIGTERM when SIGBREAK is received.
            # https://learn.microsoft.com/zh-cn/cpp/c-runtime-library/reference/signal?view=msvc-170
            signal.signal(
                signal.SIGBREAK,  # type: ignore[attr-defined]
                lambda sig, frame: signal.raise_signal(signal.SIGTERM),
            )

        threading.Thread(target=self.always_pong, daemon=True).start()
        self.server.run(sockets)

    def is_alive(self, timeout: float = 5) -> bool:
        if not self.process.is_alive():
            return False  # pragma: full coverage

        return self.ping(timeout)

    def wait_until_ready(self, timeout: float, should_exit: threading.Event | None = None) -> bool:
        """Receives a timeout and returns True if the worker starts serving, or False on exit, shutdown, or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if should_exit is not None and should_exit.is_set():
                return False
            if not self.process.is_alive():
                return False
            if self.is_ready(timeout=1):
                return True
            time.sleep(0.1)
        return False

    def start(self) -> None:
        self.process.start()

    def terminate(self) -> None:
        if self.process.exitcode is None:  # Process is still running
            assert self.process.pid is not None
            if os.name == "nt":  # pragma: py-not-win32
                # Windows doesn't support SIGTERM.
                # So send SIGBREAK, and then in process raise SIGTERM.
                os.kill(self.process.pid, signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            else:
                os.kill(self.process.pid, signal.SIGTERM)
            logger.info(f"Terminated child process [{self.process.pid}]")

            self.parent_conn.close()
            self.child_conn.close()

    def kill(self) -> None:
        # In Windows, the method will call `TerminateProcess` to kill the process.
        # In Unix, the method will send SIGKILL to the process.
        self.process.kill()
        self.parent_conn.close()
        self.child_conn.close()

    def join(self) -> None:
        logger.info(f"Waiting for child process [{self.process.pid}]")
        self.process.join()

    @property
    def server(self) -> Server:
        if self._server is None:
            self._server = Server(config=self.config)
        return self._server

    @property
    def pid(self) -> int | None:
        return self.process.pid

    @property
    def exitcode(self) -> int | None:
        return self.process.exitcode


class Multiprocess:
    def __init__(
        self,
        config: Config,
        sockets: list[socket],
    ) -> None:
        self.config = config
        self.sockets = sockets

        self.processes_num = config.workers
        self.processes: list[Process] = []

        self.should_exit = threading.Event()

        self.signal_queue: list[int] = []
        for sig in SIGNALS:
            signal.signal(sig, lambda sig, frame: self.signal_queue.append(sig))

    def init_processes(self) -> None:
        for _ in range(self.processes_num):
            process = Process(self.config, self.sockets)
            process.start()
            self.processes.append(process)

    def terminate_all(self) -> None:
        for process in self.processes:
            process.terminate()

    def join_all(self) -> None:
        for process in self.processes:
            process.join()

    def restart_all(self) -> None:
        """Replaces each worker, bringing its replacement into service before retiring the old worker."""
        for idx, old_process in enumerate(self.processes):
            if self.should_exit.is_set():
                return

            new_process = Process(self.config, self.sockets)
            new_process.start()

            if not new_process.wait_until_ready(self.config.timeout_worker_healthcheck, self.should_exit):
                new_process.kill()
                new_process.join()
                if not self.should_exit.is_set():
                    logger.error(
                        f"New child process [{new_process.pid}] was not ready in time; "
                        f"keeping worker [{old_process.pid}] and aborting the restart."
                    )
                return

            old_process.terminate()
            old_process.join()
            self.processes[idx] = new_process

    def run(self) -> None:
        message = f"Started parent process [{os.getpid()}]"
        color_message = "Started parent process [{}]".format(style(str(os.getpid()), fg="cyan", bold=True))
        logger.info(message, extra={"color_message": color_message})

        self.init_processes()

        while not self.should_exit.wait(0.5):
            self.handle_signals()
            self.keep_subprocess_alive()

        self.terminate_all()
        self.join_all()

        message = f"Stopping parent process [{os.getpid()}]"
        color_message = "Stopping parent process [{}]".format(style(str(os.getpid()), fg="cyan", bold=True))
        logger.info(message, extra={"color_message": color_message})

    def keep_subprocess_alive(self) -> None:
        if self.should_exit.is_set():
            return  # parent process is exiting, no need to keep subprocess alive

        for idx, process in enumerate(self.processes):
            if process.is_alive(timeout=self.config.timeout_worker_healthcheck):
                continue

            process.kill()  # process is hung, kill it
            process.join()

            if process.exitcode == STARTUP_FAILURE:
                # The worker failed before it started serving, so the app, TLS or socket
                # bind is broken and would fail the same way on every restart.
                # See https://github.com/encode/uvicorn/discussions/2440.
                logger.error(f"Child process [{process.pid}] failed to start, stopping the parent process.")
                self.should_exit.set()
                return

            if self.should_exit.is_set():
                return  # pragma: full coverage

            logger.info(f"Child process [{process.pid}] died")
            process = Process(self.config, self.sockets)
            process.start()
            self.processes[idx] = process

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
        logger.info("Received SIGHUP, restarting processes.")
        self.restart_all()

    def handle_ttin(self) -> None:  # pragma: py-win32
        logger.info("Received SIGTTIN, increasing the number of processes.")
        self.processes_num += 1
        process = Process(self.config, self.sockets)
        process.start()
        self.processes.append(process)

    def handle_ttou(self) -> None:  # pragma: py-win32
        logger.info("Received SIGTTOU, decreasing number of processes.")
        if self.processes_num <= 1:
            logger.info("Already reached one process, cannot decrease the number of processes anymore.")
            return
        self.processes_num -= 1
        process = self.processes.pop()
        process.terminate()
        process.join()

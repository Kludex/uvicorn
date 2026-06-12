from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from multiprocessing import Pipe
from socket import socket

import click

from uvicorn._subprocess import get_subprocess
from uvicorn.config import Config
from uvicorn.server import STARTUP_FAILURE, Server
from uvicorn.supervisors.basereload import BaseReload, _display_path

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
        self.server: Server | None = None
        self.ready = False
        self.failed = False

        self.parent_conn, self.child_conn = Pipe()
        self.process = get_subprocess(config, self.target, sockets)

    def ping(self, timeout: float = 5) -> bool:
        self.parent_conn.send(b"ping")
        if self.parent_conn.poll(timeout):
            started: bool = self.parent_conn.recv()
            self.ready = self.ready or started
            return True
        return False

    def pong(self) -> None:
        # The pong carries `Server.started`, so the supervisor can tell a worker that died
        # before startup completed (fatal) from one that crashed while serving (restart).
        self.child_conn.recv()
        self.child_conn.send(self.server is not None and self.server.started)

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

        self.server = Server(config=self.config)
        threading.Thread(target=self.always_pong, daemon=True).start()
        self.server.run(sockets)

    def is_alive(self, timeout: float = 5) -> bool:
        if not self.process.is_alive():
            return False  # pragma: full coverage

        return self.ping(timeout)

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

    def join(self) -> None:
        logger.info(f"Waiting for child process [{self.process.pid}]")
        self.process.join()

    @property
    def pid(self) -> int | None:
        return self.process.pid


class Multiprocess:
    def __init__(
        self,
        config: Config,
        sockets: list[socket],
        watcher: BaseReload | None = None,
    ) -> None:
        self.config = config
        self.sockets = sockets
        self.watcher = watcher

        self.processes_num = config.workers
        self.processes: list[Process] = []

        self.should_exit = threading.Event()
        self.startup_failed = False

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
        for idx, process in enumerate(self.processes):
            process.terminate()
            process.join()
            new_process = Process(self.config, self.sockets)
            new_process.start()
            self.processes[idx] = new_process

    def run(self) -> None:
        role = "parent" if self.watcher is None else "reloader"
        message = f"Started {role} process [{os.getpid()}]"
        color_message = "Started {} process [{}]".format(role, click.style(str(os.getpid()), fg="cyan", bold=True))
        logger.info(message, extra={"color_message": color_message})

        self.init_processes()

        while not self.should_exit.wait(0.5):
            self.handle_signals()
            self.keep_subprocess_alive()
            self.check_for_changes()

        self.terminate_all()
        self.join_all()

        message = f"Stopping {role} process [{os.getpid()}]"
        color_message = "Stopping {} process [{}]".format(role, click.style(str(os.getpid()), fg="cyan", bold=True))
        logger.info(message, extra={"color_message": color_message})

        if self.startup_failed:
            sys.exit(STARTUP_FAILURE)

    def keep_subprocess_alive(self) -> None:
        if self.should_exit.is_set():
            return  # parent process is exiting, no need to keep subprocess alive

        for idx, process in enumerate(self.processes):
            if process.failed:
                continue  # already dead before startup, only a reload can bring it back

            if process.is_alive(timeout=self.config.timeout_worker_healthcheck):
                continue

            process.kill()  # process is hung, kill it
            process.join()

            if self.should_exit.is_set():
                return  # pragma: full coverage

            if not process.ready:
                if self.watcher is None:
                    logger.error(f"Child process [{process.pid}] died before startup completed, shutting down.")
                    self.startup_failed = True
                    self.should_exit.set()
                    return
                logger.error(f"Child process [{process.pid}] died before startup completed, waiting for changes.")
                process.failed = True
                continue

            logger.info(f"Child process [{process.pid}] died")
            process = Process(self.config, self.sockets)
            process.start()
            self.processes[idx] = process

    def check_for_changes(self) -> None:
        if self.watcher is None or self.should_exit.is_set():
            return

        changes = self.watcher.should_restart()
        if changes:
            logger.warning(
                "%s detected changes in %s. Reloading...",
                self.watcher.reloader_name,
                ", ".join(map(_display_path, changes)),
            )
            self.restart_all()

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

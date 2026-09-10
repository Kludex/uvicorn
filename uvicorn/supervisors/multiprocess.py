from __future__ import annotations

import logging
import os
import signal
import threading
from socket import socket

from uvicorn._ansi import style
from uvicorn.config import STARTUP_FAILURE, Config
from uvicorn.supervisors.process import Process

SIGNALS = {
    getattr(signal, f"SIG{x}"): x
    for x in "INT TERM BREAK HUP QUIT TTIN TTOU USR1 USR2 WINCH".split()
    if hasattr(signal, f"SIG{x}")
}

logger = logging.getLogger("uvicorn.error")


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
            return

        for idx, process in enumerate(self.processes):
            if process.is_alive(timeout=self.config.timeout_worker_healthcheck):
                continue

            process.kill()
            process.join()

            if process.exitcode == STARTUP_FAILURE:
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

from __future__ import annotations

import functools
import os
import signal
import socket
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

import pytest

from uvicorn import Config
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.supervisors import Multiprocess
from uvicorn.supervisors.multiprocess import Process


def new_console_in_windows(test_function: Callable[[], Any]) -> Callable[[], Any]:  # pragma: no cover
    if os.name != "nt":
        return test_function

    @functools.wraps(test_function)
    def new_function():
        import subprocess
        import sys

        module = test_function.__module__
        name = test_function.__name__

        subprocess.check_call(
            [sys.executable, "-c", f"from {module} import {name}; {name}.__wrapped__()"],
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

    return new_function


@contextmanager
def with_running_supervisor(supervisor: Multiprocess):
    """Context manager that runs supervisor in a thread and ensures cleanup on exit."""
    thread = threading.Thread(target=supervisor.run, daemon=True)
    thread.start()
    time.sleep(1)  # Wait for supervisor to start
    try:
        yield thread
    finally:
        # Signal supervisor to exit (in case test failed before sending SIGINT)
        supervisor.should_exit.set()
        thread.join(timeout=10)
        if thread.is_alive():
            raise RuntimeError("Supervisor thread did not exit in time")


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    pass  # pragma: no cover


def run(sockets: list[socket.socket] | None) -> None:
    while True:  # pragma: no cover
        time.sleep(1)


def test_process_ping_pong() -> None:
    process = Process(Config(app=app), target=lambda x: None, sockets=[])
    threading.Thread(target=process.always_pong, daemon=True).start()
    assert process.ping()


def test_process_ping_pong_multiple() -> None:
    process = Process(Config(app=app), target=lambda x: None, sockets=[])
    threading.Thread(target=process.always_pong, daemon=True).start()
    for _ in range(5):
        assert process.ping()


def test_process_ping_pong_timeout() -> None:
    process = Process(Config(app=app), target=lambda x: None, sockets=[])
    assert not process.ping(0.1)


def test_process_ping_after_socket_closed() -> None:
    """Test that ping returns False when socket is closed."""
    process = Process(Config(app=app), target=lambda x: None, sockets=[])
    process.parent_sock.close()
    assert not process.ping(0.1)


def test_process_is_alive_when_not_started() -> None:
    """Test is_alive returns False for a process that hasn't started."""
    process = Process(Config(app=app), target=lambda x: None, sockets=[])
    assert not process.is_alive(timeout=0.1)


@new_console_in_windows
def test_multiprocess_run() -> None:
    """
    A basic sanity check.

    Simply run the supervisor against a no-op server, and signal for it to
    quit immediately.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        supervisor.signal_queue.append(signal.SIGINT)


@new_console_in_windows
def test_multiprocess_health_check() -> None:
    """
    Ensure that the health check works as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        process = supervisor.processes[0]
        process.kill()
        assert not process.is_alive()
        deadline = time.monotonic() + 10
        while not all(p.is_alive() for p in supervisor.processes):  # pragma: no cover
            assert time.monotonic() < deadline, "Timed out waiting for processes to be alive"
            time.sleep(0.1)
        supervisor.signal_queue.append(signal.SIGINT)


@new_console_in_windows
def test_multiprocess_sigterm() -> None:
    """
    Ensure that the SIGTERM signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        time.sleep(1)
        supervisor.signal_queue.append(signal.SIGTERM)


@pytest.mark.skipif(not hasattr(signal, "SIGBREAK"), reason="platform unsupports SIGBREAK")
@new_console_in_windows
def test_multiprocess_sigbreak() -> None:  # pragma: py-not-win32
    """
    Ensure that the SIGBREAK signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        time.sleep(1)
        supervisor.signal_queue.append(getattr(signal, "SIGBREAK"))


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="platform unsupports SIGHUP")
def test_multiprocess_sighup() -> None:
    """
    Ensure that the SIGHUP signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        pids = [p.pid for p in supervisor.processes]
        supervisor.signal_queue.append(signal.SIGHUP)
        # Poll instead of a fixed sleep — the supervisor loop runs on a 0.5s interval and
        # `restart_all()` terminates/joins each worker sequentially, so the total time is non-deterministic.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if [p.pid for p in supervisor.processes] != pids:
                break
            time.sleep(0.1)
        assert pids != [p.pid for p in supervisor.processes]
        supervisor.signal_queue.append(signal.SIGINT)


@pytest.mark.skipif(not hasattr(signal, "SIGTTIN"), reason="platform unsupports SIGTTIN")
def test_multiprocess_sigttin() -> None:
    """
    Ensure that the SIGTTIN signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        supervisor.signal_queue.append(signal.SIGTTIN)
        time.sleep(1)
        assert len(supervisor.processes) == 3
        supervisor.signal_queue.append(signal.SIGINT)


@pytest.mark.skipif(not hasattr(signal, "SIGTTOU"), reason="platform unsupports SIGTTOU")
def test_multiprocess_sigttou() -> None:
    """
    Ensure that the SIGTTOU signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        supervisor.signal_queue.append(signal.SIGTTOU)
        time.sleep(1)
        assert len(supervisor.processes) == 1
        supervisor.signal_queue.append(signal.SIGTTOU)
        time.sleep(1)
        assert len(supervisor.processes) == 1
        supervisor.signal_queue.append(signal.SIGINT)


@new_console_in_windows
def test_multiprocess_single_worker() -> None:
    """Test multiprocess with a single worker."""
    config = Config(app=app, workers=1)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        time.sleep(0.5)
        assert len(supervisor.processes) == 1
        assert supervisor.processes[0].is_alive()
        supervisor.signal_queue.append(signal.SIGINT)


@new_console_in_windows
def test_multiprocess_all_workers_alive() -> None:
    """Test that all workers are alive after startup."""
    config = Config(app=app, workers=3)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        time.sleep(0.5)  # Wait for processes to be initialized
        assert len(supervisor.processes) == 3
        for process in supervisor.processes:
            assert process.is_alive()
        supervisor.signal_queue.append(signal.SIGINT)
    # After context exits, all processes should be dead
    for process in supervisor.processes:
        assert not process.is_alive()


@new_console_in_windows
def test_multiprocess_terminate_already_dead_process() -> None:
    """Test that terminating an already dead process doesn't raise."""
    config = Config(app=app, workers=1)
    supervisor = Multiprocess(config, target=run, sockets=[])
    with with_running_supervisor(supervisor):
        time.sleep(0.5)
        process = supervisor.processes[0]
        # Kill the process first
        process.kill()
        time.sleep(0.5)
        # Terminate should not raise even though process is dead
        process.terminate()
        supervisor.signal_queue.append(signal.SIGINT)

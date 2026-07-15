from __future__ import annotations

import functools
import os
import signal
import threading
import time
from collections.abc import Callable
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


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    pass  # pragma: no cover


def test_process_ping_pong() -> None:
    process = Process(Config(app=app), sockets=[])
    threading.Thread(target=process.always_pong, daemon=True).start()
    assert process.ping()


def test_process_ping_pong_timeout() -> None:
    process = Process(Config(app=app), sockets=[])
    assert not process.ping(0.1)


def test_process_ping_broken_pipe() -> None:
    process = Process(Config(app=app), sockets=[])
    process.parent_conn.close()
    process.child_conn.close()
    assert not process.ping(0.1)


def test_process_ready() -> None:
    """`is_ready()` reflects whether the worker's server has finished startup."""
    process = Process(Config(app=app), sockets=[])
    threading.Thread(target=process.always_pong, daemon=True).start()

    assert process.ping()
    assert not process.is_ready()

    process.server.started = True
    assert process.is_ready()


@new_console_in_windows
def test_multiprocess_run() -> None:
    """
    A basic sanity check.

    Simply run the supervisor against a no-op server, and signal for it to
    quit immediately.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()


@new_console_in_windows
def test_multiprocess_health_check() -> None:
    """
    Ensure that the health check works as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    time.sleep(1)
    process = supervisor.processes[0]
    process.kill()
    assert not process.is_alive()
    deadline = time.monotonic() + 10
    while not all(p.is_alive() for p in supervisor.processes):  # pragma: no cover
        assert time.monotonic() < deadline, "Timed out waiting for processes to be alive"
        time.sleep(0.1)
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()


@new_console_in_windows
def test_multiprocess_worker_dies_on_startup() -> None:
    """A worker that fails to load the app stops the parent instead of restarting forever.

    Regression for https://github.com/encode/uvicorn/discussions/2440.
    """
    config = Config(app="tests.supervisors.test_multiprocess:does_not_exist", workers=2)
    supervisor = Multiprocess(config, sockets=[])
    thread = threading.Thread(target=supervisor.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not supervisor.should_exit.is_set():  # pragma: no cover
        assert time.monotonic() < deadline, "Timed out waiting for the supervisor to stop"
        time.sleep(0.1)
    thread.join()


@new_console_in_windows
def test_multiprocess_sigterm() -> None:
    """
    Ensure that the SIGTERM signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    time.sleep(1)
    supervisor.signal_queue.append(signal.SIGTERM)
    supervisor.join_all()


@pytest.mark.skipif(not hasattr(signal, "SIGBREAK"), reason="platform unsupports SIGBREAK")
@new_console_in_windows
def test_multiprocess_sigbreak() -> None:  # pragma: py-not-win32
    """
    Ensure that the SIGBREAK signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    time.sleep(1)
    supervisor.signal_queue.append(getattr(signal, "SIGBREAK"))
    supervisor.join_all()


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="platform unsupports SIGHUP")
def test_multiprocess_sighup() -> None:
    """
    Ensure that the SIGHUP signal is handled as expected.
    """
    config = Config(app=app, workers=2, timeout_worker_healthcheck=30)
    supervisor = Multiprocess(config, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    time.sleep(1)
    pids = [p.pid for p in supervisor.processes]
    supervisor.signal_queue.append(signal.SIGHUP)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if [p.pid for p in supervisor.processes] != pids:
            break
        time.sleep(0.1)
    assert pids != [p.pid for p in supervisor.processes]
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()


@pytest.mark.skipif(os.name == "nt", reason="test spawns real worker processes")
def test_multiprocess_restart_aborts_when_replacement_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """If a replacement never becomes ready, the existing worker is kept and the restart is aborted."""
    config = Config(app=app, workers=2, timeout_worker_healthcheck=1)
    supervisor = Multiprocess(config, sockets=[])
    supervisor.init_processes()
    original_pids = [p.pid for p in supervisor.processes]

    monkeypatch.setattr(Process, "is_ready", lambda self, timeout=1: False)
    supervisor.restart_all()

    assert [p.pid for p in supervisor.processes] == original_pids
    assert all(process.is_alive() for process in supervisor.processes)
    supervisor.terminate_all()
    supervisor.join_all()


def test_wait_until_ready_bails_on_shutdown_or_dead_worker() -> None:
    process = Process(Config(app=app), sockets=[])

    should_exit = threading.Event()
    should_exit.set()
    assert process.wait_until_ready(timeout=1, should_exit=should_exit) is False
    assert process.wait_until_ready(timeout=0.5) is False


def test_multiprocess_restart_stops_when_shutting_down() -> None:
    supervisor = Multiprocess(Config(app=app, workers=1), sockets=[])
    supervisor.processes = [Process(supervisor.config, [])]
    supervisor.should_exit.set()

    supervisor.restart_all()

    assert len(supervisor.processes) == 1


@pytest.mark.skipif(not hasattr(signal, "SIGTTIN"), reason="platform unsupports SIGTTIN")
def test_multiprocess_sigttin() -> None:
    """
    Ensure that the SIGTTIN signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    supervisor.signal_queue.append(signal.SIGTTIN)
    time.sleep(1)
    assert len(supervisor.processes) == 3
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()


@pytest.mark.skipif(not hasattr(signal, "SIGTTOU"), reason="platform unsupports SIGTTOU")
def test_multiprocess_sigttou() -> None:
    """
    Ensure that the SIGTTOU signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    supervisor.signal_queue.append(signal.SIGTTOU)
    time.sleep(1)
    assert len(supervisor.processes) == 1
    supervisor.signal_queue.append(signal.SIGTTOU)
    time.sleep(1)
    assert len(supervisor.processes) == 1
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()

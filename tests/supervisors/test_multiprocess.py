from __future__ import annotations

import functools
import os
import signal
import socket
import threading
import time
from typing import Any, Callable

import pytest

from tests.utils import with_retry
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
            [
                sys.executable,
                "-c",
                f"from {module} import {name}; {name}.__wrapped__()",
            ],
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )

    return new_function


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    pass  # pragma: no cover


def run(sockets: list[socket.socket] | None) -> None:
    while True:  # pragma: no cover
        time.sleep(1)


def test_process_ping_pong() -> None:
    process = Process(Config(app=app), target=lambda x: None, sockets=[])
    threading.Thread(target=process.always_pong, daemon=True).start()
    assert process.ping()


def test_process_ping_pong_timeout() -> None:
    process = Process(Config(app=app), target=lambda x: None, sockets=[])
    assert not process.ping(0.1)


@new_console_in_windows
def test_multiprocess_run() -> None:
    """
    A basic sanity check.

    Simply run the supervisor against a no-op server, and signal for it to
    quit immediately.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()


@new_console_in_windows
@with_retry(3)
def test_multiprocess_health_check() -> None:
    """
    Ensure that the health check works as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    time.sleep(0)  # release gil.
    time.sleep(1)  # ensure server is up.
    process = supervisor.processes[0]
    assert process.is_alive()
    process.kill()
    process.join()
    try:
        assert not process.is_alive(0.5)
        time.sleep(0)  # release gil.
        time.sleep(1)  # ensure process restart complete.
        for p in supervisor.processes:
            assert p.is_alive()
    finally:
        supervisor.signal_queue.append(signal.SIGINT)
        supervisor.join_all()


@new_console_in_windows
def test_multiprocess_sigterm() -> None:
    """
    Ensure that the SIGTERM signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
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
    supervisor = Multiprocess(config, target=run, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    time.sleep(1)
    supervisor.signal_queue.append(getattr(signal, "SIGBREAK"))
    supervisor.join_all()


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="platform unsupports SIGHUP")
def test_multiprocess_sighup() -> None:
    """
    Ensure that the SIGHUP signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    time.sleep(1)
    pids = [p.pid for p in supervisor.processes]
    supervisor.signal_queue.append(signal.SIGHUP)
    time.sleep(1)
    assert pids != [p.pid for p in supervisor.processes]
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()


@pytest.mark.skipif(not hasattr(signal, "SIGTTIN"), reason="platform unsupports SIGTTIN")
def test_multiprocess_sigttin() -> None:
    """
    Ensure that the SIGTTIN signal is handled as expected.
    """
    config = Config(app=app, workers=2)
    supervisor = Multiprocess(config, target=run, sockets=[])
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
    supervisor = Multiprocess(config, target=run, sockets=[])
    threading.Thread(target=supervisor.run, daemon=True).start()
    supervisor.signal_queue.append(signal.SIGTTOU)
    time.sleep(1)
    assert len(supervisor.processes) == 1
    supervisor.signal_queue.append(signal.SIGTTOU)
    time.sleep(1)
    assert len(supervisor.processes) == 1
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.join_all()

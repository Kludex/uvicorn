from __future__ import annotations

import signal
import socket
import threading
from collections.abc import Callable

import pytest
from pytest_mock import MockerFixture

from uvicorn import Config
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.server import Server
from uvicorn.supervisors.multithread import Multithread, Thread, ThreadServer


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    pass  # pragma: no cover


class FakeThread:
    def __init__(
        self,
        config: Config,
        target: Callable[[list[socket.socket] | None], None],
        sockets: list[socket.socket],
    ) -> None:
        self.config = config
        self.target = target
        self.sockets = sockets
        self.started = False
        self.alive = True
        self.terminated = False
        self.joined = False
        self.healthy = True
        self.join_result = True

    def is_alive(self) -> bool:
        return self.alive

    def is_healthy(self, timeout: float) -> bool:
        return self.healthy

    def start(self) -> None:
        self.started = True

    def terminate(self) -> None:
        self.terminated = True
        self.alive = False

    def join(self, timeout: float | None = None) -> bool:
        self.joined = True
        if self.join_result:
            self.alive = False
        return self.join_result


def test_thread_target_passes_duplicated_sockets() -> None:
    captured_sockets: list[socket.socket] | None = None

    def target(sockets: list[socket.socket] | None) -> None:
        nonlocal captured_sockets
        captured_sockets = sockets

    sock = socket.socket()
    try:
        thread = Thread(Config(app=app), target=target, sockets=[sock])
        thread.target()
    finally:
        sock.close()

    assert captured_sockets is not None
    assert len(captured_sockets) == 1
    assert captured_sockets[0].fileno() == -1


def test_thread_terminate_sets_server_exit_flag() -> None:
    config = Config(app=app)
    thread = Thread(config, target=Server(config).run, sockets=[])
    target = thread._get_target()

    assert thread.server is not None
    assert isinstance(thread.server, ThreadServer)
    assert target.__self__ is thread.server
    assert thread.server.should_exit is False

    thread.terminate()

    assert thread.server.should_exit is True


def test_thread_record_heartbeat_and_is_healthy() -> None:
    thread = Thread(Config(app=app, timeout_worker_healthcheck=1), target=lambda sockets: None, sockets=[])
    thread.last_heartbeat -= 5

    assert thread.is_healthy(1) is False

    thread.record_heartbeat()

    assert thread.is_healthy(1) is True


@pytest.mark.anyio
async def test_thread_server_records_heartbeat_on_tick() -> None:
    thread = Thread(Config(app=app), target=lambda sockets: None, sockets=[])
    server = ThreadServer(config=Config(app=app), worker_thread=thread)
    before = thread.last_heartbeat

    thread.last_heartbeat -= 5
    await server.on_tick(10)

    assert thread.last_heartbeat > before


def test_thread_start_and_join() -> None:
    finished = threading.Event()

    def target(sockets: list[socket.socket] | None) -> None:
        finished.set()

    thread = Thread(Config(app=app), target=target, sockets=[])
    thread.start()

    assert thread.join() is True
    assert finished.is_set()
    assert thread.is_alive() is False


def test_thread_join_timeout_returns_false_for_hung_thread() -> None:
    blocker = threading.Event()

    def target(sockets: list[socket.socket] | None) -> None:
        blocker.wait()

    thread = Thread(Config(app=app), target=target, sockets=[])
    thread.start()

    try:
        assert thread.join(timeout=0.01) is False
        assert thread.is_alive() is True
    finally:
        blocker.set()
        assert thread.join(timeout=1) is True


def test_multithread_init_terminate_join_and_restart(mocker: MockerFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(Config(app=app, workers=2), target=lambda sockets: None, sockets=[])

    supervisor.init_threads()
    original_threads = list(supervisor.threads)

    assert len(supervisor.threads) == 2
    assert all(thread.started for thread in supervisor.threads)

    supervisor.terminate_all()
    assert all(thread.terminated for thread in original_threads)

    supervisor.join_all()
    assert all(thread.joined for thread in original_threads)

    supervisor.restart_all()
    assert len(supervisor.threads) == 2
    assert all(thread is not old for thread, old in zip(supervisor.threads, original_threads))
    assert all(thread.started for thread in supervisor.threads)


def test_multithread_keep_subthread_alive_replaces_dead_thread(mocker: MockerFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(Config(app=app, workers=2), target=lambda sockets: None, sockets=[])
    supervisor.init_threads()

    dead_thread = supervisor.threads[0]
    dead_thread.alive = False

    supervisor.keep_subthread_alive()

    assert supervisor.threads[0] is not dead_thread
    assert supervisor.threads[0].started is True


def test_multithread_keep_subthread_alive_replaces_unhealthy_thread(mocker: MockerFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(Config(app=app, workers=2), target=lambda sockets: None, sockets=[])
    supervisor.init_threads()

    unhealthy_thread = supervisor.threads[0]
    unhealthy_thread.healthy = False

    supervisor.keep_subthread_alive()

    assert supervisor.threads[0] is not unhealthy_thread
    assert supervisor.threads[0].started is True


def test_multithread_keep_subthread_alive_replaces_unhealthy_thread_without_blocking_join(
    mocker: MockerFixture,
) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(Config(app=app, workers=1), target=lambda sockets: None, sockets=[])
    supervisor.init_threads()

    unhealthy_thread = supervisor.threads[0]
    unhealthy_thread.healthy = False
    unhealthy_thread.join_result = False

    supervisor.keep_subthread_alive()

    assert supervisor.threads[0] is not unhealthy_thread
    assert unhealthy_thread in supervisor.stale_threads


def test_multithread_keep_subthread_alive_noop_when_exiting(mocker: MockerFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(Config(app=app, workers=1), target=lambda sockets: None, sockets=[])
    supervisor.init_threads()
    dead_thread = supervisor.threads[0]
    dead_thread.alive = False
    supervisor.should_exit.set()

    supervisor.keep_subthread_alive()

    assert supervisor.threads[0] is dead_thread


def test_multithread_signal_handlers(mocker: MockerFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(Config(app=app, workers=2), target=lambda sockets: None, sockets=[])
    supervisor.init_threads()

    supervisor.handle_ttin()
    assert len(supervisor.threads) == 3

    removed_thread = supervisor.threads[-1]
    supervisor.handle_ttou()
    assert len(supervisor.threads) == 2
    assert removed_thread.terminated is True
    assert removed_thread.joined is True

    supervisor.handle_ttou()
    supervisor.handle_ttou()
    assert len(supervisor.threads) == 1

    original_threads = list(supervisor.threads)
    supervisor.handle_hup()
    assert len(supervisor.threads) == 1
    assert supervisor.threads[0] is not original_threads[0]

    supervisor.handle_term()
    assert supervisor.should_exit.is_set()


def test_multithread_join_all_uses_timeout_and_warns(mocker: MockerFixture, caplog: pytest.LogCaptureFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(
        Config(app=app, workers=1, timeout_worker_healthcheck=2, timeout_graceful_shutdown=3),
        target=lambda sockets: None,
        sockets=[],
    )
    supervisor.init_threads()
    thread = supervisor.threads[0]
    thread.join_result = False

    supervisor.join_all()

    assert thread.joined is True
    assert "Worker thread did not exit within 3.00 seconds." in caplog.records[-1].message


def test_multithread_thread_shutdown_timeout_defaults_to_healthcheck(mocker: MockerFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(
        Config(app=app, workers=1, timeout_worker_healthcheck=7),
        target=lambda sockets: None,
        sockets=[],
    )

    assert supervisor._thread_shutdown_timeout == 7.0


@pytest.mark.skipif(not hasattr(signal, "SIGBREAK"), reason="platform unsupports SIGBREAK")
def test_multithread_handle_break() -> None:  # pragma: py-not-win32
    supervisor = Multithread(Config(app=app, workers=1), target=lambda sockets: None, sockets=[])
    supervisor.handle_break()
    assert supervisor.should_exit.is_set()


def test_multithread_handle_signals_and_run(mocker: MockerFixture) -> None:
    mocker.patch("uvicorn.supervisors.multithread.Thread", FakeThread)
    supervisor = Multithread(Config(app=app, workers=1), target=lambda sockets: None, sockets=[])
    supervisor.signal_queue.extend([signal.SIGINT, signal.SIGUSR1])

    supervisor.handle_signals()
    assert supervisor.should_exit.is_set()
    assert supervisor.signal_queue == []

    supervisor = Multithread(Config(app=app, workers=1), target=lambda sockets: None, sockets=[])
    supervisor.signal_queue.append(signal.SIGINT)
    supervisor.run()

    assert supervisor.should_exit.is_set()

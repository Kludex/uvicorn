from __future__ import annotations

import asyncio
import contextlib
import logging
import os

import pytest

from tests.utils import run_server
from uvicorn._types import ASGIApplication, ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.server import Server, worker_id_from_env

pytestmark = pytest.mark.anyio

factory_env: list[str | None] = []


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    pass  # pragma: no cover


def factory_reads_worker_id() -> ASGIApplication:
    factory_env.append(os.environ.get("UVICORN_WORKER_ID"))
    return app


async def _serve_until_started(server: Server) -> None:
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    await server.shutdown()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def _record_lifespan_state(
    scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable, seen: dict[str, object]
) -> None:
    assert scope["type"] == "lifespan"
    message = await receive()
    assert message["type"] == "lifespan.startup"
    seen["has_worker_id"] = "uvicorn_worker_id" in scope["state"]
    seen["worker_id"] = scope["state"].get("uvicorn_worker_id")
    seen["env"] = os.environ.get("UVICORN_WORKER_ID")
    await send({"type": "lifespan.startup.complete"})
    message = await receive()
    assert message["type"] == "lifespan.shutdown"
    await send({"type": "lifespan.shutdown.complete"})


async def test_server_defaults_worker_id_to_one(unused_tcp_port: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UVICORN_WORKER_ID", raising=False)
    seen: dict[str, object] = {}

    async def lifespan_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await _record_lifespan_state(scope, receive, send, seen)

    config = Config(app=lifespan_app, lifespan="on", port=unused_tcp_port)
    async with run_server(config):
        pass
    assert seen["worker_id"] == 1
    assert seen["env"] == "1"


async def test_server_injects_worker_id_into_lifespan_state(
    unused_tcp_port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("UVICORN_WORKER_ID", raising=False)
    seen: dict[str, object] = {}

    async def lifespan_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await _record_lifespan_state(scope, receive, send, seen)

    config = Config(app=lifespan_app, lifespan="on", port=unused_tcp_port)
    server = Server(config=config, worker_id=5)
    await _serve_until_started(server)
    assert seen["worker_id"] == 5
    assert seen["env"] == "5"


async def test_server_does_not_adopt_leftover_worker_id_env(
    unused_tcp_port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UVICORN_WORKER_ID", "9")
    seen: dict[str, object] = {}

    async def lifespan_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await _record_lifespan_state(scope, receive, send, seen)

    config = Config(app=lifespan_app, lifespan="on", port=unused_tcp_port)
    server = Server(config=config)
    await _serve_until_started(server)
    assert seen["worker_id"] == 1
    assert seen["env"] == "1"


def test_worker_id_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UVICORN_WORKER_ID", raising=False)
    assert worker_id_from_env() is None
    monkeypatch.setenv("UVICORN_WORKER_ID", "9")
    assert worker_id_from_env() == 9
    monkeypatch.setenv("UVICORN_WORKER_ID", "nope")
    assert worker_id_from_env() is None


async def test_explicit_worker_id_from_env_is_injected(unused_tcp_port: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UVICORN_WORKER_ID", "9")
    seen: dict[str, object] = {}

    async def lifespan_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await _record_lifespan_state(scope, receive, send, seen)

    config = Config(app=lifespan_app, lifespan="on", port=unused_tcp_port)
    worker_id = worker_id_from_env()
    assert worker_id is not None
    server = Server(config=config, worker_id=worker_id)
    await _serve_until_started(server)
    assert seen["worker_id"] == 9


async def test_worker_id_env_is_set_before_app_load(unused_tcp_port: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UVICORN_WORKER_ID", raising=False)
    factory_env.clear()
    config = Config(
        app="tests.test_worker_id:factory_reads_worker_id",
        factory=True,
        lifespan="off",
        port=unused_tcp_port,
    )
    server = Server(config=config, worker_id=3)
    await _serve_until_started(server)
    assert factory_env == ["3"]


async def test_server_logs_worker_id(
    unused_tcp_port: int, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("UVICORN_WORKER_ID", raising=False)
    caplog.set_level(logging.INFO, logger="uvicorn.error")
    config = Config(app=app, lifespan="off", port=unused_tcp_port)
    server = Server(config=config, worker_id=2)
    await _serve_until_started(server)
    assert "Started server process [" in caplog.text
    assert "(worker 2)" in caplog.text


async def test_server_startup_override_without_worker_id_kwarg(unused_tcp_port: int) -> None:
    """Subclasses that override startup(sockets=None) must keep working."""

    class CustomServer(Server):
        async def startup(self, sockets=None) -> None:
            self.custom_startup = True
            await super().startup(sockets)

    config = Config(app=app, lifespan="off", port=unused_tcp_port)
    server = CustomServer(config=config, worker_id=4)
    await _serve_until_started(server)
    assert server.custom_startup is True

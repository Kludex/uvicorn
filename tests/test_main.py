import importlib
import inspect
import socket
import sys
from logging import WARNING
from pathlib import Path

import httpx
import pytest

import uvicorn.server
from tests.utils import run_server
from uvicorn import Server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import STARTUP_FAILURE, Config
from uvicorn.main import run
from uvicorn.supervisors import Multiprocess

pytestmark = pytest.mark.anyio


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    assert scope["type"] == "http"
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


def _has_ipv6(host: str):
    sock = None
    has_ipv6 = False
    if socket.has_ipv6:
        try:
            sock = socket.socket(socket.AF_INET6)
            sock.bind((host, 0))
            has_ipv6 = True
        except Exception:  # pragma: no cover
            pass
    if sock:
        sock.close()
    return has_ipv6


@pytest.mark.parametrize(
    "host, url",
    [
        pytest.param(None, "http://127.0.0.1", id="default"),
        pytest.param("localhost", "http://127.0.0.1", id="hostname"),
        pytest.param(
            "::1",
            "http://[::1]",
            id="ipv6",
            marks=pytest.mark.skipif(not _has_ipv6("::1"), reason="IPV6 not enabled"),
        ),
    ],
)
async def test_run(host, url: str, unused_tcp_port: int):
    config = Config(app=app, host=host, loop="asyncio", limit_max_requests=1, port=unused_tcp_port)
    async with run_server(config):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{url}:{unused_tcp_port}")
    assert response.status_code == 204


async def test_run_multiprocess(unused_tcp_port: int):
    config = Config(app=app, loop="asyncio", workers=2, limit_max_requests=1, port=unused_tcp_port)
    async with run_server(config):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


async def test_run_reload(unused_tcp_port: int):
    config = Config(app=app, loop="asyncio", reload=True, limit_max_requests=1, port=unused_tcp_port)
    async with run_server(config):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


def test_run_invalid_app_config_combination(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit) as exit_exception:
        run(app, reload=True)
    assert exit_exception.value.code == STARTUP_FAILURE
    assert caplog.records[-1].name == "uvicorn.error"
    assert caplog.records[-1].levelno == WARNING
    assert caplog.records[-1].message == (
        "You must pass the application as an import string to enable 'reload' or 'workers'."
    )


def test_run_fails_fast_in_parent_on_bad_app_path(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bad app path exits in the parent for the single-process case.

    Regression for https://github.com/encode/uvicorn/issues/941: the app is
    imported eagerly before the event loop starts.
    """

    def fail(self: Server, sockets: object = None) -> None:  # pragma: no cover
        pytest.fail("parent reached Server.run; should have exited on bad app path")

    monkeypatch.setattr(Server, "run", fail)

    with pytest.raises(SystemExit) as exit_exception:
        run("tests.test_main:nonexistent_attr")
    assert exit_exception.value.code == STARTUP_FAILURE
    assert any("Error loading ASGI app" in record.message for record in caplog.records)


def test_run_skips_eager_app_import_with_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    """With `--workers > 1` the parent does not import the app.

    Spawn-based workers re-import everything, so loading it in the supervisor
    only wastes memory. See https://github.com/Kludex/uvicorn/discussions/2980.
    """

    def fail(self: Config) -> object:  # pragma: no cover
        pytest.fail("parent loaded the app; spawn workers re-import it themselves")

    with socket.socket() as sock:
        monkeypatch.setattr(Config, "load_app", fail)
        monkeypatch.setattr(Multiprocess, "run", lambda self: None)
        monkeypatch.setattr(Config, "bind_socket", lambda self: sock)

        run("tests.test_main:app", workers=2)


def test_run_imports_app_before_starting_event_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`uvicorn.run()` imports the app before `Server.run` opens the event loop.

    Regression for https://github.com/encode/uvicorn/issues/941: an app whose
    module body calls `asyncio.run(...)` crashes with "loop already running"
    if Uvicorn imports it inside the server's event loop. The parent must
    import the app synchronously, before `Server.run` enters `asyncio.run`.
    """
    module = tmp_path / "eager_async_app.py"
    module.write_text(
        "import asyncio\n"
        "async def _build():\n"
        "    async def app(scope, receive, send):\n"
        "        pass\n"
        "    return app\n"
        "app = asyncio.run(_build())\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    imported_before_server_run: list[bool] = []

    def tracking_run(self: Server, sockets: object = None) -> None:
        imported_before_server_run.append("eager_async_app" in sys.modules)
        self.started = True

    monkeypatch.setattr(Server, "run", tracking_run)

    # The import side effect (`eager_async_app` lands in `sys.modules`) must
    # happen before `Server.run`, which is where the event loop opens.
    run("eager_async_app:app")

    assert imported_before_server_run == [True]


def test_run_startup_failure(caplog: pytest.LogCaptureFixture) -> None:
    async def app(scope, receive, send):
        assert scope["type"] == "lifespan"
        message = await receive()
        if message["type"] == "lifespan.startup":
            raise RuntimeError("Startup failed")

    with pytest.raises(SystemExit) as exit_exception:
        run(app, lifespan="on")
    assert exit_exception.value.code == 3


def test_run_match_config_params() -> None:
    config_params = {
        key: repr(value)
        for key, value in inspect.signature(Config.__init__).parameters.items()
        if key not in ("self", "timeout_notify", "callback_notify")
    }
    run_params = {
        key: repr(value) for key, value in inspect.signature(run).parameters.items() if key not in ("app_dir",)
    }
    assert config_params == run_params


async def test_exit_on_create_server_with_invalid_host() -> None:
    with pytest.raises(SystemExit) as exc_info:
        config = Config(app=app, host="illegal_host")
        server = Server(config=config)
        await server.serve()
    assert exc_info.value.code == STARTUP_FAILURE


def test_deprecated_server_state_from_main() -> None:
    with pytest.deprecated_call(
        match="uvicorn.main.ServerState is deprecated, use uvicorn.server.ServerState instead."
    ):
        main = importlib.import_module("uvicorn.main")
        server_state_cls = getattr(main, "ServerState")
    assert server_state_cls is uvicorn.server.ServerState

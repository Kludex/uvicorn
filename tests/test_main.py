import importlib
import inspect
import socket
from logging import WARNING

import httpx
import pytest

import uvicorn.server
from tests.utils import run_server
from uvicorn import Server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.main import run

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
    assert exit_exception.value.code == 1
    assert caplog.records[-1].name == "uvicorn.error"
    assert caplog.records[-1].levelno == WARNING
    assert caplog.records[-1].message == (
        "You must pass the application as an import string to enable 'reload' or 'workers'."
    )


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
    assert exc_info.value.code == 1


def test_deprecated_server_state_from_main() -> None:
    with pytest.deprecated_call(
        match="uvicorn.main.ServerState is deprecated, use uvicorn.server.ServerState instead."
    ):
        main = importlib.import_module("uvicorn.main")
        server_state_cls = getattr(main, "ServerState")
    assert server_state_cls is uvicorn.server.ServerState

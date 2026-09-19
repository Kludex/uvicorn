import contextlib

import pytest

from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.server import Server

entered = False
exited = False


async def dummy_asgi_app(scope, receive, send):
    if scope["type"] == "http":
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK"})


@contextlib.asynccontextmanager
async def async_cm_factory():
    global entered, exited
    entered = True
    try:
        yield dummy_asgi_app
    finally:
        exited = True


@pytest.mark.anyio
async def test_asynccontextmanager_factory():
    global entered, exited
    entered = False
    exited = False

    config = Config(app=async_cm_factory, factory=True, lifespan="on")
    config.load()
    server = Server(config=config)
    server.lifespan = config.lifespan_class(config)

    await server.lifespan.startup()
    assert entered is True
    assert exited is False
    assert isinstance(config.loaded_app, ProxyHeadersMiddleware)
    assert config.loaded_app.app is dummy_asgi_app

    await server.lifespan.shutdown()
    assert exited is True


def test_asynccontextmanager_factory_lifespan_off():
    config = Config(app=async_cm_factory, factory=True, lifespan="off")
    with pytest.raises(SystemExit):
        config.load()

import contextlib

import pytest

from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.server import Server

entered = False
exited = False


async def dummy_asgi_app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    elif scope["type"] == "http":
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
    assert server.lifespan.startup_failed is False
    assert server.lifespan.should_exit is False
    assert entered is True
    assert exited is False
    assert isinstance(config.loaded_app, ProxyHeadersMiddleware)

    response_events = []

    async def mock_send(event):
        response_events.append(event)

    await config.loaded_app({"type": "http"}, None, mock_send)
    assert len(response_events) == 2

    await server.lifespan.shutdown()
    assert server.lifespan.shutdown_failed is False
    assert exited is True


def test_asynccontextmanager_factory_lifespan_off():
    config = Config(app=async_cm_factory, factory=True, lifespan="off")
    with pytest.raises(SystemExit):
        config.load()


@pytest.mark.anyio
async def test_asynccontextmanager_startup_error():
    @contextlib.asynccontextmanager
    async def broken_startup_factory():
        raise RuntimeError("Startup fail")
        yield dummy_asgi_app  # pragma: no cover

    config = Config(app=broken_startup_factory, factory=True, lifespan="on")
    config.load()
    server = Server(config=config)
    server.lifespan = config.lifespan_class(config)

    await server.lifespan.startup()
    assert server.lifespan.startup_failed is True
    assert server.lifespan.should_exit is True


@pytest.mark.anyio
async def test_asynccontextmanager_shutdown_error():
    @contextlib.asynccontextmanager
    async def broken_shutdown_factory():
        try:
            yield dummy_asgi_app
        finally:
            raise RuntimeError("Shutdown fail")

    config = Config(app=broken_shutdown_factory, factory=True, lifespan="on")
    config.load()
    server = Server(config=config)
    server.lifespan = config.lifespan_class(config)

    await server.lifespan.startup()
    assert server.lifespan.startup_failed is False
    await server.lifespan.shutdown()
    assert server.lifespan.shutdown_failed is True
    assert server.lifespan.should_exit is True

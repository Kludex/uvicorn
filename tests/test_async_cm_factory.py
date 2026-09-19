import asyncio
import contextlib

import pytest

from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.server import Server


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


def test_asynccontextmanager_factory():
    events = []

    @contextlib.asynccontextmanager
    async def async_cm_factory():
        events.append("enter")
        try:
            yield dummy_asgi_app
        finally:
            events.append("exit")

    async def run_test():
        config = Config(app=async_cm_factory, factory=True, lifespan="on")
        config.load()
        server = Server(config=config)
        server.lifespan = config.lifespan_class(config)

        await server.lifespan.startup()
        assert server.lifespan.startup_failed is False
        assert server.lifespan.should_exit is False
        assert events == ["enter"]
        assert isinstance(config.loaded_app, ProxyHeadersMiddleware)

        response_events = []

        async def mock_receive():
            return {"type": "http.request"}

        async def mock_send(event):
            response_events.append(event)

        await config.loaded_app({"type": "http"}, mock_receive, mock_send)
        assert len(response_events) == 2

        await server.lifespan.shutdown()
        assert server.lifespan.shutdown_failed is False
        assert events == ["enter", "exit"]

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


def test_asynccontextmanager_factory_lifespan_off():
    @contextlib.asynccontextmanager
    async def async_cm_factory():
        yield dummy_asgi_app  # pragma: no cover

    config = Config(app=async_cm_factory, factory=True, lifespan="off")
    with pytest.raises(SystemExit):
        config.load()


def test_asynccontextmanager_startup_error():
    @contextlib.asynccontextmanager
    async def broken_startup_factory():
        raise RuntimeError("Startup fail")
        yield dummy_asgi_app  # pragma: no cover

    async def run_test():
        config = Config(app=broken_startup_factory, factory=True, lifespan="on")
        config.load()
        server = Server(config=config)
        server.lifespan = config.lifespan_class(config)

        await server.lifespan.startup()
        assert server.lifespan.startup_failed is True
        assert server.lifespan.should_exit is True

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


def test_asynccontextmanager_shutdown_error():
    @contextlib.asynccontextmanager
    async def broken_shutdown_factory():
        try:
            yield dummy_asgi_app
        finally:
            raise RuntimeError("Shutdown fail")

    async def run_test():
        config = Config(app=broken_shutdown_factory, factory=True, lifespan="on")
        config.load()
        server = Server(config=config)
        server.lifespan = config.lifespan_class(config)

        await server.lifespan.startup()
        assert server.lifespan.startup_failed is False
        await server.lifespan.shutdown()
        assert server.lifespan.shutdown_failed is True
        assert server.lifespan.should_exit is True

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()

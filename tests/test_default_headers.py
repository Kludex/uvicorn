from __future__ import annotations

import httpx2
import pytest

from tests.utils import run_server
from uvicorn import Config
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope

pytestmark = pytest.mark.anyio


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    assert scope["type"] == "http"
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


async def test_default_default_headers(unused_tcp_port: int):
    config = Config(app=app, loop="asyncio", limit_max_requests=1, port=unused_tcp_port)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
            assert response.headers["server"] == "uvicorn" and response.headers["date"]


async def test_override_server_header(unused_tcp_port: int):
    headers: list[tuple[str, str]] = [("Server", "over-ridden")]
    config = Config(app=app, loop="asyncio", limit_max_requests=1, headers=headers, port=unused_tcp_port)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
            assert response.headers["server"] == "over-ridden" and response.headers["date"]


async def test_disable_default_server_header(unused_tcp_port: int):
    config = Config(app=app, loop="asyncio", limit_max_requests=1, server_header=False, port=unused_tcp_port)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
            assert "server" not in response.headers


async def test_override_server_header_multiple_times(unused_tcp_port: int):
    headers: list[tuple[str, str]] = [("Server", "over-ridden"), ("Server", "another-value")]
    config = Config(app=app, loop="asyncio", limit_max_requests=1, headers=headers, port=unused_tcp_port)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
            assert response.headers["server"] == "over-ridden, another-value" and response.headers["date"]


async def test_add_additional_header(unused_tcp_port: int):
    headers: list[tuple[str, str]] = [("X-Additional", "new-value")]
    config = Config(app=app, loop="asyncio", limit_max_requests=1, headers=headers, port=unused_tcp_port)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
            assert response.headers["x-additional"] == "new-value"
            assert response.headers["server"] == "uvicorn"
            assert response.headers["date"]


async def test_disable_default_date_header(unused_tcp_port: int):
    config = Config(app=app, loop="asyncio", limit_max_requests=1, date_header=False, port=unused_tcp_port)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")
            assert "date" not in response.headers

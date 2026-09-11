from __future__ import annotations

import asyncio
import os
import random
from typing import TYPE_CHECKING

import anyio
import pytest

from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config

if TYPE_CHECKING:
    from uvicorn.protocols.http.h11_impl import H11Protocol
    from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

pytestmark = [pytest.mark.anyio, pytest.mark.stress]

CLIENTS = int(os.getenv("UVICORN_STRESS_CLIENTS", "20"))
REQUESTS_PER_CLIENT = int(os.getenv("UVICORN_STRESS_REQUESTS", "25"))
SEEDS = [int(value) for value in os.getenv("UVICORN_STRESS_SEEDS", "42").split(",")]


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    assert scope["type"] == "http"
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return
        assert message["type"] == "http.request"
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break

    response_body = body if scope["path"] == "/echo" else scope["path"].encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", str(len(response_body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": response_body})


@pytest.mark.parametrize("seed", SEEDS)
async def test_concurrent_http_connections(
    seed: int,
    unused_tcp_port: int,
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol],
) -> None:
    config = Config(
        app=app,
        access_log=False,
        http=http_protocol_cls,
        lifespan="off",
        log_level="warning",
        port=unused_tcp_port,
    )

    with anyio.fail_after(60):
        async with run_server(config):
            async with anyio.create_task_group() as task_group:
                for client_id in range(CLIENTS):
                    task_group.start_soon(_persistent_client, unused_tcp_port, seed, client_id)
                    task_group.start_soon(_connection_churn, unused_tcp_port, seed, client_id)
                    task_group.start_soon(_incomplete_requests, unused_tcp_port, seed, client_id)

            await _request(unused_tcp_port, b"GET /healthy HTTP/1.1\r\nHost: localhost\r\n\r\n", b"/healthy")


async def _persistent_client(port: int, seed: int, client_id: int) -> None:
    randomizer = random.Random((seed << 32) | client_id)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        for request_id in range(REQUESTS_PER_CLIENT):
            token = f"/{seed}-{client_id}-{request_id}".encode()
            if randomizer.randrange(4) == 0:
                following_token = token + b"-pipelined"
                writer.write(_get_request(token) + _get_request(following_token))
                await writer.drain()
                assert await _read_response(reader) == token
                assert await _read_response(reader) == following_token
            else:
                body = randomizer.randbytes(randomizer.randrange(1, 2049))
                request = _post_request(body)
                offset = 0
                while offset < len(request):
                    chunk_size = randomizer.randrange(1, min(64, len(request) - offset) + 1)
                    writer.write(request[offset : offset + chunk_size])
                    await writer.drain()
                    offset += chunk_size
                    await anyio.lowlevel.checkpoint()
                assert await _read_response(reader) == body
    finally:
        writer.close()
        await writer.wait_closed()


async def _connection_churn(port: int, seed: int, client_id: int) -> None:
    for request_id in range(max(1, REQUESTS_PER_CLIENT // 5)):
        token = f"/{seed}-{client_id}-churn-{request_id}".encode()
        await _request(port, _get_request(token, close=True), token)


async def _incomplete_requests(port: int, seed: int, client_id: int) -> None:
    randomizer = random.Random((seed << 32) | (1 << 31) | client_id)
    requests = [
        b"GET / HTTP/1.1\r\nHost: localhost\r\n",
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\npartial",
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n10\r\npartial",
    ]
    for _ in range(max(1, REQUESTS_PER_CLIENT // 5)):
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        request = randomizer.choice(requests)
        writer.write(request[: randomizer.randrange(1, len(request) + 1)])
        await writer.drain()
        writer.close()
        await writer.wait_closed()


async def _request(port: int, request: bytes, expected_body: bytes) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        assert await _read_response(reader) == expected_body
    finally:
        writer.close()
        await writer.wait_closed()


def _get_request(path: bytes, *, close: bool = False) -> bytes:
    connection = b"close" if close else b"keep-alive"
    return b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\nConnection: " + connection + b"\r\n\r\n"


def _post_request(body: bytes) -> bytes:
    return b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


async def _read_response(reader: asyncio.StreamReader) -> bytes:
    header_block = await reader.readuntil(b"\r\n\r\n")
    status_line, *headers = header_block.split(b"\r\n")
    assert status_line == b"HTTP/1.1 200 OK"
    content_length = next(
        int(value)
        for name, value in (header.split(b":", 1) for header in headers if b":" in header)
        if name.lower() == b"content-length"
    )
    return await reader.readexactly(content_length)

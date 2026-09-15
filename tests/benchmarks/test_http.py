from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.benchmarks.http import (
    CONNECTION_CLOSE_REQUEST,
    FINISH_POST_REQUEST,
    FRAGMENTED_BODY_CHUNKS,
    FRAGMENTED_POST_HEADERS,
    HTTP10_GET_REQUEST,
    LARGE_POST_REQUEST,
    SIMPLE_GET_REQUEST,
    SIMPLE_POST_REQUEST,
    START_POST_REQUEST,
    get_connected_protocol,
    make_config,
)
from tests.response import Response
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope

if TYPE_CHECKING:
    from tests.benchmarks.http import HTTPProtocol

pytestmark = [pytest.mark.anyio, pytest.mark.benchmark]

_plain_text_app = Response("Hello, world", media_type="text/plain")
_no_content_app = Response(b"", status_code=204)
_chunked_app = Response(b"Hello, world!", status_code=200, headers={"transfer-encoding": "chunked"})

_plain_text_config = make_config(_plain_text_app)
_chunked_config = make_config(_chunked_app)


async def _body_echo_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")  # type: ignore[operator]
        if not message.get("more_body", False):
            break
    headers = [(b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": 200, "headers": headers})
    await send({"type": "http.response.body", "body": body})


_body_echo_config = make_config(_body_echo_app)


async def test_bench_simple_get(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()


async def test_bench_simple_post(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(SIMPLE_POST_REQUEST)
    await protocol.loop.run_one()


async def test_bench_large_post(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(LARGE_POST_REQUEST)
    await protocol.loop.run_one()


async def test_bench_pipelined_requests(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(SIMPLE_GET_REQUEST * 3)
    await protocol.loop.run_one()
    await protocol.loop.run_one()
    await protocol.loop.run_one()


async def test_bench_keepalive_reuse(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()


async def test_bench_chunked_response(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_chunked_config, http_protocol_cls)
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()


async def test_bench_http10(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(HTTP10_GET_REQUEST)
    await protocol.loop.run_one()


async def test_bench_connection_close(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(CONNECTION_CLOSE_REQUEST)
    await protocol.loop.run_one()


async def test_bench_fragmented_body(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_plain_text_config, http_protocol_cls)
    protocol.data_received(FRAGMENTED_POST_HEADERS)
    for chunk in FRAGMENTED_BODY_CHUNKS:
        protocol.data_received(chunk)
    await protocol.loop.run_one()


async def test_bench_post_body_receive(http_protocol_cls: type[HTTPProtocol]) -> None:
    protocol = get_connected_protocol(_body_echo_config, http_protocol_cls)
    protocol.data_received(START_POST_REQUEST)
    protocol.data_received(FINISH_POST_REQUEST)
    await protocol.loop.run_one()

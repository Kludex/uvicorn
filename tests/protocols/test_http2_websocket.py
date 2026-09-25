from __future__ import annotations

import contextvars
import ssl
from typing import Any

import anyio
import pytest

pytest.importorskip("wsproto")
pytest.importorskip("zttp")

import zttp
from wsproto import ConnectionType, events
from wsproto.connection import Connection
from wsproto.extensions import PerMessageDeflate

from tests.protocols.test_http2 import H2Client, frame, get_connected_protocol, skip_if_no_zttp_h2
from tests.response import Response
from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config

pytestmark = [
    pytest.mark.anyio,
    skip_if_no_zttp_h2,
    pytest.mark.skipif(not hasattr(zttp.Request, "protocol"), reason="zttp >= 0.0.32 is required"),
]


def connect(
    client: H2Client,
    target: bytes = b"/chat?token=abc",
    headers: list[tuple[bytes, bytes]] | None = None,
    protocol: bytes = b"websocket",
    end: bool = False,
    scheme: bytes = b"http",
) -> tuple[zttp.Stream, bytes]:
    preface = client.data_to_send()
    stream = client.request(b"CONNECT", target, end=False)
    opening = preface + client.data_to_send()
    offset = 24 if opening.startswith(b"PRI * HTTP/2.0") else 0
    while opening[offset + 3] != 1:
        offset += 9 + int.from_bytes(opening[offset : offset + 3], "big")
    # ponytail: short HPACK literals until zttp's client can send :protocol.
    fields = [
        (b":method", b"CONNECT"),
        (b":protocol", protocol),
        (b":scheme", scheme),
        (b":path", target),
        (b":authority", b"example.org"),
        *(headers if headers is not None else [(b"sec-websocket-version", b"13")]),
    ]
    block = b"".join(bytes([0, len(name)]) + name + bytes([len(value)]) + value for name, value in fields)
    return stream, opening[:offset] + frame(1, 4 | int(end), stream.stream_id, block)


@pytest.mark.parametrize("ws", ["auto", "wsproto"])
@pytest.mark.parametrize("compression", [False, True])
@pytest.mark.parametrize("tls", [False, True])
async def test_echo_over_tcp(
    unused_tcp_port: int,
    ws: str,
    compression: bool,
    tls: bool,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_ssl_context: ssl.SSLContext,
) -> None:
    scopes: list[Scope] = []
    disconnected = anyio.Event()
    context = contextvars.ContextVar("websocket_context", default="default")
    context.set("inherited")

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        scopes.append(scope)
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b"sibling"})
            return
        assert context.get() == ("default" if ws == "wsproto" else "inherited")
        assert await receive() == {"type": "websocket.connect"}
        await send(
            {
                "type": "websocket.accept",
                "subprotocol": "chat",
                "headers": [(b"x-accepted", b"yes"), (b"connection", b"upgrade"), (b"content-length", b"0")],
            }
        )
        for _ in range(3):
            message = await receive()
            if message["type"] == "websocket.disconnect":
                assert message["code"] == 1000
                disconnected.set()
                return
            assert message["type"] == "websocket.receive"
            text = message.get("text")
            if text is not None:
                await send({"type": "websocket.send", "text": text})
            else:
                data = message["bytes"]
                assert data is not None
                await send({"type": "websocket.send", "bytes": data})

    config = Config(
        app,
        http="zttp",
        http2=True,
        ws=ws,
        lifespan="off",
        port=unused_tcp_port,
        root_path="/root",
        ws_per_message_deflate=compression,
        reset_contextvars=ws == "wsproto",
        ssl_certfile=tls_certificate_server_cert_path if tls else None,
        ssl_keyfile=tls_certificate_private_key_path if tls else None,
    )
    client = H2Client()
    stream, opening = connect(
        client,
        target=b"/ch%61t?token=abc",
        scheme=b"https" if tls else b"http",
        headers=[
            (b"sec-websocket-version", b"13"),
            (b"sec-websocket-protocol", b"other, chat"),
            (b"sec-websocket-extensions", b"permessage-deflate"),
        ],
    )
    extension = PerMessageDeflate()
    responses: list[Any] = []
    received: list[Any] = []
    tls_ca_ssl_context.set_alpn_protocols(["h2"])
    with anyio.fail_after(5):
        async with (
            run_server(config) as server,
            await (
                anyio.connect_tcp("127.0.0.1", unused_tcp_port, ssl_context=tls_ca_ssl_context)
                if tls
                else anyio.connect_tcp("127.0.0.1", unused_tcp_port)
            ) as socket,
        ):
            await socket.send(opening)
            while not any(isinstance(event, zttp.Response) for event in responses):
                responses.extend(client.events(await socket.receive()))
            response = next(event for event in responses if isinstance(event, zttp.Response))
            assert response.status_code == 200
            headers = dict(response.headers)
            assert headers[b"sec-websocket-protocol"] == b"chat"
            assert headers[b"x-accepted"] == b"yes"
            assert not {b"upgrade", b"connection", b"sec-websocket-accept", b"content-length"} & headers.keys()
            if compression:
                extension.finalize(headers[b"sec-websocket-extensions"].decode())
            else:
                assert b"sec-websocket-extensions" not in headers
            websocket = Connection(ConnectionType.CLIENT, [extension] if compression else [])
            assert len(server.server_state.connections) == 1
            messages: list[events.TextMessage | events.BytesMessage] = [
                events.TextMessage(data="hello"),
                events.BytesMessage(data=b"x" * 100_000),
            ]
            for message in messages:
                stream.send_data(websocket.send(message))
                await socket.send(client.data_to_send())
                fragments: list[bytes] = []
                finished = False
                while not finished:
                    for event in client.events(await socket.receive()):
                        if isinstance(event, zttp.Data):
                            websocket.receive_data(event.data)
                    for event in websocket.events():
                        assert isinstance(event, (events.TextMessage, events.BytesMessage))
                        fragments.append(event.data.encode() if isinstance(event.data, str) else bytes(event.data))
                        finished = event.message_finished
                    await socket.send(client.data_to_send())
                expected = message.data.encode() if isinstance(message.data, str) else message.data
                assert b"".join(fragments) == expected
            sibling = client.request()
            stream.send_data(websocket.send(events.CloseConnection(code=1000, reason="done")))
            await socket.send(client.data_to_send())
            while not any(
                isinstance(event, zttp.EndOfMessage) and event.stream_id == sibling.stream_id for event in received
            ):
                received.extend(client.events(await socket.receive()))
                await socket.send(client.data_to_send())
            await disconnected.wait()
            assert any(isinstance(event, zttp.Data) and event.data == b"sibling" for event in received)
    scope = scopes[0]
    assert scope["type"] == "websocket"
    assert scope["http_version"] == "2"
    assert scope["scheme"] == ("wss" if tls else "ws")
    assert scope["path"] == "/root/chat"
    assert scope["raw_path"] == b"/root/ch%61t"
    assert scope["query_string"] == b"token=abc"
    assert scope["subprotocols"] == ["other", "chat"]
    assert (b"host", b"example.org") in scope["headers"]
    assert not any(name.startswith(b":") for name, _ in scope["headers"])


@pytest.mark.parametrize("denial", [False, True])
async def test_rejection(denial: bool) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert await receive() == {"type": "websocket.connect"}
        if denial:
            await send({"type": "websocket.http.response.start", "status": 401, "headers": [(b"x-denied", b"yes")]})
            await send({"type": "websocket.http.response.body", "body": b"denied"})
        else:
            await send({"type": "websocket.close"})

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening)
    await protocol.loop.run_one()
    status, headers, body, ended = client.parse_response(protocol.transport.buffer)
    assert status == (401 if denial else 403)
    assert body == (b"denied" if denial else b"")
    assert ended
    assert not protocol.transport.closed


@pytest.mark.parametrize(
    ("kwargs", "headers", "extended", "end", "status"),
    [
        ({"ws": "none"}, None, b"websocket", False, 501),
        ({"ws": "websockets-sansio"}, None, b"websocket", False, 501),
        ({}, None, b"unknown", False, 501),
        ({}, [], b"websocket", False, 400),
        ({}, [(b"sec-websocket-version", b"12")], b"websocket", False, 426),
        ({}, [(b"sec-websocket-version", b"13"), (b"sec-websocket-protocol", b"\xff")], b"websocket", False, 400),
        ({}, None, b"websocket", True, 400),
        ({"limit_concurrency": 1}, None, b"websocket", False, 503),
    ],
)
async def test_invalid_connect(kwargs: dict[str, Any], headers: Any, extended: bytes, end: bool, status: int) -> None:
    protocol = get_connected_protocol(Response("not a websocket"), **kwargs)
    client = H2Client()
    _, opening = connect(client, headers=headers, protocol=extended, end=end)
    protocol.data_received(opening)
    assert client.parse_response(protocol.transport.buffer)[0] == status
    assert not protocol.transport.closed


@pytest.mark.parametrize("termination", ["reset", "end", "lost", "shutdown"])
async def test_disconnect(termination: str) -> None:
    from uvicorn.protocols.utils import ClientDisconnected

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "http":
            await Response("sibling")(scope, receive, send)
            return
        await receive()
        await send({"type": "websocket.accept"})
        if termination == "reset":
            protocol.data_received(frame(3, 0, 1, (8).to_bytes(4, "big")))
        elif termination == "end":
            protocol.data_received(frame(0, 1, 1, b""))
        elif termination == "lost":
            protocol.transport.close()
            protocol.data_received(frame(0, 0, 1, Connection(ConnectionType.CLIENT).send(events.Ping())))
            protocol.connection_lost(OSError("connection lost"))
        else:
            protocol.shutdown()
        message = await receive()
        assert message["type"] == "websocket.disconnect"
        assert message["code"] == (1012 if termination == "shutdown" else 1006)
        with pytest.raises(ClientDisconnected):
            await send({"type": "websocket.send", "text": "too late"})

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening)
    await protocol.loop.run_one()
    if termination in ("end", "reset"):
        assert not protocol.transport.closed
        sibling = client.request()
        protocol.data_received(client.data_to_send())
        await protocol.loop.run_one()
        responses = client.events(protocol.transport.buffer)
        assert any(isinstance(event, zttp.Data) and event.stream_id == sibling.stream_id for event in responses)
    else:
        assert protocol.transport.closed


@pytest.mark.parametrize("reply", [False, True])
async def test_server_close(reply: bool) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await receive()
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.close", "code": 1001, "reason": "leaving"})

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening)
    await protocol.loop.run_one()
    response = client.events(protocol.transport.buffer)
    protocol.transport.clear_buffer()
    websocket = Connection(ConnectionType.CLIENT)
    for event in response:
        if isinstance(event, zttp.Data):
            websocket.receive_data(event.data)
    close = next(websocket.events())
    assert isinstance(close, events.CloseConnection)
    assert close.code == 1001
    assert close.reason == "leaving"
    if reply:
        protocol.data_received(frame(0, 0, 1, websocket.send(close.response())))
    else:
        protocol.loop.run_later(10)
    assert any(isinstance(event, zttp.EndOfMessage) for event in client.events(protocol.transport.buffer))


@pytest.mark.parametrize("failure", ["return", "raise", "subprotocol", "status"])
async def test_application_errors(failure: str, caplog: pytest.LogCaptureFixture) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await receive()
        if failure == "raise":
            raise ValueError("broken app")
        if failure == "subprotocol":
            await send({"type": "websocket.accept", "subprotocol": "not-offered"})
        if failure == "status":
            await send({"type": "websocket.http.response.start", "status": 200, "headers": []})

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening)
    await protocol.loop.run_one()
    response = client.events(protocol.transport.buffer)
    if failure in ("return", "raise"):
        assert any(isinstance(event, zttp.Response) and event.status_code == 500 for event in response)
    else:
        assert any(isinstance(event, zttp.RstStream) for event in response)
    assert caplog.records
    assert not protocol.transport.closed


@pytest.mark.parametrize("violation", ["size", "queue", "unmasked"])
async def test_bad_messages_only_close_the_websocket(violation: str) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "http":
            await Response("sibling")(scope, receive, send)
            return
        await receive()
        await send({"type": "websocket.accept"})
        websocket = Connection(ConnectionType.CLIENT)
        if violation == "size":
            data = websocket.send(events.TextMessage(data="too long"))
        elif violation == "queue":
            data = websocket.send(events.TextMessage(data="one")) * 3
        else:
            data = b"\x81\x01x"
        protocol.data_received(frame(0, 0, 1, data))
        message = await receive()
        assert message["type"] == "websocket.disconnect"
        assert message["code"] == {"size": 1009, "queue": 1013, "unmasked": 1002}[violation]

    protocol = get_connected_protocol(app, ws="wsproto", ws_max_size=4, ws_max_queue=1)
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening)
    await protocol.loop.run_one()
    client.request()
    protocol.data_received(client.data_to_send())
    await protocol.loop.run_one()
    assert not protocol.transport.closed
    assert not protocol.transport.read_paused


@pytest.mark.parametrize("early", ["data", "end", "shutdown"])
async def test_disconnected_before_accept(early: str) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert await receive() == {"type": "websocket.connect"}
        assert (await receive())["type"] == "websocket.disconnect"

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening)
    if early == "shutdown":
        protocol.shutdown()
    else:
        protocol.data_received(frame(0, int(early == "end"), 1, b"early" if early == "data" else b""))
    await protocol.loop.run_one()
    response = client.events(protocol.transport.buffer)
    assert any(
        isinstance(event, zttp.Response) and event.status_code == (500 if early == "shutdown" else 400)
        for event in response
    )


async def test_transport_backpressure() -> None:
    paused = anyio.Event()
    sent = anyio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await receive()
        await send({"type": "websocket.accept"})
        protocol.pause_writing()
        paused.set()
        await send({"type": "websocket.send", "text": "resumed"})
        sent.set()
        await send({"type": "websocket.close"})

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening)
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(protocol.loop.run_one)
        await paused.wait()
        assert not sent.is_set()
        protocol.resume_writing()
        await sent.wait()
    protocol.loop.run_later(10)
    response = client.events(protocol.transport.buffer)
    assert any(isinstance(event, zttp.Data) and b"resumed" in event.data for event in response)


async def test_shutdown_drains_pending_data() -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await receive()
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.send", "text": "pending"})

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    _, opening = connect(client)
    protocol.data_received(opening + frame(4, 0, 0, (4).to_bytes(2, "big") + bytes(4)))
    await protocol.loop.run_one()
    response = client.events(protocol.transport.buffer)
    protocol.transport.clear_buffer()
    assert not any(isinstance(event, (zttp.Data, zttp.EndOfMessage)) for event in response)
    protocol.shutdown()
    assert not protocol.transport.closed
    protocol.data_received(frame(8, 0, 1, (1024).to_bytes(4, "big")))
    response = client.events(protocol.transport.buffer)
    assert any(isinstance(event, zttp.Data) and b"pending" in event.data for event in response)
    assert any(isinstance(event, zttp.EndOfMessage) for event in response)
    assert protocol.transport.closed


async def test_multiplexed_websockets() -> None:
    ready = {"/one": anyio.Event(), "/two": anyio.Event()}
    echoed = anyio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "websocket"
        await receive()
        await send({"type": "websocket.accept"})
        ready[scope["path"]].set()
        if scope["path"] == "/one":
            assert await receive() == {"type": "websocket.disconnect", "code": 1006}
            return
        assert await receive() == {"type": "websocket.receive", "text": "hello"}
        await send({"type": "websocket.send", "text": "hello"})
        echoed.set()
        assert (await receive())["type"] == "websocket.disconnect"

    protocol = get_connected_protocol(app, ws="wsproto")
    client = H2Client()
    first, opening = connect(client, target=b"/one")
    protocol.data_received(opening)
    second, opening = connect(client, target=b"/two")
    protocol.data_received(opening)
    websocket = Connection(ConnectionType.CLIENT)
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(protocol.loop.run_one)
        tasks.start_soon(protocol.loop.run_one)
        await ready["/one"].wait()
        await ready["/two"].wait()
        protocol.data_received(frame(3, 0, first.stream_id, (8).to_bytes(4, "big")))
        protocol.data_received(frame(0, 0, second.stream_id, websocket.send(events.TextMessage(data="hello"))))
        await echoed.wait()
        protocol.data_received(frame(0, 0, second.stream_id, websocket.send(events.CloseConnection(code=1000))))
    response = client.events(protocol.transport.buffer)
    assert any(
        isinstance(event, zttp.Data) and event.stream_id == second.stream_id and b"hello" in event.data
        for event in response
    )
    assert not protocol.transport.closed

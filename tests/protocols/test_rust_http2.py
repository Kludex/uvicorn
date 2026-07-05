from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.server import ServerState

try:
    import h2.config
    import h2.connection
    import h2.events

    # Importing the protocol pulls in `rh2`; ModuleNotFoundError means it is absent.
    from uvicorn.protocols.http.rust_h2_impl import RustH2Protocol

    skip_if_no_rh2 = pytest.mark.skipif(False, reason="")
except ModuleNotFoundError:  # pragma: no cover
    skip_if_no_rh2 = pytest.mark.skipif(True, reason="rh2 or h2 is not installed")

pytestmark = [pytest.mark.anyio, skip_if_no_rh2]


class MockSSLObject:
    def __init__(self, alpn_protocol: str | None) -> None:
        self._alpn_protocol = alpn_protocol

    def selected_alpn_protocol(self) -> str | None:
        return self._alpn_protocol


class MockTransport:
    def __init__(self, sslcontext: bool = True, alpn_protocol: str | None = "h2") -> None:
        self.buffer = b""
        self.closed = False
        self.read_paused = False
        self.sslcontext = sslcontext
        self.alpn_protocol = alpn_protocol
        self.protocol: asyncio.Protocol | None = None

    def get_extra_info(self, key: str) -> Any:
        return {
            "sockname": ("127.0.0.1", 8000),
            "peername": ("127.0.0.1", 8001),
            "sslcontext": self.sslcontext,
            "ssl_object": MockSSLObject(self.alpn_protocol) if self.sslcontext else None,
        }.get(key)

    def set_protocol(self, protocol: asyncio.Protocol) -> None:
        self.protocol = protocol

    def get_protocol(self) -> asyncio.Protocol | None:
        return self.protocol

    def write(self, data: bytes) -> None:
        assert not self.closed
        self.buffer += data

    def drain(self) -> None:
        self.buffer = b""

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def pause_reading(self) -> None:
        self.read_paused = True

    def resume_reading(self) -> None:
        self.read_paused = False


def get_connected_protocol(app: Callable[..., Any], **kwargs: Any) -> tuple[RustH2Protocol, MockTransport]:
    loop = asyncio.get_event_loop()
    transport = MockTransport()
    config = Config(app=app, http2=True, **kwargs)
    server_state = ServerState()
    lifespan = LifespanOff(config)
    protocol = RustH2Protocol(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol, transport


class H2Client:
    def __init__(self) -> None:
        self.conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
        self.conn.initiate_connection()

    def preface(self) -> bytes:
        return self.conn.data_to_send()

    def request(
        self,
        method: bytes = b"GET",
        path: bytes = b"/",
        body: bytes = b"",
        extra_headers: list[tuple[bytes, bytes]] | None = None,
    ) -> tuple[int, bytes]:
        stream_id = self.conn.get_next_available_stream_id()
        headers = [
            (b":method", method),
            (b":scheme", b"https"),
            (b":authority", b"example.org"),
            (b":path", path),
        ] + (extra_headers or [])
        self.conn.send_headers(stream_id, headers, end_stream=not body)
        if body:
            self.conn.send_data(stream_id, body, end_stream=True)
        return stream_id, self.conn.data_to_send()

    def receive(self, data: bytes) -> list[Any]:
        return self.conn.receive_data(data)


async def drain_tasks() -> None:
    # Let the ASGI task(s) created by the protocol run to completion.
    for _ in range(50):
        await asyncio.sleep(0)


async def _collect_response(client: H2Client, protocol: RustH2Protocol, transport: MockTransport) -> dict[str, Any]:
    await drain_tasks()
    events = client.receive(transport.buffer)
    transport.buffer = b""
    status = None
    headers: list[tuple[bytes, bytes]] = []
    body = b""
    ended = False
    for event in events:
        if isinstance(event, h2.events.ResponseReceived):
            for name, value in event.headers:
                if name == b":status":
                    status = int(value)
                else:
                    headers.append((name, value))
        elif isinstance(event, h2.events.DataReceived):
            body += event.data
        elif isinstance(event, h2.events.StreamEnded):
            ended = True
    return {"status": status, "headers": headers, "body": body, "ended": ended}


async def test_get_request() -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "http"
        assert scope["http_version"] == "2"
        assert scope["method"] == "GET"
        assert scope["path"] == "/hello"
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"hello world"})

    client = H2Client()
    protocol, transport = get_connected_protocol(app)
    protocol.data_received(client.preface())
    _, data = client.request(path=b"/hello")
    protocol.data_received(data)

    response = await _collect_response(client, protocol, transport)
    assert response["status"] == 200
    assert response["body"] == b"hello world"
    assert response["ended"] is True


async def test_post_request_with_body() -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b"got:" + body})

    client = H2Client()
    protocol, transport = get_connected_protocol(app)
    protocol.data_received(client.preface())
    _, data = client.request(method=b"POST", path=b"/upload", body=b"payload")
    protocol.data_received(data)

    response = await _collect_response(client, protocol, transport)
    assert response["status"] == 201
    assert response["body"] == b"got:payload"


async def test_h2c_prior_knowledge_upgrade_from_h11() -> None:
    from uvicorn.protocols.http.h11_impl import H11Protocol

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["http_version"] == "2"
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"h2c ok"})

    loop = asyncio.get_event_loop()
    transport = MockTransport(sslcontext=False)  # cleartext -> prior-knowledge sniffing
    config = Config(app=app, http2=True)
    server_state = ServerState()
    lifespan = LifespanOff(config)
    h11 = H11Protocol(config=config, server_state=server_state, app_state=lifespan.state, _loop=loop)
    h11.connection_made(transport)  # type: ignore[arg-type]

    client = H2Client()
    _, data = client.request(path=b"/")
    # The client's preface + first frames arrive on the h11 protocol, which sniffs
    # the HTTP/2 preface and hands the connection to RustH2Protocol.
    h11.data_received(client.preface() + data)

    assert isinstance(transport.get_protocol(), RustH2Protocol)
    await drain_tasks()
    events = client.receive(transport.buffer)
    body = b"".join(e.data for e in events if isinstance(e, h2.events.DataReceived))
    assert body == b"h2c ok"


async def test_concurrent_streams() -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        path = scope["path"].encode("ascii")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"path=" + path})

    client = H2Client()
    protocol, transport = get_connected_protocol(app)
    protocol.data_received(client.preface())
    _, d1 = client.request(path=b"/a")
    _, d2 = client.request(path=b"/b")
    protocol.data_received(d1)
    protocol.data_received(d2)

    await drain_tasks()
    events = client.receive(transport.buffer)
    bodies = b"".join(e.data for e in events if isinstance(e, h2.events.DataReceived))
    assert b"path=/a" in bodies
    assert b"path=/b" in bodies

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import socket
import ssl
from typing import TypeAlias

import pytest
from typing_extensions import TypedDict, Unpack

from uvicorn._types import ASGIApplication
from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.server import Server, ServerState

try:
    import zttp

    from uvicorn.protocols.http.zttp_h3_impl import ZttpH3Protocol

    skip_if_no_zttp_h3 = pytest.mark.skipif(
        not hasattr(zttp, "QuicEndpoint"), reason="zttp with HTTP/3 support is not installed"
    )
except (ImportError, AttributeError):  # pragma: no cover
    skip_if_no_zttp_h3 = pytest.mark.skipif(True, reason="zttp with HTTP/3 support is not installed")

pytestmark = [pytest.mark.anyio, skip_if_no_zttp_h3]

DatagramAddress: TypeAlias = tuple[str, int] | tuple[str, int, int, int]


class ProtocolConfig(TypedDict, total=False):
    limit_concurrency: int
    reset_contextvars: bool
    ssl_certfile: str
    ssl_keyfile: str


SERVER_ADDR: DatagramAddress = ("127.0.0.1", 443)
CLIENT_ADDR: DatagramAddress = ("127.0.0.1", 55555)


class MockDatagramTransport:
    def __init__(self, sockname: DatagramAddress = SERVER_ADDR) -> None:
        self.sockname = sockname
        self.outbox: list[bytes] = []
        self.sent_addresses: list[DatagramAddress | None] = []
        self.closed = False

    def get_extra_info(self, key: str) -> object | None:
        return {"sockname": self.sockname}.get(key)

    def sendto(self, data: bytes, addr: DatagramAddress | None = None) -> None:
        assert not self.closed
        self.outbox.append(data)
        self.sent_addresses.append(addr)

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def drain(self) -> list[bytes]:
        out = self.outbox[:]
        self.outbox.clear()
        return out


class H3Harness:
    """Drives a zttp client against a real `ZttpH3Protocol` over in-memory datagrams."""

    def __init__(
        self,
        protocol: ZttpH3Protocol,
        transport: MockDatagramTransport,
        client_addr: DatagramAddress = CLIENT_ADDR,
    ) -> None:
        self.protocol = protocol
        self.transport = transport
        self.client_addr = client_addr
        self.client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"localhost")
        self.responses: dict[int, zttp.Response] = {}
        self.bodies: dict[int, bytes] = {}
        self.ended: set[int] = set()

    @staticmethod
    def _now() -> int:
        return int(asyncio.get_event_loop().time() * 1_000_000)

    async def pump(self, rounds: int = 10) -> None:
        for _ in range(rounds):
            for datagram in self.client.data_to_send():
                self.protocol.datagram_received(datagram, self.client_addr)
            # Let the ASGI response tasks run to completion.
            for _ in range(6):
                await asyncio.sleep(0)
            for datagram in self.transport.drain():
                self.client.receive_datagram(datagram, self._now(), b"srv")
            while (event := self.client.next_event()) not in (zttp.NEED_DATA, zttp.CONNECTION_CLOSED):
                if isinstance(event, zttp.Response):
                    self.responses[event.stream_id] = event
                    self.bodies.setdefault(event.stream_id, b"")
                elif isinstance(event, zttp.Data):
                    self.bodies[event.stream_id] = self.bodies.get(event.stream_id, b"") + event.data
                    self.client.consume_data(event.stream_id, len(event.data))
                elif isinstance(event, zttp.EndOfMessage):
                    self.ended.add(event.stream_id)

    def send_request(
        self,
        method: bytes = b"GET",
        target: bytes = b"/",
        headers: list[tuple[bytes, bytes]] | None = None,
        body: bytes = b"",
    ) -> int:
        headers = [(b"host", b"localhost")] if headers is None else headers
        stream = self.client.send_request(method, target, b"3", headers)
        if body:
            stream.send_data(body)
        stream.end_message()
        return stream.stream_id


def make_protocol(
    app: ASGIApplication, **kwargs: Unpack[ProtocolConfig]
) -> tuple[ZttpH3Protocol, MockDatagramTransport, ServerState]:
    config = Config(app=app, http3=True, **kwargs)
    lifespan = LifespanOff(config)
    server_state = ServerState()
    protocol = ZttpH3Protocol(
        config=config, server_state=server_state, app_state=lifespan.state, _loop=asyncio.get_event_loop()
    )
    transport = MockDatagramTransport()
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol, transport, server_state


async def connected(
    app: ASGIApplication, **kwargs: Unpack[ProtocolConfig]
) -> tuple[H3Harness, ZttpH3Protocol, ServerState]:
    protocol, transport, server_state = make_protocol(app, **kwargs)
    harness = H3Harness(protocol, transport)
    await harness.pump()  # complete the QUIC handshake
    return harness, protocol, server_state


def teardown(protocol: ZttpH3Protocol) -> None:
    # Cancel any armed loss/idle timers so no callback survives the test.
    protocol.connection_lost(None)


def only_state(protocol: ZttpH3Protocol):
    """The endpoint's single QUIC connection state (the tests drive one client)."""
    return next(iter(protocol.states.values()))


def make_initial(connection_id: bytes) -> bytes:
    """A real client Initial datagram whose destination connection id is `connection_id`."""
    client = zttp.Connection(zttp.CLIENT, protocol=zttp.HTTP3, server_name=b"localhost", connection_id=connection_id)
    return client.data_to_send()[0]


# -- applications -------------------------------------------------------------


def echo_app(status: int = 200):
    async def app(scope, receive, send):
        assert scope["type"] == "http"
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
        payload = b"echo:" + body
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain"), (b"content-length", str(len(payload)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    return app


# -- tests --------------------------------------------------------------------


async def test_http3_get_request() -> None:
    harness, protocol, state = await connected(echo_app())
    sid = harness.send_request(b"GET", b"/hello")
    await harness.pump()
    assert harness.responses[sid].status_code == 200
    assert harness.bodies[sid] == b"echo:"
    assert state.total_requests == 1
    teardown(protocol)


async def test_http3_post_with_body_is_echoed() -> None:
    harness, protocol, _ = await connected(echo_app())
    sid = harness.send_request(b"POST", b"/submit", body=b"payload-bytes")
    await harness.pump()
    assert harness.responses[sid].status_code == 200
    assert harness.bodies[sid] == b"echo:payload-bytes"
    teardown(protocol)


async def test_http3_scope_is_http3_and_https() -> None:
    seen: dict[str, object] = {}

    async def app(scope, receive, send):
        seen.update(scope)
        await app_reply(receive, send)

    async def app_reply(receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    harness, protocol, _ = await connected(app)
    harness.send_request(b"GET", b"/a%2Fb?x=1")
    await harness.pump()
    assert seen["http_version"] == "3"
    assert seen["scheme"] == "https"
    assert seen["method"] == "GET"
    assert seen["path"] == "/a/b"
    assert seen["raw_path"] == b"/a%2Fb"
    assert seen["query_string"] == b"x=1"
    assert seen["client"] == CLIENT_ADDR
    teardown(protocol)


async def test_http3_ipv6_scope_addresses() -> None:
    seen: dict[str, object] = {}

    async def app(scope, receive, send):
        seen.update(scope)
        await receive()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    config = Config(app=app, http3=True)
    lifespan = LifespanOff(config)
    protocol = ZttpH3Protocol(
        config=config, server_state=ServerState(), app_state=lifespan.state, _loop=asyncio.get_event_loop()
    )
    transport = MockDatagramTransport(("::1", 443, 0, 0))
    protocol.connection_made(transport)  # type: ignore[arg-type]
    client_addr: DatagramAddress = ("fe80::1", 55555, 0, 3)
    harness = H3Harness(protocol, transport, client_addr)
    await harness.pump()
    harness.send_request()
    await harness.pump()
    assert seen["server"] == ("::1", 443)
    assert seen["client"] == ("fe80::1", 55555)
    assert client_addr in transport.sent_addresses
    teardown(protocol)


async def test_http3_sustained_requests() -> None:
    # Regression for the zttp final-size bug: a third and later request on the same
    # connection must not tear it down. Exercised end-to-end through uvicorn here.
    harness, protocol, state = await connected(echo_app())
    for i in range(6):
        sid = harness.send_request(b"POST", f"/n{i}".encode(), body=f"body{i}".encode())
        await harness.pump()
        assert harness.responses[sid].status_code == 200
        assert harness.bodies[sid] == b"echo:body%d" % i
    assert state.total_requests == 6
    teardown(protocol)


async def test_http3_head_response_has_no_body() -> None:
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"5")]})
        await send({"type": "http.response.body", "body": b"hello"})

    harness, protocol, _ = await connected(app)
    sid = harness.send_request(b"HEAD", b"/")
    await harness.pump()
    assert harness.responses[sid].status_code == 200
    assert harness.bodies[sid] == b""
    teardown(protocol)


async def test_http3_app_exception_returns_500() -> None:
    async def app(scope, receive, send):
        raise RuntimeError("boom")

    harness, protocol, _ = await connected(app)
    sid = harness.send_request(b"GET", b"/")
    await harness.pump()
    assert harness.responses[sid].status_code == 500
    assert harness.bodies[sid] == b"Internal Server Error"
    teardown(protocol)


async def test_http3_forbidden_headers_are_stripped() -> None:
    async def app(scope, receive, send):
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"connection", b"keep-alive"), (b"content-length", b"2")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    harness, protocol, _ = await connected(app)
    sid = harness.send_request(b"GET", b"/")
    await harness.pump()
    resp = harness.responses[sid]
    assert resp.status_code == 200
    assert not any(name == b"connection" for name, _ in resp.headers)
    teardown(protocol)


async def test_http3_access_log_is_emitted() -> None:
    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b""})

    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    protocol, transport, _ = make_protocol(app)
    protocol.access_log = True
    handler = Capture()
    protocol.access_logger.addHandler(handler)
    protocol.access_logger.setLevel(logging.INFO)
    try:
        harness = H3Harness(protocol, transport)
        await harness.pump()
        harness.send_request(b"GET", b"/logged")
        await harness.pump()
        assert any("/logged" in record.getMessage() for record in records)
    finally:
        protocol.access_logger.removeHandler(handler)
    teardown(protocol)


async def test_http3_graceful_shutdown_drains_and_closes() -> None:
    harness, protocol, _ = await connected(echo_app())
    harness.send_request(b"GET", b"/")
    await harness.pump()
    assert protocol in protocol.server_state.connections
    protocol.shutdown()
    # No live connections remain, so the endpoint deregisters and closes its socket.
    assert protocol not in protocol.server_state.connections
    assert protocol.transport.is_closing()
    teardown(protocol)


async def test_http3_shutdown_refuses_new_connections() -> None:
    protocol, _transport, _ = make_protocol(echo_app())
    protocol.shutdown()
    assert protocol.shutdown_requested
    # An Initial from a brand-new peer during shutdown is dropped, not accepted.
    protocol.datagram_received(make_initial(b"new-peer"), ("127.0.0.1", 40000))
    assert not protocol.states
    teardown(protocol)


async def test_http3_concurrency_limit_counts_all_listeners() -> None:
    protocol, transport, server_state = make_protocol(echo_app(), limit_concurrency=1)
    server_state.h3_connections.add(object())  # type: ignore[arg-type]
    assert protocol._at_capacity()
    harness = H3Harness(protocol, transport)
    await harness.pump()
    assert not protocol.states
    server_state.h3_connections.clear()
    teardown(protocol)


async def test_http3_migration_is_routed_by_connection_id() -> None:
    # Routing by connection id (not peer address) means a client that changes its
    # UDP address mid-connection still reaches the same connection.
    harness, protocol, _ = await connected(echo_app())
    state = only_state(protocol)
    new_addr = ("127.0.0.2", 61000)
    stream = harness.client.send_request(b"GET", b"/moved", b"3", [(b"host", b"localhost")])
    stream.end_message()
    for datagram in harness.client.data_to_send():
        protocol.datagram_received(datagram, new_addr)  # same client, new address
    for _ in range(6):
        await asyncio.sleep(0)
    assert only_state(protocol) is state  # same connection, not a new one
    assert state.addr == new_addr  # send path now follows the migrated peer
    teardown(protocol)


async def test_http3_stray_datagram_is_dropped_without_allocating() -> None:
    protocol, transport, _ = make_protocol(echo_app())
    # A short-header (1-RTT) packet for a connection id we do not know matches no
    # connection and must be dropped without constructing any state.
    protocol.datagram_received(b"\x40" + b"unknown-cid-bytes", CLIENT_ADDR)
    # A non-Initial long-header packet for an unknown id is not a new connection
    # either. Take a real Initial and flip its packet-type bits to Handshake (10).
    initial = make_initial(b"\x09\x08\x07\x06")
    handshake_like = bytes([(initial[0] & 0xCF) | 0x20]) + initial[1:]
    protocol.datagram_received(handshake_like, CLIENT_ADDR)
    # And a truly malformed datagram that fails to parse at all.
    protocol.datagram_received(b"\xc0\x00", CLIENT_ADDR)
    assert not protocol.states


async def test_http3_undersized_initial_is_dropped_without_retry() -> None:
    protocol, transport, _ = make_protocol(echo_app())
    protocol.datagram_received(make_initial(b"eight-cd")[:100], CLIENT_ADDR)
    assert not transport.outbox
    assert not protocol.states
    teardown(protocol)


async def test_http3_remote_protocol_error_drops_the_address() -> None:
    class ErrorEndpoint:
        def receive_datagram(self, data: bytes, peer_address: bytes, now: int):
            raise zttp.RemoteProtocolError("bad datagram")

        def data_to_send(self) -> list[zttp.OutboundDatagram]:
            return []

        def next_timeout(self) -> int | None:
            return None

    protocol, _transport, _ = make_protocol(echo_app())
    protocol.endpoint = ErrorEndpoint()  # type: ignore[assignment]
    protocol.datagram_received(b"\x40invalid", CLIENT_ADDR)
    assert not protocol.addr_by_key
    teardown(protocol)


async def test_http3_malformed_initial_tears_down_the_connection() -> None:
    protocol, transport, _ = make_protocol(echo_app())
    initial = make_initial(b"\x0f\x0e\x0d\x0c")
    # A valid Initial header (so it routes and opens a connection) followed by a body
    # zttp cannot parse: the state is created, then discarded when the datagram is rejected.
    protocol.datagram_received(initial[:20] + b"\xff" * 40, CLIENT_ADDR)
    assert not protocol.states


async def test_http3_connection_ceiling_drops_new_peers() -> None:
    import uvicorn.protocols.http.zttp_h3_impl as impl

    protocol, transport, _ = make_protocol(echo_app())
    original = impl.MAX_QUIC_CONNECTIONS
    impl.MAX_QUIC_CONNECTIONS = 1
    try:
        protocol.server_state.h3_connections.add(object())  # type: ignore[arg-type]
        harness = H3Harness(protocol, transport)
        await harness.pump()
        assert not protocol.states
    finally:
        protocol.server_state.h3_connections.clear()
        impl.MAX_QUIC_CONNECTIONS = original
        teardown(protocol)


async def test_http3_oversized_request_body_resets_the_stream() -> None:
    import uvicorn.protocols.http.zttp_h3_impl as impl

    received: list[str] = []

    async def slow_app(scope, receive, send):
        # Never drains the body, forcing it to accumulate past the cap.
        message = await receive()
        received.append(message["type"])

    original = impl.MAX_REQUEST_BODY
    impl.MAX_REQUEST_BODY = 1024
    try:
        harness, protocol, _ = await connected(slow_app)
        stream = harness.client.send_request(b"POST", b"/upload", b"3", [(b"host", b"localhost")])
        sid = stream.stream_id
        stream.send_data(b"x" * 4096)
        for datagram in harness.client.data_to_send():
            protocol.datagram_received(datagram, CLIENT_ADDR)
        for _ in range(10):
            await asyncio.sleep(0)
        # The stream's cycle was reset and dropped; the app saw a disconnect.
        assert sid not in only_state(protocol).cycles
        assert received == ["http.disconnect"]
        teardown(protocol)
    finally:
        impl.MAX_REQUEST_BODY = original


async def test_http3_endpoint_registers_with_server_state() -> None:
    protocol, transport, server_state = make_protocol(echo_app())
    assert protocol in server_state.connections
    protocol.connection_lost(None)
    assert protocol not in server_state.connections


# -- configuration ------------------------------------------------------------


def _p256_pem(tmp_path) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


# -- request cycle unit tests (drive the ASGI bridge directly) ----------------


class FakeStream:
    def __init__(self, stream_id: int = 0) -> None:
        self.stream_id = stream_id
        self.calls: list[tuple[object, ...]] = []

    def send_response(self, status: int, headers: list[tuple[bytes, bytes]]) -> None:
        self.calls.append(("response", status))

    def send_data(self, data: bytes) -> None:
        self.calls.append(("data", data))

    def end_message(self, *args: object) -> None:
        self.calls.append(("end",))

    def reset(self, *args: object) -> None:
        self.calls.append(("reset",))


def make_cycle(method: str = "GET"):
    from uvicorn.protocols.http.zttp_h3_impl import RequestResponseCycle

    scope = {
        "type": "http",
        "http_version": "3",
        "method": method,
        "scheme": "https",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "client": CLIENT_ADDR,
        "server": SERVER_ADDR,
    }
    stream = FakeStream()
    cycle = RequestResponseCycle(
        scope=scope,  # type: ignore[arg-type]
        stream=stream,  # type: ignore[arg-type]
        flush=lambda: None,
        logger=logging.getLogger("uvicorn.error"),
        access_logger=logging.getLogger("uvicorn.access"),
        access_log=False,
        default_headers=[],
        message_event=asyncio.Event(),
        consume_data=lambda stream_id, length: None,
        on_response=lambda stream_id: None,
    )
    return cycle, stream


async def test_cycle_disconnected_send_is_dropped() -> None:
    cycle, stream = make_cycle()
    cycle.disconnected = True
    await cycle.send({"type": "http.response.start", "status": 200, "headers": []})
    assert stream.calls == []


async def test_cycle_first_message_must_be_response_start() -> None:
    cycle, _ = make_cycle()
    with pytest.raises(RuntimeError, match=r"http\.response\.start"):
        await cycle.send({"type": "http.response.body", "body": b""})


async def test_cycle_second_message_must_be_response_body() -> None:
    cycle, _ = make_cycle()
    await cycle.send({"type": "http.response.start", "status": 200, "headers": []})
    with pytest.raises(RuntimeError, match=r"http\.response\.body"):
        await cycle.send({"type": "http.response.start", "status": 200, "headers": []})


async def test_cycle_body_longer_than_content_length() -> None:
    cycle, _ = make_cycle()
    await cycle.send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
    with pytest.raises(RuntimeError, match="longer than Content-Length"):
        await cycle.send({"type": "http.response.body", "body": b"toolong"})


async def test_cycle_body_shorter_than_content_length() -> None:
    cycle, _ = make_cycle()
    await cycle.send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"5")]})
    with pytest.raises(RuntimeError, match="shorter than Content-Length"):
        await cycle.send({"type": "http.response.body", "body": b"hi", "more_body": False})


async def test_cycle_send_after_complete_raises() -> None:
    cycle, _ = make_cycle()
    await cycle.send({"type": "http.response.start", "status": 200, "headers": []})
    await cycle.send({"type": "http.response.body", "body": b"", "more_body": False})
    with pytest.raises(RuntimeError, match="after response already completed"):
        await cycle.send({"type": "http.response.body", "body": b""})


async def test_cycle_receive_after_disconnect() -> None:
    cycle, _ = make_cycle()
    cycle.disconnected = True
    assert await cycle.receive() == {"type": "http.disconnect"}


async def test_cycle_receive_returns_http3_flow_credit() -> None:
    cycle, _ = make_cycle()
    consumed: list[tuple[int, int]] = []
    cycle.consume_data = lambda stream_id, length: consumed.append((stream_id, length))
    cycle.body.extend(b"request body")
    cycle.more_body = False
    cycle.message_event.set()
    assert await cycle.receive() == {"type": "http.request", "body": b"request body", "more_body": False}
    assert consumed == [(0, 12)]


async def test_cycle_run_asgi_returned_non_none() -> None:
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        return "unexpected"

    cycle, stream = make_cycle()
    await cycle.run_asgi(app)
    assert ("reset",) in stream.calls


async def test_cycle_run_asgi_without_starting_response() -> None:
    async def app(scope, receive, send):
        return None

    cycle, stream = make_cycle()
    await cycle.run_asgi(app)
    assert ("response", 500) in stream.calls


async def test_cycle_run_asgi_without_completing_response() -> None:
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    cycle, stream = make_cycle()
    await cycle.run_asgi(app)
    assert ("reset",) in stream.calls


async def test_cycle_run_asgi_exception_after_response_started() -> None:
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("boom")

    cycle, stream = make_cycle()
    await cycle.run_asgi(app)
    assert ("reset",) in stream.calls


# -- connection-level branch tests --------------------------------------------


async def test_http3_trace_logging_on_connect() -> None:
    protocol, transport, _ = make_protocol(echo_app())
    protocol.logger.setLevel(5)  # TRACE_LOG_LEVEL
    try:
        protocol.connection_made(transport)  # type: ignore[arg-type]
    finally:
        protocol.logger.setLevel(logging.NOTSET)
    teardown(protocol)


async def test_http3_uses_configured_credentials(tmp_path) -> None:
    cert_path, key_path = _p256_pem(tmp_path)
    protocol, transport, _ = make_protocol(echo_app(), ssl_certfile=cert_path, ssl_keyfile=key_path)
    assert protocol.credentials is not None
    harness = H3Harness(protocol, transport)
    await harness.pump()
    assert protocol.states
    teardown(protocol)


async def test_http3_reset_contextvars_path(tmp_path) -> None:
    harness, protocol, _ = await connected(echo_app(), reset_contextvars=True)
    sid = harness.send_request(b"GET", b"/")
    await harness.pump()
    assert harness.responses[sid].status_code == 200
    teardown(protocol)


async def test_http3_request_during_shutdown_gets_503() -> None:
    harness, protocol, _ = await connected(echo_app())
    # Endpoint-level drain: in-flight streams still answer (with 503), and once the
    # connection closes, re-sent client datagrams are refused rather than re-handshaked.
    protocol.shutdown_requested = True
    sid = harness.send_request(b"GET", b"/")
    await harness.pump()
    assert harness.responses[sid].status_code == 503
    teardown(protocol)


async def test_http3_request_over_capacity_gets_503() -> None:
    harness, protocol, _ = await connected(echo_app(), limit_concurrency=1)
    sid = harness.send_request(b"GET", b"/")
    await harness.pump()
    assert harness.responses[sid].status_code == 503
    teardown(protocol)


async def test_http3_timeout_handler_reschedules() -> None:
    harness, protocol, _ = await connected(echo_app())
    state = only_state(protocol)
    protocol._on_timeout()
    assert not state.conn.is_closed()
    teardown(protocol)


async def test_http3_timeout_discards_a_closed_connection() -> None:
    harness, protocol, _ = await connected(echo_app())
    only_state(protocol).conn.close()
    protocol._on_timeout()
    assert not protocol.states
    teardown(protocol)


async def test_http3_bounds_remembered_peer_addresses() -> None:
    harness, protocol, _ = await connected(echo_app())
    state = only_state(protocol)
    for index in range(9):
        addr: DatagramAddress = ("127.0.0.1", 60000 + index)
        key = f"peer-{index}".encode()
        protocol.addr_by_key[key] = addr
        state.receive(addr, key)
    assert len(state.address_keys) == 8
    assert len(protocol.addr_by_key) == 8
    teardown(protocol)


async def test_http3_client_close_tears_down_connection() -> None:
    harness, protocol, _ = await connected(echo_app())
    harness.client.close(error_code=0)
    for datagram in harness.client.data_to_send():
        protocol.datagram_received(datagram, CLIENT_ADDR)
    assert not protocol.states
    teardown(protocol)


async def test_http3_close_cancels_pending_timer() -> None:
    harness, protocol, _ = await connected(echo_app())
    state = only_state(protocol)
    # In-memory exchanges rarely arm a loss timer, so force one to prove close() cancels it.
    protocol.timer = asyncio.get_event_loop().call_later(30, lambda: None)
    state.close()
    assert protocol.timer is None
    assert not protocol.states


async def test_http3_stray_body_after_response_is_ignored() -> None:
    async def quick_app(scope, receive, send):
        # Answer immediately, without reading the request body.
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    harness, protocol, _ = await connected(quick_app)
    stream = harness.client.send_request(b"POST", b"/", b"3", [(b"host", b"localhost")])
    for datagram in harness.client.data_to_send():  # deliver the request head only
        protocol.datagram_received(datagram, CLIENT_ADDR)
    for _ in range(10):
        await asyncio.sleep(0)  # let the app answer and the cycle be reaped
    # The stream's cycle is gone; late body and end frames must be ignored, not crash.
    stream.send_data(b"late-body")
    stream.end_message()
    for datagram in harness.client.data_to_send():
        protocol.datagram_received(datagram, CLIENT_ADDR)
    for _ in range(5):
        await asyncio.sleep(0)
    assert protocol.states
    teardown(protocol)


async def test_http3_connection_lost_disconnects_in_flight_request() -> None:
    started = asyncio.Event()

    async def slow_app(scope, receive, send):
        started.set()
        # Block forever waiting for a body that never fully arrives.
        await receive()
        await receive()

    protocol, transport, _ = make_protocol(slow_app)
    harness = H3Harness(protocol, transport)
    await harness.pump()
    harness.send_request(b"POST", b"/", body=b"partial")
    await harness.pump(rounds=2)
    state = only_state(protocol)
    assert state.cycles  # a request is in flight
    protocol.connection_lost(None)
    assert not protocol.states


def test_http3_config_sets_protocol_class() -> None:
    config = Config(app=echo_app(), http3=True)
    config.load()
    assert config.h3_protocol_class is ZttpH3Protocol
    assert config.h3_credentials is None


def test_http3_config_accepts_import_string() -> None:
    config = Config(app=echo_app(), http3="uvicorn.protocols.http.zttp_h3_impl:ZttpH3Protocol")
    config.load()
    assert config.h3_protocol_class is ZttpH3Protocol


def test_http3_config_accepts_protocol_class() -> None:
    config = Config(app=echo_app(), http3=ZttpH3Protocol)
    config.load()
    assert config.h3_protocol_class is ZttpH3Protocol


async def test_http3_server_binds_udp_to_resolved_tcp_port() -> None:
    from tests.utils import run_server

    config = Config(app=echo_app(), host="localhost", port=0, http3=True, log_level="warning")
    async with run_server(config) as server:
        assert server.h3_transport is not None
        assert server.servers[0].sockets is not None
        tcp_addresses = {sock.getsockname()[:2] for sock in server.servers[0].sockets}
        udp_addresses = {transport.get_extra_info("sockname")[:2] for transport in server.h3_transports}
        assert udp_addresses == tcp_addresses


async def test_http3_server_preserves_scoped_ipv6_bind_address(monkeypatch: pytest.MonkeyPatch) -> None:
    local_addr: DatagramAddress = ("fe80::1", 8000, 0, 3)
    bound: list[DatagramAddress] = []

    class ScopedSocket:
        def bind(self, address: DatagramAddress) -> None:
            bound.append(address)

        def close(self) -> None:
            pass

    scoped_socket = ScopedSocket()

    class ScopedIPv6Loop:
        async def create_datagram_endpoint(self, protocol_factory, *, sock):
            assert sock is scoped_socket
            return MockDatagramTransport(local_addr), protocol_factory()

    monkeypatch.setattr("uvicorn.server.socket.socket", lambda family, kind: scoped_socket)
    config = Config(app=echo_app(), http3=True, log_level="warning")
    config.load()
    server = Server(config)
    server.lifespan = LifespanOff(config)
    await server._serve_http3(ScopedIPv6Loop(), local_addr)  # type: ignore[arg-type]
    assert bound == [local_addr]
    scoped_socket.close()
    for transport in server.h3_transports:
        transport.close()


async def test_http3_closes_udp_socket_after_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingSocket:
        def __init__(self) -> None:
            self.closed = False

        def bind(self, address: DatagramAddress) -> None:
            raise OSError("cannot bind")

        def close(self) -> None:
            self.closed = True

    failing_socket = FailingSocket()
    monkeypatch.setattr("uvicorn.server.socket.socket", lambda family, kind: failing_socket)
    config = Config(app=echo_app(), http3=True, log_level="warning")
    config.load()
    server = Server(config)
    server.lifespan = LifespanOff(config)
    with pytest.raises(SystemExit) as exc_info:
        await server._serve_http3(asyncio.get_running_loop(), SERVER_ADDR)
    assert exc_info.value.code == 3
    assert failing_socket.closed


async def test_http3_skips_prebound_sockets(caplog: pytest.LogCaptureFixture) -> None:
    from tests.utils import run_server

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    config = Config(app=echo_app(), http3=True, log_level="warning")
    async with run_server(config, sockets=[sock]) as server:
        assert server.h3_transport is None
    assert "HTTP/3 is not supported with pre-bound sockets" in caplog.text


def test_http3_disabled_by_default() -> None:
    config = Config(app=echo_app())
    config.load()
    assert config.h3_protocol_class is None


def test_http3_credentials_are_derived_from_pem(tmp_path) -> None:
    cert_path, key_path = _p256_pem(tmp_path)
    config = Config(app=echo_app(), http3=True, ssl_certfile=cert_path, ssl_keyfile=key_path)
    config.load()
    assert config.h3_credentials is not None
    assert len(config.h3_credentials["private_key_scalar"]) == 32
    assert len(config.h3_credentials["certificates"]) == 1
    assert len(config.h3_credentials["certificates"][0]) > 32


def test_http3_loads_certificate_chain(tmp_path) -> None:
    cert_path, key_path = _p256_pem(tmp_path)
    with open(cert_path, "rb") as cert_file:
        certificate = cert_file.read()
    with open(cert_path, "ab") as cert_file:
        cert_file.write(certificate)
    config = Config(app=echo_app(), http3=True, ssl_certfile=cert_path, ssl_keyfile=key_path)
    config.load()
    assert config.h3_credentials is not None
    assert len(config.h3_credentials["certificates"]) == 2


def test_http3_rejects_ssl_context_without_pem_credentials() -> None:
    def ssl_context_factory(config, default_factory):
        return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    config = Config(app=echo_app(), http3=True, ssl_context_factory=ssl_context_factory)
    with pytest.raises(RuntimeError, match="cannot use `ssl_context_factory`"):
        config.load()


def test_http3_rejects_ssl_context_with_pem_credentials(tmp_path) -> None:
    def ssl_context_factory(config, default_factory):
        return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    cert_path, key_path = _p256_pem(tmp_path)
    config = Config(
        app=echo_app(),
        http3=True,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
        ssl_context_factory=ssl_context_factory,
    )
    with pytest.raises(RuntimeError, match="cannot use `ssl_context_factory`"):
        config.load()


def test_http3_rejects_non_p256_key(tmp_path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    config = Config(app=echo_app(), http3=True, ssl_certfile=str(cert_path), ssl_keyfile=str(key_path))
    with pytest.raises(RuntimeError, match="P-256"):
        config.load()

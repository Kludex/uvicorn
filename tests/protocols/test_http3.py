from __future__ import annotations

import asyncio
import datetime as dt
import logging
from importlib.metadata import version
from typing import Any

import pytest

from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.server import ServerState

try:
    import zttp

    from uvicorn.protocols.http.zttp_h3_impl import ZttpH3Protocol

    _zttp_version = tuple(int(part) for part in version("zttp").split(".")[:3])
    skip_if_no_zttp_h3 = pytest.mark.skipif(
        _zttp_version < (0, 0, 14), reason="zttp>=0.0.14 with HTTP/3 support is not installed"
    )
except ModuleNotFoundError:  # pragma: no cover
    skip_if_no_zttp_h3 = pytest.mark.skipif(True, reason="zttp is not installed")

pytestmark = [pytest.mark.anyio, skip_if_no_zttp_h3]

SERVER_ADDR = ("127.0.0.1", 443)
CLIENT_ADDR = ("127.0.0.1", 55555)


class MockDatagramTransport:
    def __init__(self, sockname: tuple[str, int] = SERVER_ADDR) -> None:
        self.sockname = sockname
        self.outbox: list[bytes] = []
        self.closed = False

    def get_extra_info(self, key: str) -> Any:
        return {"sockname": self.sockname}.get(key)

    def sendto(self, data: bytes, addr: Any = None) -> None:
        assert not self.closed
        self.outbox.append(data)

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

    def __init__(self, protocol: ZttpH3Protocol, transport: MockDatagramTransport) -> None:
        self.protocol = protocol
        self.transport = transport
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
                self.protocol.datagram_received(datagram, CLIENT_ADDR)
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


def make_protocol(app: Any, **kwargs: Any) -> tuple[ZttpH3Protocol, MockDatagramTransport, ServerState]:
    config = Config(app=app, http3=True, **kwargs)
    lifespan = LifespanOff(config)
    server_state = ServerState()
    protocol = ZttpH3Protocol(
        config=config, server_state=server_state, app_state=lifespan.state, _loop=asyncio.get_event_loop()
    )
    transport = MockDatagramTransport()
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol, transport, server_state


async def connected(app: Any, **kwargs: Any) -> tuple[H3Harness, ZttpH3Protocol, ServerState]:
    protocol, transport, server_state = make_protocol(app, **kwargs)
    harness = H3Harness(protocol, transport)
    await harness.pump()  # complete the QUIC handshake
    return harness, protocol, server_state


def teardown(protocol: ZttpH3Protocol) -> None:
    # Cancel any armed loss/idle timers so no callback survives the test.
    protocol.connection_lost(None)


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
    seen: dict[str, Any] = {}

    async def app(scope, receive, send):
        seen.update(scope)
        await app_reply(receive, send)

    async def app_reply(receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    harness, protocol, _ = await connected(app)
    harness.send_request(b"GET", b"/a/b?x=1")
    await harness.pump()
    assert seen["http_version"] == "3"
    assert seen["scheme"] == "https"
    assert seen["method"] == "GET"
    assert seen["path"] == "/a/b"
    assert seen["query_string"] == b"x=1"
    assert seen["client"] == CLIENT_ADDR
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


async def test_http3_graceful_shutdown_drains_and_closes(caplog: pytest.LogCaptureFixture) -> None:
    harness, protocol, _ = await connected(echo_app())
    harness.send_request(b"GET", b"/")
    await harness.pump()
    assert protocol in protocol.server_state.connections
    protocol.shutdown()
    # No live connections remain, so the endpoint deregisters and closes its socket.
    assert protocol not in protocol.server_state.connections
    assert protocol.transport.is_closing()


async def test_http3_shutdown_refuses_new_connections() -> None:
    protocol, transport, _ = make_protocol(echo_app())
    protocol.shutdown()
    assert protocol.shutdown_requested
    # A datagram from a brand-new peer during shutdown is dropped, not accepted.
    protocol.datagram_received(b"\x00" * 64, ("127.0.0.1", 40000))
    assert not protocol.quic


async def test_http3_concurrency_limit_drops_new_connections() -> None:
    protocol, transport, _ = make_protocol(echo_app(), limit_concurrency=1)
    # Pretend one connection already exists so a fresh peer is over the limit.
    protocol.quic[("127.0.0.1", 1)] = object()  # type: ignore[assignment]
    protocol.datagram_received(b"\x00" * 64, ("127.0.0.1", 40001))
    assert ("127.0.0.1", 40001) not in protocol.quic


async def test_http3_malformed_datagram_closes_that_connection() -> None:
    protocol, transport, _ = make_protocol(echo_app())
    # A garbage first datagram cannot start a QUIC handshake; the state is discarded.
    protocol.datagram_received(b"not-a-quic-packet", CLIENT_ADDR)
    assert CLIENT_ADDR not in protocol.quic


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
        self.calls: list[tuple[Any, ...]] = []

    def send_response(self, status: int, headers: Any) -> None:
        self.calls.append(("response", status))

    def send_data(self, data: bytes) -> None:
        self.calls.append(("data", data))

    def end_message(self, *args: Any) -> None:
        self.calls.append(("end",))

    def reset(self, *args: Any) -> None:
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
    with pytest.raises(RuntimeError, match="http.response.start"):
        await cycle.send({"type": "http.response.body", "body": b""})


async def test_cycle_second_message_must_be_response_body() -> None:
    cycle, _ = make_cycle()
    await cycle.send({"type": "http.response.start", "status": 200, "headers": []})
    with pytest.raises(RuntimeError, match="http.response.body"):
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
    # A first datagram builds the per-connection state (with credentials wired in).
    protocol.datagram_received(b"\x00" * 40, CLIENT_ADDR)
    # Garbage cannot complete a handshake, so the state is torn down again.
    assert CLIENT_ADDR not in protocol.quic


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


async def test_http3_request_over_capacity_gets_503() -> None:
    harness, protocol, _ = await connected(echo_app(), limit_concurrency=1)
    sid = harness.send_request(b"GET", b"/")
    await harness.pump()
    assert harness.responses[sid].status_code == 503
    teardown(protocol)


async def test_http3_timeout_handler_reschedules() -> None:
    harness, protocol, _ = await connected(echo_app())
    state = protocol.quic[CLIENT_ADDR]
    state._on_timeout()  # fire the loss/idle timer manually
    assert not state.conn.is_closed()
    teardown(protocol)


async def test_http3_client_close_tears_down_connection() -> None:
    harness, protocol, _ = await connected(echo_app())
    harness.client.close(error_code=0)
    for datagram in harness.client.data_to_send():
        protocol.datagram_received(datagram, CLIENT_ADDR)
    assert CLIENT_ADDR not in protocol.quic


async def test_http3_close_cancels_pending_timer() -> None:
    harness, protocol, _ = await connected(echo_app())
    state = protocol.quic[CLIENT_ADDR]
    # In-memory exchanges rarely arm a loss timer, so force one to prove close() cancels it.
    state.timer = asyncio.get_event_loop().call_later(30, lambda: None)
    state.close()
    assert state.timer is None
    assert CLIENT_ADDR not in protocol.quic


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
    assert CLIENT_ADDR in protocol.quic
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
    state = protocol.quic[CLIENT_ADDR]
    assert state.cycles  # a request is in flight
    protocol.connection_lost(None)
    assert CLIENT_ADDR not in protocol.quic


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


async def test_http3_server_binds_udp_endpoint(unused_tcp_port: int) -> None:
    from tests.utils import run_server

    config = Config(app=echo_app(), host="127.0.0.1", port=unused_tcp_port, http3=True, log_level="warning")
    async with run_server(config) as server:
        assert server.h3_transport is not None
        assert server.h3_transport.get_extra_info("sockname")[1] == unused_tcp_port


def test_http3_disabled_by_default() -> None:
    config = Config(app=echo_app())
    config.load()
    assert config.h3_protocol_class is None


def test_http3_credentials_are_derived_from_pem(tmp_path) -> None:
    cert_path, key_path = _p256_pem(tmp_path)
    config = Config(app=echo_app(), http3=True, ssl_certfile=cert_path, ssl_keyfile=key_path)
    config.load()
    assert isinstance(config.h3_credentials, zttp.TlsCredentials)
    assert len(config.h3_credentials.private_key) == 32
    assert len(config.h3_credentials.certificate) > 32


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

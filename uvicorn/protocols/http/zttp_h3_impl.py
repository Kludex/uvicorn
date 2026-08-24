from __future__ import annotations

import asyncio
import contextvars
import logging
import sys
import warnings
from collections.abc import Callable, Generator
from typing import Any, TypeAlias
from urllib.parse import unquote

import zttp
from zttp import Event

from uvicorn._types import (
    ASGI3Application,
    ASGIReceiveEvent,
    ASGISendEvent,
    HTTPResponseBodyEvent,
    HTTPResponseStartEvent,
    HTTPScope,
)
from uvicorn.config import Config
from uvicorn.logging import TRACE_LOG_LEVEL
from uvicorn.protocols.http.flow_control import service_unavailable
from uvicorn.protocols.utils import get_client_addr, get_local_addr, get_path_with_query_string
from uvicorn.server import ServerState

warnings.warn(
    "Uvicorn's HTTP/3 support is experimental. It rides a from-scratch QUIC stack in zttp "
    "and only serves P-256 (SECP256R1) TLS keys. Please try it out and report back! "
    "See the docs at https://uvicorn.dev/concepts/http3/.",
    UserWarning,
    stacklevel=2,
)

# RFC 9114 section 4.2: the same connection-specific headers HTTP/2 forbids are
# also malformed in HTTP/3. Strip them on the way out so an HTTP/1.1-tuned app
# does not trip zttp's LocalProtocolError.
FORBIDDEN_HEADERS = frozenset({b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade"})

# zttp's clock is a monotonic microsecond integer (RFC 9002 loss/PTO math is in
# microseconds); asyncio's loop clock is float seconds, so scale between them.
MICROSECONDS = 1_000_000

# Hard ceiling on concurrent QUIC connections, enforced across every UDP listener
# regardless of `limit_concurrency`. Stateless Retry prevents unauthenticated
# Initials from allocating connection state, while this bounds authenticated peers.
MAX_QUIC_CONNECTIONS = 16_384

# Hard ceiling on a single request's in-memory body buffer. zttp's QUIC stream
# flow control bounds one flight, but a client that keeps sending while the ASGI app
# is slow to `receive()` would otherwise grow this bytearray without limit, so the
# stream is reset once its buffered body crosses the ceiling.
MAX_REQUEST_BODY = 4 * 1024 * 1024

# Keep enough recent paths for migration validation without allowing spoofed source
# addresses sent to a known connection ID to grow the address map without bound.
MAX_PEER_ADDRESSES = 8

DatagramAddress: TypeAlias = tuple[str, int] | tuple[str, int, int, int]


def _now(loop: asyncio.AbstractEventLoop) -> int:
    return int(loop.time() * MICROSECONDS)


def _peer_key(addr: DatagramAddress) -> bytes:
    # zttp's opaque path-validation key for a UDP peer. Keep it 1:1 with the address
    # so endpoint output can map the key back to a socket address.
    return "\x00".join(str(part) for part in addr).encode()


class ZttpH3Protocol(asyncio.DatagramProtocol):
    """A UDP endpoint fronting many QUIC connections through `zttp.QuicEndpoint`."""

    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if not config.loaded:
            config.load()

        self.config = config
        self.app = config.loaded_app
        self.loop = _loop or asyncio.get_event_loop()
        self.logger = logging.getLogger("uvicorn.error")
        self.access_logger = logging.getLogger("uvicorn.access")
        self.access_log = self.access_logger.hasHandlers()
        self.root_path = config.root_path
        self.asgi_version = config.asgi_version
        self.limit_concurrency = config.limit_concurrency
        self.credentials: zttp.TlsCredentials | None = config.h3_credentials
        self.app_state = app_state

        self.server_state = server_state
        self.connections = server_state.connections
        self.tasks = server_state.tasks

        self.transport: asyncio.DatagramTransport = None  # type: ignore[assignment]
        self.server: tuple[str, int | None] | None = None
        self.shutdown_requested = False
        self.endpoint = zttp.QuicEndpoint(
            credentials=self.credentials,
            alpn=b"h3",
            retry=True,
            max_connections=MAX_QUIC_CONNECTIONS,
        )
        self.states: dict[zttp.H3Connection, QuicConnectionState] = {}
        self.addr_by_key: dict[bytes, DatagramAddress] = {}
        self.timer: asyncio.TimerHandle | None = None

    def connection_made(  # type: ignore[override]
        self, transport: asyncio.DatagramTransport
    ) -> None:
        self.transport = transport
        self.server = get_local_addr(transport)
        self.connections.add(self)

        if self.logger.level <= TRACE_LOG_LEVEL:
            self.logger.log(TRACE_LOG_LEVEL, "HTTP/3 endpoint listening on %s", self.server)

    def connection_lost(self, exc: Exception | None) -> None:
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
        for state in list(self.states.values()):
            state.close()
        self.connections.discard(self)

    def datagram_received(self, data: bytes, addr: DatagramAddress) -> None:
        if self.shutdown_requested and not self.states:
            return
        if len(data) < 1200 and data and data[0] & 0x80:
            try:
                if zttp.parse_datagram_header(data).is_initial:
                    return
            except zttp.RemoteProtocolError:
                return

        key = _peer_key(addr)
        self.addr_by_key[key] = addr
        state: QuicConnectionState | None = None
        try:
            connection = self.endpoint.receive_datagram(data, key, _now(self.loop))
        except zttp.RemoteProtocolError as exc:
            self.logger.warning("Invalid HTTP/3 datagram received: %s", exc)
            self.flush()
            self._forget_address(key)
            return

        if connection is not None:
            state = self.states.get(connection)
            if state is None:
                if (
                    self.shutdown_requested
                    or len(self.server_state.h3_connections) >= MAX_QUIC_CONNECTIONS
                    or self._at_capacity()
                ):
                    connection.close(app=True, error_code=0x100)
                    self.flush_connection(connection)
                    self.endpoint.discard(connection)
                    self._reschedule()
                    self._forget_address(key)
                    return
                state = QuicConnectionState(self, connection, addr, key)
                self.states[connection] = state
                self.server_state.h3_connections.add(state)
            state.receive(addr, key)
            self.flush_connection(connection)
        else:
            self.flush()
        if state is None:
            self._forget_address(key)
        elif state.conn.is_closed():
            state.close()

    def flush(self) -> None:
        self._send_datagrams(self.endpoint.data_to_send())

    def flush_connection(self, connection: zttp.H3Connection) -> None:
        self._send_datagrams(connection.data_to_send_with_addresses())

    def _send_datagrams(self, datagrams: list[zttp.OutboundDatagram]) -> None:
        for outbound in datagrams:
            key = outbound.peer_address
            if key is None:  # pragma: no cover - server datagrams always have a received peer address
                continue
            addr = self.addr_by_key.get(key)
            if addr is None:  # pragma: no cover - defensive against an invalid endpoint address key
                continue
            self.transport.sendto(outbound.data, addr)
        self._reschedule()

    def _forget_address(self, key: bytes) -> None:
        if not any(key in state.address_keys for state in self.states.values()):
            self.addr_by_key.pop(key, None)

    def _reschedule(self) -> None:
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
        deadline = self.endpoint.next_timeout()
        if deadline is not None:
            self.timer = self.loop.call_at(deadline / MICROSECONDS, self._on_timeout)

    def _on_timeout(self) -> None:
        self.timer = None
        self.endpoint.handle_timeout(_now(self.loop))
        states = list(self.states.values())
        for state in states:
            state.handle_events()
        self.flush()
        for state in states:
            if state.conn.is_closed():
                state.close()

    def error_received(self, exc: Exception) -> None:
        if self.logger.level <= TRACE_LOG_LEVEL:  # pragma: no cover
            self.logger.log(TRACE_LOG_LEVEL, "HTTP/3 endpoint error_received: %s", exc)

    def _at_capacity(self) -> bool:
        if self.limit_concurrency is None:
            return False
        tcp_connections = sum(not isinstance(connection, ZttpH3Protocol) for connection in self.connections)
        return (
            tcp_connections + len(self.server_state.h3_connections) >= self.limit_concurrency
            or len(self.tasks) >= self.limit_concurrency
        )

    def discard(self, state: QuicConnectionState) -> None:
        if self.states.pop(state.conn, None) is not None:
            self.endpoint.discard(state.conn)
            self.server_state.h3_connections.discard(state)
            for key in state.address_keys:
                self._forget_address(key)
        self._reschedule()
        self._finish_if_drained()

    def shutdown(self) -> None:
        """Begin a graceful shutdown: refuse new connections and drain live ones."""
        self.shutdown_requested = True
        for state in list(self.states.values()):
            state.shutdown()
        self._finish_if_drained()

    def _finish_if_drained(self) -> None:
        if self.shutdown_requested and not self.states:
            self.connections.discard(self)
            if self.transport is not None and not self.transport.is_closing():
                self.transport.close()


class QuicConnectionState:
    """One accepted QUIC connection and its active ASGI request cycles."""

    def __init__(self, endpoint: ZttpH3Protocol, conn: zttp.H3Connection, addr: DatagramAddress, key: bytes) -> None:
        self.endpoint = endpoint
        self.conn = conn
        self.addr = addr
        self.client = (str(addr[0]), int(addr[1]))
        self.loop = endpoint.loop
        self.logger = endpoint.logger
        self.address_keys: list[bytes] = [key]
        self.shutdown_requested = False
        self.cycles: dict[int, RequestResponseCycle] = {}

    def receive(self, addr: DatagramAddress, key: bytes) -> None:
        self.addr = addr
        self.client = (str(addr[0]), int(addr[1]))
        if key in self.address_keys:
            self.address_keys.remove(key)
        self.address_keys.append(key)
        if len(self.address_keys) > MAX_PEER_ADDRESSES:
            self.endpoint._forget_address(self.address_keys.pop(0))
        self.handle_events()

    def flush(self) -> None:
        self.endpoint.flush_connection(self.conn)

    def events(self) -> Generator[Event]:
        while True:
            event = self.conn.next_event()
            # NEED_DATA means "drained for now"; CONNECTION_CLOSED is terminal - once
            # the QUIC connection is gone it stays gone, so stop rather than spin.
            if event is zttp.NEED_DATA or event is zttp.CONNECTION_CLOSED:
                return
            yield event

    def handle_events(self) -> None:
        for event in self.events():
            if isinstance(event, zttp.Request):
                self.handle_request(event)
            elif isinstance(event, zttp.Data):
                cycle = self.cycles.get(event.stream_id)
                if cycle is None or cycle.response_complete:
                    self.conn.consume_data(event.stream_id, len(event.data))
                    continue
                cycle.body += event.data
                if len(cycle.body) > MAX_REQUEST_BODY:
                    # The app is not draining the body fast enough to keep it
                    # bounded; reset the request stream and disconnect the cycle
                    # rather than buffer without limit.
                    self.conn.stream(event.stream_id).reset()
                    cycle.disconnected = True
                    cycle.message_event.set()
                    self.cycles.pop(event.stream_id, None)
                    continue
                cycle.message_event.set()
            elif isinstance(event, zttp.EndOfMessage):
                cycle = self.cycles.get(event.stream_id)
                if cycle is None or cycle.response_complete:
                    continue
                cycle.more_body = False
                cycle.message_event.set()
            # zttp surfaces GOAWAY and connection close through methods
            # (`goaway_received`, `close_info`), not the event stream, so there
            # is nothing stream-level to do for other events here.

    def handle_request(self, event: zttp.Request) -> None:
        path = unquote(event.path.decode("ascii"))
        full_path = self.root_path + path
        full_raw_path = self.root_path.encode("ascii") + event.path
        scope: HTTPScope = {
            "type": "http",
            "asgi": {"version": self.endpoint.asgi_version, "spec_version": "2.3"},
            "http_version": "3",
            "server": self.endpoint.server,
            "client": self.client,
            "scheme": "https",
            "method": event.method.decode("ascii"),
            "root_path": self.root_path,
            "path": full_path,
            "raw_path": full_raw_path,
            "query_string": event.query,
            "headers": event.headers,
            "state": self.endpoint.app_state.copy(),
        }

        if self.shutdown_requested or self.endpoint.shutdown_requested:
            app = service_unavailable
        elif self.endpoint._at_capacity():
            app = service_unavailable
            self.logger.warning("Exceeded concurrency limit.")
        else:
            app = self.endpoint.app

        cycle = RequestResponseCycle(
            scope=scope,
            stream=self.conn.stream(event.stream_id),
            flush=self.flush,
            logger=self.logger,
            access_logger=self.access_logger,
            access_log=self.access_log,
            default_headers=self.endpoint.server_state.default_headers,
            message_event=asyncio.Event(),
            consume_data=self.conn.consume_data,
            on_response=self.on_response_complete,
        )
        self.cycles[event.stream_id] = cycle

        config = self.endpoint.config
        if config.reset_contextvars:
            if sys.version_info >= (3, 11):  # pragma: py-lt-311
                task = self.loop.create_task(cycle.run_asgi(app), context=contextvars.Context())
            else:  # pragma: py-gte-311
                task = contextvars.Context().run(self.loop.create_task, cycle.run_asgi(app))
        else:
            task = self.loop.create_task(cycle.run_asgi(app))
        task.add_done_callback(self.endpoint.tasks.discard)
        self.endpoint.tasks.add(task)

    @property
    def root_path(self) -> str:
        return self.endpoint.root_path

    @property
    def access_logger(self) -> logging.Logger:
        return self.endpoint.access_logger

    @property
    def access_log(self) -> bool:
        return self.endpoint.access_log

    def on_response_complete(self, stream_id: int) -> None:
        self.endpoint.server_state.total_requests += 1
        self.cycles.pop(stream_id, None)
        # A datagram carrying the response's final bytes may be queued; push it.
        self.flush()
        if not self.cycles and (self.shutdown_requested or self.endpoint.shutdown_requested):
            self._graceful_close()
        else:
            self.endpoint._reschedule()

    def shutdown(self) -> None:
        """Refuse new streams and close once in-flight requests finish."""
        self.shutdown_requested = True
        if not self.cycles:
            self._graceful_close()

    def _graceful_close(self) -> None:
        if not self.conn.is_closed():
            self.conn.close(app=True, error_code=0x100)  # H3_NO_ERROR
            self.flush()
        self.close()

    def close(self) -> None:
        for cycle in self.cycles.values():
            if not cycle.response_complete:
                cycle.disconnected = True
            cycle.message_event.set()
        self.cycles.clear()
        self.endpoint.discard(self)


class RequestResponseCycle:
    def __init__(
        self,
        scope: HTTPScope,
        stream: zttp.Stream,
        flush: Callable[[], None],
        logger: logging.Logger,
        access_logger: logging.Logger,
        access_log: bool,
        default_headers: list[tuple[bytes, bytes]],
        message_event: asyncio.Event,
        consume_data: Callable[[int, int], None],
        on_response: Callable[[int], None],
    ) -> None:
        self.scope = scope
        self.stream = stream
        self.flush = flush
        self.logger = logger
        self.access_logger = access_logger
        self.access_log = access_log
        self.default_headers = default_headers
        self.message_event = message_event
        self.consume_data = consume_data
        self.on_response = on_response

        # Connection state
        self.disconnected = False

        # Request state
        self.body = bytearray()
        self.more_body = True

        # Response state
        self.response_started = False
        self.response_complete = False
        self.bodyless = False
        self.expected_content_length: int | None = None

    # ASGI exception wrapper
    async def run_asgi(self, app: ASGI3Application) -> None:
        try:
            result = await app(self.scope, self.receive, self.send)  # type: ignore[func-returns-value]
        except BaseException as exc:
            self.logger.error("Exception in ASGI application\n", exc_info=exc)
            if not self.response_started:
                await self.send_500_response()
            else:
                self.stream.reset()
                self.flush()
        else:
            if result is not None:
                self.logger.error("ASGI callable should return None, but returned '%s'.", result)
                self.stream.reset()
                self.flush()
            elif not self.response_started and not self.disconnected:
                self.logger.error("ASGI callable returned without starting response.")
                await self.send_500_response()
            elif not self.response_complete and not self.disconnected:
                self.logger.error("ASGI callable returned without completing response.")
                self.stream.reset()
                self.flush()
        finally:
            self.on_response(self.stream.stream_id)
            self.on_response = lambda stream_id: None

    async def send_500_response(self) -> None:
        response_start_event: HTTPResponseStartEvent = {
            "type": "http.response.start",
            "status": 500,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        }
        await self.send(response_start_event)
        response_body_event: HTTPResponseBodyEvent = {
            "type": "http.response.body",
            "body": b"Internal Server Error",
            "more_body": False,
        }
        await self.send(response_body_event)

    # ASGI interface
    async def send(self, message: ASGISendEvent) -> None:
        if self.disconnected:
            return

        if not self.response_started:
            if message["type"] != "http.response.start":
                raise RuntimeError(f"Expected ASGI message 'http.response.start', but got '{message['type']}'.")

            self.response_started = True

            status = message["status"]
            headers: list[tuple[bytes, bytes]] = []
            for name, value in list(self.default_headers) + list(message.get("headers", [])):
                name = name.lower()
                if name in FORBIDDEN_HEADERS:
                    continue
                if name == b"content-length":
                    self.expected_content_length = int(value.decode())
                headers.append((name, value))

            self.bodyless = self.scope["method"] == "HEAD" or status in (204, 304) or status < 200
            if self.bodyless:
                self.expected_content_length = None

            if self.access_log:
                self.access_logger.info(
                    '%s - "%s %s HTTP/%s" %d',
                    get_client_addr(self.scope),
                    self.scope["method"],
                    get_path_with_query_string(self.scope),
                    self.scope["http_version"],
                    status,
                )

            self.stream.send_response(status, headers)
            self.flush()

        elif not self.response_complete:
            if message["type"] != "http.response.body":
                raise RuntimeError(f"Expected ASGI message 'http.response.body', but got '{message['type']}'.")

            body = message.get("body", b"")
            more_body = message.get("more_body", False)

            if self.bodyless:
                body = b""
            elif self.expected_content_length is not None:
                if len(body) > self.expected_content_length:
                    raise RuntimeError("Response content longer than Content-Length")
                self.expected_content_length -= len(body)
            if body:
                self.stream.send_data(body)
                self.flush()

            if not more_body:
                if self.expected_content_length not in (None, 0):
                    raise RuntimeError("Response content shorter than Content-Length")
                self.response_complete = True
                self.message_event.set()
                self.stream.end_message()
                self.flush()
                self.on_response(self.stream.stream_id)
                self.on_response = lambda stream_id: None

        else:
            raise RuntimeError(f"Unexpected ASGI message '{message['type']}' sent, after response already completed.")

    async def receive(self) -> ASGIReceiveEvent:
        if not self.disconnected and not self.response_complete:
            await self.message_event.wait()
            self.message_event.clear()

        if self.disconnected or self.response_complete:
            return {"type": "http.disconnect"}

        body = bytes(self.body)
        self.body.clear()
        if body:
            self.consume_data(self.stream.stream_id, len(body))
        return {"type": "http.request", "body": body, "more_body": self.more_body}

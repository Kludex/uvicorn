from __future__ import annotations

import asyncio
import contextvars
import logging
import sys
import warnings
from collections.abc import Callable
from typing import Any, Literal

import rh2

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
from uvicorn.protocols.http.flow_control import FlowControl, service_unavailable
from uvicorn.protocols.utils import get_client_addr, get_local_addr, get_path_with_query_string, get_remote_addr, is_ssl
from uvicorn.server import ServerState

_EXPERIMENTAL_WARNING_EMITTED = False


def _warn_experimental_once() -> None:
    global _EXPERIMENTAL_WARNING_EMITTED
    if _EXPERIMENTAL_WARNING_EMITTED:
        return
    _EXPERIMENTAL_WARNING_EMITTED = True
    warnings.warn(
        "Uvicorn's HTTP/2 support is experimental. I'd really appreciate if you try it out and report back! "
        "See the docs at https://uvicorn.dev/concepts/http2/.",
        UserWarning,
        stacklevel=2,
    )


# RFC 9113 section 8.2.2: connection-specific headers MUST NOT appear in HTTP/2.
# An ASGI app or middleware tuned for HTTP/1.1 may still emit them, so strip
# them on the way out rather than letting the codec reject the response.
FORBIDDEN_HEADERS = frozenset({b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade"})

PSEUDO_HEADERS = frozenset({b":method", b":scheme", b":authority", b":path"})


class RustH2Protocol(asyncio.Protocol):
    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if not config.loaded:
            config.load()

        _warn_experimental_once()
        self.config = config
        self.app = config.loaded_app
        self.loop = _loop or asyncio.get_event_loop()
        self.logger = logging.getLogger("uvicorn.error")
        self.access_logger = logging.getLogger("uvicorn.access")
        self.access_log = self.access_logger.hasHandlers()
        self.conn = rh2.H2Connection()
        self.root_path = config.root_path
        self.asgi_version = config.asgi_version
        self.limit_concurrency = config.limit_concurrency
        self.app_state = app_state

        # Timeouts
        self.timeout_keep_alive_task: asyncio.TimerHandle | None = None
        self.timeout_keep_alive = config.timeout_keep_alive

        # Shared server state
        self.server_state = server_state
        self.connections = server_state.connections
        self.tasks = server_state.tasks

        # Per-connection state
        self.transport: asyncio.Transport = None  # type: ignore[assignment]
        self.flow: FlowControl = None  # type: ignore[assignment]
        self.server: tuple[str, int | None] | None = None
        self.client: tuple[str, int] | None = None
        self.scheme: Literal["http", "https"] | None = None
        self.shutdown_requested = False

        # Per-stream state, keyed by HTTP/2 stream id.
        self.cycles: dict[int, RequestResponseCycle] = {}

    # asyncio.Protocol interface
    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        self.connections.add(self)
        self.transport = transport  # type: ignore[assignment]
        self.flow = FlowControl(transport)  # type: ignore[arg-type]
        self.server = get_local_addr(transport)
        self.client = get_remote_addr(transport)
        self.scheme = "https" if is_ssl(transport) else "http"

        if self.logger.level <= TRACE_LOG_LEVEL:
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sHTTP/2 connection made", prefix)

        # Emit the connection preface / initial SETTINGS immediately.
        self.transport.write(self.conn.data_to_send())

    def connection_lost(self, exc: Exception | None) -> None:
        self.connections.discard(self)

        if self.logger.level <= TRACE_LOG_LEVEL:
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sHTTP/2 connection lost", prefix)

        for cycle in self.cycles.values():
            if not cycle.response_complete:
                cycle.disconnected = True
            cycle.message_event.set()
        if self.flow is not None:
            self.flow.resume_writing()
        self._unset_keepalive_if_required()

    def eof_received(self) -> None:
        pass

    def _unset_keepalive_if_required(self) -> None:
        if self.timeout_keep_alive_task is not None:
            self.timeout_keep_alive_task.cancel()
            self.timeout_keep_alive_task = None

    def data_received(self, data: bytes) -> None:
        self._unset_keepalive_if_required()

        try:
            events = self.conn.receive_data(data)
        except ValueError as exc:
            self.logger.warning("Invalid HTTP/2 frame received: %s", exc)
            self.transport.close()
            return

        self.handle_events(events)
        self.flush()

        # Frames that carry no stream-level event (SETTINGS, PING, WINDOW_UPDATE)
        # cancelled the keep-alive timer above but never re-arm it, so re-arm now
        # if the connection is idle.
        if not self.cycles and self.timeout_keep_alive_task is None and not self.transport.is_closing():
            self.timeout_keep_alive_task = self.loop.call_later(
                self.timeout_keep_alive, self.timeout_keep_alive_handler
            )

    def flush(self) -> None:
        """Write out bytes the codec queued outside a cycle's send path - the
        connection preface and DATA released by an inbound WINDOW_UPDATE."""
        data = self.conn.data_to_send()
        if data:
            self.transport.write(data)

    def handle_events(self, events: list[Any]) -> None:
        for event in events:
            if isinstance(event, rh2.RequestReceived):
                self.handle_request(event)
            elif isinstance(event, rh2.DataReceived):
                cycle = self.cycles.get(event.stream_id)
                if cycle is None or cycle.response_complete:
                    continue
                cycle.body += event.data
                if event.stream_ended:
                    cycle.more_body = False
                cycle.message_event.set()
            elif isinstance(event, rh2.StreamEnded):
                cycle = self.cycles.get(event.stream_id)
                if cycle is None or cycle.response_complete:
                    continue
                cycle.more_body = False
                cycle.message_event.set()
            elif isinstance(event, rh2.StreamReset):
                self.handle_rst_stream(event)
            elif isinstance(event, rh2.ConnectionTerminated):
                self.shutdown_requested = True
                if not self.cycles:
                    self.transport.close()

    def handle_request(self, event: rh2.RequestReceived) -> None:
        pseudo: dict[bytes, bytes] = {}
        headers: list[tuple[bytes, bytes]] = []
        for raw_name, raw_value in event.headers:
            name, value = bytes(raw_name), bytes(raw_value)
            if name in PSEUDO_HEADERS:
                pseudo[name] = value
            else:
                headers.append((name, value))

        method = pseudo.get(b":method", b"GET")
        raw_path = pseudo.get(b":path", b"/")
        path, _, query = raw_path.partition(b"?")
        full_raw_path = self.root_path.encode("ascii") + raw_path.split(b"?")[0]

        scope: HTTPScope = {
            "type": "http",
            "asgi": {"version": self.asgi_version, "spec_version": "2.3"},
            "http_version": "2",
            "server": self.server,
            "client": self.client,
            "scheme": self.scheme,  # type: ignore[typeddict-item]
            "method": method.decode("ascii"),
            "root_path": self.root_path,
            "path": self.root_path + path.decode("ascii"),
            "raw_path": full_raw_path,
            "query_string": query,
            "headers": headers,
            "state": self.app_state.copy(),
        }

        # Refuse new streams once a shutdown began, and answer 503 when the
        # concurrency limit is exceeded.
        if self.shutdown_requested:
            app = service_unavailable
        elif self.limit_concurrency is not None and (
            len(self.connections) >= self.limit_concurrency or len(self.tasks) >= self.limit_concurrency
        ):
            app = service_unavailable
            self.logger.warning("Exceeded concurrency limit.")
        else:
            app = self.app

        cycle = RequestResponseCycle(
            scope=scope,
            conn=self.conn,
            stream_id=event.stream_id,
            transport=self.transport,
            flow=self.flow,
            logger=self.logger,
            access_logger=self.access_logger,
            access_log=self.access_log,
            default_headers=self.server_state.default_headers,
            message_event=asyncio.Event(),
            on_response=self.on_response_complete,
        )
        self.cycles[event.stream_id] = cycle
        if event.stream_ended:
            cycle.more_body = False
            cycle.message_event.set()

        if self.config.reset_contextvars:
            if sys.version_info >= (3, 11):  # pragma: py-lt-311
                task = self.loop.create_task(cycle.run_asgi(app), context=contextvars.Context())
            else:  # pragma: py-gte-311
                task = contextvars.Context().run(self.loop.create_task, cycle.run_asgi(app))
        else:
            task = self.loop.create_task(cycle.run_asgi(app))
        task.add_done_callback(self.tasks.discard)
        self.tasks.add(task)

    def handle_rst_stream(self, event: rh2.StreamReset) -> None:
        cycle = self.cycles.pop(event.stream_id, None)
        if cycle is None:
            return
        if not cycle.response_complete:
            cycle.disconnected = True
            cycle.message_event.set()
        self.on_stream_closed()

    def on_response_complete(self, stream_id: int) -> None:
        self.server_state.total_requests += 1
        self.cycles.pop(stream_id, None)
        self.flush()
        self.on_stream_closed()

    def on_stream_closed(self) -> None:
        if self.transport.is_closing():
            return

        self._unset_keepalive_if_required()

        if not self.cycles:
            if self.shutdown_requested:
                self.transport.close()
                return
            self.timeout_keep_alive_task = self.loop.call_later(
                self.timeout_keep_alive, self.timeout_keep_alive_handler
            )

    def shutdown(self) -> None:
        """Called by the server to commence a graceful shutdown."""
        self.shutdown_requested = True
        if not self.cycles:
            self.conn.close_connection()
            self.flush()
            self.transport.close()

    def pause_writing(self) -> None:
        self.flow.pause_writing()  # pragma: no cover

    def resume_writing(self) -> None:
        self.flow.resume_writing()  # pragma: no cover

    def timeout_keep_alive_handler(self) -> None:
        if not self.transport.is_closing():
            self.conn.close_connection()
            self.flush()
            self.transport.close()


class RequestResponseCycle:
    def __init__(
        self,
        scope: HTTPScope,
        conn: rh2.H2Connection,
        stream_id: int,
        transport: asyncio.Transport,
        flow: FlowControl,
        logger: logging.Logger,
        access_logger: logging.Logger,
        access_log: bool,
        default_headers: list[tuple[bytes, bytes]],
        message_event: asyncio.Event,
        on_response: Callable[[int], None],
    ) -> None:
        self.scope = scope
        self.conn = conn
        self.stream_id = stream_id
        self.transport = transport
        self.flow = flow
        self.logger = logger
        self.access_logger = access_logger
        self.access_log = access_log
        self.default_headers = default_headers
        self.message_event = message_event
        self.on_response = on_response

        # Connection state
        self.disconnected = False

        # Request state
        self.body = bytearray()
        self.more_body = True

        # Response state
        self.response_started = False
        self.response_complete = False

    # ASGI exception wrapper
    async def run_asgi(self, app: ASGI3Application) -> None:
        try:
            result = await app(self.scope, self.receive, self.send)  # type: ignore[func-returns-value]
        except BaseException as exc:
            self.logger.error("Exception in ASGI application\n", exc_info=exc)
            if not self.response_started:
                await self.send_500_response()
            else:
                self.transport.close()
        else:
            if result is not None:
                self.logger.error("ASGI callable should return None, but returned '%s'.", result)
                self.transport.close()
            elif not self.response_started and not self.disconnected:
                self.logger.error("ASGI callable returned without starting response.")
                await self.send_500_response()
            elif not self.response_complete and not self.disconnected:
                self.logger.error("ASGI callable returned without completing response.")
                self.transport.close()
        finally:
            self.on_response(self.stream_id)
            self.on_response = lambda stream_id: None

    async def send_500_response(self) -> None:
        await self.send(
            {
                "type": "http.response.start",
                "status": 500,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            }
        )
        await self.send({"type": "http.response.body", "body": b"Internal Server Error"})

    async def send(self, message: ASGISendEvent) -> None:
        message_type = message["type"]

        if self.flow.write_paused and not self.disconnected:
            await self.flow.drain()

        if self.disconnected:
            return

        if not self.response_started:
            if message_type != "http.response.start":
                raise RuntimeError(
                    f"Expected ASGI message 'http.response.start', but got '{message_type}'."
                )
            message = cast_response_start(message)
            self.response_started = True

            status = message["status"]
            out_headers: list[tuple[bytes, bytes]] = []
            for name, value in self.default_headers + list(message.get("headers", [])):
                if name.lower() in FORBIDDEN_HEADERS:
                    continue
                out_headers.append((name, value))

            if self.access_log:
                self.access_logger.info(
                    '%s - "%s %s HTTP/%s" %d',
                    get_client_addr(self.scope),
                    self.scope["method"],
                    get_path_with_query_string(self.scope),
                    self.scope["http_version"],
                    status,
                )

            self.conn.send_headers(self.stream_id, status, out_headers, end_stream=False)
            self.transport.write(self.conn.data_to_send())

        elif not self.response_complete:
            if message_type != "http.response.body":
                raise RuntimeError(f"Expected ASGI message 'http.response.body', but got '{message_type}'.")
            body = message.get("body", b"")
            more_body = message.get("more_body", False)

            self.conn.send_data(self.stream_id, bytes(body), end_stream=not more_body)
            self.transport.write(self.conn.data_to_send())

            if not more_body:
                self.response_complete = True
                self.message_event.set()
        else:
            raise RuntimeError(f"Unexpected ASGI message '{message_type}' sent, after response already completed.")

    async def receive(self) -> ASGIReceiveEvent:
        if not self.disconnected and not self.response_complete:
            await self.message_event.wait()
            self.message_event.clear()

        if self.disconnected:
            return {"type": "http.disconnect"}

        body = bytes(self.body)
        if body:
            self.conn.acknowledge_data(self.stream_id, len(body))
            self.transport.write(self.conn.data_to_send())
        self.body = bytearray()
        return {
            "type": "http.request",
            "body": body,
            "more_body": self.more_body,
        }


def cast_response_start(message: ASGISendEvent) -> HTTPResponseStartEvent:
    return message  # type: ignore[return-value]


def cast_response_body(message: ASGISendEvent) -> HTTPResponseBodyEvent:
    return message  # type: ignore[return-value]

"""HTTP/2 protocol implementation for uvicorn.

References:
- https://github.com/encode/uvicorn/pull/73 (by jordaneremieff)
- https://github.com/encode/uvicorn/pull/1026 (by Vibhu-Agarwal)
- https://github.com/emmett-framework/emmett/blob/a78571c/emmett/asgi/protocols/http/h2.py
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
from collections.abc import Callable
from typing import Any, Literal, cast
from urllib.parse import unquote

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    RemoteSettingsChanged,
    RequestReceived,
    StreamEnded,
    StreamReset,
    WindowUpdated,
)
from h2.exceptions import ProtocolError

from uvicorn._types import (
    ASGI3Application,
    ASGIReceiveEvent,
    ASGISendEvent,
    HTTP2Protocol,
    HTTPResponseBodyEvent,
    HTTPResponseStartEvent,
    HTTPScope,
)
from uvicorn.config import Config
from uvicorn.logging import TRACE_LOG_LEVEL
from uvicorn.protocols.http.flow_control import HIGH_WATER_LIMIT, FlowControl, service_unavailable
from uvicorn.protocols.utils import get_client_addr, get_local_addr, get_path_with_query_string, get_remote_addr, is_ssl
from uvicorn.server import ServerState


class H2Protocol(HTTP2Protocol):
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

        # HTTP/2 connection using h2 library
        # Use header_encoding=None to keep headers as bytes (avoids type issues)
        h2_config = H2Configuration(client_side=False, header_encoding=None)
        self.conn = H2Connection(config=h2_config)

        self.ws_protocol_class = config.ws_protocol_class
        self.root_path = config.root_path
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
        self.server: tuple[str, int] | None = None
        self.client: tuple[str, int] | None = None
        self.scheme: Literal["http", "https"] = "https"  # HTTP/2 typically uses TLS, but h2c uses http

        # Stream management - maps stream_id to H2Stream
        self.streams: dict[int, H2Stream] = {}

    # Protocol interface
    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self.connections.add(self)

        self.transport = transport
        self.flow = FlowControl(transport)
        self.server = get_local_addr(transport)
        self.client = get_remote_addr(transport)
        self.scheme = "https" if is_ssl(transport) else "http"

        # Initialize HTTP/2 connection
        self.conn.initiate_connection()
        self.transport.write(self.conn.data_to_send())

        if self.logger.level <= TRACE_LOG_LEVEL:  # pragma: no cover
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sHTTP/2 connection made", prefix)

    def initiate_h2c_upgrade(
        self,
        transport: asyncio.Transport,
        method: str,
        path: str,
        headers: list[tuple[bytes, bytes]],
        http2_settings: bytes | None,
    ) -> None:
        """Initialize HTTP/2 connection for h2c upgrade.

        This is called when upgrading from HTTP/1.1 to HTTP/2 cleartext.
        The 101 Switching Protocols response has already been sent.
        """
        self.connections.add(self)

        self.transport = transport
        self.flow = FlowControl(transport)
        self.server = get_local_addr(transport)
        self.client = get_remote_addr(transport)
        self.scheme = "http"

        # Initialize HTTP/2 connection for upgrade
        # This handles the upgrade case where client sent HTTP/1.1 request with Upgrade: h2c
        self.conn.initiate_upgrade_connection(http2_settings)
        self.transport.write(self.conn.data_to_send())

        if self.logger.level <= TRACE_LOG_LEVEL:  # pragma: no cover
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sHTTP/2 connection made (h2c upgrade)", prefix)

        # The initial HTTP/1.1 request becomes stream 1 in HTTP/2
        # We need to process it as if we received a RequestReceived event
        self._handle_upgraded_request(method, path, headers)

    def _handle_upgraded_request(
        self,
        method: str,
        path: str,
        headers: list[tuple[bytes, bytes]],
    ) -> None:
        """Handle the initial request that triggered the h2c upgrade."""
        stream_id = 1  # Upgraded request is always stream 1

        # Parse headers into scope format (exclude connection/upgrade related headers)
        scope_headers: list[tuple[bytes, bytes]] = []
        host: bytes = b""
        for name, value in headers:
            # Skip HTTP/1.1 specific headers that don't apply to HTTP/2
            if name.lower() not in (b"connection", b"upgrade", b"http2-settings"):
                scope_headers.append((name, value))
                if name.lower() == b"host":
                    host = value

        # Extract path and query string
        raw_path, _, query_string = path.partition("?")

        # URL decode the path
        decoded_path = unquote(raw_path)
        full_path = self.root_path + decoded_path
        full_raw_path = self.root_path.encode("ascii") + raw_path.encode("ascii")

        scope: HTTPScope = {
            "type": "http",
            "asgi": {"version": self.config.asgi_version, "spec_version": "2.3"},
            "http_version": "2",
            "server": self.server,
            "client": self.client,
            "scheme": self.scheme,
            "method": method,
            "root_path": self.root_path,
            "path": full_path,
            "raw_path": full_raw_path,
            "query_string": query_string.encode("latin-1") if query_string else b"",
            "headers": scope_headers,
            "state": self.app_state.copy(),
            "extensions": {"http.response.push": {}},
        }

        # Handle 503 responses when 'limit_concurrency' is exceeded
        if self.limit_concurrency is not None and (  # pragma: no cover
            len(self.connections) >= self.limit_concurrency or len(self.tasks) >= self.limit_concurrency
        ):
            app = service_unavailable
            message = "Exceeded concurrency limit."
            self.logger.warning(message)
        else:
            app = self.app

        # Create stream handler
        stream = H2Stream(
            stream_id=stream_id,
            conn=self.conn,
            transport=self.transport,
            flow=self.flow,
            protocol=self,
        )
        self.streams[stream_id] = stream

        # Create request/response cycle
        cycle = RequestResponseCycle(
            scope=scope,
            stream=stream,
            conn=self.conn,
            transport=self.transport,
            flow=self.flow,
            logger=self.logger,
            access_logger=self.access_logger,
            access_log=self.access_log,
            default_headers=self.server_state.default_headers,
            message_event=asyncio.Event(),
            on_response=self.on_response_complete,
            host=host,
            protocol=self,
        )
        stream.cycle = cycle

        # Mark that body is complete (h2c upgrade request has no body after upgrade)
        cycle.more_body = False
        cycle.message_event.set()  # Signal that body is ready (empty)

        # Start ASGI task
        task = contextvars.Context().run(self.loop.create_task, cycle.run_asgi(app))
        task.add_done_callback(self.tasks.discard)
        self.tasks.add(task)

    def connection_lost(self, exc: Exception | None) -> None:
        self.connections.discard(self)

        if self.logger.level <= TRACE_LOG_LEVEL:  # pragma: no cover
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sHTTP/2 connection lost", prefix)

        # Notify all active streams of disconnection
        for stream in self.streams.values():  # pragma: no cover
            if stream.cycle and not stream.cycle.response_complete:
                stream.cycle.disconnected = True
                stream.cycle.message_event.set()

        self.flow.resume_writing()  # pragma: no cover

        if exc is None:
            self.transport.close()
            self._unset_keepalive_if_required()

    def eof_received(self) -> None:  # pragma: no cover
        pass

    def _unset_keepalive_if_required(self) -> None:
        if self.timeout_keep_alive_task is not None:
            self.timeout_keep_alive_task.cancel()
            self.timeout_keep_alive_task = None

    def data_received(self, data: bytes) -> None:
        self._unset_keepalive_if_required()

        try:
            events = self.conn.receive_data(data)
        except ProtocolError as e:  # pragma: no cover
            self.logger.warning("HTTP/2 protocol error: %s", e)
            self.transport.write(self.conn.data_to_send())
            self.transport.close()
            return

        self.transport.write(self.conn.data_to_send())
        self.handle_events(events)

    def handle_events(self, events: list[Any]) -> None:
        for event in events:
            if isinstance(event, RequestReceived):
                self.handle_request_received(event)
            elif isinstance(event, DataReceived):
                self.handle_data_received(event)
            elif isinstance(event, StreamEnded):
                self.handle_stream_ended(event)
            elif isinstance(event, StreamReset):  # pragma: no cover
                self.handle_stream_reset(event)
            elif isinstance(event, WindowUpdated):  # pragma: no cover
                self.handle_window_updated(event)
            elif isinstance(event, RemoteSettingsChanged):  # pragma: no cover
                pass  # Settings acknowledged, no action needed
            elif isinstance(event, ConnectionTerminated):  # pragma: no cover
                self.transport.close()

    def handle_request_received(self, event: RequestReceived) -> None:
        stream_id = event.stream_id
        headers = event.headers

        # Parse headers into scope format
        # h2 returns headers as bytes when header_encoding=None
        pseudo_headers: dict[bytes, bytes] = {}
        scope_headers: list[tuple[bytes, bytes]] = []
        host: bytes = b""

        for name, value in headers:
            if name[0:1] == b":":
                # Pseudo-headers (HTTP/2 specific)
                pseudo_headers[name] = value
            else:
                scope_headers.append((name.lower(), value))

        # Extract :authority and add as host header
        if b":authority" in pseudo_headers:
            host = pseudo_headers[b":authority"]
            scope_headers.append((b"host", host))

        # Extract path and query string
        path = pseudo_headers.get(b":path", b"/")
        raw_path, _, query_string = path.partition(b"?")

        # URL decode the path
        decoded_path = unquote(raw_path.decode("ascii"))
        full_path = self.root_path + decoded_path
        full_raw_path = self.root_path.encode("ascii") + raw_path

        scope: HTTPScope = {
            "type": "http",
            "asgi": {"version": self.config.asgi_version, "spec_version": "2.3"},
            "http_version": "2",
            "server": self.server,
            "client": self.client,
            "scheme": self.scheme,
            "method": pseudo_headers.get(b":method", b"GET").decode("ascii"),
            "root_path": self.root_path,
            "path": full_path,
            "raw_path": full_raw_path,
            "query_string": query_string,
            "headers": scope_headers,
            "state": self.app_state.copy(),
            "extensions": {"http.response.push": {}},
        }

        # Handle 503 responses when 'limit_concurrency' is exceeded
        if self.limit_concurrency is not None and (  # pragma: no cover
            len(self.connections) >= self.limit_concurrency or len(self.tasks) >= self.limit_concurrency
        ):
            app = service_unavailable
            message = "Exceeded concurrency limit."
            self.logger.warning(message)
        else:
            app = self.app

        # Create stream handler
        stream = H2Stream(
            stream_id=stream_id,
            conn=self.conn,
            transport=self.transport,
            flow=self.flow,
            protocol=self,
        )
        self.streams[stream_id] = stream

        # Create request/response cycle
        cycle = RequestResponseCycle(
            scope=scope,
            stream=stream,
            conn=self.conn,
            transport=self.transport,
            flow=self.flow,
            logger=self.logger,
            access_logger=self.access_logger,
            access_log=self.access_log,
            default_headers=self.server_state.default_headers,
            message_event=asyncio.Event(),
            on_response=self.on_response_complete,
            host=host,
            protocol=self,
        )
        stream.cycle = cycle

        # Start ASGI task
        task = contextvars.Context().run(self.loop.create_task, cycle.run_asgi(app))
        task.add_done_callback(self.tasks.discard)
        self.tasks.add(task)

    def handle_data_received(self, event: DataReceived) -> None:
        stream_id = event.stream_id
        data = event.data

        if stream_id not in self.streams:  # pragma: no cover
            # Stream not found - send protocol error
            self.conn.reset_stream(stream_id, error_code=ErrorCodes.PROTOCOL_ERROR)
            self.transport.write(self.conn.data_to_send())
            return

        stream = self.streams[stream_id]
        if stream.cycle and not stream.cycle.response_complete:
            stream.cycle.body += data
            if len(stream.cycle.body) > HIGH_WATER_LIMIT:  # pragma: no cover
                self.flow.pause_reading()
            stream.cycle.message_event.set()

        # Acknowledge received data for flow control
        self.conn.acknowledge_received_data(event.flow_controlled_length, stream_id)
        self.transport.write(self.conn.data_to_send())

    def handle_stream_ended(self, event: StreamEnded) -> None:
        stream_id = event.stream_id

        if stream_id not in self.streams:  # pragma: no cover
            # Stream not found - send stream closed error
            self.conn.reset_stream(stream_id, error_code=ErrorCodes.STREAM_CLOSED)
            self.transport.write(self.conn.data_to_send())
            return

        stream = self.streams[stream_id]
        if stream.cycle:
            self.transport.resume_reading()
            stream.cycle.more_body = False
            stream.cycle.message_event.set()

    def handle_stream_reset(self, event: StreamReset) -> None:
        stream_id = event.stream_id

        if stream_id in self.streams:
            stream = self.streams[stream_id]
            if stream.cycle:
                stream.cycle.disconnected = True
                stream.cycle.message_event.set()
            del self.streams[stream_id]

    def handle_window_updated(self, event: WindowUpdated) -> None:  # pragma: no cover
        # Flow control window was updated, we can potentially send more data
        _ = event  # Unused, but kept for potential future flow control improvements

    def handle_request_received_for_push(self, stream_id: int, headers: list[tuple[bytes, bytes]]) -> None:
        """Handle a pushed request (server push)."""
        # Parse headers into scope format
        pseudo_headers: dict[bytes, bytes] = {}
        scope_headers: list[tuple[bytes, bytes]] = []
        host: bytes = b""

        for name, value in headers:
            if name[0:1] == b":":
                pseudo_headers[name] = value
            else:
                scope_headers.append((name.lower(), value))

        if b":authority" in pseudo_headers:
            host = pseudo_headers[b":authority"]
            scope_headers.append((b"host", host))

        path = pseudo_headers.get(b":path", b"/")
        raw_path, _, query_string = path.partition(b"?")
        decoded_path = unquote(raw_path.decode("ascii"))
        full_path = self.root_path + decoded_path
        full_raw_path = self.root_path.encode("ascii") + raw_path

        scope: HTTPScope = {
            "type": "http",
            "asgi": {"version": self.config.asgi_version, "spec_version": "2.3"},
            "http_version": "2",
            "server": self.server,
            "client": self.client,
            "scheme": self.scheme,
            "method": pseudo_headers.get(b":method", b"GET").decode("ascii"),
            "root_path": self.root_path,
            "path": full_path,
            "raw_path": full_raw_path,
            "query_string": query_string,
            "headers": scope_headers,
            "state": self.app_state.copy(),
            "extensions": {"http.response.push": {}},
        }

        stream = H2Stream(
            stream_id=stream_id,
            conn=self.conn,
            transport=self.transport,
            flow=self.flow,
            protocol=self,
        )
        self.streams[stream_id] = stream

        cycle = RequestResponseCycle(
            scope=scope,
            stream=stream,
            conn=self.conn,
            transport=self.transport,
            flow=self.flow,
            logger=self.logger,
            access_logger=self.access_logger,
            access_log=self.access_log,
            default_headers=self.server_state.default_headers,
            message_event=asyncio.Event(),
            on_response=self.on_response_complete,
            host=host,
            protocol=self,
        )
        stream.cycle = cycle

        # Pushed requests have no body
        cycle.more_body = False
        cycle.message_event.set()

        task = contextvars.Context().run(self.loop.create_task, cycle.run_asgi(self.app))
        task.add_done_callback(self.tasks.discard)
        self.tasks.add(task)

    def on_response_complete(self, stream_id: int) -> None:
        self.server_state.total_requests += 1

        # Clean up completed stream
        if stream_id in self.streams:
            del self.streams[stream_id]

        if self.transport.is_closing():  # pragma: no cover
            return

        # Reset keep-alive timer if no active streams
        self._unset_keepalive_if_required()
        if not self.streams:
            self.timeout_keep_alive_task = self.loop.call_later(
                self.timeout_keep_alive, self.timeout_keep_alive_handler
            )

    def shutdown(self) -> None:
        """
        Called by the server to commence a graceful shutdown.
        """
        if not self.streams:
            self.conn.close_connection()
            self.transport.write(self.conn.data_to_send())
            self.transport.close()
        else:  # pragma: no cover
            # Mark all active streams for closure
            for stream in self.streams.values():
                if stream.cycle:
                    stream.cycle.keep_alive = False

    def pause_writing(self) -> None:  # pragma: no cover
        """
        Called by the transport when the write buffer exceeds the high water mark.
        """
        self.flow.pause_writing()

    def resume_writing(self) -> None:  # pragma: no cover
        """
        Called by the transport when the write buffer drops below the low water mark.
        """
        self.flow.resume_writing()

    def timeout_keep_alive_handler(self) -> None:
        """
        Called on a keep-alive connection if no new data is received after a short
        delay.
        """
        if not self.transport.is_closing() and not self.streams:
            self.conn.close_connection()
            self.transport.write(self.conn.data_to_send())
            self.transport.close()


class H2Stream:
    """
    Handles a single HTTP/2 stream within a connection.
    """

    def __init__(
        self,
        stream_id: int,
        conn: H2Connection,
        transport: asyncio.Transport,
        flow: FlowControl,
        protocol: H2Protocol,
    ) -> None:
        self.stream_id = stream_id
        self.conn = conn
        self.transport = transport
        self.flow = flow
        self.protocol = protocol
        self.cycle: RequestResponseCycle | None = None

    def send_headers(self, headers: list[tuple[str, str]], end_stream: bool = False) -> None:
        """Send response headers on this stream."""
        self.conn.send_headers(self.stream_id, headers, end_stream=end_stream)
        self.transport.write(self.conn.data_to_send())

    def send_data(self, data: bytes, end_stream: bool = False) -> None:
        """Send response data on this stream with flow control."""
        if not data and not end_stream:  # pragma: no cover
            return

        # Check available flow control window
        while data:
            # Get the minimum of local flow control window and data length
            available_window = self.conn.local_flow_control_window(self.stream_id)
            max_frame_size = self.conn.max_outbound_frame_size

            if available_window <= 0:  # pragma: no cover
                # Need to wait for window update - for now, just send what we can
                break

            chunk_size = min(available_window, max_frame_size, len(data))
            chunk = data[:chunk_size]
            data = data[chunk_size:]

            is_end = end_stream and not data
            self.conn.send_data(self.stream_id, chunk, end_stream=is_end)
            self.transport.write(self.conn.data_to_send())

        # If we still have data and end_stream, send empty frame to end
        if not data and end_stream:  # pragma: no cover
            # Already handled in the loop
            pass

    def end_stream(self) -> None:  # pragma: no cover
        """End the stream."""
        self.conn.end_stream(self.stream_id)
        self.transport.write(self.conn.data_to_send())


class RequestResponseCycle:
    def __init__(
        self,
        scope: HTTPScope,
        stream: H2Stream,
        conn: H2Connection,
        transport: asyncio.Transport,
        flow: FlowControl,
        logger: logging.Logger,
        access_logger: logging.Logger,
        access_log: bool,
        default_headers: list[tuple[bytes, bytes]],
        message_event: asyncio.Event,
        on_response: Callable[[int], None],
        host: bytes,
        protocol: H2Protocol,
    ) -> None:
        self.scope = scope
        self.stream = stream
        self.conn = conn
        self.transport = transport
        self.flow = flow
        self.logger = logger
        self.access_logger = access_logger
        self.access_log = access_log
        self.default_headers = default_headers
        self.message_event = message_event
        self.on_response = on_response
        self.host = host
        self.protocol = protocol

        # Connection state
        self.disconnected = False
        self.keep_alive = True

        # Request state
        self.body = b""
        self.more_body = True

        # Response state
        self.response_started = False
        self.response_complete = False

    async def run_asgi(self, app: ASGI3Application) -> None:
        try:
            result = await app(self.scope, self.receive, self.send)  # type: ignore[func-returns-value]
        except BaseException:
            self.logger.exception("Exception in ASGI application")
            if not self.response_started:
                await self.send_500_response()
            else:
                self.transport.close()  # pragma: no cover
        else:
            if result is not None:  # pragma: no cover
                self.logger.error("ASGI callable should return None, but returned '%s'.", result)
                self.transport.close()
            elif not self.response_started and not self.disconnected:
                self.logger.error("ASGI callable returned without starting response.")
                await self.send_500_response()
            elif not self.response_complete and not self.disconnected:  # pragma: no cover
                self.logger.error("ASGI callable returned without completing response.")
                self.transport.close()
        finally:
            self.on_response(self.stream.stream_id)

    async def send_500_response(self) -> None:
        response_start_event: HTTPResponseStartEvent = {
            "type": "http.response.start",
            "status": 500,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", b"21"),
            ],
        }
        await self.send(response_start_event)
        response_body_event: HTTPResponseBodyEvent = {
            "type": "http.response.body",
            "body": b"Internal Server Error",
            "more_body": False,
        }
        await self.send(response_body_event)

    async def send(self, message: ASGISendEvent) -> None:
        message_type = message["type"]

        if self.flow.write_paused and not self.disconnected:  # pragma: no cover
            await self.flow.drain()

        if self.disconnected:  # pragma: no cover
            return

        # Handle HTTP/2 Server Push
        if message_type == "http.response.push":
            await self._handle_push_promise(cast("dict[str, Any]", message))
            return

        if not self.response_started:
            # Sending response status line and headers
            if message_type != "http.response.start":  # pragma: no cover
                msg = "Expected ASGI message 'http.response.start', but got '%s'."
                raise RuntimeError(msg % message_type)
            message = cast("HTTPResponseStartEvent", message)

            self.response_started = True

            status = message["status"]
            headers = list(message.get("headers", []))

            if self.access_log:
                self.access_logger.info(
                    '%s - "%s %s HTTP/%s" %d',
                    get_client_addr(self.scope),
                    self.scope["method"],
                    get_path_with_query_string(self.scope),
                    self.scope["http_version"],
                    status,
                )

            # Build HTTP/2 response headers
            response_headers: list[tuple[str, str]] = [(":status", str(status))]

            # Add default headers
            for name, value in self.default_headers:  # pragma: no cover
                if name.lower() != b"connection":  # Connection header not used in HTTP/2
                    response_headers.append((name.decode("latin-1"), value.decode("latin-1")))

            # Add response headers
            for name, value in headers:
                header_name = name.decode("latin-1").lower()
                if header_name == "connection":  # pragma: no cover
                    # Connection header not used in HTTP/2
                    continue
                response_headers.append((header_name, value.decode("latin-1")))

            self.stream.send_headers(response_headers)

        elif not self.response_complete:
            # Sending response body
            if message_type != "http.response.body":  # pragma: no cover
                msg = "Expected ASGI message 'http.response.body', but got '%s'."
                raise RuntimeError(msg % message_type)
            message = cast("HTTPResponseBodyEvent", message)

            body = message.get("body", b"")
            more_body = message.get("more_body", False)

            # Write response body
            if self.scope["method"] == "HEAD":  # pragma: no cover
                body = b""

            if body or not more_body:
                self.stream.send_data(body, end_stream=not more_body)

            # Handle response completion
            if not more_body:
                self.response_complete = True
                self.message_event.set()

        else:  # pragma: no cover
            # Response already sent
            raise RuntimeError(f"Unexpected ASGI message '{message_type}' sent, after response already completed.")

    async def _handle_push_promise(self, message: dict[str, Any]) -> None:
        """Handle HTTP/2 server push (http.response.push)."""
        try:
            push_stream_id = self.conn.get_next_available_stream_id()
            path = message["path"]
            push_headers: list[tuple[bytes, bytes]] = [
                (b":authority", self.host),
                (b":method", b"GET"),
                (b":path", path.encode("ascii") if isinstance(path, str) else path),
                (b":scheme", self.scope["scheme"].encode("ascii")),
            ]
            # Add any additional headers from the message
            for name, value in message.get("headers", []):
                push_headers.append((name, value))

            self.conn.push_stream(
                stream_id=self.stream.stream_id,
                promised_stream_id=push_stream_id,
                request_headers=push_headers,
            )
            self.transport.write(self.conn.data_to_send())

            # Create a synthetic RequestReceived event for the pushed stream
            self.protocol.handle_request_received_for_push(push_stream_id, push_headers)
        except ProtocolError:  # pragma: no cover
            self.logger.debug("HTTP/2 server push failed", exc_info=True)

    async def receive(self) -> ASGIReceiveEvent:
        if not self.disconnected and not self.response_complete:
            self.flow.resume_reading()
            await self.message_event.wait()
            self.message_event.clear()

        if self.disconnected or self.response_complete:  # pragma: no cover
            return {"type": "http.disconnect"}

        body = self.body
        self.body = b""
        return {"type": "http.request", "body": body, "more_body": self.more_body}

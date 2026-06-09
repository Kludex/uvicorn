from __future__ import annotations

import asyncio
import contextvars
import logging
import sys
import warnings
from collections.abc import Callable, Generator
from typing import Any, Literal
from urllib.parse import unquote

import zttp
from zttp import Event

from uvicorn._types import (
    ASGI3Application,
    ASGIReceiveEvent,
    ASGISendEvent,
    HTTPRequestEvent,
    HTTPResponseBodyEvent,
    HTTPResponseStartEvent,
    HTTPScope,
)
from uvicorn.config import Config
from uvicorn.logging import TRACE_LOG_LEVEL
from uvicorn.protocols.http.flow_control import CLOSE_HEADER, HIGH_WATER_LIMIT, FlowControl, service_unavailable
from uvicorn.protocols.utils import get_client_addr, get_local_addr, get_path_with_query_string, get_remote_addr, is_ssl
from uvicorn.server import ServerState

warnings.warn(
    "The 'zttp' HTTP/1.1 protocol is experimental. I'd really appreciate if you try it out and report back! "
    "See the docs at https://zttp.marcelotryle.com/.",
    UserWarning,
    stacklevel=2,
)


class ZttpProtocol(asyncio.Protocol):
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
        self.conn = zttp.Connection(zttp.SERVER)
        self.ws_protocol_class = config.ws_protocol_class
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

        # Per-request state
        self.scope: HTTPScope = None  # type: ignore[assignment]
        self.headers: list[tuple[bytes, bytes]] = None  # type: ignore[assignment]
        self.cycle: RequestResponseCycle = None  # type: ignore[assignment]

    # Protocol interface
    def connection_made(  # type: ignore[override]
        self, transport: asyncio.Transport
    ) -> None:
        self.connections.add(self)

        self.transport = transport
        self.flow = FlowControl(transport)
        self.server = get_local_addr(transport)
        self.client = get_remote_addr(transport)
        self.scheme = "https" if is_ssl(transport) else "http"

        if self.logger.level <= TRACE_LOG_LEVEL:
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sHTTP connection made", prefix)

    def connection_lost(self, exc: Exception | None) -> None:
        self.connections.discard(self)

        if self.logger.level <= TRACE_LOG_LEVEL:
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sHTTP connection lost", prefix)

        if self.cycle and not self.cycle.response_complete:
            self.cycle.disconnected = True
        if self.cycle is not None:
            self.cycle.message_event.set()
        if self.flow is not None:
            self.flow.resume_writing()
        if exc is None:
            self.transport.close()
            self._unset_keepalive_if_required()

    def eof_received(self) -> None:
        pass

    def _unset_keepalive_if_required(self) -> None:
        if self.timeout_keep_alive_task is not None:
            self.timeout_keep_alive_task.cancel()
            self.timeout_keep_alive_task = None

    def _should_upgrade_to_ws(self) -> bool:
        if self.ws_protocol_class is None:
            return False
        return True

    def _unsupported_upgrade_warning(self) -> None:
        msg = "Unsupported upgrade request."
        self.logger.warning(msg)
        if not self._should_upgrade_to_ws():
            msg = "No supported WebSocket library detected. Please use \"pip install 'uvicorn[standard]'\", or install 'websockets' or 'wsproto' manually."  # noqa: E501
            self.logger.warning(msg)

    def _should_upgrade(self) -> bool:
        upgrade = self.conn.upgrade()
        if upgrade is not None:
            upgrade = upgrade.lower()
        if upgrade == b"websocket" and self._should_upgrade_to_ws():
            return True
        if upgrade is not None:
            self._unsupported_upgrade_warning()
        return False

    def data_received(self, data: bytes) -> None:
        self._unset_keepalive_if_required()

        self.conn.receive_data(data)
        self.handle_events()

    def events(self) -> Generator[Event]:
        """Yield every complete event currently available."""
        while True:
            event = self.conn.next_event()
            if event is zttp.NEED_DATA:
                return
            yield event

    def handle_events(self) -> None:
        try:
            for event in self.events():
                if isinstance(event, zttp.Request):
                    self.headers = [(key.lower(), value) for key, value in event.headers]
                    path = unquote(event.path.decode("ascii"))
                    full_path = self.root_path + path
                    full_raw_path = self.root_path.encode("ascii") + event.path
                    self.scope = {
                        "type": "http",
                        "asgi": {"version": self.asgi_version, "spec_version": "2.3"},
                        "http_version": event.http_version.decode("ascii"),
                        "server": self.server,
                        "client": self.client,
                        "scheme": self.scheme,  # type: ignore[typeddict-item]
                        "method": event.method.decode("ascii"),
                        "root_path": self.root_path,
                        "path": full_path,
                        "raw_path": full_raw_path,
                        "query_string": event.query,
                        "headers": self.headers,
                        "state": self.app_state.copy(),
                    }
                    if self._should_upgrade():
                        self.handle_websocket_upgrade(event)
                        return

                    # Handle 503 responses when 'limit_concurrency' is exceeded.
                    if self.limit_concurrency is not None and (
                        len(self.connections) >= self.limit_concurrency or len(self.tasks) >= self.limit_concurrency
                    ):
                        app = service_unavailable
                        message = "Exceeded concurrency limit."
                        self.logger.warning(message)
                    else:
                        app = self.app

                    self._unset_keepalive_if_required()

                    self.cycle = RequestResponseCycle(
                        scope=self.scope,
                        conn=self.conn,
                        transport=self.transport,
                        flow=self.flow,
                        logger=self.logger,
                        access_logger=self.access_logger,
                        access_log=self.access_log,
                        default_headers=self.server_state.default_headers,
                        message_event=asyncio.Event(),
                        expect_100_continue=event.expect_continue,
                        keep_alive=not self.conn.should_close(),
                        on_response=self.on_response_complete,
                    )
                    if self.config.reset_contextvars:
                        if sys.version_info >= (3, 11):  # pragma: py-lt-311
                            task = self.loop.create_task(self.cycle.run_asgi(app), context=contextvars.Context())
                        else:  # pragma: py-gte-311
                            task = contextvars.Context().run(self.loop.create_task, self.cycle.run_asgi(app))
                    else:
                        task = self.loop.create_task(self.cycle.run_asgi(app))
                    task.add_done_callback(self.tasks.discard)
                    self.tasks.add(task)

                elif isinstance(event, zttp.Data):
                    if self.cycle is None or self.cycle.response_complete:
                        continue  # pragma: no cover
                    self.cycle.body += event.data
                    if len(self.cycle.body) > HIGH_WATER_LIMIT:
                        self.flow.pause_reading()
                    self.cycle.message_event.set()

                elif isinstance(event, zttp.EndOfMessage):
                    if self.cycle is None or self.cycle.response_complete:
                        continue  # pragma: no cover
                    self.cycle.more_body = False
                    self.cycle.message_event.set()
        except zttp.RemoteProtocolError:
            msg = "Invalid HTTP request received."
            self.logger.warning(msg)
            self.send_400_response(msg)

    def handle_websocket_upgrade(self, event: zttp.Request) -> None:
        if self.logger.level <= TRACE_LOG_LEVEL:  # pragma: no cover
            prefix = "%s:%d - " % self.client if self.client else ""
            self.logger.log(TRACE_LOG_LEVEL, "%sUpgrading to WebSocket", prefix)

        self.connections.discard(self)
        output = bytearray(event.method + b" " + event.target + b" HTTP/1.1\r\n")
        for name, value in self.headers:
            output += name + b": " + value + b"\r\n"
        output += b"\r\n"
        protocol = self.ws_protocol_class(  # type: ignore[call-arg, misc]
            config=self.config,
            server_state=self.server_state,
            app_state=self.app_state,
        )
        protocol.connection_made(self.transport)
        protocol.data_received(bytes(output))
        self.transport.set_protocol(protocol)

    def send_400_response(self, msg: str) -> None:
        body = msg.encode("ascii")
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"connection", b"close"),
        ]
        self.conn.send_response(400, headers)
        self.conn.send_data(body)
        self.conn.end_message()
        self.transport.write(self.conn.data_to_send())
        self.transport.close()

    def on_response_complete(self) -> None:
        self.server_state.total_requests += 1

        if self.transport.is_closing():
            return

        # Set a short Keep-Alive timeout.
        self._unset_keepalive_if_required()

        self.timeout_keep_alive_task = self.loop.call_later(self.timeout_keep_alive, self.timeout_keep_alive_handler)

        # Unpause data reads if needed.
        self.flow.resume_reading()

        # Reset the parser for the next request on a keep-alive connection,
        # then unblock any events that arrived while we were responding.
        self.conn.start_next_cycle()
        self.handle_events()

    def shutdown(self) -> None:
        """
        Called by the server to commence a graceful shutdown.
        """
        if self.cycle is None or self.cycle.response_complete:
            self.transport.close()
        else:
            self.cycle.keep_alive = False

    def pause_writing(self) -> None:
        """
        Called by the transport when the write buffer exceeds the high water mark.
        """
        self.flow.pause_writing()  # pragma: no cover

    def resume_writing(self) -> None:
        """
        Called by the transport when the write buffer drops below the low water mark.
        """
        self.flow.resume_writing()  # pragma: no cover

    def timeout_keep_alive_handler(self) -> None:
        """
        Called on a keep-alive connection if no new data is received after a short
        delay.
        """
        if not self.transport.is_closing():
            self.transport.close()


class RequestResponseCycle:
    def __init__(
        self,
        scope: HTTPScope,
        conn: zttp.Connection,
        transport: asyncio.Transport,
        flow: FlowControl,
        logger: logging.Logger,
        access_logger: logging.Logger,
        access_log: bool,
        default_headers: list[tuple[bytes, bytes]],
        message_event: asyncio.Event,
        expect_100_continue: bool,
        keep_alive: bool,
        on_response: Callable[..., None],
    ) -> None:
        self.scope = scope
        self.conn = conn
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
        self.keep_alive = keep_alive
        self.waiting_for_100_continue = expect_100_continue

        # Request state
        self.body = bytearray()
        self.more_body = True

        # Response state
        self.response_started = False
        self.response_complete = False
        self.bodyless = False
        self.chunked_encoding = False
        self.expected_content_length = 0

    # ASGI exception wrapper
    async def run_asgi(self, app: ASGI3Application) -> None:
        try:
            result = await app(  # type: ignore[func-returns-value]
                self.scope, self.receive, self.send
            )
        except BaseException as exc:
            msg = "Exception in ASGI application\n"
            self.logger.error(msg, exc_info=exc)
            if not self.response_started:
                await self.send_500_response()
            else:
                self.transport.close()
        else:
            if result is not None:
                msg = "ASGI callable should return None, but returned '%s'."
                self.logger.error(msg, result)
                self.transport.close()
            elif not self.response_started and not self.disconnected:
                msg = "ASGI callable returned without starting response."
                self.logger.error(msg)
                await self.send_500_response()
            elif not self.response_complete and not self.disconnected:
                msg = "ASGI callable returned without completing response."
                self.logger.error(msg)
                self.transport.close()
        finally:
            self.on_response = lambda: None

    async def send_500_response(self) -> None:
        response_start_event: HTTPResponseStartEvent = {
            "type": "http.response.start",
            "status": 500,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"connection", b"close"),
            ],
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
        if self.flow.write_paused and not self.disconnected:
            await self.flow.drain()  # pragma: no cover

        if self.disconnected:
            return  # pragma: no cover

        if not self.response_started:
            # Sending response status line and headers
            if message["type"] != "http.response.start":
                raise RuntimeError(f"Expected ASGI message 'http.response.start', but got '{message['type']}'.")

            self.response_started = True
            self.waiting_for_100_continue = False

            status = message["status"]
            headers = self.default_headers + list(message.get("headers", []))

            if CLOSE_HEADER in self.scope["headers"] and CLOSE_HEADER not in headers:
                headers = headers + [CLOSE_HEADER]

            bodyless = self.scope["method"] == "HEAD" or status in (204, 304) or status < 200
            has_content_length = False
            for name, value in headers:
                name = name.lower()
                if name == b"content-length":
                    has_content_length = True
                    self.expected_content_length = int(value.decode())
                elif name == b"transfer-encoding" and value.lower() == b"chunked":
                    self.chunked_encoding = True
                elif name == b"connection" and value.lower() == b"close":
                    self.keep_alive = False

            # A response carrying both Content-Length and Transfer-Encoding is
            # a framing conflict that zttp rejects, so drop the Content-Length.
            if self.chunked_encoding and has_content_length:
                headers = [(name, value) for name, value in headers if name.lower() != b"content-length"]
                has_content_length = False
                self.expected_content_length = 0

            # zttp refuses to frame the body unless the response declares
            # Content-Length or Transfer-Encoding, so add chunked encoding
            # ourselves when the application provides neither.
            if not bodyless and not self.chunked_encoding and not has_content_length:
                self.chunked_encoding = True
                headers = headers + [(b"transfer-encoding", b"chunked")]

            if self.access_log:
                self.access_logger.info(
                    '%s - "%s %s HTTP/%s" %d',
                    get_client_addr(self.scope),
                    self.scope["method"],
                    get_path_with_query_string(self.scope),
                    self.scope["http_version"],
                    status,
                )

            # Write response status line and headers
            self.bodyless = bodyless
            self.conn.send_response(status, headers)
            self.transport.write(self.conn.data_to_send())

        elif not self.response_complete:
            # Sending response body
            if message["type"] != "http.response.body":
                raise RuntimeError(f"Expected ASGI message 'http.response.body', but got '{message['type']}'.")

            body = message.get("body", b"")
            more_body = message.get("more_body", False)

            # Write response body
            if self.bodyless:
                self.expected_content_length = 0
            elif self.chunked_encoding:
                if body:
                    self.conn.send_data(body)
                    self.transport.write(self.conn.data_to_send())
            else:
                if len(body) > self.expected_content_length:
                    raise RuntimeError("Response content longer than Content-Length")
                self.expected_content_length -= len(body)
                if body:
                    self.conn.send_data(body)
                    self.transport.write(self.conn.data_to_send())

            # Handle response completion
            if not more_body:
                if self.expected_content_length != 0:
                    raise RuntimeError("Response content shorter than Content-Length")
                self.response_complete = True
                self.message_event.set()
                self.conn.end_message()
                self.transport.write(self.conn.data_to_send())

        else:
            # Response already sent
            raise RuntimeError(f"Unexpected ASGI message '{message['type']}' sent, after response already completed.")

        if self.response_complete:
            if not self.keep_alive:
                self.transport.close()
            self.on_response()

    async def receive(self) -> ASGIReceiveEvent:
        if self.waiting_for_100_continue and not self.transport.is_closing():
            self.conn.send_informational(100)
            self.transport.write(self.conn.data_to_send())
            self.waiting_for_100_continue = False

        if not self.disconnected and not self.response_complete:
            self.flow.resume_reading()
            await self.message_event.wait()
            self.message_event.clear()

        if self.disconnected or self.response_complete:
            return {"type": "http.disconnect"}

        message: HTTPRequestEvent = {"type": "http.request", "body": bytes(self.body), "more_body": self.more_body}
        self.body = bytearray()
        return message

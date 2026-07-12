from __future__ import annotations

import asyncio
import http
import logging
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import unquote

from httpunk.asyncio import AutoServerProtocol, H1ServerProtocol, H2ServerProtocol
from httpunk.h2.server import ServerRequest as _H2ServerRequest

from uvicorn.config import Config
from uvicorn.protocols.utils import (
    get_client_addr,
    get_local_addr,
    get_path_with_query_string,
    get_remote_addr,
    is_ssl,
)
from uvicorn.server import ServerState

if TYPE_CHECKING:
    # `_ASGIBridge` is only ever mixed in *before* one of httpunk's server-protocol classes
    # (all `_ServerProtocol` subclasses), so at type-check time it sees that base's members —
    # `connection_made`/`connection_lost`/`close`/`_transport` (from `_AsyncioStream`) and
    # `graceful_shutdown` (from `_ServerProtocol`). At runtime the base is `object` and the real
    # MRO supplies them.
    from httpunk.asyncio import _ServerProtocol as _BridgeBase

    from uvicorn._types import WWWScope
    from uvicorn.server import Protocols
else:
    _BridgeBase = object


async def _body_gen(queue: asyncio.Queue[tuple[bytes, bool]]) -> Any:
    """Drain (body, more_body) items from `queue` into the byte stream httpunk's respond()
    consumes; used only on the streaming fallback path."""
    while True:
        chunk, more = await queue.get()
        if chunk:
            yield chunk
        if not more:
            return


def _is_ws_upgrade(request: Any) -> bool:
    """A WebSocket upgrade request: `Connection` carries an `upgrade` token AND `Upgrade` is
    `websocket` (mirrors uvicorn's `_get_upgrade`). httpunk lower-cases header names + keeps
    bytes values; a `HeaderMap` may hold multiple `connection` values."""
    connection_tokens: list[bytes] = []
    upgrade: bytes | None = None
    for name, value in request.headers.items():
        if name == "connection":
            connection_tokens += [t.strip().lower() for t in bytes(value).split(b",")]
        elif name == "upgrade":
            upgrade = bytes(value).lower()
    return b"upgrade" in connection_tokens and upgrade == b"websocket"


class _ASGIBridge(_BridgeBase):
    """ASGI bridge shared by the httpunk-backed protocols (mixed in *before* the httpunk
    server-protocol base, so these overrides win in the MRO). Holds no HTTP-protocol logic —
    httpunk does that — only the uvicorn wiring and the ASGI scope/receive/send translation."""

    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if not config.loaded:
            config.load()
        super().__init__()  # the httpunk server-protocol base (no args)

        self.config = config
        self.app = config.loaded_app
        self.loop = _loop or asyncio.get_event_loop()
        self.logger = logging.getLogger("uvicorn.error")
        self.access_logger = logging.getLogger("uvicorn.access")
        self.access_log = self.access_logger.hasHandlers()
        self.root_path = config.root_path
        self.asgi_version = config.asgi_version

        self.server_state = server_state
        self.connections = server_state.connections
        self.tasks = server_state.tasks
        self.app_state = app_state
        self.ws_protocol_class = config.ws_protocol_class

        self.server: tuple[str, int | None] | None = None
        self.client: tuple[str, int] | None = None
        self.scheme: str | None = None

    # ----- asyncio.Protocol lifecycle (httpunk owns the serve loop) -----

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        super().connection_made(transport)  # httpunk: store _transport + spawn _serve
        self.connections.add(cast("Protocols", self))
        transport = cast(asyncio.Transport, transport)
        self.server = get_local_addr(transport)
        self.client = get_remote_addr(transport)
        self.scheme = "https" if is_ssl(transport) else "http"

    def connection_lost(self, exc: Exception | None) -> None:
        self.connections.discard(self)
        super().connection_lost(exc)

    def shutdown(self) -> None:
        # uvicorn's server calls this synchronously on graceful shutdown; bridge to httpunk's
        # async graceful_shutdown (h2 GOAWAY / h1 disable-keep-alive). In-flight requests finish
        # as httpunk keeps driving its own accept loop, which then ends and closes.
        self.loop.create_task(self.graceful_shutdown())

    # ----- ASGI bridge -----

    def _build_scope(self, request: Any) -> dict[str, Any]:
        is_h2 = isinstance(request, _H2ServerRequest)
        raw_target = request.target or "/"
        raw_path, _, query_string = raw_target.partition("?")
        path = self.root_path + unquote(raw_path)
        raw_path_bytes = self.root_path.encode("ascii") + raw_path.encode("latin-1")
        scheme = request.scheme if (is_h2 and request.scheme) else self.scheme
        return {
            "type": "http",
            "asgi": {"version": self.asgi_version, "spec_version": "2.3"},
            "http_version": "2" if is_h2 else "1.1",
            "server": self.server,
            "client": self.client,
            "scheme": scheme,
            "method": request.method,
            "root_path": self.root_path,
            "path": path,
            "raw_path": raw_path_bytes,
            "query_string": query_string.encode("latin-1"),
            # httpunk lower-cases header names to str and keeps values as bytes.
            "headers": [(name.encode("latin-1"), value) for name, value in request.headers.items()],
            "state": self.app_state.copy(),
        }

    async def handle(self, request: Any) -> None:
        if self.ws_protocol_class is not None and getattr(request, "is_upgrade", False) and _is_ws_upgrade(request):
            self._upgrade_websocket(request)
            return
        scope = self._build_scope(request)
        # Response headers must NOT include a second Date — httpunk's h1 codec writes one.
        default_headers = [h for h in self.server_state.default_headers if h[0].lower() != b"date"]

        st: dict[str, Any] = {"started": False, "complete": False, "status": 500, "headers": default_headers}
        # `stream` stays None for the common single-body response (fast path: one direct
        # respond(), no task/queue). It becomes (queue, responder_task) only if the app sends
        # a body with more_body=True — genuine streaming, where respond() must run concurrently.
        stream: tuple[asyncio.Queue[tuple[bytes, bool]], asyncio.Future[Any]] | None = None

        body_iter = request.aiter_bytes()

        async def receive() -> dict[str, Any]:
            if st["complete"]:
                return {"type": "http.disconnect"}
            try:
                chunk = await body_iter.__anext__()
                return {"type": "http.request", "body": chunk, "more_body": True}
            except StopAsyncIteration:
                return {"type": "http.request", "body": b"", "more_body": False}
            except Exception:
                return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            nonlocal stream
            mtype = message["type"]
            if not st["started"]:
                if mtype != "http.response.start":
                    raise RuntimeError(f"Expected ASGI 'http.response.start' but got '{mtype}'.")
                st["started"] = True
                st["status"] = message["status"]
                st["headers"] = default_headers + list(message.get("headers", []))
                return
            if st["complete"]:
                raise RuntimeError(f"Unexpected ASGI message '{mtype}' after response completed.")
            if mtype != "http.response.body":
                raise RuntimeError(f"Expected ASGI 'http.response.body' but got '{mtype}'.")
            body = message.get("body", b"")
            more = message.get("more_body", False)
            if stream is None and not more:
                # Fast path: the whole body arrived in one event — a single respond() call sends
                # head + body, no responder task, no queue.
                st["complete"] = True
                await request.respond(st["status"], headers=st["headers"], body=body)
                self._access(scope, st["status"])
                return
            if stream is None:
                # Switch to streaming: respond() drains a queue that send() feeds; maxsize=1 ties
                # ASGI send() backpressure to httpunk's send rate (h2 DATA is flow-control-gated).
                queue: asyncio.Queue[tuple[bytes, bool]] = asyncio.Queue(maxsize=1)
                responder = asyncio.ensure_future(
                    request.respond(st["status"], headers=st["headers"], body=_body_gen(queue))
                )
                stream = (queue, responder)
            await stream[0].put((body, more))
            if not more:
                st["complete"] = True
                self._access(scope, st["status"])

        try:
            await self.app(scope, receive, send)
        except Exception:
            self.logger.error("Exception in ASGI application\n", exc_info=True)
            if not st["started"]:
                await self._send_500(request)
            else:
                if stream is not None:
                    stream[1].cancel()
                self.close()
            return

        if not st["started"]:
            self.logger.error("ASGI callable returned without starting a response.")
            await self._send_500(request)
        elif stream is not None:
            if not st["complete"]:  # app returned mid-stream: end the body generator
                await stream[0].put((b"", False))
            # Await the send BEFORE returning: httpunk's serial h1 loop won't yield the next
            # request until handle() returns, so the response must fully flush first.
            await stream[1]
        elif not st["complete"]:  # started but sent no body event
            await request.respond(st["status"], headers=st["headers"], body=b"")
            self._access(scope, st["status"])

    def _access(self, scope: dict[str, Any], status: int) -> None:
        if self.access_log:
            www_scope = cast("WWWScope", scope)
            self.access_logger.info(
                '%s - "%s %s HTTP/%s" %d',
                get_client_addr(www_scope),
                scope["method"],
                get_path_with_query_string(www_scope),
                scope["http_version"],
                status,
            )

    async def _send_500(self, request: Any) -> None:
        try:
            await request.respond(
                500,
                headers=[(b"content-type", b"text/plain; charset=utf-8")],
                body=http.HTTPStatus.INTERNAL_SERVER_ERROR.phrase.encode("ascii"),
            )
        except Exception:
            self.close()

    def _upgrade_websocket(self, request: Any) -> None:
        # Mirror uvicorn's h11/httptools handle_websocket_upgrade: detach the raw connection from
        # httpunk (it stops serving, leaving the socket open) and hand it to uvicorn's WebSocket
        # protocol, which re-parses the handshake, computes Sec-WebSocket-Accept, builds the ASGI
        # `websocket` scope, and runs the app. httpunk itself has no WebSocket support.
        leftover = request.detach()  # bytes read past the head (to replay); usually empty (client waits)
        transport = self._transport  # the real asyncio transport (this protocol IS the _AsyncioStream)
        # Reconstruct the raw handshake request; httpunk lower-cases header names (fine), values are bytes.
        parts = [request.method.encode("latin-1"), b" ", request.target.encode("latin-1"), b" HTTP/1.1\r\n"]
        for name, value in request.headers.items():
            parts += [name.encode("latin-1"), b": ", bytes(value), b"\r\n"]
        parts.append(b"\r\n")
        protocol = self.ws_protocol_class(  # type: ignore[call-arg, misc]
            config=self.config, server_state=self.server_state, app_state=self.app_state
        )
        self.connections.discard(self)  # the WS protocol re-registers itself in its connection_made
        protocol.connection_made(transport)
        protocol.data_received(b"".join(parts) + leftover)
        transport.set_protocol(protocol)


class HTTPunkAutoProtocol(_ASGIBridge, AutoServerProtocol):
    """Serve each connection as HTTP/1 or HTTP/2, sniffed from the client's opening bytes
    (so h2c prior-knowledge works). Registered as ``--http httpunk``."""


class HTTPunkH1Protocol(_ASGIBridge, H1ServerProtocol):
    """Serve every connection as HTTP/1."""


class HTTPunkH2Protocol(_ASGIBridge, H2ServerProtocol):
    """Serve every connection as HTTP/2."""

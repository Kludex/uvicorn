from __future__ import annotations

import asyncio
import contextvars
import http
import logging
import sys
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import unquote

from httpunk.asyncio import AutoServerProtocol, H1ServerProtocol, H2ServerProtocol
from httpunk.h2.server import ServerRequest as _H2ServerRequest

from uvicorn.config import Config
from uvicorn.protocols.http.flow_control import service_unavailable
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


# Connection-specific header fields are forbidden in HTTP/2 (RFC 9113 §8.2.2); httpunk's h2 codec
# rejects a response carrying one (RST_STREAM PROTOCOL_ERROR). uvicorn's `service_unavailable`
# emits `connection: close` and apps may set these too, so they are stripped from h2 responses.
_H2_ILLEGAL_HEADERS = frozenset((b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade"))


class _StreamAborted(Exception):
    """Raised into respond()'s body iteration to abort a streaming response mid-body (app
    crash / teardown): httpunk's send path then closes the transport, so the peer sees a
    truncated (chunked-incomplete / RST) response rather than a falsely-complete one."""


class _BodyHandoff:
    """Single-slot handoff of response-body chunks from ASGI ``send()`` (the producer) to
    the body iterable ``respond()`` consumes (streaming responses only). Cheaper than the
    queue + responder-task it replaces: in the common producer-ahead flow neither side
    suspends — a non-empty chunk parks the producer only while the previous one is still
    unconsumed (which is what ties ASGI send() backpressure to httpunk's send rate; h2
    DATA is flow-control-gated), and the end-of-body marker never parks. ``abort()``
    mirrors the h11/httptools disconnect behavior: the consumer raises (truncating the
    wire response), while a parked producer is released and further puts no-op so the app
    can run to completion."""

    __slots__ = ("_loop", "_chunk", "_ended", "_aborted", "_get_waiter", "_put_waiter")

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._chunk: bytes | None = None  # pending non-empty chunk (the slot)
        self._ended = False  # no more chunks will arrive (final body event seen)
        self._aborted = False
        self._get_waiter: asyncio.Future[None] | None = None  # consumer parked in __anext__
        self._put_waiter: asyncio.Future[None] | None = None  # producer parked in put

    def __aiter__(self) -> _BodyHandoff:
        return self

    async def __anext__(self) -> bytes:
        while True:
            if self._aborted:
                raise _StreamAborted
            chunk = self._chunk
            if chunk is not None:
                self._chunk = None
                if self._put_waiter is not None and not self._put_waiter.done():
                    self._put_waiter.set_result(None)
                return chunk
            if self._ended:
                raise StopAsyncIteration
            self._get_waiter = self._loop.create_future()
            try:
                await self._get_waiter
            finally:
                self._get_waiter = None

    async def put(self, chunk: bytes, more: bool) -> None:
        if self._aborted:
            return
        if chunk:
            if self._chunk is not None:  # slot occupied — backpressure the producer
                self._put_waiter = self._loop.create_future()
                try:
                    await self._put_waiter
                finally:
                    self._put_waiter = None
                if self._aborted:
                    return
            self._chunk = chunk
        elif more:
            return  # empty non-final chunk: nothing to send, nothing to signal
        if not more:
            self._ended = True
        if self._get_waiter is not None and not self._get_waiter.done():
            self._get_waiter.set_result(None)

    def abort(self) -> None:
        self._aborted = True
        for waiter in (self._get_waiter, self._put_waiter):
            if waiter is not None and not waiter.done():
                waiter.set_result(None)


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
        self.limit_concurrency = config.limit_concurrency

        self.server: tuple[str, int | None] | None = None
        self.client: tuple[str, int] | None = None
        self.scheme: str | None = None

        # Cache of server_state.default_headers with the Date header stripped, keyed on
        # the source list's identity (see _response_default_headers).
        self._default_headers_src: list[tuple[bytes, bytes]] | None = None
        self._default_headers: list[tuple[bytes, bytes]] = []

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

    def _response_default_headers(self) -> list[tuple[bytes, bytes]]:
        # Response headers must NOT include a second Date — httpunk's codecs write one.
        # The server rebuilds `default_headers` as a fresh list once per second (the date
        # tick), so the date-stripped copy is cached keyed on the source list's identity
        # rather than recomputed per request.
        src = self.server_state.default_headers
        if src is not self._default_headers_src:
            self._default_headers_src = src
            self._default_headers = [h for h in src if h[0].lower() != b"date"]
        return self._default_headers

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
            self._upgrade_websocket(request)  # pragma: no cover
            return  # pragma: no cover
        scope = self._build_scope(request)
        is_h2 = scope["http_version"] == "2"
        default_headers = self._response_default_headers()

        # Enforce the concurrency limit up front, as the h11/httptools protocols do: over the
        # limit, serve uvicorn's 503 instead of the app. `tasks` (one per in-flight request, see
        # below) is what makes this meaningful under HTTP/2, where a single connection multiplexes
        # many concurrent requests and `connections` alone would badly undercount them.
        app = self.app
        if self.limit_concurrency is not None and (
            len(self.connections) >= self.limit_concurrency or len(self.tasks) >= self.limit_concurrency
        ):
            app = service_unavailable
            self.logger.warning("Exceeded concurrency limit.")

        st: dict[str, Any] = {
            "started": False,
            "complete": False,
            "aborted": False,
            "status": 500,
            "headers": default_headers,
        }
        # `stream` stays None for the common single-body response (fast path: one direct
        # respond() inside the app task, nothing extra). It becomes a `_BodyHandoff` only if
        # the app sends a body with more_body=True — genuine streaming, where respond() must
        # run concurrently with the app. It then runs HERE, in handle() (which would otherwise
        # just idle awaiting the app task), fed through the handoff — no responder task, no
        # queue. `streaming` is how handle() learns which of the two happened: resolved True
        # at the first streaming chunk, False once the app task finishes without streaming.
        stream: _BodyHandoff | None = None
        streaming: asyncio.Future[bool] = self.loop.create_future()
        # First streaming chunk, buffered for one loop tick before committing to a streamed
        # response (see `commit` below). Distinct states: pending is None + stream is None =
        # no streaming body event yet; pending set + stream None = deferred, nothing on the
        # wire; stream set = committed, respond() is (about to be) running in handle().
        pending: bytes | None = None

        body_iter = request.aiter_bytes()

        def commit() -> None:
            # Commit to a genuinely streamed response: wake handle() to run respond() over
            # the handoff, pre-loaded with the deferred first chunk. Runs one loop tick after
            # that chunk arrived (via call_soon) — i.e. only once the app has suspended — or
            # directly from send() when a second chunk shows up within the tick.
            nonlocal stream, pending
            if stream is not None or st["complete"] or st["aborted"]:
                return
            stream = _BodyHandoff(self.loop)
            if pending:
                stream._chunk = pending  # slot is empty by construction — no park, no wake
            pending = None
            streaming.set_result(True)

        async def receive() -> dict[str, Any]:
            if st["complete"]:
                return {"type": "http.disconnect"}  # pragma: no cover
            try:
                chunk = await body_iter.__anext__()
                return {"type": "http.request", "body": chunk, "more_body": True}
            except StopAsyncIteration:
                return {"type": "http.request", "body": b"", "more_body": False}
            except Exception:  # pragma: no cover
                return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            nonlocal stream
            mtype = message["type"]
            if not st["started"]:
                if mtype != "http.response.start":
                    raise RuntimeError(f"Expected ASGI 'http.response.start' but got '{mtype}'.")  # pragma: no cover
                st["started"] = True
                st["status"] = message["status"]
                headers = default_headers + list(message.get("headers", []))
                if is_h2:
                    headers = [h for h in headers if h[0].lower() not in _H2_ILLEGAL_HEADERS]
                st["headers"] = headers
                return
            if st["complete"]:
                raise RuntimeError(f"Unexpected ASGI message '{mtype}' after response completed.")  # pragma: no cover
            if mtype != "http.response.body":
                raise RuntimeError(f"Expected ASGI 'http.response.body' but got '{mtype}'.")  # pragma: no cover
            nonlocal pending
            body = message.get("body", b"")
            more = message.get("more_body", False)
            if stream is None:
                if pending is None:
                    if not more:
                        # Fast path: the whole body arrived in one event — a single respond()
                        # call sends head + body.
                        st["complete"] = True
                        await request.respond(st["status"], headers=st["headers"], body=body)
                        self._access(scope, st["status"])
                        return
                    # more_body=True: don't commit to a streamed response yet — buffer this one
                    # chunk and give the app one loop tick. Apps that emit their whole body
                    # without suspending (a receive() served from the buffer, back-to-back
                    # sends) collapse into the single-respond fast path above; a real streamer
                    # suspends, the tick elapses, and `commit` flushes this chunk immediately.
                    pending = body
                    self.loop.call_soon(commit)
                    return
                if not more:
                    # The rest of the body arrived within the deferral tick: de-stream into
                    # one respond() — nothing is on the wire yet.
                    st["complete"] = True
                    body = pending + body if pending and body else pending or body
                    pending = None
                    await request.respond(st["status"], headers=st["headers"], body=body)
                    self._access(scope, st["status"])
                    return
                commit()  # a second chunk within the tick: stop buffering, stream for real
            await stream.put(body, more)  # type: ignore[union-attr]
            if not more:
                st["complete"] = True
                self._access(scope, st["status"])

        async def run_asgi() -> None:
            # `except BaseException` (not `Exception`) so that if this task is cancelled — e.g. the
            # server force-cancels it after `timeout_graceful_shutdown` — the cancellation is still
            # logged and the connection cleaned up, exactly as h11's `run_asgi` does.
            try:
                try:
                    await app(scope, receive, send)
                except BaseException:
                    self.logger.error("Exception in ASGI application\n", exc_info=True)
                    st["aborted"] = True  # a still-pending deferred commit must not fire now
                    if not st["started"]:
                        await self._send_500(request, default_headers)
                    else:  # pragma: no cover
                        if stream is not None:
                            stream.abort()  # respond() in handle() raises -> transport closed
                        self.close()
                    return

                if not st["started"]:
                    self.logger.error("ASGI callable returned without starting a response.")
                    await self._send_500(request, default_headers)
                elif stream is not None:
                    if not st["complete"]:  # app returned mid-stream: end the body iterator
                        await stream.put(b"", False)  # pragma: no cover
                elif not st["complete"]:
                    # Started but never finished the body: either no body event at all, or the
                    # app returned inside the deferral tick — its buffered chunk (if any) is
                    # the whole body, and nothing is on the wire yet.
                    st["complete"] = True
                    await request.respond(st["status"], headers=st["headers"], body=pending or b"")
                    self._access(scope, st["status"])
            finally:
                if not streaming.done():  # tell handle() no streaming response will come
                    streaming.set_result(False)

        # Run the request as a task registered in `server_state.tasks`, so the server can (a) count
        # it toward the concurrency limit and (b) cancel it if `timeout_graceful_shutdown` is
        # exceeded — mirroring the h11/httptools protocols, which register their request cycle the
        # same way. Under HTTP/2 each concurrent stream runs its own `handle()`, so this yields one
        # tracked task per in-flight request rather than one per connection.
        if self.config.reset_contextvars:
            # Opt-in: run the app in a fresh context so ContextVars from the serve task don't leak
            # into it (matches h11/httptools; see https://github.com/encode/uvicorn/issues/2167).
            if sys.version_info >= (3, 11):  # pragma: py-lt-311
                task = self.loop.create_task(run_asgi(), context=contextvars.Context())
            else:  # pragma: py-gte-311
                task = contextvars.Context().run(self.loop.create_task, run_asgi())
        else:
            task = self.loop.create_task(run_asgi())
        self.tasks.add(task)

        def _on_task_done(t: asyncio.Future[None]) -> None:
            self.tasks.discard(t)
            if not streaming.done():  # pragma: no cover
                # run_asgi's finally normally resolves this; a task cancelled before its
                # first step never entered that try, and would park handle() forever.
                streaming.set_result(False)

        task.add_done_callback(_on_task_done)
        try:
            if await streaming:
                try:
                    # The streaming respond() runs here, in handle()'s otherwise-idle await,
                    # consuming chunks straight from ASGI send() via the handoff. It returns
                    # once the final chunk is flushed — before the next h1 request is read.
                    await request.respond(st["status"], headers=st["headers"], body=stream)
                except Exception:  # pragma: no cover
                    # Mid-stream failure: client gone, or the app crashed and abort()ed the
                    # body. httpunk already closed the transport; release a parked producer
                    # (further sends no-op, as h11/httptools do on disconnect) and let the
                    # app task run to completion below.
                    stream.abort()  # type: ignore[union-attr]
                    self.close()
            await task
        except BaseException:  # pragma: no cover
            # handle() dying for any other reason (e.g. cancelled on h2 connection failure /
            # force shutdown) must release a producer parked in put(), or the app task would
            # never finish.
            if stream is not None:
                stream.abort()
            raise
        finally:
            self.server_state.total_requests += 1

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

    async def _send_500(self, request: Any, default_headers: list[tuple[bytes, bytes]]) -> None:
        try:
            await request.respond(
                500,
                headers=default_headers + [(b"content-type", b"text/plain; charset=utf-8")],
                body=http.HTTPStatus.INTERNAL_SERVER_ERROR.phrase.encode("ascii"),
            )
        except Exception:  # pragma: no cover
            self.close()

    def _upgrade_websocket(self, request: Any) -> None:  # pragma: no cover
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

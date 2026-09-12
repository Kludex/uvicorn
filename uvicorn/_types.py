"""
Copyright (c) Django Software Foundation and individual contributors.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    3. Neither the name of Django nor the names of its contributors may be used
       to endorse or promote products derived from this software without
       specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from __future__ import annotations

import types
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any, Literal, Protocol, TypedDict

# WSGI
Environ = MutableMapping[str, Any]
ExcInfo = tuple[type[BaseException], BaseException, types.TracebackType | None]
StartResponse = Callable[[str, Iterable[tuple[str, str]], ExcInfo | None], None]
WSGIApp = Callable[[Environ, StartResponse], Iterable[bytes] | BaseException]


# ASGI
class ASGIVersions(TypedDict):
    spec_version: str
    version: Literal["2.0"] | Literal["3.0"]


class _OptionalState(TypedDict, total=False):
    state: dict[str, Any]


class _OptionalScope(_OptionalState, total=False):
    extensions: dict[str, dict[object, object]]


class HTTPScope(_OptionalScope):
    type: Literal["http"]
    asgi: ASGIVersions
    http_version: str
    method: str
    scheme: str
    path: str
    raw_path: bytes
    query_string: bytes
    root_path: str
    headers: Iterable[tuple[bytes, bytes]]
    client: tuple[str, int] | None
    server: tuple[str, int | None] | None


class WebSocketScope(_OptionalScope):
    type: Literal["websocket"]
    asgi: ASGIVersions
    http_version: str
    scheme: str
    path: str
    raw_path: bytes
    query_string: bytes
    root_path: str
    headers: Iterable[tuple[bytes, bytes]]
    client: tuple[str, int] | None
    server: tuple[str, int | None] | None
    subprotocols: Iterable[str]


class LifespanScope(_OptionalState):
    type: Literal["lifespan"]
    asgi: ASGIVersions


WWWScope = HTTPScope | WebSocketScope
Scope = HTTPScope | WebSocketScope | LifespanScope


class HTTPRequestEvent(TypedDict):
    type: Literal["http.request"]
    body: bytes
    more_body: bool


class HTTPResponseDebugEvent(TypedDict):
    type: Literal["http.response.debug"]
    info: dict[str, object]


class _HTTPResponseStartEventOptional(TypedDict, total=False):
    headers: Iterable[tuple[bytes, bytes]]
    trailers: bool


class HTTPResponseStartEvent(_HTTPResponseStartEventOptional):
    type: Literal["http.response.start"]
    status: int


class _OptionalMoreBody(TypedDict, total=False):
    more_body: bool


class HTTPResponseBodyEvent(_OptionalMoreBody):
    type: Literal["http.response.body"]
    body: bytes


class HTTPResponseTrailersEvent(TypedDict):
    type: Literal["http.response.trailers"]
    headers: Iterable[tuple[bytes, bytes]]
    more_trailers: bool


class HTTPServerPushEvent(TypedDict):
    type: Literal["http.response.push"]
    path: str
    headers: Iterable[tuple[bytes, bytes]]


class HTTPDisconnectEvent(TypedDict):
    type: Literal["http.disconnect"]


class WebSocketConnectEvent(TypedDict):
    type: Literal["websocket.connect"]


class _WebSocketAcceptEventOptional(TypedDict, total=False):
    subprotocol: str | None
    headers: Iterable[tuple[bytes, bytes]]


class WebSocketAcceptEvent(_WebSocketAcceptEventOptional):
    type: Literal["websocket.accept"]


class _OptionalText(TypedDict, total=False):
    text: None


class _WebSocketReceiveEventBytes(_OptionalText):
    type: Literal["websocket.receive"]
    bytes: bytes


class _OptionalBytes(TypedDict, total=False):
    bytes: None


class _WebSocketReceiveEventText(_OptionalBytes):
    type: Literal["websocket.receive"]
    text: str


WebSocketReceiveEvent = _WebSocketReceiveEventBytes | _WebSocketReceiveEventText


class _WebSocketSendEventBytes(_OptionalText):
    type: Literal["websocket.send"]
    bytes: bytes


class _WebSocketSendEventText(_OptionalBytes):
    type: Literal["websocket.send"]
    text: str


WebSocketSendEvent = _WebSocketSendEventBytes | _WebSocketSendEventText


class WebSocketResponseStartEvent(TypedDict):
    type: Literal["websocket.http.response.start"]
    status: int
    headers: Iterable[tuple[bytes, bytes]]


class WebSocketResponseBodyEvent(_OptionalMoreBody):
    type: Literal["websocket.http.response.body"]
    body: bytes


class _OptionalReason(TypedDict, total=False):
    reason: str | None


class WebSocketDisconnectEvent(_OptionalReason):
    type: Literal["websocket.disconnect"]
    code: int


class _WebSocketCloseEventOptional(_OptionalReason, total=False):
    code: int


class WebSocketCloseEvent(_WebSocketCloseEventOptional):
    type: Literal["websocket.close"]


class LifespanStartupEvent(TypedDict):
    type: Literal["lifespan.startup"]


class LifespanShutdownEvent(TypedDict):
    type: Literal["lifespan.shutdown"]


class LifespanStartupCompleteEvent(TypedDict):
    type: Literal["lifespan.startup.complete"]


class LifespanStartupFailedEvent(TypedDict):
    type: Literal["lifespan.startup.failed"]
    message: str


class LifespanShutdownCompleteEvent(TypedDict):
    type: Literal["lifespan.shutdown.complete"]


class LifespanShutdownFailedEvent(TypedDict):
    type: Literal["lifespan.shutdown.failed"]
    message: str


WebSocketEvent = WebSocketReceiveEvent | WebSocketDisconnectEvent | WebSocketConnectEvent


ASGIReceiveEvent = (
    HTTPRequestEvent
    | HTTPDisconnectEvent
    | WebSocketConnectEvent
    | WebSocketReceiveEvent
    | WebSocketDisconnectEvent
    | LifespanStartupEvent
    | LifespanShutdownEvent
)


ASGISendEvent = (
    HTTPResponseStartEvent
    | HTTPResponseBodyEvent
    | HTTPResponseTrailersEvent
    | HTTPServerPushEvent
    | HTTPDisconnectEvent
    | WebSocketAcceptEvent
    | WebSocketSendEvent
    | WebSocketResponseStartEvent
    | WebSocketResponseBodyEvent
    | WebSocketCloseEvent
    | LifespanStartupCompleteEvent
    | LifespanStartupFailedEvent
    | LifespanShutdownCompleteEvent
    | LifespanShutdownFailedEvent
)


ASGIReceiveCallable = Callable[[], Awaitable[ASGIReceiveEvent]]
ASGISendCallable = Callable[[ASGISendEvent], Awaitable[None]]


class ASGI2Protocol(Protocol):
    def __init__(self, scope: Scope) -> None: ...  # pragma: no cover

    async def __call__(self, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None: ...  # pragma: no cover


ASGI2Application = type[ASGI2Protocol]
ASGI3Application = Callable[[Scope, ASGIReceiveCallable, ASGISendCallable], Awaitable[None]]
ASGIApplication = ASGI2Application | ASGI3Application

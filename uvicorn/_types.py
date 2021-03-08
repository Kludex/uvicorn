import sys
from typing import Dict, Iterable, Optional, Tuple, Union

if sys.version_info < (3, 8):
    from typing_extensions import Literal, TypedDict
else:
    from typing import Literal, TypedDict


class ASGISpecInfo(TypedDict):
    version: Literal["2.0", "3.0"]
    spec_version: Optional[Literal["2.0", "2.1"]]


class LifespanScope(TypedDict):
    type: Literal["lifespan"]
    asgi: ASGISpecInfo


class LifespanReceiveMessage(TypedDict):
    type: Literal["lifespan.startup", "lifespan.shutdown"]


class LifespanSendMessage(TypedDict):
    type: Literal[
        "lifespan.startup.complete",
        "lifespan.startup.failed",
        "lifespan.shutdown.complete",
        "lifespan.shutdown.failed",
    ]
    message: Optional[str]


class HTTPScope(TypedDict):
    type: Literal["http"]
    asgi: ASGISpecInfo
    http_version: str
    method: str
    scheme: str
    path: str
    raw_path: bytes
    query_string: bytes
    root_path: str
    headers: Iterable[Tuple[bytes, bytes]]
    client: Optional[Tuple[str, int]]
    server: Optional[Tuple[str, Optional[int]]]
    extensions: Dict[str, Dict[object, object]]


class WebsocketScope(TypedDict):
    type: Literal["websocket"]
    asgi: ASGISpecInfo
    http_version: str
    scheme: str
    path: str
    raw_path: bytes
    query_string: bytes
    root_path: str
    headers: Iterable[Tuple[bytes, bytes]]
    client: Optional[Tuple[str, int]]
    server: Optional[Tuple[str, Optional[int]]]
    subprotocols: Iterable[str]
    extensions: Dict[str, Dict[object, object]]


WWWScope = Union[HTTPScope, WebsocketScope]
Scope = Union[HTTPScope, WebsocketScope, LifespanScope]

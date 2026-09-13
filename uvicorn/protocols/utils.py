from __future__ import annotations

import asyncio
import socket
import ssl
import urllib.parse
from typing import Protocol, runtime_checkable

from uvicorn._types import TLSExtension, WWWScope


@runtime_checkable
class _SSLObjectWithVerifiedChain(Protocol):
    @property
    def context(self) -> ssl.SSLContext: ...

    def get_verified_chain(self) -> list[bytes]: ...


class ClientDisconnected(OSError): ...


def get_remote_addr(transport: asyncio.Transport) -> tuple[str, int] | None:
    socket_info: socket.socket | None = transport.get_extra_info("socket")
    if socket_info is not None:
        try:
            info = socket_info.getpeername()
            return (str(info[0]), int(info[1])) if isinstance(info, tuple) else None
        except OSError:  # pragma: no cover
            # This case appears to inconsistently occur with uvloop
            # bound to a unix domain socket.
            return None

    info = transport.get_extra_info("peername")
    if info is not None and isinstance(info, list | tuple) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    return None


def get_local_addr(transport: asyncio.Transport) -> tuple[str, int | None] | None:
    socket_info: socket.socket | None = transport.get_extra_info("socket")
    if socket_info is not None:
        info = socket_info.getsockname()
        if isinstance(info, tuple):
            return (str(info[0]), int(info[1]))
        if isinstance(info, str):
            return (info, None)
        return None
    info = transport.get_extra_info("sockname")
    if info is not None and isinstance(info, list | tuple) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    if isinstance(info, str):
        return (info, None)
    return None


def is_ssl(transport: asyncio.Transport) -> bool:
    return bool(transport.get_extra_info("sslcontext"))


def get_tls_extension(transport: asyncio.Transport) -> TLSExtension:
    ssl_object: object = transport.get_extra_info("ssl_object")

    client_cert_chain: tuple[str, ...] = ()
    if isinstance(ssl_object, _SSLObjectWithVerifiedChain) and ssl_object.context.verify_mode != ssl.CERT_NONE:
        client_cert_chain = tuple(ssl.DER_cert_to_PEM_cert(cert) for cert in ssl_object.get_verified_chain())
    return {"client_cert_chain": client_cert_chain}


def get_client_addr(scope: WWWScope) -> str:
    client = scope.get("client")
    if not client:
        return ""
    return "%s:%d" % client


def get_path_with_query_string(scope: WWWScope) -> str:
    path_with_query_string = urllib.parse.quote(scope["path"])
    if scope["query_string"]:
        path_with_query_string = "{}?{}".format(path_with_query_string, scope["query_string"].decode("ascii"))
    return path_with_query_string

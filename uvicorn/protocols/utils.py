from __future__ import annotations

import asyncio
import socket
import ssl
import urllib.parse

from uvicorn._types import TLSExtension, WWWScope


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
    ssl_object: ssl.SSLObject | ssl.SSLSocket | None = transport.get_extra_info("ssl_object")

    client_cert = None
    if ssl_object is not None and ssl_object.context.verify_mode != ssl.CERT_NONE:
        client_cert = ssl_object.getpeercert(binary_form=True)
    return {"client_cert": client_cert}


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

from __future__ import annotations

import asyncio
import socket
import ssl
import sys
import urllib.parse
from collections.abc import Iterable
from typing import Any

from uvicorn._types import WWWScope


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


def _get_client_cert_dict(ssl_object: ssl.SSLObject) -> dict[str, Any] | None:
    """Return the peer (client) certificate as a dict, `None` if the peer sent none.

    See `ssl.SSLSocket.getpeercert` for the structure of the returned dict.
    """
    try:
        return ssl_object.getpeercert()
    except ValueError:  # pragma: no cover
        # The handshake has not been completed yet.
        return None


# `ssl.SSLObject.version()` reports the negotiated version as a string, while the ASGI
# TLS extension asks for the integer used on the wire.
_TLS_VERSIONS: dict[str, int] = {
    "SSLv3": 0x0300,
    "TLSv1": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}

# Attribute names as reported by `getpeercert()`, mapped to the short forms registered in
# RFC 4514 section 3. Attributes outside this table keep their long name.
_RFC4514_ATTRIBUTE_NAMES: dict[str, str] = {
    "commonName": "CN",
    "localityName": "L",
    "stateOrProvinceName": "ST",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "streetAddress": "STREET",
    "domainComponent": "DC",
    "userId": "UID",
}


def _escape_rfc4514_value(value: str) -> str:
    """Escape an attribute value as described in RFC 4514 section 2.4."""
    last = len(value) - 1
    escaped: list[str] = []
    for index, char in enumerate(value):
        if char in ',+"\\<>;':
            escaped.append("\\" + char)
        elif char == "\x00":
            escaped.append("\\00")
        elif char == " " and index in (0, last):
            escaped.append("\\ ")
        elif char == "#" and index == 0:
            escaped.append("\\#")
        else:
            escaped.append(char)
    return "".join(escaped)


def _rfc4514_distinguished_name(rdn_sequence: Iterable[Iterable[tuple[str, str]]]) -> str:
    """Render the `subject`/`issuer` structure of `getpeercert()` as an RFC 4514 string."""
    # `getpeercert()` lists the relative distinguished names in the order they appear in
    # the certificate, while RFC 4514 section 2.1 requires them in reverse order.
    return ",".join(
        "+".join(f"{_RFC4514_ATTRIBUTE_NAMES.get(name, name)}={_escape_rfc4514_value(value)}" for name, value in rdn)
        for rdn in reversed(list(rdn_sequence))
    )


def _get_client_cert_chain(ssl_object: ssl.SSLObject) -> list[str]:
    if sys.version_info >= (3, 13):  # pragma: py-lt-313
        # Note that the verified chain also contains the issuing CA certificate(s), which
        # the client itself did not necessarily send.
        return [ssl.DER_cert_to_PEM_cert(der) for der in ssl_object.get_verified_chain()]
    else:  # pragma: py-gte-313
        # Before Python 3.13 there is no way to reach anything but the leaf certificate.
        der = ssl_object.getpeercert(binary_form=True)
        return [] if der is None else [ssl.DER_cert_to_PEM_cert(der)]


def _get_cipher_suite(ssl_object: ssl.SSLObject) -> int | None:
    cipher = ssl_object.cipher()
    if cipher is None:  # pragma: no cover
        return None
    for entry in ssl_object.context.get_ciphers():
        if entry["name"] == cipher[0]:
            # OpenSSL reports the suite as 0x0300XXXX; the wire format is the low 16 bits.
            return int(entry["id"]) & 0xFFFF
    return None  # pragma: no cover


class TLSExtension:
    """The `tls` entry of the ASGI scope `extensions`, for one TLS connection.

    `from_transport` returns `None` for unencrypted connections, for which the ASGI
    TLS extension (version 0.2) forbids providing the entry at all. Constructing an
    instance is cheap; the TLS data is only gathered once `scope_entry` is first
    called, so connections that never carry a request do no work.

    Two of the mandatory keys are always `None`, because CPython's `ssl` module cannot
    provide them: `server_cert` (there is no API to read back the server's own
    certificate) and `client_cert_error` (a certificate that fails verification aborts
    the handshake, so such a connection never reaches the application).

    In addition to the keys defined by the extension, the entry carries the
    Uvicorn-specific `client_cert_dict` key: the client certificate in the parsed form
    of `ssl.SSLSocket.getpeercert`, or `None` if the client did not present one.
    """

    __slots__ = ("_ssl_object", "_entry")

    def __init__(self, ssl_object: ssl.SSLObject) -> None:
        self._ssl_object = ssl_object
        self._entry: dict[str, Any] | None = None

    @classmethod
    def from_transport(cls, transport: asyncio.Transport) -> TLSExtension | None:
        ssl_object: ssl.SSLObject | None = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        return cls(ssl_object)

    def scope_entry(self) -> dict[object, object]:
        """Return the `tls` dict for one request scope.

        The underlying data is gathered at most once per connection, but every call
        returns fresh containers, so an application mutating its scope cannot affect
        later requests on the same connection.
        """
        if self._entry is None:
            self._entry = self._build()
        # Typed to match the `extensions` field of the ASGI connection scope.
        entry: dict[object, object] = {}
        entry.update(self._entry)
        entry["client_cert_chain"] = list(self._entry["client_cert_chain"])
        if self._entry["client_cert_dict"] is not None:
            entry["client_cert_dict"] = dict(self._entry["client_cert_dict"])
        return entry

    def _build(self) -> dict[str, Any]:
        ssl_object = self._ssl_object
        client_cert_dict = _get_client_cert_dict(ssl_object)
        subject = client_cert_dict.get("subject") if client_cert_dict else None
        return {
            "server_cert": None,
            "client_cert_chain": _get_client_cert_chain(ssl_object),
            "client_cert_name": _rfc4514_distinguished_name(subject) if subject else None,
            "client_cert_error": None,
            "tls_version": _TLS_VERSIONS.get(ssl_object.version() or ""),
            "cipher_suite": _get_cipher_suite(ssl_object),
            # Uvicorn addition, not part of the ASGI TLS extension.
            "client_cert_dict": client_cert_dict,
        }


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

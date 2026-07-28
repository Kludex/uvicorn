"""Tests for the ASGI TLS extension that Uvicorn puts into `scope["extensions"]["tls"]`."""

from __future__ import annotations

import copy
import ssl
import sys
from typing import Any

import httpx
import pytest
from websockets.asyncio.client import connect

from tests.conftest import CLIENT_CERT_COMMON_NAME
from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config

pytestmark = pytest.mark.anyio

# Sentinel telling apart "the key was missing" from "the key was set to None".
MISSING = object()

# Keys mandated by version 0.2 of the ASGI TLS extension, plus Uvicorn's own addition.
TLS_EXTENSION_KEYS = {
    "server_cert",
    "client_cert_chain",
    "client_cert_name",
    "client_cert_error",
    "tls_version",
    "cipher_suite",
    "client_cert_dict",
}


class CaptureScope:
    """An ASGI app that records `scope["extensions"]` of every connection."""

    def __init__(self) -> None:
        self.captured: list[Any] = []

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "lifespan":
            raise NotImplementedError  # let Uvicorn fall back to "lifespan unsupported"
        tls = scope.get("extensions", {}).get("tls", MISSING)
        if tls is MISSING:
            self.captured.append(MISSING)
        else:
            assert isinstance(tls, dict)
            self.captured.append(copy.deepcopy(tls))
            # Trash the scope's entry: mutations by one request must not leak into
            # later requests on the same connection.
            tls["client_cert_chain"].append("bogus")
            if tls["client_cert_dict"] is not None:
                tls["client_cert_dict"]["forged"] = True
            tls.clear()
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        else:
            assert scope["type"] == "websocket"
            await receive()  # websocket.connect
            await send({"type": "websocket.accept"})
            await send({"type": "websocket.close", "code": 1000})

    @property
    def tls(self) -> Any:
        assert len(self.captured) == 1, f"expected exactly one connection, got {len(self.captured)}"
        return self.captured[0]


def assert_common_tls_keys(tls: Any) -> None:
    """Assert the parts of the extension that do not depend on the client certificate."""
    assert isinstance(tls, dict)
    assert set(tls) == TLS_EXTENSION_KEYS
    # CPython offers no way to read back the server's own certificate.
    assert tls["server_cert"] is None
    # A rejected certificate aborts the handshake, so the app never sees an error.
    assert tls["client_cert_error"] is None
    # 0x0303 is TLS 1.2, 0x0304 is TLS 1.3.
    assert tls["tls_version"] in (0x0303, 0x0304)
    assert isinstance(tls["cipher_suite"], int)
    assert 0 < tls["cipher_suite"] <= 0xFFFF


def assert_is_test_client_cert(tls: Any) -> None:
    """Assert the extension describes the certificate from the `tls_client_certificate` fixture."""
    assert_common_tls_keys(tls)

    chain = tls["client_cert_chain"]
    # Python 3.13 added `SSLObject.get_verified_chain()`; before that only the leaf
    # certificate is reachable, so the chain has no CA certificate appended.
    assert len(chain) == (2 if sys.version_info >= (3, 13) else 1)
    for pem in chain:
        assert isinstance(pem, str)
        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert pem.rstrip().endswith("-----END CERTIFICATE-----")

    # RFC 4514 orders the RDNs most-specific first, the reverse of the certificate order.
    assert tls["client_cert_name"].startswith(f"CN={CLIENT_CERT_COMMON_NAME},OU=Testing cert ")
    assert tls["client_cert_name"].endswith(",O=Uvicorn Test Suite")

    # Uvicorn addition: the same certificate in `getpeercert()` form.
    cert = tls["client_cert_dict"]
    assert isinstance(cert, dict)
    subject = {name: value for rdn in cert["subject"] for name, value in rdn}
    issuer = {name: value for rdn in cert["issuer"] for name, value in rdn}
    assert subject["commonName"] == CLIENT_CERT_COMMON_NAME
    assert subject["organizationName"] == "Uvicorn Test Suite"
    assert issuer["organizationalUnitName"].startswith("Testing CA")
    assert ("email", "client@example.com") in cert["subjectAltName"]
    assert cert["notAfter"]
    assert cert["notBefore"]
    assert cert["serialNumber"]


def assert_no_client_cert(tls: Any) -> None:
    """Assert the extension is present, but reports no client certificate."""
    assert_common_tls_keys(tls)
    assert tls["client_cert_chain"] == []
    assert tls["client_cert_name"] is None
    assert tls["client_cert_dict"] is None


def client_context(tls_ca_ssl_context: ssl.SSLContext, client_cert_path: str | None = None) -> ssl.SSLContext:
    """The CA-trusting client context, optionally presenting a client certificate."""
    if client_cert_path is not None:
        tls_ca_ssl_context.load_cert_chain(client_cert_path)
    return tls_ca_ssl_context


def tls_config(
    app: CaptureScope,
    unused_tcp_port: int,
    certfile: str,
    keyfile: str,
    *,
    cert_reqs: int = ssl.CERT_NONE,
    ca_certs: str | None = None,
    limit_max_requests: int = 1,
    **kwargs: Any,
) -> Config:
    return Config(
        app=app,
        loop="asyncio",
        limit_max_requests=limit_max_requests,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        ssl_cert_reqs=cert_reqs,
        ssl_ca_certs=ca_certs,
        port=unused_tcp_port,
        **kwargs,
    )


# --------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------


async def test_http_without_tls_omits_the_extension(http_protocol_cls, unused_tcp_port: int):
    """Version 0.2 of the extension forbids providing it for non-TLS connections."""
    app = CaptureScope()
    config = Config(app=app, loop="asyncio", limit_max_requests=1, http=http_protocol_cls, port=unused_tcp_port)

    async with run_server(config):
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert app.tls is MISSING


async def test_https_without_client_cert(
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    unused_tcp_port: int,
):
    """HTTPS, but the client never presents a certificate."""
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        http=http_protocol_cls,
    )

    async with run_server(config):
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert_no_client_cert(app.tls)


async def test_https_with_required_client_cert(
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    tls_client_certificate_key_and_chain_path: str,
    unused_tcp_port: int,
):
    """mTLS: the validated peer certificate shows up in the scope."""
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=tls_ca_certificate_pem_path,
        http=http_protocol_cls,
    )

    async with run_server(config):
        context = client_context(tls_ca_ssl_context, tls_client_certificate_key_and_chain_path)
        async with httpx.AsyncClient(verify=context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert_is_test_client_cert(app.tls)


async def test_https_with_optional_client_cert_provided(
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    tls_client_certificate_key_and_chain_path: str,
    unused_tcp_port: int,
):
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        cert_reqs=ssl.CERT_OPTIONAL,
        ca_certs=tls_ca_certificate_pem_path,
        http=http_protocol_cls,
    )

    async with run_server(config):
        context = client_context(tls_ca_ssl_context, tls_client_certificate_key_and_chain_path)
        async with httpx.AsyncClient(verify=context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert_is_test_client_cert(app.tls)


async def test_https_with_optional_client_cert_omitted(
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
):
    """`CERT_OPTIONAL` lets the connection through; the certificate fields stay empty."""
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        cert_reqs=ssl.CERT_OPTIONAL,
        ca_certs=tls_ca_certificate_pem_path,
        http=http_protocol_cls,
    )

    async with run_server(config):
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert_no_client_cert(app.tls)


async def test_https_with_required_client_cert_omitted_is_rejected(
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
):
    """`CERT_REQUIRED` without a client certificate never reaches the application."""
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=tls_ca_certificate_pem_path,
        http=http_protocol_cls,
    )

    async with run_server(config):
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
            with pytest.raises((httpx.ConnectError, httpx.ReadError, ssl.SSLError)):
                await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert app.captured == []


async def test_https_client_cert_not_requested_by_server(
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    tls_client_certificate_key_and_chain_path: str,
    unused_tcp_port: int,
):
    """With the default `CERT_NONE` the server never asks for a certificate.

    The client holds one, but TLS only sends it when the server requests it, so
    nothing ends up in the scope.
    """
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        cert_reqs=ssl.CERT_NONE,
        ca_certs=tls_ca_certificate_pem_path,
        http=http_protocol_cls,
    )

    async with run_server(config):
        context = client_context(tls_ca_ssl_context, tls_client_certificate_key_and_chain_path)
        async with httpx.AsyncClient(verify=context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert_no_client_cert(app.tls)


async def test_https_extension_is_rebuilt_per_request_on_keepalive_connections(
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    tls_client_certificate_key_and_chain_path: str,
    unused_tcp_port: int,
):
    """Every request on a kept-alive connection sees the same certificate.

    `CaptureScope` trashes each scope's `tls` entry after reading it, so this also
    proves that one request's mutations cannot leak into the next request.
    """
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=tls_ca_certificate_pem_path,
        http=http_protocol_cls,
        limit_max_requests=3,
    )

    async with run_server(config):
        context = client_context(tls_ca_ssl_context, tls_client_certificate_key_and_chain_path)
        async with httpx.AsyncClient(verify=context) as client:
            for _ in range(3):
                response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
                assert response.status_code == 204

    assert len(app.captured) == 3
    for tls in app.captured:
        assert_is_test_client_cert(tls)


# --------------------------------------------------------------------------------------
# WebSockets
# --------------------------------------------------------------------------------------


async def test_websocket_without_tls_omits_the_extension(ws_protocol_cls, http_protocol_cls, unused_tcp_port: int):
    app = CaptureScope()
    config = Config(
        app=app,
        loop="asyncio",
        limit_max_requests=1,
        ws=ws_protocol_cls,
        http=http_protocol_cls,
        port=unused_tcp_port,
    )

    async with run_server(config):
        async with connect(f"ws://127.0.0.1:{unused_tcp_port}"):
            pass

    assert app.tls is MISSING


async def test_websocket_with_required_client_cert(
    ws_protocol_cls,
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    tls_client_certificate_key_and_chain_path: str,
    unused_tcp_port: int,
):
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=tls_ca_certificate_pem_path,
        ws=ws_protocol_cls,
        http=http_protocol_cls,
    )

    async with run_server(config):
        context = client_context(tls_ca_ssl_context, tls_client_certificate_key_and_chain_path)
        async with connect(f"wss://localhost:{unused_tcp_port}", ssl=context):
            pass

    assert_is_test_client_cert(app.tls)


async def test_websocket_over_tls_without_client_cert(
    ws_protocol_cls,
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    unused_tcp_port: int,
):
    app = CaptureScope()
    config = tls_config(
        app,
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        ws=ws_protocol_cls,
        http=http_protocol_cls,
    )

    async with run_server(config):
        async with connect(f"wss://localhost:{unused_tcp_port}", ssl=tls_ca_ssl_context):
            pass

    assert_no_client_cert(app.tls)


async def test_websocket_keeps_the_response_extension(
    ws_protocol_cls,
    http_protocol_cls,
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    unused_tcp_port: int,
):
    """Adding `tls` must not displace the existing `websocket.http.response` extension."""
    seen: list[Any] = []

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "lifespan":
            raise NotImplementedError
        seen.append(scope["extensions"])
        await receive()
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.close", "code": 1000})

    config = tls_config(
        app,  # type: ignore[arg-type]
        unused_tcp_port,
        tls_certificate_server_cert_path,
        tls_certificate_private_key_path,
        ws=ws_protocol_cls,
        http=http_protocol_cls,
    )

    async with run_server(config):
        async with connect(f"wss://localhost:{unused_tcp_port}", ssl=tls_ca_ssl_context):
            pass

    assert set(seen[0]) == {"websocket.http.response", "tls"}

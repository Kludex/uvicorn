from __future__ import annotations

import asyncio
import ssl
import sys
from collections.abc import Callable, Iterator
from typing import Any, TypeAlias

import httpx2
import pytest
import trustme
from websockets.asyncio.client import connect

from tests.utils import run_server
from uvicorn.config import Config

DefaultFactory: TypeAlias = Callable[[], ssl.SSLContext]


@pytest.fixture
def tls_client_certificate(tls_certificate_authority: trustme.CA) -> trustme.LeafCert:
    return tls_certificate_authority.create_child_ca().issue_cert("uvicorn-client")


@pytest.fixture
def tls_client_ssl_context(
    tls_ca_ssl_context: ssl.SSLContext,
    tls_client_certificate: trustme.LeafCert,
) -> Iterator[ssl.SSLContext]:
    with tls_client_certificate.private_key_and_cert_chain_pem.tempfile() as certfile:
        tls_ca_ssl_context.load_cert_chain(certfile)
        yield tls_ca_ssl_context


def client_certificate_chain_pem(
    certificate: trustme.LeafCert,
    certificate_authority: trustme.CA,
) -> tuple[str, ...]:
    chain = [*certificate.cert_chain_pems, certificate_authority.cert_pem]
    return (
        tuple(ssl.DER_cert_to_PEM_cert(ssl.PEM_cert_to_DER_cert(item.bytes().decode("ascii"))) for item in chain)
        if sys.version_info >= (3, 13)
        else ()
    )


async def app(scope, receive, send):
    assert scope["type"] == "http"
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


@pytest.mark.anyio
async def test_run(
    tls_ca_ssl_context,
    tls_certificate_server_cert_path,
    tls_certificate_private_key_path,
    tls_ca_certificate_pem_path,
    unused_tcp_port: int,
):
    config = Config(
        app=app,
        loop="asyncio",
        limit_max_requests=1,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


@pytest.mark.anyio
async def test_client_certificate_chain_in_http_scope(
    http_protocol_cls: type[asyncio.Protocol],
    tls_client_certificate: trustme.LeafCert,
    tls_client_ssl_context: ssl.SSLContext,
    tls_certificate_authority: trustme.CA,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
) -> None:
    scopes: list[dict[str, Any]] = []

    async def certificate_app(scope, receive, send):
        scopes.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    config = Config(
        app=certificate_app,
        http=http_protocol_cls,
        loop="asyncio",
        lifespan="off",
        limit_max_requests=2,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_client_ssl_context) as client:
            responses = [
                await client.get(f"https://127.0.0.1:{unused_tcp_port}"),
                await client.get(f"https://127.0.0.1:{unused_tcp_port}"),
            ]

    assert [response.status_code for response in responses] == [204, 204]
    assert scopes[0]["client"] == scopes[1]["client"]
    first_client_cert_chain = scopes[0]["extensions"]["tls"]["client_cert_chain"]
    second_client_cert_chain = scopes[1]["extensions"]["tls"]["client_cert_chain"]
    assert first_client_cert_chain == client_certificate_chain_pem(tls_client_certificate, tls_certificate_authority)
    assert second_client_cert_chain is first_client_cert_chain


@pytest.mark.anyio
async def test_client_certificate_chain_in_http2_scope(
    tls_client_certificate: trustme.LeafCert,
    tls_client_ssl_context: ssl.SSLContext,
    tls_certificate_authority: trustme.CA,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
) -> None:
    scopes: list[dict[str, Any]] = []

    async def certificate_app(scope, receive, send):
        scopes.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    config = Config(
        app=certificate_app,
        http="zttp",
        http2=True,
        loop="asyncio",
        lifespan="off",
        limit_max_requests=1,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(http2=True, verify=tls_client_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert response.http_version == "HTTP/2"
    assert scopes[0]["extensions"]["tls"] == {
        "client_cert_chain": client_certificate_chain_pem(tls_client_certificate, tls_certificate_authority)
    }


@pytest.mark.anyio
async def test_client_certificate_chain_in_websocket_scope(
    ws_protocol_cls: type[asyncio.Protocol],
    tls_client_certificate: trustme.LeafCert,
    tls_client_ssl_context: ssl.SSLContext,
    tls_certificate_authority: trustme.CA,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
) -> None:
    scopes: list[dict[str, Any]] = []

    async def certificate_app(scope, receive, send):
        scopes.append(scope)
        await receive()
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.close", "code": 1000})

    config = Config(
        app=certificate_app,
        ws=ws_protocol_cls,
        loop="asyncio",
        lifespan="off",
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with connect(f"wss://127.0.0.1:{unused_tcp_port}", ssl=tls_client_ssl_context):
            pass

    assert scopes[0]["extensions"]["tls"] == {
        "client_cert_chain": client_certificate_chain_pem(tls_client_certificate, tls_certificate_authority)
    }


@pytest.mark.anyio
async def test_tls_scope_without_client_certificate(
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
) -> None:
    scopes: list[dict[str, Any]] = []

    async def certificate_app(scope, receive, send):
        scopes.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    config = Config(
        app=certificate_app,
        http="h11",
        loop="asyncio",
        lifespan="off",
        limit_max_requests=1,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        ssl_cert_reqs=ssl.CERT_OPTIONAL,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert response.status_code == 204
    assert scopes[0]["extensions"]["tls"] == {"client_cert_chain": ()}


@pytest.mark.anyio
async def test_required_client_certificate_rejected_before_application(
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
) -> None:
    app_called = False

    async def certificate_app(scope, receive, send):
        nonlocal app_called
        app_called = True  # pragma: no cover - a rejected TLS handshake cannot invoke ASGI

    config = Config(
        app=certificate_app,
        http="h11",
        loop="asyncio",
        lifespan="off",
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            with pytest.raises((httpx2.ConnectError, httpx2.RemoteProtocolError)):
                await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert app_called is False


@pytest.mark.anyio
async def test_untrusted_client_certificate_rejected_before_application(
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    tls_ca_certificate_pem_path: str,
    unused_tcp_port: int,
) -> None:
    app_called = False

    async def certificate_app(scope, receive, send):
        nonlocal app_called
        app_called = True  # pragma: no cover - a rejected TLS handshake cannot invoke ASGI

    rogue_certificate = trustme.CA().issue_cert("untrusted-client")
    with rogue_certificate.private_key_and_cert_chain_pem.tempfile() as certfile:
        tls_ca_ssl_context.load_cert_chain(certfile)
        config = Config(
            app=certificate_app,
            http="h11",
            loop="asyncio",
            lifespan="off",
            ssl_keyfile=tls_certificate_private_key_path,
            ssl_certfile=tls_certificate_server_cert_path,
            ssl_ca_certs=tls_ca_certificate_pem_path,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            port=unused_tcp_port,
        )
        async with run_server(config):
            async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
                with pytest.raises((httpx2.ConnectError, httpx2.RemoteProtocolError)):
                    await client.get(f"https://127.0.0.1:{unused_tcp_port}")

    assert app_called is False


@pytest.mark.anyio
async def test_tls_extension_absent_without_tls(unused_tcp_port: int) -> None:
    scopes: list[dict[str, Any]] = []

    async def certificate_app(scope, receive, send):
        scopes.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    config = Config(
        app=certificate_app,
        http="h11",
        loop="asyncio",
        lifespan="off",
        limit_max_requests=1,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(
                f"http://127.0.0.1:{unused_tcp_port}",
                headers={"x-client-cert": "not-a-certificate", "x-forwarded-proto": "https"},
            )

    assert response.status_code == 204
    assert scopes[0]["scheme"] == "https"
    assert "extensions" not in scopes[0]


@pytest.mark.anyio
async def test_run_chain(
    tls_ca_ssl_context,
    tls_certificate_key_and_chain_path,
    tls_ca_certificate_pem_path,
    unused_tcp_port: int,
):
    config = Config(
        app=app,
        loop="asyncio",
        limit_max_requests=1,
        ssl_certfile=tls_certificate_key_and_chain_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


@pytest.mark.anyio
async def test_run_chain_only(tls_ca_ssl_context, tls_certificate_key_and_chain_path, unused_tcp_port: int):
    config = Config(
        app=app,
        loop="asyncio",
        limit_max_requests=1,
        ssl_certfile=tls_certificate_key_and_chain_path,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


@pytest.mark.anyio
async def test_run_password(
    tls_ca_ssl_context,
    tls_certificate_server_cert_path,
    tls_ca_certificate_pem_path,
    tls_certificate_private_key_encrypted_path,
    unused_tcp_port: int,
):
    config = Config(
        app=app,
        loop="asyncio",
        limit_max_requests=1,
        ssl_keyfile=tls_certificate_private_key_encrypted_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_keyfile_password="uvicorn password for the win",
        ssl_ca_certs=tls_ca_certificate_pem_path,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


@pytest.mark.anyio
async def test_run_ssl_context_factory_default(
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    unused_tcp_port: int,
) -> None:
    """A factory that just delegates to the default factory should produce a working server."""

    def ssl_context_factory(config: Config, default_ssl_context_factory: DefaultFactory) -> ssl.SSLContext:
        return default_ssl_context_factory()

    config = Config(
        app=app,
        loop="asyncio",
        limit_max_requests=1,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_context_factory=ssl_context_factory,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


@pytest.mark.anyio
async def test_run_ssl_context_factory_custom(
    tls_ca_ssl_context: ssl.SSLContext,
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
    unused_tcp_port: int,
) -> None:
    """A factory that builds its own SSLContext from scratch should work without ssl_keyfile/ssl_certfile."""

    def ssl_context_factory(config: Config, default_ssl_context_factory: DefaultFactory) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_certificate_server_cert_path, tls_certificate_private_key_path)
        return ctx

    config = Config(
        app=app,
        loop="asyncio",
        limit_max_requests=1,
        ssl_context_factory=ssl_context_factory,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx2.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


def test_ssl_context_factory_mutates_default(
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
) -> None:
    """The factory can call the default and mutate the result (e.g., bump TLS minimum version)."""

    def ssl_context_factory(config: Config, default_ssl_context_factory: DefaultFactory) -> ssl.SSLContext:
        ctx = default_ssl_context_factory()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        return ctx

    config = Config(
        app=app,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_context_factory=ssl_context_factory,
    )
    config.load()
    assert config.is_ssl
    assert isinstance(config.ssl, ssl.SSLContext)
    assert config.ssl.minimum_version == ssl.TLSVersion.TLSv1_3


def test_default_ssl_context_factory_requires_ssl_certfile() -> None:
    """Calling `default_ssl_context_factory()` without `ssl_certfile` raises a clear error."""

    def ssl_context_factory(config: Config, default_ssl_context_factory: DefaultFactory) -> ssl.SSLContext:
        return default_ssl_context_factory()

    config = Config(app=app, ssl_context_factory=ssl_context_factory)
    with pytest.raises(RuntimeError, match="requires `ssl_certfile`"):
        config.load()


def test_ssl_context_factory_must_return_ssl_context() -> None:
    def bad_factory(config: Config, default_ssl_context_factory: DefaultFactory) -> object:
        return "not an SSLContext"

    config = Config(app=app, ssl_context_factory=bad_factory)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must return an `ssl.SSLContext`"):
        config.load()


def test_ssl_ciphers_applied_when_set(
    tls_certificate_server_cert_path: str,
    tls_certificate_private_key_path: str,
) -> None:
    config = Config(
        app=app,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ciphers="HIGH",
    )
    config.load()
    assert isinstance(config.ssl, ssl.SSLContext)


def test_is_ssl_true_when_only_factory_set() -> None:
    def ssl_context_factory(config: Config, default_ssl_context_factory: DefaultFactory) -> ssl.SSLContext:
        return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # pragma: no cover

    config = Config(app=app, ssl_context_factory=ssl_context_factory)
    assert config.is_ssl is True

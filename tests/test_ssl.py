from __future__ import annotations

import ssl
from collections.abc import Callable
from typing import TypeAlias

import httpx
import pytest

from tests.utils import run_server
from uvicorn.config import Config

DefaultFactory: TypeAlias = Callable[[], ssl.SSLContext]


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
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


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
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
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
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
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
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
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
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
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
        async with httpx.AsyncClient(verify=tls_ca_ssl_context) as client:
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

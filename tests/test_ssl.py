import ssl

import httpx
import pytest

from tests.utils import run_server
from uvicorn.config import Config


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
async def test_run_ssl_context_factory(
    tls_ca_ssl_context,
    tls_certificate_server_cert_path,
    tls_certificate_private_key_path,
    unused_tcp_port: int,
):
    def ssl_context_factory() -> ssl.SSLContext:
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

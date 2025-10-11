import ssl

import httpx
import pytest
from cryptography import x509

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
@pytest.mark.parametrize(
    "tls_client_certificate, expected_common_name",
    [
        ("test common name", "test common name"),
    ],
    indirect=["tls_client_certificate"],
)
@pytest.mark.anyio
async def test_run_httptools_client_cert(
    tls_client_ssl_context,
    tls_certificate_server_cert_path,
    tls_certificate_private_key_path,
    tls_ca_certificate_pem_path,
    expected_common_name,
    unused_tcp_port: int,
):
    async def app(scope, receive, send):
        assert scope["type"] == "http"
        assert len(scope["extensions"]["tls"]["client_cert_chain"]) >= 1
        cert = x509.load_pem_x509_certificate(scope["extensions"]["tls"]["client_cert_chain"][0].encode("utf-8"))
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == expected_common_name
        cipher_suites = [cipher["name"] for cipher in ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).get_ciphers()]
        assert scope["extensions"]["tls"]["cipher_suite"] in cipher_suites
        assert scope["extensions"]["tls"]["tls_version"].startswith("TLSv") or scope["extensions"]["tls"][
            "tls_version"
        ].startswith("SSLv")

        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    config = Config(
        app=app,
        loop="asyncio",
        http="httptools",
        limit_max_requests=1,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx.AsyncClient(verify=tls_client_ssl_context) as client:
            response = await client.get(f"https://127.0.0.1:{unused_tcp_port}")
    assert response.status_code == 204


@pytest.mark.anyio
async def test_run_h11_client_cert(
    tls_client_ssl_context,
    tls_ca_certificate_pem_path,
    tls_certificate_server_cert_path,
    tls_certificate_private_key_path,
    unused_tcp_port: int,
):
    config = Config(
        app=app,
        loop="asyncio",
        http="h11",
        limit_max_requests=1,
        ssl_keyfile=tls_certificate_private_key_path,
        ssl_certfile=tls_certificate_server_cert_path,
        ssl_ca_certs=tls_ca_certificate_pem_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx.AsyncClient(verify=tls_client_ssl_context) as client:
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

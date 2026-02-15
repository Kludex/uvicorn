from __future__ import annotations

import contextlib
import importlib.util
import os
import socket
import ssl
from copy import deepcopy
from hashlib import md5
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

import pytest

try:
    import trustme
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    HAVE_TRUSTME = True
except ImportError:  # pragma: no cover
    HAVE_TRUSTME = False

from uvicorn.config import LOGGING_CONFIG
from uvicorn.importer import import_from_string

# Note: We explicitly turn the propagate on just for tests, because pytest
# caplog not able to capture no-propagate loggers.
#
# And the caplog_for_logger helper also not work on test config cases, because
# when create Config object, Config.configure_logging will remove caplog.handler.
#
# The simple solution is set propagate=True before execute tests.
#
# See also: https://github.com/pytest-dev/pytest/issues/3697
LOGGING_CONFIG["loggers"]["uvicorn"]["propagate"] = True


@pytest.fixture
def tls_certificate_authority() -> trustme.CA:
    if not HAVE_TRUSTME:
        pytest.skip("trustme not installed")  # pragma: no cover
    return trustme.CA()


@pytest.fixture
def tls_certificate(tls_certificate_authority: trustme.CA) -> trustme.LeafCert:
    return tls_certificate_authority.issue_cert(
        "localhost",
        "127.0.0.1",
        "::1",
    )


@pytest.fixture
def tls_ca_certificate_pem_path(tls_certificate_authority: trustme.CA):
    with tls_certificate_authority.cert_pem.tempfile() as ca_cert_pem:
        yield ca_cert_pem


@pytest.fixture
def tls_ca_certificate_private_key_path(tls_certificate_authority: trustme.CA):
    with tls_certificate_authority.private_key_pem.tempfile() as private_key:
        yield private_key


@pytest.fixture
def tls_certificate_private_key_encrypted_path(tls_certificate):
    private_key = serialization.load_pem_private_key(
        tls_certificate.private_key_pem.bytes(),
        password=None,
        backend=default_backend(),
    )
    encrypted_key = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(b"uvicorn password for the win"),
    )
    with trustme.Blob(encrypted_key).tempfile() as private_encrypted_key:
        yield private_encrypted_key


@pytest.fixture
def tls_certificate_private_key_path(tls_certificate: trustme.CA):
    with tls_certificate.private_key_pem.tempfile() as private_key:
        yield private_key


@pytest.fixture
def tls_certificate_key_and_chain_path(tls_certificate: trustme.LeafCert):
    with tls_certificate.private_key_and_cert_chain_pem.tempfile() as cert_pem:
        yield cert_pem


@pytest.fixture
def tls_certificate_server_cert_path(tls_certificate: trustme.LeafCert):
    with tls_certificate.cert_chain_pems[0].tempfile() as cert_pem:
        yield cert_pem


@pytest.fixture
def tls_ca_ssl_context(tls_certificate_authority: trustme.CA) -> ssl.SSLContext:
    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    tls_certificate_authority.configure_trust(ssl_ctx)
    return ssl_ctx


@pytest.fixture(scope="package")
def reload_directory_structure(tmp_path_factory: pytest.TempPathFactory):
    """
    This fixture creates a directory structure to enable reload parameter tests

    The fixture has the following structure:
    root
    ├── [app, app_first, app_second, app_third]
    │   ├── css
    │   │   └── main.css
    │   ├── js
    │   │   └── main.js
    │   ├── src
    │   │   └── main.py
    │   └── sub
    │       └── sub.py
    ├── ext
    │   └── ext.jpg
    ├── .dotted
    ├── .dotted_dir
    │   └── file.txt
    └── main.py
    """
    root = tmp_path_factory.mktemp("reload_directory")
    apps = ["app", "app_first", "app_second", "app_third"]

    root_file = root / "main.py"
    root_file.touch()

    dotted_file = root / ".dotted"
    dotted_file.touch()

    dotted_dir = root / ".dotted_dir"
    dotted_dir.mkdir()
    dotted_dir_file = dotted_dir / "file.txt"
    dotted_dir_file.touch()

    for app in apps:
        app_path = root / app
        app_path.mkdir()
        dir_files = [
            ("src", ["main.py"]),
            ("js", ["main.js"]),
            ("css", ["main.css"]),
            ("sub", ["sub.py"]),
        ]
        for directory, files in dir_files:
            directory_path = app_path / directory
            directory_path.mkdir()
            for file in files:
                file_path = directory_path / file
                file_path.touch()
    ext_dir = root / "ext"
    ext_dir.mkdir()
    ext_file = ext_dir / "ext.jpg"
    ext_file.touch()

    yield root


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="function")
def logging_config() -> dict[str, Any]:
    return deepcopy(LOGGING_CONFIG)


@pytest.fixture
def short_socket_name(tmp_path, tmp_path_factory):  # pragma: py-win32
    max_sock_len = 100
    socket_filename = "my.sock"
    identifier = f"{uuid4()}-"
    identifier_len = len(identifier.encode())
    tmp_dir = Path("/tmp").resolve()
    os_tmp_dir = Path(os.getenv("TMPDIR", "/tmp")).resolve()
    basetemp = Path(
        str(tmp_path_factory.getbasetemp()),
    ).resolve()
    hash_basetemp = md5(
        str(basetemp).encode(),
    ).hexdigest()

    def make_tmp_dir(base_dir):
        return TemporaryDirectory(
            dir=str(base_dir),
            prefix="p-",
            suffix=f"-{hash_basetemp}",
        )

    paths = basetemp, os_tmp_dir, tmp_dir
    for _num, tmp_dir_path in enumerate(paths, 1):
        with make_tmp_dir(tmp_dir_path) as tmpd:
            tmpd = Path(tmpd).resolve()
            sock_path = str(tmpd / socket_filename)
            sock_path_len = len(sock_path.encode())
            if sock_path_len <= max_sock_len:
                if max_sock_len - sock_path_len >= identifier_len:  # pragma: no cover
                    sock_path = str(tmpd / "".join((identifier, socket_filename)))
                yield sock_path
                return


def _unused_port(socket_type: int) -> int:
    """Find an unused localhost port from 1024-65535 and return it."""
    with contextlib.closing(socket.socket(type=socket_type)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# This was copied from pytest-asyncio.
# Ref.: https://github.com/pytest-dev/pytest-asyncio/blob/25d9592286682bc6dbfbf291028ff7a9594cf283/pytest_asyncio/plugin.py#L525-L527  # noqa: E501
@pytest.fixture
def unused_tcp_port() -> int:
    return _unused_port(socket.SOCK_STREAM)


@pytest.fixture(
    params=[
        pytest.param(
            "uvicorn.protocols.websockets.wsproto_impl:WSProtocol",
            marks=pytest.mark.skipif(not importlib.util.find_spec("wsproto"), reason="wsproto not installed."),
            id="wsproto",
        ),
        pytest.param("uvicorn.protocols.websockets.websockets_impl:WebSocketProtocol", id="websockets"),
        pytest.param(
            "uvicorn.protocols.websockets.websockets_sansio_impl:WebSocketsSansIOProtocol", id="websockets-sansio"
        ),
    ]
)
def ws_protocol_cls(request: pytest.FixtureRequest):
    return import_from_string(request.param)


@pytest.fixture(
    params=[
        pytest.param(
            "uvicorn.protocols.http.httptools_impl:HttpToolsProtocol",
            marks=pytest.mark.skipif(
                not importlib.util.find_spec("httptools"),
                reason="httptools not installed.",
            ),
            id="httptools",
        ),
        pytest.param("uvicorn.protocols.http.h11_impl:H11Protocol", id="h11"),
    ]
)
def http_protocol_cls(request: pytest.FixtureRequest):
    return import_from_string(request.param)

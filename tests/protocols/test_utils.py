from __future__ import annotations

import socket
import ssl
from asyncio import Transport
from typing import Any

import pytest

from uvicorn.protocols.utils import TLSExtension, get_client_addr, get_local_addr, get_remote_addr


class MockSocket:
    def __init__(
        self,
        family: socket.AddressFamily,
        peername: tuple[str, int] | None = None,
        sockname: tuple[str, int] | str | None = None,
    ):
        self.peername = peername
        self.sockname = sockname
        self.family = family

    def getpeername(self):
        return self.peername

    def getsockname(self):
        return self.sockname


class MockTransport(Transport):
    def __init__(self, info: dict[str, Any]) -> None:
        self.info = info

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return self.info.get(name)


def test_get_local_addr_with_socket():
    transport = MockTransport({"socket": MockSocket(family=socket.AF_IPX)})
    assert get_local_addr(transport) is None

    transport = MockTransport({"socket": MockSocket(family=socket.AF_INET6, sockname=("::1", 123))})
    assert get_local_addr(transport) == ("::1", 123)

    transport = MockTransport({"socket": MockSocket(family=socket.AF_INET, sockname=("123.45.6.7", 123))})
    assert get_local_addr(transport) == ("123.45.6.7", 123)

    transport = MockTransport({"socket": MockSocket(family=socket.AF_INET, sockname="/tmp/test.sock")})
    assert get_local_addr(transport) == ("/tmp/test.sock", None)


def test_get_remote_addr_with_socket():
    transport = MockTransport({"socket": MockSocket(family=socket.AF_IPX)})
    assert get_remote_addr(transport) is None

    transport = MockTransport({"socket": MockSocket(family=socket.AF_INET6, peername=("::1", 123))})
    assert get_remote_addr(transport) == ("::1", 123)

    transport = MockTransport({"socket": MockSocket(family=socket.AF_INET, peername=("123.45.6.7", 123))})
    assert get_remote_addr(transport) == ("123.45.6.7", 123)

    if hasattr(socket, "AF_UNIX"):  # pragma: no cover
        transport = MockTransport({"socket": MockSocket(family=socket.AF_UNIX, peername=("127.0.0.1", 8000))})
        assert get_remote_addr(transport) == ("127.0.0.1", 8000)


def test_get_local_addr():
    transport = MockTransport({"sockname": "path/to/unix-domain-socket"})
    assert get_local_addr(transport) == ("path/to/unix-domain-socket", None)

    transport = MockTransport({"sockname": ("123.45.6.7", 123)})
    assert get_local_addr(transport) == ("123.45.6.7", 123)

    transport = MockTransport({})
    assert get_local_addr(transport) is None


def test_get_remote_addr():
    transport = MockTransport({"peername": None})
    assert get_remote_addr(transport) is None

    transport = MockTransport({"peername": ("123.45.6.7", 123)})
    assert get_remote_addr(transport) == ("123.45.6.7", 123)


@pytest.mark.parametrize(
    "scope, expected_client",
    [({"client": ("127.0.0.1", 36000)}, "127.0.0.1:36000"), ({"client": None}, "")],
    ids=["ip:port client", "None client"],
)
def test_get_client_addr(scope: Any, expected_client: str):
    assert get_client_addr(scope) == expected_client


CIPHER_NAME = "TLS_AES_256_GCM_SHA384"
# OpenSSL reports cipher suites as 0x0300XXXX; the low 16 bits are the wire value.
CIPHER_ID = 0x03001302


class MockSSLContext:
    def get_ciphers(self) -> list[dict[str, Any]]:
        return [{"name": CIPHER_NAME, "id": CIPHER_ID}]


class MockSSLObject:
    def __init__(self, peercert: dict[str, Any] | None, chain: list[bytes] | None = None):
        self.peercert = peercert
        self.chain = chain or []
        self.context = MockSSLContext()
        # `cipher()` runs exactly once per `TLSExtension._build()`, so this counts builds.
        self.cipher_calls = 0

    def getpeercert(self, binary_form: bool = False) -> Any:
        # Only Python versions without `get_verified_chain()` ask for the binary form.
        if binary_form:  # pragma: py-gte-313
            return self.chain[0] if self.chain else None
        return self.peercert

    def get_verified_chain(self) -> list[bytes]:
        return self.chain

    def version(self) -> str:
        return "TLSv1.3"

    def cipher(self) -> tuple[str, str, int]:
        self.cipher_calls += 1
        return (CIPHER_NAME, "TLSv1.3", 256)


PEER_CERT = {
    "subject": ((("commonName", "client.example.org"),),),
    "issuer": ((("commonName", "Example CA"),),),
    "serialNumber": "01",
}


def tls_extension(ssl_object: MockSSLObject) -> TLSExtension:
    extension = TLSExtension.from_transport(MockTransport({"ssl_object": ssl_object}))
    assert extension is not None
    return extension


def test_tls_extension_absent_without_tls():
    """The ASGI TLS extension must not be provided for unencrypted connections."""
    assert TLSExtension.from_transport(MockTransport({})) is None


def test_tls_extension_with_unvalidated_peer_cert():
    """An unvalidated certificate is reported by CPython as an empty dict."""
    tls = tls_extension(MockSSLObject(peercert={})).scope_entry()
    assert tls["client_cert_dict"] == {}
    assert tls["client_cert_name"] is None


@pytest.mark.parametrize(
    "subject, expected",
    [
        pytest.param(
            ((("commonName", "client.example.org"),),),
            "CN=client.example.org",
            id="single attribute",
        ),
        pytest.param(
            ((("countryName", "DE"),), (("organizationName", "Example"),), (("commonName", "leaf"),)),
            "CN=leaf,O=Example,C=DE",
            # RFC 4514 section 2.1 writes the RDNs in reverse order.
            id="reversed rdn order",
        ),
        pytest.param(
            ((("commonName", "leaf"), ("organizationName", "Example")),),
            "CN=leaf+O=Example",
            id="multi-valued rdn",
        ),
        pytest.param(
            ((("jurisdictionCountryName", "DE"),),),
            "jurisdictionCountryName=DE",
            id="unmapped attribute keeps its long name",
        ),
        pytest.param(
            ((("commonName", "a,b+c<d>e;f\\g"),),),
            "CN=a\\,b\\+c\\<d\\>e\\;f\\\\g",
            id="escaped special characters",
        ),
        pytest.param(
            ((("commonName", " leading"),), (("organizationName", "trailing "),)),
            "O=trailing\\ ,CN=\\ leading",
            id="escaped leading and trailing space",
        ),
        pytest.param(
            ((("commonName", "#hash"),), (("organizationName", "mid#hash"),)),
            "O=mid#hash,CN=\\#hash",
            id="hash only escaped at the start",
        ),
        pytest.param(
            ((("commonName", "nul\x00byte"),),),
            "CN=nul\\00byte",
            id="escaped nul byte",
        ),
    ],
)
def test_client_cert_name_is_rfc4514(subject: Any, expected: str):
    tls = tls_extension(MockSSLObject(peercert={"subject": subject})).scope_entry()
    assert tls["client_cert_name"] == expected


def test_tls_extension_without_client_cert():
    tls = tls_extension(MockSSLObject(peercert=None)).scope_entry()
    assert tls == {
        "server_cert": None,
        "client_cert_chain": [],
        "client_cert_name": None,
        "client_cert_error": None,
        "tls_version": 0x0304,
        "cipher_suite": 0x1302,
        "client_cert_dict": None,
    }


def test_tls_extension_with_client_cert():
    der = b"0\x82 not really a certificate"
    tls = tls_extension(MockSSLObject(peercert=PEER_CERT, chain=[der])).scope_entry()
    assert tls["client_cert_chain"] == [ssl.DER_cert_to_PEM_cert(der)]
    assert tls["client_cert_name"] == "CN=client.example.org"
    assert tls["client_cert_dict"] == PEER_CERT


def test_tls_extension_is_lazy_and_cached():
    """No TLS data is gathered before the first scope, and only once per connection."""
    ssl_object = MockSSLObject(peercert=PEER_CERT, chain=[b"0\x82 der"])
    extension = tls_extension(ssl_object)
    assert ssl_object.cipher_calls == 0
    extension.scope_entry()
    extension.scope_entry()
    assert ssl_object.cipher_calls == 1


def test_scope_entry_is_isolated_per_request():
    """Mutating one scope's entry must not affect entries handed to later scopes."""
    extension = tls_extension(MockSSLObject(peercert=PEER_CERT, chain=[b"0\x82 der"]))
    first = extension.scope_entry()
    chain, cert = first["client_cert_chain"], first["client_cert_dict"]
    assert isinstance(chain, list) and isinstance(cert, dict)
    chain.append("bogus")
    cert["forged"] = True
    first.clear()

    second = extension.scope_entry()
    assert second["client_cert_chain"] == [ssl.DER_cert_to_PEM_cert(b"0\x82 der")]
    assert second["client_cert_dict"] == PEER_CERT
    assert second["client_cert_name"] == "CN=client.example.org"

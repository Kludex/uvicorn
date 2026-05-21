from __future__ import annotations

import contextlib
import ipaddress
from typing import TYPE_CHECKING

import httpx
import pytest
import websockets.client

from tests.response import Response
from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware, _TrustedHosts

if TYPE_CHECKING:
    from uvicorn.protocols.http.h11_impl import H11Protocol
    from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
    from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
    from uvicorn.protocols.websockets.wsproto_impl import WSProtocol


X_FORWARDED_FOR = "X-Forwarded-For"
X_FORWARDED_PROTO = "X-Forwarded-Proto"
FORWARDED = "Forwarded"


async def default_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    scheme = scope["scheme"]  # type: ignore
    if (client := scope["client"]) is None:  # type: ignore
        client_addr = "NONE"  # pragma: no cover
    else:
        host, port = client
        with contextlib.suppress(ValueError):
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        client_addr = f"{host}:{port}"

    response = Response(f"{scheme}://{client_addr}", media_type="text/plain")
    await response(scope, receive, send)


def make_httpx_client(
    trusted_hosts: str | list[str],
    client: tuple[str, int] = ("127.0.0.1", 123),
) -> httpx.AsyncClient:
    """Create async client for use in test cases.

    Args:
        trusted_hosts: trusted_hosts for proxy middleware
        client: transport client to use
    """

    app = ProxyHeadersMiddleware(default_app, trusted_hosts)
    transport = httpx.ASGITransport(app=app, client=client)  # type: ignore
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


# Note: we vary the format here to also test some of the functionality
# of the _TrustedHosts.__init__ method.
_TRUSTED_NOTHING: list[str] = []
_TRUSTED_EVERYTHING = "*"
_TRUSTED_EVERYTHING_LIST = ["*"]
_TRUSTED_IPv4_ADDRESSES = "127.0.0.1, 10.0.0.1"
_TRUSTED_IPv4_NETWORKS = ["127.0.0.0/8", "10.0.0.0/8"]
_TRUSTED_IPv6_ADDRESSES = [
    "2001:db8::",
    "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
    "2001:db8:3333:4444:5555:6666:1.2.3.4",  # This is a dual address
    "::11.22.33.44",  # This is a dual address
]
_TRUSTED_IPv6_NETWORKS = "2001:db8:abcd:0012::0/64"
_TRUSTED_LITERALS = "some-literal , unix:///foo/bar  ,  /foo/bar, garba*gewith*"


@pytest.mark.parametrize(
    ("init_hosts", "test_host", "expected"),
    [
        ## Never Trust trust
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_NOTHING, "127.0.0.0", False),
        (_TRUSTED_NOTHING, "127.0.0.1", False),
        (_TRUSTED_NOTHING, "127.1.1.1", False),
        (_TRUSTED_NOTHING, "127.255.255.255", False),
        (_TRUSTED_NOTHING, "10.0.0.0", False),
        (_TRUSTED_NOTHING, "10.0.0.1", False),
        (_TRUSTED_NOTHING, "10.1.1.1", False),
        (_TRUSTED_NOTHING, "10.255.255.255", False),
        (_TRUSTED_NOTHING, "192.168.0.0", False),
        (_TRUSTED_NOTHING, "192.168.0.1", False),
        (_TRUSTED_NOTHING, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_NOTHING, "2001:db8::", False),
        (_TRUSTED_NOTHING, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_NOTHING, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_NOTHING, "::", False),
        (_TRUSTED_NOTHING, "::1", False),
        (
            _TRUSTED_NOTHING,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_NOTHING, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_NOTHING, "a:b:c:d::", False),
        (_TRUSTED_NOTHING, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_NOTHING, "some-literal", False),
        (_TRUSTED_NOTHING, "unix:///foo/bar", False),
        (_TRUSTED_NOTHING, "/foo/bar", False),
        (_TRUSTED_NOTHING, "*", False),
        (_TRUSTED_NOTHING, "another-literal", False),
        (_TRUSTED_NOTHING, "unix:///another/path", False),
        (_TRUSTED_NOTHING, "/another/path", False),
        (_TRUSTED_NOTHING, "", False),
        ## Always trust
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_EVERYTHING, "127.0.0.0", True),
        (_TRUSTED_EVERYTHING, "127.0.0.1", True),
        (_TRUSTED_EVERYTHING, "127.1.1.1", True),
        (_TRUSTED_EVERYTHING, "127.255.255.255", True),
        (_TRUSTED_EVERYTHING, "10.0.0.0", True),
        (_TRUSTED_EVERYTHING, "10.0.0.1", True),
        (_TRUSTED_EVERYTHING, "10.1.1.1", True),
        (_TRUSTED_EVERYTHING, "10.255.255.255", True),
        (_TRUSTED_EVERYTHING, "192.168.0.0", True),
        (_TRUSTED_EVERYTHING, "192.168.0.1", True),
        (_TRUSTED_EVERYTHING, "1.1.1.1", True),
        (_TRUSTED_EVERYTHING_LIST, "1.1.1.1", True),
        # Test IPv6 Addresses
        (_TRUSTED_EVERYTHING, "2001:db8::", True),
        (_TRUSTED_EVERYTHING, "2001:db8:abcd:0012::0", True),
        (_TRUSTED_EVERYTHING, "2001:db8:abcd:0012::1:1", True),
        (_TRUSTED_EVERYTHING, "::", True),
        (_TRUSTED_EVERYTHING, "::1", True),
        (
            _TRUSTED_EVERYTHING,
            "2001:db8:3333:4444:5555:6666:102:304",
            True,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_EVERYTHING, "::b16:212c", True),  # aka ::11.22.33.44
        (_TRUSTED_EVERYTHING, "a:b:c:d::", True),
        (_TRUSTED_EVERYTHING, "::a:b:c:d", True),
        (_TRUSTED_EVERYTHING_LIST, "::a:b:c:d", True),
        # Test Literals
        (_TRUSTED_EVERYTHING, "some-literal", True),
        (_TRUSTED_EVERYTHING, "unix:///foo/bar", True),
        (_TRUSTED_EVERYTHING, "/foo/bar", True),
        (_TRUSTED_EVERYTHING, "*", True),
        (_TRUSTED_EVERYTHING, "another-literal", True),
        (_TRUSTED_EVERYTHING, "unix:///another/path", True),
        (_TRUSTED_EVERYTHING, "/another/path", True),
        (_TRUSTED_EVERYTHING, "", True),
        (_TRUSTED_EVERYTHING_LIST, "", True),
        ## Trust IPv4 Addresses
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv4_ADDRESSES, "127.0.0.0", False),
        (_TRUSTED_IPv4_ADDRESSES, "127.0.0.1", True),
        (_TRUSTED_IPv4_ADDRESSES, "127.1.1.1", False),
        (_TRUSTED_IPv4_ADDRESSES, "127.255.255.255", False),
        (_TRUSTED_IPv4_ADDRESSES, "10.0.0.0", False),
        (_TRUSTED_IPv4_ADDRESSES, "10.0.0.1", True),
        (_TRUSTED_IPv4_ADDRESSES, "10.1.1.1", False),
        (_TRUSTED_IPv4_ADDRESSES, "10.255.255.255", False),
        (_TRUSTED_IPv4_ADDRESSES, "192.168.0.0", False),
        (_TRUSTED_IPv4_ADDRESSES, "192.168.0.1", False),
        (_TRUSTED_IPv4_ADDRESSES, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv4_ADDRESSES, "2001:db8::", False),
        (_TRUSTED_IPv4_ADDRESSES, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_IPv4_ADDRESSES, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_IPv4_ADDRESSES, "::", False),
        (_TRUSTED_IPv4_ADDRESSES, "::1", False),
        (
            _TRUSTED_IPv4_ADDRESSES,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv4_ADDRESSES, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_IPv4_ADDRESSES, "a:b:c:d::", False),
        (_TRUSTED_IPv4_ADDRESSES, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv4_ADDRESSES, "some-literal", False),
        (_TRUSTED_IPv4_ADDRESSES, "unix:///foo/bar", False),
        (_TRUSTED_IPv4_ADDRESSES, "*", False),
        (_TRUSTED_IPv4_ADDRESSES, "/foo/bar", False),
        (_TRUSTED_IPv4_ADDRESSES, "another-literal", False),
        (_TRUSTED_IPv4_ADDRESSES, "unix:///another/path", False),
        (_TRUSTED_IPv4_ADDRESSES, "/another/path", False),
        (_TRUSTED_IPv4_ADDRESSES, "", False),
        ## Trust IPv6 Addresses
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv6_ADDRESSES, "127.0.0.0", False),
        (_TRUSTED_IPv6_ADDRESSES, "127.0.0.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "127.1.1.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "127.255.255.255", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.0.0.0", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.0.0.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.1.1.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "10.255.255.255", False),
        (_TRUSTED_IPv6_ADDRESSES, "192.168.0.0", False),
        (_TRUSTED_IPv6_ADDRESSES, "192.168.0.1", False),
        (_TRUSTED_IPv6_ADDRESSES, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv6_ADDRESSES, "2001:db8::", True),
        (_TRUSTED_IPv6_ADDRESSES, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_IPv6_ADDRESSES, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_IPv6_ADDRESSES, "::", False),
        (_TRUSTED_IPv6_ADDRESSES, "::1", False),
        (
            _TRUSTED_IPv6_ADDRESSES,
            "2001:db8:3333:4444:5555:6666:102:304",
            True,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv6_ADDRESSES, "::b16:212c", True),  # aka ::11.22.33.44
        (_TRUSTED_IPv6_ADDRESSES, "a:b:c:d::", False),
        (_TRUSTED_IPv6_ADDRESSES, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv6_ADDRESSES, "some-literal", False),
        (_TRUSTED_IPv6_ADDRESSES, "unix:///foo/bar", False),
        (_TRUSTED_IPv6_ADDRESSES, "*", False),
        (_TRUSTED_IPv6_ADDRESSES, "/foo/bar", False),
        (_TRUSTED_IPv6_ADDRESSES, "another-literal", False),
        (_TRUSTED_IPv6_ADDRESSES, "unix:///another/path", False),
        (_TRUSTED_IPv6_ADDRESSES, "/another/path", False),
        (_TRUSTED_IPv6_ADDRESSES, "", False),
        ## Trust IPv4 Networks
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv4_NETWORKS, "127.0.0.0", True),
        (_TRUSTED_IPv4_NETWORKS, "127.0.0.1", True),
        (_TRUSTED_IPv4_NETWORKS, "127.1.1.1", True),
        (_TRUSTED_IPv4_NETWORKS, "127.255.255.255", True),
        (_TRUSTED_IPv4_NETWORKS, "10.0.0.0", True),
        (_TRUSTED_IPv4_NETWORKS, "10.0.0.1", True),
        (_TRUSTED_IPv4_NETWORKS, "10.1.1.1", True),
        (_TRUSTED_IPv4_NETWORKS, "10.255.255.255", True),
        (_TRUSTED_IPv4_NETWORKS, "192.168.0.0", False),
        (_TRUSTED_IPv4_NETWORKS, "192.168.0.1", False),
        (_TRUSTED_IPv4_NETWORKS, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv4_NETWORKS, "2001:db8::", False),
        (_TRUSTED_IPv4_NETWORKS, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_IPv4_NETWORKS, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_IPv4_NETWORKS, "::", False),
        (_TRUSTED_IPv4_NETWORKS, "::1", False),
        (
            _TRUSTED_IPv4_NETWORKS,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv4_NETWORKS, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_IPv4_NETWORKS, "a:b:c:d::", False),
        (_TRUSTED_IPv4_NETWORKS, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv4_NETWORKS, "some-literal", False),
        (_TRUSTED_IPv4_NETWORKS, "unix:///foo/bar", False),
        (_TRUSTED_IPv4_NETWORKS, "*", False),
        (_TRUSTED_IPv4_NETWORKS, "/foo/bar", False),
        (_TRUSTED_IPv4_NETWORKS, "another-literal", False),
        (_TRUSTED_IPv4_NETWORKS, "unix:///another/path", False),
        (_TRUSTED_IPv4_NETWORKS, "/another/path", False),
        (_TRUSTED_IPv4_NETWORKS, "", False),
        ## Trust IPv6 Networks
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_IPv6_NETWORKS, "127.0.0.0", False),
        (_TRUSTED_IPv6_NETWORKS, "127.0.0.1", False),
        (_TRUSTED_IPv6_NETWORKS, "127.1.1.1", False),
        (_TRUSTED_IPv6_NETWORKS, "127.255.255.255", False),
        (_TRUSTED_IPv6_NETWORKS, "10.0.0.0", False),
        (_TRUSTED_IPv6_NETWORKS, "10.0.0.1", False),
        (_TRUSTED_IPv6_NETWORKS, "10.1.1.1", False),
        (_TRUSTED_IPv6_NETWORKS, "10.255.255.255", False),
        (_TRUSTED_IPv6_NETWORKS, "192.168.0.0", False),
        (_TRUSTED_IPv6_NETWORKS, "192.168.0.1", False),
        (_TRUSTED_IPv6_NETWORKS, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_IPv6_NETWORKS, "2001:db8::", False),
        (_TRUSTED_IPv6_NETWORKS, "2001:db8:abcd:0012::0", True),
        (_TRUSTED_IPv6_NETWORKS, "2001:db8:abcd:0012::1:1", True),
        (_TRUSTED_IPv6_NETWORKS, "::", False),
        (_TRUSTED_IPv6_NETWORKS, "::1", False),
        (
            _TRUSTED_IPv6_NETWORKS,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_IPv6_NETWORKS, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_IPv6_NETWORKS, "a:b:c:d::", False),
        (_TRUSTED_IPv6_NETWORKS, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_IPv6_NETWORKS, "some-literal", False),
        (_TRUSTED_IPv6_NETWORKS, "unix:///foo/bar", False),
        (_TRUSTED_IPv6_NETWORKS, "*", False),
        (_TRUSTED_IPv6_NETWORKS, "/foo/bar", False),
        (_TRUSTED_IPv6_NETWORKS, "another-literal", False),
        (_TRUSTED_IPv6_NETWORKS, "unix:///another/path", False),
        (_TRUSTED_IPv6_NETWORKS, "/another/path", False),
        (_TRUSTED_IPv6_NETWORKS, "", False),
        ## Trust Literals
        ## -----------------------------
        # Test IPv4 Addresses
        (_TRUSTED_LITERALS, "127.0.0.0", False),
        (_TRUSTED_LITERALS, "127.0.0.1", False),
        (_TRUSTED_LITERALS, "127.1.1.1", False),
        (_TRUSTED_LITERALS, "127.255.255.255", False),
        (_TRUSTED_LITERALS, "10.0.0.0", False),
        (_TRUSTED_LITERALS, "10.0.0.1", False),
        (_TRUSTED_LITERALS, "10.1.1.1", False),
        (_TRUSTED_LITERALS, "10.255.255.255", False),
        (_TRUSTED_LITERALS, "192.168.0.0", False),
        (_TRUSTED_LITERALS, "192.168.0.1", False),
        (_TRUSTED_LITERALS, "1.1.1.1", False),
        # Test IPv6 Addresses
        (_TRUSTED_LITERALS, "2001:db8::", False),
        (_TRUSTED_LITERALS, "2001:db8:abcd:0012::0", False),
        (_TRUSTED_LITERALS, "2001:db8:abcd:0012::1:1", False),
        (_TRUSTED_LITERALS, "::", False),
        (_TRUSTED_LITERALS, "::1", False),
        (
            _TRUSTED_LITERALS,
            "2001:db8:3333:4444:5555:6666:102:304",
            False,
        ),  # aka 2001:db8:3333:4444:5555:6666:1.2.3.4
        (_TRUSTED_LITERALS, "::b16:212c", False),  # aka ::11.22.33.44
        (_TRUSTED_LITERALS, "a:b:c:d::", False),
        (_TRUSTED_LITERALS, "::a:b:c:d", False),
        # Test Literals
        (_TRUSTED_LITERALS, "some-literal", True),
        (_TRUSTED_LITERALS, "unix:///foo/bar", True),
        (_TRUSTED_LITERALS, "*", False),
        (_TRUSTED_LITERALS, "/foo/bar", True),
        (_TRUSTED_LITERALS, "another-literal", False),
        (_TRUSTED_LITERALS, "unix:///another/path", False),
        (_TRUSTED_LITERALS, "/another/path", False),
        (_TRUSTED_LITERALS, "", False),
    ],
)
def test_forwarded_hosts(init_hosts: str | list[str], test_host: str, expected: bool) -> None:
    trusted_hosts = _TrustedHosts(init_hosts)
    assert (test_host in trusted_hosts) is expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted_hosts", "expected"),
    [
        # always trust
        ("*", "https://1.2.3.4:0"),
        # trusted proxy
        ("127.0.0.1", "https://1.2.3.4:0"),
        (["127.0.0.1"], "https://1.2.3.4:0"),
        # trusted proxy list
        (["127.0.0.1", "10.0.0.1"], "https://1.2.3.4:0"),
        ("127.0.0.1, 10.0.0.1", "https://1.2.3.4:0"),
        # trusted proxy network
        # https://github.com/Kludex/uvicorn/issues/1068#issuecomment-1004813267
        ("127.0.0.0/24, 10.0.0.1", "https://1.2.3.4:0"),
        # request from untrusted proxy
        ("192.168.0.1", "http://127.0.0.1:123"),
        # request from untrusted proxy network
        ("192.168.0.0/16", "http://127.0.0.1:123"),
        # request from client running on proxy server itself
        # https://github.com/Kludex/uvicorn/issues/1068#issuecomment-855371576
        (["127.0.0.1", "1.2.3.4"], "https://1.2.3.4:0"),
    ],
)
async def test_proxy_headers_trusted_hosts(trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx_client(trusted_hosts) as client:
        headers = {X_FORWARDED_FOR: "1.2.3.4", X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded_for", "forwarded_proto", "expected"),
    [
        ("", "", "http://127.0.0.1:123"),
        ("", None, "http://127.0.0.1:123"),
        ("", "asdf", "http://127.0.0.1:123"),
        (" , ", "https", "https://127.0.0.1:123"),
        (", , ", "https", "https://127.0.0.1:123"),
        (" , 10.0.0.1", "https", "https://127.0.0.1:123"),
        ("9.9.9.9 , , , 10.0.0.1", "https", "https://127.0.0.1:123"),
        (", , 9.9.9.9", "https", "https://9.9.9.9:0"),
        (", , 9.9.9.9, , ", "https", "https://127.0.0.1:123"),
    ],
)
async def test_proxy_headers_trusted_hosts_malformed(
    forwarded_for: str,
    forwarded_proto: str | None,
    expected: str,
) -> None:
    async with make_httpx_client("127.0.0.1, 10.0.0.0/8") as client:
        headers = {X_FORWARDED_FOR: forwarded_for}
        if forwarded_proto is not None:
            headers[X_FORWARDED_PROTO] = forwarded_proto
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted_hosts", "expected"),
    [
        # always trust
        ("*", "https://1.2.3.4:0"),
        # all proxies are trusted
        (["127.0.0.1", "10.0.2.1", "192.168.0.2"], "https://1.2.3.4:0"),
        # order doesn't matter
        (["10.0.2.1", "192.168.0.2", "127.0.0.1"], "https://1.2.3.4:0"),
        # should set first untrusted as remote address
        (["192.168.0.2", "127.0.0.1"], "https://10.0.2.1:0"),
        # Mixed literals and networks
        (["127.0.0.1", "10.0.0.0/8", "192.168.0.2"], "https://1.2.3.4:0"),
    ],
)
async def test_proxy_headers_multiple_proxies(trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx_client(trusted_hosts) as client:
        headers = {X_FORWARDED_FOR: "1.2.3.4, 10.0.2.1, 192.168.0.2", X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted_hosts", "expected"),
    [
        # always trust
        ("*", "https://1.2.3.4:1234"),
        # all proxies are trusted
        (["127.0.0.1", "2001:db8::1", "192.168.0.2"], "https://1.2.3.4:1234"),
        # should set first untrusted as remote address
        (["192.168.0.2", "127.0.0.1"], "https://[2001:db8::1]:8080"),
        # Mixed literals and networks
        (["127.0.0.1", "2001:db8::/32", "192.168.0.2"], "https://1.2.3.4:1234"),
    ],
)
async def test_proxy_headers_multiple_proxies_with_ports(trusted_hosts: str | list[str], expected: str) -> None:
    async with make_httpx_client(trusted_hosts) as client:
        headers = {
            X_FORWARDED_FOR: "1.2.3.4:1234, [2001:db8::1]:8080, 192.168.0.2:9000",
            X_FORWARDED_PROTO: "https",
        }
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
async def test_proxy_headers_invalid_x_forwarded_for() -> None:
    async with make_httpx_client("*") as client:
        headers = httpx.Headers(
            {
                X_FORWARDED_FOR: "1.2.3.4, \xf0\xfd\xfd\xfd, unix:, ::1",
                X_FORWARDED_PROTO: "https",
            },
            encoding="latin-1",
        )
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "https://1.2.3.4:0"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("forwarded_for", "expected"),
    [
        # IPv4 without port
        ("1.2.3.4", "https://1.2.3.4:0"),
        # IPv4 with port
        ("1.2.3.4:1234", "https://1.2.3.4:1234"),
        # Bracketed IPv6 with port
        ("[2001:db8::1]:443", "https://[2001:db8::1]:443"),
        # Bracketed IPv6 without port
        ("[2001:db8::1]", "https://[2001:db8::1]:0"),
        # Bare IPv6 without port
        ("2001:db8::1", "https://[2001:db8::1]:0"),
        # Invalid IPv4 port falls back to the original host value
        ("1.2.3.4:notaport", "https://1.2.3.4:notaport:0"),
        # Invalid bracketed IPv6 port keeps the host and drops the port
        ("[2001:db8::1]:notaport", "https://[2001:db8::1]:0"),
        # Trailing data after a bracketed IPv6 host is left untouched
        ("[2001:db8::1]extra", "https://[2001:db8::1]extra:0"),
        # Malformed bracket is left untouched
        ("[2001:db8::1", "https://[2001:db8::1:0"),
    ],
)
async def test_proxy_headers_x_forwarded_for_port_shapes(forwarded_for: str, expected: str) -> None:
    async with make_httpx_client("*") as client:
        headers = {X_FORWARDED_FOR: forwarded_for, X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    "forwarded_proto,expected",
    [
        ("http", "ws://1.2.3.4:0"),
        ("https", "wss://1.2.3.4:0"),
        ("ws", "ws://1.2.3.4:0"),
        ("wss", "wss://1.2.3.4:0"),
    ],
)
async def test_proxy_headers_websocket_x_forwarded_proto(
    forwarded_proto: str,
    expected: str,
    ws_protocol_cls: type[WSProtocol | WebSocketProtocol],
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol],
    unused_tcp_port: int,
) -> None:
    async def websocket_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "websocket"
        scheme = scope["scheme"]
        assert scope["client"] is not None
        host, port = scope["client"]
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.send", "text": f"{scheme}://{host}:{port}"})
        await send({"type": "websocket.close"})

    app_with_middleware = ProxyHeadersMiddleware(websocket_app, trusted_hosts="*")
    config = Config(
        app=app_with_middleware,
        ws=ws_protocol_cls,
        http=http_protocol_cls,
        lifespan="off",
        port=unused_tcp_port,
    )

    async with run_server(config):
        url = f"ws://127.0.0.1:{unused_tcp_port}"
        headers = {X_FORWARDED_FOR: "1.2.3.4", X_FORWARDED_PROTO: forwarded_proto}
        async with websockets.client.connect(url, extra_headers=headers) as websocket:
            data = await websocket.recv()
            assert data == expected


@pytest.mark.anyio
async def test_proxy_headers_empty_x_forwarded_for() -> None:
    # fallback to the default behavior if x-forwarded-for is an empty list
    # https://github.com/Kludex/uvicorn/issues/1068#issuecomment-855371576
    async with make_httpx_client("*") as client:
        headers = {X_FORWARDED_FOR: "", X_FORWARDED_PROTO: "https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "https://127.0.0.1:123"


# ---------------------------------------------------------------------------
# RFC 7239 `Forwarded` header (mode="forwarded")
# ---------------------------------------------------------------------------


async def forwarded_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    """Echoes scheme, client, and host header as space-separated `key=value` pairs."""
    headers = dict(scope["headers"])  # type: ignore
    host_header = headers.get(b"host", b"").decode("latin1")
    client = scope["client"]  # type: ignore
    scheme = scope["scheme"]  # type: ignore
    assert client is not None
    body = f"scheme={scheme} client={client[0]}:{client[1]} host={host_header}"
    await Response(body, media_type="text/plain")(scope, receive, send)


def parse_echo(text: str) -> dict[str, str]:
    """Parse `forwarded_app`'s `key=value key=value ...` echo into a dict."""
    return dict(part.split("=", 1) for part in text.split(" "))


def make_forwarded_client(
    trusted_hosts: str | list[str],
    client: tuple[str, int] = ("127.0.0.1", 123),
) -> httpx.AsyncClient:
    """httpx client wired to a `mode='forwarded'` middleware over `forwarded_app`."""
    app = ProxyHeadersMiddleware(forwarded_app, trusted_hosts, mode="forwarded")
    transport = httpx.ASGITransport(app=app, client=client)  # type: ignore
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@pytest.mark.anyio
async def test_forwarded_mode_multiple_hops_picks_rightmost() -> None:
    """Walks from the right; first hop whose `for=` is not trusted is the client."""
    async with make_forwarded_client("10.0.0.0/8", client=("10.0.0.5", 1234)) as client:
        headers = {FORWARDED: "for=1.2.3.4, for=10.0.0.5;proto=http, for=10.0.0.6"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert parse_echo(response.text)["client"] == "1.2.3.4:0"


@pytest.mark.anyio
async def test_forwarded_mode_falls_back_to_leftmost_when_all_trusted() -> None:
    async with make_forwarded_client("10.0.0.0/8", client=("10.0.0.5", 1234)) as client:
        headers = {FORWARDED: "for=10.0.0.1, for=10.0.0.2"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert parse_echo(response.text)["client"] == "10.0.0.1:0"


@pytest.mark.anyio
async def test_forwarded_mode_quoted_string_escape_is_unescaped() -> None:
    """RFC 7230 quoted-string: `\\"` inside quotes decodes to a literal `"`."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: r'for="1.2.3.4";host="weird\"name"'}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert parse_echo(response.text)["client"] == "1.2.3.4:0"


@pytest.mark.anyio
async def test_forwarded_mode_case_insensitive_param_keys() -> None:
    """RFC 7239 §4: parameter names are case-insensitive."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "For=1.2.3.4;PROTO=https;Host=public.example"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["scheme"] == "https"
    assert echo["client"] == "1.2.3.4:0"
    assert echo["host"] == "public.example"


@pytest.mark.anyio
async def test_forwarded_mode_unknown_params_ignored() -> None:
    """Unrecognized parameters (here, `secret`) must not affect scope mutation."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "for=1.2.3.4;secret=hunter2;proto=https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["scheme"] == "https"


@pytest.mark.anyio
async def test_forwarded_mode_empty_header_does_not_mutate_scope() -> None:
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: ""}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    # Untouched scope: peer client is the httpx transport peer, scheme stays http.
    echo = parse_echo(response.text)
    assert echo["client"] == "127.0.0.1:123"
    assert echo["scheme"] == "http"


@pytest.mark.anyio
async def test_forwarded_mode_malformed_pair_in_entry_is_dropped_but_entry_survives() -> None:
    """Pairs without `=` are skipped, other params on the same hop survive."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "for=1.2.3.4;novalue;proto=https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["scheme"] == "https"


@pytest.mark.anyio
async def test_forwarded_mode_duplicate_param_drops_entry() -> None:
    """RFC 7239 §4: each parameter appears at most once per element. Smuggling defense -
    a single hop with two `for=` values must be rejected so an attacker cannot prepend
    a fake value that some downstream parser might pick over the real one."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "for=attacker.example;for=1.2.3.4"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    # Entire entry is dropped; scope falls through to the peer client.
    assert parse_echo(response.text)["client"] == "127.0.0.1:123"


@pytest.mark.anyio
async def test_forwarded_mode_duplicate_param_only_drops_offending_entry() -> None:
    """A poisoned entry must not contaminate a later, well-formed entry in the same header."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "for=attacker.example;for=1.2.3.4, for=5.6.7.8"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert parse_echo(response.text)["client"] == "5.6.7.8:0"


@pytest.mark.anyio
async def test_forwarded_mode_missing_for_is_unanchorable() -> None:
    """An entry without `for=` cannot identify a client and must be skipped entirely."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "host=attacker.example;proto=https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    # `host=`/`proto=` from an unanchorable entry must NOT apply to the request.
    echo = parse_echo(response.text)
    assert echo["host"] != "attacker.example"
    assert echo["scheme"] == "http"


@pytest.mark.anyio
async def test_forwarded_mode_placeholder_for_filtered_under_always_trust() -> None:
    """With `always_trust=*`, an unanchorable leftmost entry must not be the fallback."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "for=unknown;proto=https;host=attacker.example, for=1.2.3.4"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["host"] != "attacker.example"


@pytest.mark.anyio
@pytest.mark.parametrize("placeholder", ["unknown", "Unknown", "_hidden"])
async def test_forwarded_mode_placeholder_for_variants_are_unanchorable(placeholder: str) -> None:
    """`unknown` (case-insensitive) and `_*` obfuscated identifiers cannot anchor a hop."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: f"for={placeholder};host=attacker.example;proto=https"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["host"] != "attacker.example"
    assert echo["scheme"] == "http"


@pytest.mark.anyio
async def test_forwarded_mode_basic() -> None:
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "for=1.2.3.4;proto=https;host=public.example:9000"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["scheme"] == "https"
    assert echo["client"] == "1.2.3.4:0"
    assert echo["host"] == "public.example:9000"


@pytest.mark.anyio
async def test_forwarded_mode_untrusted_peer_ignored() -> None:
    async with make_forwarded_client("192.168.0.1") as client:
        headers = {FORWARDED: "for=attacker.example;proto=https;host=attacker.example"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["client"] != "attacker.example:0"
    assert echo["host"] != "attacker.example"


@pytest.mark.anyio
async def test_forwarded_mode_ipv6_quoted() -> None:
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: 'for="[2001:db8::1]:443";proto=https;host="public.example"'}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["scheme"] == "https"
    assert echo["client"] == "2001:db8::1:443"
    assert echo["host"] == "public.example"


@pytest.mark.anyio
async def test_forwarded_mode_chained_proxy_picks_rightmost_untrusted() -> None:
    """The connecting peer (10.0.0.5) and the next-to-last hop are both trusted; client = 1.2.3.4."""
    async with make_forwarded_client("10.0.0.0/8", client=("10.0.0.5", 1234)) as client:
        headers = {FORWARDED: "for=1.2.3.4;proto=https, for=10.0.0.5;proto=http;host=internal.lan"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    # The rightmost untrusted hop is `for=1.2.3.4`, which carries `proto=https` only.
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["scheme"] == "https"
    assert echo["host"] != "internal.lan"


@pytest.mark.anyio
async def test_forwarded_mode_placeholder_for_falls_through() -> None:
    """`for=unknown` is unanchorable; the next anchorable hop wins."""
    async with make_forwarded_client("10.0.0.0/8", client=("10.0.0.5", 1234)) as client:
        headers = {FORWARDED: "for=unknown;proto=https;host=attacker.example, for=1.2.3.4;proto=http"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["host"] != "attacker.example"


@pytest.mark.anyio
async def test_forwarded_mode_proto_case_insensitive() -> None:
    """RFC 3986 - URI schemes are case-insensitive. `proto=HTTPS` must work."""
    async with make_forwarded_client("*") as client:
        headers = {FORWARDED: "for=1.2.3.4;proto=HTTPS;host=public.example"}
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    assert parse_echo(response.text)["scheme"] == "https"


@pytest.mark.anyio
async def test_forwarded_mode_ignores_x_forwarded_headers() -> None:
    """When mode='forwarded', the X-Forwarded-* family must be completely ignored."""
    async with make_forwarded_client("*") as client:
        headers = {
            FORWARDED: "for=1.2.3.4;proto=https",
            X_FORWARDED_FOR: "9.9.9.9",
            X_FORWARDED_PROTO: "http",
            "X-Forwarded-Host": "attacker.example",
        }
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["scheme"] == "https"
    assert echo["host"] != "attacker.example"


@pytest.mark.anyio
async def test_x_forwarded_mode_ignores_forwarded_header() -> None:
    """And vice versa: when mode='x-forwarded' (default), `Forwarded` is ignored."""
    app = ProxyHeadersMiddleware(forwarded_app, trusted_hosts="*", mode="x-forwarded")
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))  # type: ignore
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        headers = {
            FORWARDED: "for=attacker.example;proto=https;host=attacker.example",
            X_FORWARDED_FOR: "1.2.3.4",
            X_FORWARDED_PROTO: "https",
        }
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["host"] != "attacker.example"


@pytest.mark.anyio
async def test_forwarded_mode_via_config(unused_tcp_port: int) -> None:
    """Programmatic API: `Config(proxy_headers_mode='forwarded')` wires the right mode."""
    config = Config(
        app=forwarded_app,
        loop="asyncio",
        limit_max_requests=1,
        proxy_headers_mode="forwarded",
        forwarded_allow_ips="*",
        port=unused_tcp_port,
    )
    async with run_server(config):
        async with httpx.AsyncClient() as client:
            headers = {FORWARDED: "for=1.2.3.4;proto=https;host=public.example:9000"}
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}", headers=headers)
    assert response.status_code == 200
    echo = parse_echo(response.text)
    assert echo["scheme"] == "https"
    assert echo["client"] == "1.2.3.4:0"
    assert echo["host"] == "public.example:9000"


@pytest.mark.anyio
async def test_x_forwarded_proto_last_wins_on_duplicates() -> None:
    """X-Forwarded-Proto is single-valued; if duplicated, take the rightmost (the value
    appended by the trusted upstream proxy, not a client-supplied earlier copy)."""
    async with make_httpx_client("*") as client:
        # httpx.Headers preserves multiple values for the same name in order.
        headers = httpx.Headers(
            [(X_FORWARDED_PROTO, "http"), (X_FORWARDED_PROTO, "https"), (X_FORWARDED_FOR, "1.2.3.4")]
        )
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    # The default_app echoes scheme://client; last X-Forwarded-Proto value (https) wins.
    assert response.text == "https://1.2.3.4:0"


@pytest.mark.anyio
async def test_forwarded_mode_joins_multiple_forwarded_headers() -> None:
    """Multiple `Forwarded` headers are list-equivalent per RFC 7230 §3.2.2."""
    async with make_forwarded_client("10.0.0.0/8", client=("10.0.0.5", 1234)) as client:
        headers = httpx.Headers([(FORWARDED, "for=1.2.3.4;proto=https"), (FORWARDED, "for=10.0.0.5")])
        response = await client.get("/", headers=headers)
    assert response.status_code == 200
    # Right-most untrusted in the joined list is `for=1.2.3.4` (10.0.0.5 is trusted).
    echo = parse_echo(response.text)
    assert echo["client"] == "1.2.3.4:0"
    assert echo["scheme"] == "https"

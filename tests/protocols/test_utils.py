from __future__ import annotations

import socket
from asyncio import Transport
from typing import Any

import pytest

from uvicorn.protocols.utils import get_client_addr, get_local_addr, get_origin_form_path, get_remote_addr


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


@pytest.mark.parametrize(
    "raw_path, expected",
    [
        # origin-form is already what the scope wants
        (b"/", b"/"),
        (b"/one/two", b"/one/two"),
        (b"/one%2Ftwo", b"/one%2Ftwo"),
        # absolute-form, which servers must accept (RFC 9112, section 3.2.2)
        (b"http://example.org/one/two", b"/one/two"),
        (b"https://example.org:8443/one/two", b"/one/two"),
        (b"https://user:pass@example.org:8443/one/two", b"/one/two"),
        (b"HTTP://EXAMPLE.ORG/One", b"/One"),
        (b"http://example.org/", b"/"),
        # an absolute-form target with an empty path means "/"
        (b"http://example.org", b"/"),
        # asterisk-form and authority-form are left alone
        (b"*", b"*"),
        (b"example.org:443", b"example.org:443"),
    ],
)
def test_get_origin_form_path(raw_path: bytes, expected: bytes) -> None:
    assert get_origin_form_path(raw_path) == expected

import socket

import pytest

from uvicorn.protocols.utils import get_client_addr, get_local_addr, get_remote_addr


class MockSocket:
    def __init__(self, family, peername=None, sockname=None):
        self.peername = peername
        self.sockname = sockname
        self.family = family

    def getpeername(self):
        return self.peername

    def getsockname(self):
        return self.sockname


class MockTransport:
    def __init__(self, info):
        self.info = info

    def get_extra_info(self, info_type):
        return self.info.get(info_type)


def test_get_local_addr_with_socket():
    transport = MockTransport({"socket": MockSocket(family=socket.AF_IPX)})
    assert get_local_addr(transport) is None

    transport = MockTransport(
        {"socket": MockSocket(family=socket.AF_INET6, sockname=("::1", 123))}
    )
    assert get_local_addr(transport) == ("::1", 123)

    transport = MockTransport(
        {"socket": MockSocket(family=socket.AF_INET, sockname=("123.45.6.7", 123))}
    )
    assert get_local_addr(transport) == ("123.45.6.7", 123)

    if hasattr(socket, "AF_UNIX"):  # pragma: no cover
        transport = MockTransport(
            {"socket": MockSocket(family=socket.AF_UNIX, sockname=("127.0.0.1", 8000))}
        )
        assert get_local_addr(transport) == ("127.0.0.1", 8000)


def test_get_remote_addr_with_socket():
    transport = MockTransport({"socket": MockSocket(family=socket.AF_IPX)})
    assert get_remote_addr(transport) is None

    transport = MockTransport(
        {"socket": MockSocket(family=socket.AF_INET6, peername=("::1", 123))}
    )
    assert get_remote_addr(transport) == ("::1", 123)

    transport = MockTransport(
        {"socket": MockSocket(family=socket.AF_INET, peername=("123.45.6.7", 123))}
    )
    assert get_remote_addr(transport) == ("123.45.6.7", 123)

    if hasattr(socket, "AF_UNIX"):  # pragma: no cover
        transport = MockTransport(
            {"socket": MockSocket(family=socket.AF_UNIX, peername=("127.0.0.1", 8000))}
        )
        assert get_remote_addr(transport) == ("127.0.0.1", 8000)


def test_get_local_addr():
    transport = MockTransport({"sockname": "path/to/unix-domain-socket"})
    assert get_local_addr(transport) is None

    transport = MockTransport({"sockname": ("123.45.6.7", 123)})
    assert get_local_addr(transport) == ("123.45.6.7", 123)


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
def test_get_client_addr(scope, expected_client):
    assert get_client_addr(scope) == expected_client

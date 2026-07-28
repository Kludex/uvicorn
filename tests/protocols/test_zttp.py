from __future__ import annotations

import pytest

pytest.importorskip("zttp")

from tests.protocols.test_http import SIMPLE_GET_REQUEST, get_connected_protocol  # noqa: E402
from tests.response import Response  # noqa: E402
from uvicorn.protocols.http.zttp_impl import ZttpProtocol  # noqa: E402

pytestmark = pytest.mark.anyio


async def test_transfer_encoding_stripped_when_forbidden():
    """RFC 9112 §6.1 forbids `Transfer-Encoding` on 1xx/204; zttp rejects it, so we drop it."""
    app = Response(b"", status_code=204, headers={"transfer-encoding": "chunked"})

    protocol = get_connected_protocol(app, ZttpProtocol)
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()
    assert b"HTTP/1.1 204 No Content" in protocol.transport.buffer
    assert b"transfer-encoding" not in protocol.transport.buffer.lower()


async def test_connection_close_within_multiple_tokens():
    """A `close` token in a multi-valued `Connection` header must close the connection."""
    app = Response(b"Hello, world!", status_code=200, headers={"connection": "keep-alive, close"})

    protocol = get_connected_protocol(app, ZttpProtocol)
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()
    assert b"HTTP/1.1 200 OK" in protocol.transport.buffer
    assert protocol.transport.is_closing()

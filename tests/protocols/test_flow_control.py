import asyncio
import contextvars
from unittest.mock import Mock

from uvicorn.protocols.http.flow_control import FlowControl


def test_resume_reading_in_connection_context() -> None:
    request: contextvars.ContextVar[str | None] = contextvars.ContextVar("request", default=None)
    seen: list[str | None] = []

    def resume_reading() -> None:
        seen.append(request.get())
        request.set("/transport")

    transport = Mock(spec=asyncio.Transport)
    transport.resume_reading.side_effect = resume_reading
    flow = FlowControl(transport)

    token = request.set("/first")
    try:
        for _ in range(2):
            flow.pause_reading()
            flow.resume_reading()
            assert request.get() == "/first"
    finally:
        request.reset(token)

    assert seen == [None, None]

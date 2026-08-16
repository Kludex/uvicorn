import asyncio
import signal
from asyncio import Event

import httpx
import pytest

from tests.utils import assert_signal, run_server
from uvicorn import Server
from uvicorn.config import Config


@pytest.mark.anyio
async def test_sigint_finish_req(unused_tcp_port: int):
    """
    1. Request is sent
    2. Sigint is sent to uvicorn
    3. Shutdown sequence start
    4. Request is finished before timeout_graceful_shutdown=1

    Result: Request should go through, even though the server was cancelled.
    """

    server_event = Event()

    async def wait_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"start", "more_body": True})
        await server_event.wait()
        await send({"type": "http.response.body", "body": b"end", "more_body": False})

    config = Config(app=wait_app, reload=False, port=unused_tcp_port, timeout_graceful_shutdown=1)
    server: Server
    with assert_signal(signal.SIGINT):
        async with run_server(config) as server, httpx.AsyncClient() as client:
            req = asyncio.create_task(client.get(f"http://127.0.0.1:{unused_tcp_port}"))
            await asyncio.sleep(0.1)  # ensure next tick
            server.handle_exit(sig=signal.SIGINT, frame=None)  # exit
            server_event.set()  # continue request
            # ensure httpx has processed the response and result is complete
            await req
            assert req.result().status_code == 200
            await asyncio.sleep(0.1)  # ensure shutdown is complete


@pytest.mark.anyio
async def test_sigint_abort_req(unused_tcp_port: int, caplog):
    """
    1. Request is sent
    2. Sigint is sent to uvicorn
    3. Shutdown sequence start
    4. Request is _NOT_ finished before timeout_graceful_shutdown=1

    Result: Request is cancelled mid-execution, and httpx will raise a
        `RemoteProtocolError`.
    """

    async def forever_app(scope, receive, send):
        server_event = Event()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"start", "more_body": True})
        # we never continue this one, so this request will time out
        await server_event.wait()
        await send({"type": "http.response.body", "body": b"end", "more_body": False})  # pragma: full coverage

    config = Config(app=forever_app, reload=False, port=unused_tcp_port, timeout_graceful_shutdown=1)
    server: Server
    with assert_signal(signal.SIGINT):
        async with run_server(config) as server, httpx.AsyncClient() as client:
            req = asyncio.create_task(client.get(f"http://127.0.0.1:{unused_tcp_port}"))
            await asyncio.sleep(0.1)  # next tick
            # trigger exit, this request should time out in ~1 sec
            server.handle_exit(sig=signal.SIGINT, frame=None)
            with pytest.raises(httpx.RemoteProtocolError):
                await req

    message = "Cancel 1 running task(s), timeout graceful shutdown exceeded"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 5
    while message not in caplog.messages and loop.time() < deadline:
        await asyncio.sleep(0.1)  # pragma: no cover
    assert message in caplog.messages


@pytest.mark.anyio
async def test_sigint_deny_request_after_triggered(unused_tcp_port: int, caplog):
    """
    1. Server is started
    2. Shutdown sequence start
    3. Request is sent, but not accepted

    Result: Request should fail, and not be able to be sent, since server is no longer
        accepting connections.
    """

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await asyncio.sleep(1)  # pragma: full coverage

    config = Config(app=app, reload=False, port=unused_tcp_port, timeout_graceful_shutdown=1)
    server: Server
    with assert_signal(signal.SIGINT):
        async with run_server(config) as server, httpx.AsyncClient() as client:
            # exit and ensure we do not accept more requests
            server.handle_exit(sig=signal.SIGINT, frame=None)
            await asyncio.sleep(0.1)  # next tick
            with pytest.raises(httpx.ConnectError):
                await client.get(f"http://127.0.0.1:{unused_tcp_port}")

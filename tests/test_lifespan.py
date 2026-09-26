import asyncio
import logging

import pytest

from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.lifespan.on import LifespanOn


def test_lifespan_on():
    startup_complete = False
    shutdown_complete = False

    async def app(scope, receive, send):
        nonlocal startup_complete, shutdown_complete
        message = await receive()
        assert message["type"] == "lifespan.startup"
        startup_complete = True
        await send({"type": "lifespan.startup.complete"})
        message = await receive()
        assert message["type"] == "lifespan.shutdown"
        shutdown_complete = True
        await send({"type": "lifespan.shutdown.complete"})

    async def test():
        config = Config(app=app, lifespan="on")
        lifespan = LifespanOn(config)

        assert not startup_complete
        assert not shutdown_complete
        await lifespan.startup()
        assert startup_complete
        assert not shutdown_complete
        await lifespan.shutdown()
        assert startup_complete
        assert shutdown_complete

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


def test_lifespan_off():
    async def app(scope, receive, send):
        pass  # pragma: no cover

    async def test():
        config = Config(app=app, lifespan="off")
        lifespan = LifespanOff(config)

        await lifespan.startup()
        await lifespan.shutdown()
        lifespan.cancel()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


def test_lifespan_auto():
    startup_complete = False
    shutdown_complete = False

    async def app(scope, receive, send):
        nonlocal startup_complete, shutdown_complete
        message = await receive()
        assert message["type"] == "lifespan.startup"
        startup_complete = True
        await send({"type": "lifespan.startup.complete"})
        message = await receive()
        assert message["type"] == "lifespan.shutdown"
        shutdown_complete = True
        await send({"type": "lifespan.shutdown.complete"})

    async def test():
        config = Config(app=app, lifespan="auto")
        lifespan = LifespanOn(config)

        assert not startup_complete
        assert not shutdown_complete
        await lifespan.startup()
        assert startup_complete
        assert not shutdown_complete
        await lifespan.shutdown()
        assert startup_complete
        assert shutdown_complete

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


def test_lifespan_auto_with_error():
    async def app(scope, receive, send):
        assert scope["type"] == "http"

    async def test():
        config = Config(app=app, lifespan="auto")
        lifespan = LifespanOn(config)

        await lifespan.startup()
        assert lifespan.error_occurred
        assert not lifespan.should_exit
        await lifespan.shutdown()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


def test_lifespan_on_with_error():
    async def app(scope, receive, send):
        if scope["type"] != "http":
            raise RuntimeError()

    async def test():
        config = Config(app=app, lifespan="on")
        lifespan = LifespanOn(config)

        await lifespan.startup()
        assert lifespan.error_occurred
        assert lifespan.should_exit
        await lifespan.shutdown()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


@pytest.mark.parametrize("mode", ("auto", "on"))
@pytest.mark.parametrize("raise_exception", (True, False))
def test_lifespan_with_failed_startup(mode, raise_exception, caplog):
    async def app(scope, receive, send):
        message = await receive()
        assert message["type"] == "lifespan.startup"
        await send({"type": "lifespan.startup.failed", "message": "the lifespan event failed"})
        if raise_exception:
            # App should be able to re-raise an exception if startup failed.
            raise RuntimeError()

    async def test():
        config = Config(app=app, lifespan=mode)
        lifespan = LifespanOn(config)

        await lifespan.startup()
        assert lifespan.startup_failed
        assert lifespan.error_occurred is raise_exception
        assert lifespan.should_exit
        await lifespan.shutdown()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()
    error_messages = [
        record.message for record in caplog.records if record.name == "uvicorn.error" and record.levelname == "ERROR"
    ]
    assert "the lifespan event failed" in error_messages.pop(0)
    assert "Application startup failed. Exiting." in error_messages.pop(0)


def test_lifespan_cancel_before_main_task_runs():
    """cancel() must unblock startup() even if the lifespan task is cancelled
    before its coroutine ever runs, in which case main()'s try/finally never
    executes. Regression test for https://github.com/encode/uvicorn/issues/2751."""

    async def app(scope, receive, send):  # pragma: no cover
        pass

    async def test():
        config = Config(app=app, lifespan="auto")
        lifespan = LifespanOn(config)

        loop = asyncio.get_event_loop()
        lifespan.main_lifespan_task = loop.create_task(lifespan.main())
        # Cancel before the event loop has ever scheduled main() to run.
        lifespan.cancel()

        # Must complete instead of hanging forever.
        await asyncio.wait_for(lifespan.startup_event.wait(), timeout=3)
        assert lifespan.shutdown_event.is_set()
        assert lifespan.error_occurred
        assert lifespan.startup_failed

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


def test_lifespan_cancel_while_frozen_in_startup(caplog):
    """Cancelling an app frozen inside lifespan startup must report the startup
    as interrupted/failed, not 'Application startup complete.'."""
    caplog.set_level(logging.INFO, logger="uvicorn.error")

    async def app(scope, receive, send):
        message = await receive()
        assert message["type"] == "lifespan.startup"
        await asyncio.sleep(30)  # pragma: no cover  # Never yields control back.

    async def test():
        config = Config(app=app, lifespan="auto")
        lifespan = LifespanOn(config)

        startup_task = asyncio.create_task(lifespan.startup())
        # Let the app reach its frozen await inside startup handling.
        for _ in range(10):
            await asyncio.sleep(0)
        assert not lifespan.startup_event.is_set()

        lifespan.cancel()
        await asyncio.wait_for(startup_task, timeout=3)

        assert lifespan.error_occurred
        assert lifespan.startup_failed
        assert lifespan.should_exit

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()
    messages = [record.message for record in caplog.records if record.name == "uvicorn.error"]
    assert "Application startup interrupted." in messages
    assert "Application startup failed. Exiting." in messages
    assert "Application startup complete." not in messages


def test_lifespan_scope_asgi3app():
    async def asgi3app(scope, receive, send):
        assert scope == {
            "type": "lifespan",
            "asgi": {"version": "3.0", "spec_version": "2.0"},
            "state": {},
        }

    async def test():
        config = Config(app=asgi3app, lifespan="on")
        lifespan = LifespanOn(config)

        await lifespan.startup()
        assert not lifespan.startup_failed
        assert not lifespan.error_occurred
        assert not lifespan.should_exit
        await lifespan.shutdown()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


def test_lifespan_scope_asgi2app():
    def asgi2app(scope):
        assert scope == {
            "type": "lifespan",
            "asgi": {"version": "2.0", "spec_version": "2.0"},
            "state": {},
        }

        async def asgi(receive, send):
            pass

        return asgi

    async def test():
        config = Config(app=asgi2app, lifespan="on")
        lifespan = LifespanOn(config)

        await lifespan.startup()
        await lifespan.shutdown()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()


@pytest.mark.parametrize("mode", ("auto", "on"))
@pytest.mark.parametrize("raise_exception", (True, False))
def test_lifespan_with_failed_shutdown(mode, raise_exception, caplog):
    async def app(scope, receive, send):
        message = await receive()
        assert message["type"] == "lifespan.startup"
        await send({"type": "lifespan.startup.complete"})
        message = await receive()
        assert message["type"] == "lifespan.shutdown"
        await send({"type": "lifespan.shutdown.failed", "message": "the lifespan event failed"})

        if raise_exception:
            # App should be able to re-raise an exception if startup failed.
            raise RuntimeError()

    async def test():
        config = Config(app=app, lifespan=mode)
        lifespan = LifespanOn(config)

        await lifespan.startup()
        assert not lifespan.startup_failed
        await lifespan.shutdown()
        assert lifespan.shutdown_failed
        assert lifespan.error_occurred is raise_exception
        assert lifespan.should_exit

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    error_messages = [
        record.message for record in caplog.records if record.name == "uvicorn.error" and record.levelname == "ERROR"
    ]
    assert "the lifespan event failed" in error_messages.pop(0)
    assert "Application shutdown failed. Exiting." in error_messages.pop(0)
    loop.close()


def test_lifespan_state():
    async def app(scope, receive, send):
        message = await receive()
        assert message["type"] == "lifespan.startup"
        await send({"type": "lifespan.startup.complete"})
        scope["state"]["foo"] = 123
        message = await receive()
        assert message["type"] == "lifespan.shutdown"
        await send({"type": "lifespan.shutdown.complete"})

    async def test():
        config = Config(app=app, lifespan="on")
        lifespan = LifespanOn(config)

        await lifespan.startup()
        assert lifespan.state == {"foo": 123}
        await lifespan.shutdown()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(test())
    loop.close()

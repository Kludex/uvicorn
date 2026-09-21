from __future__ import annotations

import asyncio
from asyncio import AbstractEventLoop

import pytest

from tests.custom_loop_utils import CustomLoop
from tests.utils import get_asyncio_default_loop_per_os
from uvicorn._compat import asyncio_run


async def assert_event_loop(expected_loop_class: type[AbstractEventLoop]):
    assert isinstance(asyncio.get_running_loop(), expected_loop_class)


def test_asyncio_run__default_loop_factory() -> None:
    asyncio_run(assert_event_loop(get_asyncio_default_loop_per_os()), loop_factory=None)


def test_asyncio_run__custom_loop_factory() -> None:
    asyncio_run(assert_event_loop(CustomLoop), loop_factory=CustomLoop)


def test_asyncio_run__passing_a_non_awaitable_callback_should_throw_error() -> None:
    # TypeError on Python >= 3.14
    with pytest.raises((ValueError, TypeError)):
        asyncio_run(lambda: None, loop_factory=CustomLoop)  # type: ignore

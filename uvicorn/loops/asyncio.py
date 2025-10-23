from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable


def asyncio_loop_factory(use_subprocess: bool = False) -> Callable[[], asyncio.AbstractEventLoop]:
    if sys.platform == "win32" and not use_subprocess:  # pragma: py-not-win32
        return asyncio.ProactorEventLoop
    return asyncio.SelectorEventLoop  # pragma: py-win32

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable


def auto_loop_factory(use_subprocess: bool = False) -> Callable[[], asyncio.AbstractEventLoop]:
    try:
        if sys.platform == "win32":
            from uvicorn.loops.winloop import winloop_loop_factory as loop_factory
        else:
            from uvicorn.loops.uvloop import uvloop_loop_factory as loop_factory
    except ImportError:  # pragma: no cover
        from uvicorn.loops.asyncio import asyncio_loop_factory as loop_factory
    return loop_factory(use_subprocess=use_subprocess)

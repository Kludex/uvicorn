from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

__all__ = ["asyncio_run", "iscoroutinefunction"]

if sys.version_info >= (3, 14):
    from inspect import iscoroutinefunction
else:
    from asyncio import iscoroutinefunction

_T = TypeVar("_T")

if sys.version_info >= (3, 12):
    asyncio_run = asyncio.run
else:

    def asyncio_run(
        main: Coroutine[Any, Any, _T],
        *,
        debug: bool = False,
        loop_factory: Callable[[], asyncio.AbstractEventLoop] | None = None,
    ) -> _T:
        # asyncio.run from Python 3.12
        # https://docs.python.org/3/license.html#psf-license
        with asyncio.Runner(debug=debug, loop_factory=loop_factory) as runner:
            return runner.run(main)

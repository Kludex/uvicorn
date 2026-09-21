from __future__ import annotations

import sys

__all__ = ["iscoroutinefunction"]

if sys.version_info >= (3, 14):
    from inspect import iscoroutinefunction
else:
    from asyncio import iscoroutinefunction

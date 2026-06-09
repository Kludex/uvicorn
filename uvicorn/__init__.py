from __future__ import annotations

from typing import TYPE_CHECKING, Any

from uvicorn.config import Config
from uvicorn.server import Server

if TYPE_CHECKING:
    from uvicorn.main import run

__version__ = "0.49.0"
__all__ = ["run", "Config", "Server"]


def __getattr__(name: str) -> Any:
    if name == "run":
        from uvicorn.main import run

        return run
    raise AttributeError(f"module {__name__} has no attribute {name}")

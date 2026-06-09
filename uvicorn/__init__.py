from typing import TYPE_CHECKING, Any

from uvicorn._run import run
from uvicorn.config import Config
from uvicorn.server import Server

if TYPE_CHECKING:
    from uvicorn.main import main

__version__ = "0.49.0"
__all__ = ["main", "run", "Config", "Server"]


def __getattr__(name: str) -> Any:  # pragma: no cover
    if name == "main":
        from uvicorn.main import main

        globals()["main"] = main
        return main
    raise AttributeError(f"module {__name__} has no attribute {name}")

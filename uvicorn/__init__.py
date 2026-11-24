from importlib.metadata import version as _metadata_version

from uvicorn.config import Config
from uvicorn.main import Server, main, run

__version__ = _metadata_version("uvicorn")
__all__ = ["main", "run", "Config", "Server"]

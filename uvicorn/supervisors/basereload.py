from __future__ import annotations

from pathlib import Path

from uvicorn.config import Config


class BaseReload:
    """Watches the application's files and reports changes to the supervisor."""

    reloader_name: str | None = None

    def __init__(self, config: Config) -> None:
        self.config = config

    def should_restart(self) -> list[Path] | None:
        raise NotImplementedError("Reload strategies should override should_restart()")


def _display_path(path: Path) -> str:
    try:
        return f"'{path.relative_to(Path.cwd())}'"
    except ValueError:
        return f"'{path}'"

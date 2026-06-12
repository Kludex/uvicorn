from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from uvicorn.config import Config
from uvicorn.supervisors.basereload import BaseReload

logger = logging.getLogger("uvicorn.error")


class StatReload(BaseReload):
    reloader_name = "StatReload"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.mtimes: dict[Path, float] = {}

        if config.reload_excludes or config.reload_includes:
            logger.warning("--reload-include and --reload-exclude have no effect unless watchfiles is installed.")

    def should_restart(self) -> list[Path] | None:
        for file in self.iter_py_files():
            try:
                mtime = file.stat().st_mtime
            except OSError:  # pragma: nocover
                continue

            old_time = self.mtimes.get(file)
            if old_time is None:
                self.mtimes[file] = mtime
                continue
            elif mtime > old_time:
                # Reset so the baseline is rebuilt after the restart, instead of
                # reporting the same change again on the next scan.
                self.mtimes = {}
                return [file]
        return None

    def iter_py_files(self) -> Iterator[Path]:
        for reload_dir in self.config.reload_dirs:
            for path in list(reload_dir.rglob("*.py")):
                yield path.resolve()

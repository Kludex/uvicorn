from __future__ import annotations

from pathlib import Path

from watchfiles import watch

from uvicorn.config import Config
from uvicorn.supervisors.basereload import BaseReload


class FileFilter:
    def __init__(self, config: Config):
        default_includes = ["*.py"]
        self.includes = [default for default in default_includes if default not in config.reload_excludes]
        self.includes.extend(config.reload_includes)
        self.includes = list(set(self.includes))

        default_excludes = [".*", ".py[cod]", ".sw.*", "~*"]
        self.excludes = [default for default in default_excludes if default not in config.reload_includes]
        self.exclude_dirs = []
        for e in config.reload_excludes:
            p = Path(e)
            try:
                is_dir = p.is_dir()
            except OSError:  # pragma: no cover
                # gets raised on Windows for values like "*.py"
                is_dir = False

            if is_dir:
                self.exclude_dirs.append(p)
            else:
                self.excludes.append(e)  # pragma: full coverage
        self.excludes = list(set(self.excludes))

    def __call__(self, path: Path) -> bool:
        for include_pattern in self.includes:
            if path.match(include_pattern):
                if str(path).endswith(include_pattern):
                    return True  # pragma: full coverage

                for exclude_dir in self.exclude_dirs:
                    if exclude_dir in path.parents:
                        return False  # pragma: no cover

                for exclude_pattern in self.excludes:
                    if path.match(exclude_pattern):
                        return False  # pragma: full coverage

                return True
        return False


class WatchFilesReload(BaseReload):
    reloader_name = "WatchFiles"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.reload_dirs: list[Path] = []
        for directory in config.reload_dirs:
            self.reload_dirs.append(directory)

        self.watch_filter = FileFilter(config)
        self.watcher = watch(
            *self.reload_dirs,
            watch_filter=None,
            # Return control to the supervisor loop on a short timeout, so it stays
            # responsive to signals and worker deaths while watching for changes.
            rust_timeout=max(int(config.reload_delay * 1000), 100),
            yield_on_timeout=True,
            ignore_permission_denied=True,
        )

    def should_restart(self) -> list[Path] | None:
        changes = next(self.watcher)
        if changes:
            unique_paths = {Path(c[1]) for c in changes}
            return [p for p in unique_paths if self.watch_filter(p)]
        return None

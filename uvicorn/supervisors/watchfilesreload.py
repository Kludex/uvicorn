from __future__ import annotations

from pathlib import Path
from socket import socket
from typing import Callable

from watchfiles import watch

from uvicorn.config import Config
from uvicorn.supervisors.basereload import BaseReload


class FileFilter:
    def __init__(self, config: Config):
        default_includes = ["*.py"]
        self.includes = list(
            # Remove any included defaults that are excluded
            (set(default_includes) - set(config.reload_excludes))
            # Merge with any user-provided includes
            | set(config.reload_includes)
        )

        self.exclude_dirs = []
        """List of excluded directories resolved to absolute paths"""

        for e in config.reload_excludes:
            p = Path(e)
            try:
                if p.is_dir():
                    # Storing absolute path to always match `path.parents` values (which are absolute)
                    self.exclude_dirs.append(p.absolute())
            except OSError:  # pragma: no cover
                # gets raised on Windows for values like "*.py"
                pass

        default_excludes = [".*", ".py[cod]", ".sw.*", "~*"]
        self.excludes = list(
            # Remove any excluded defaults that are included
            (set(default_excludes) - set(config.reload_includes))
            # Merge with any user-provided excludes (excluding directories)
            | (set(config.reload_excludes) - set(str(ex_dir) for ex_dir in self.exclude_dirs))
        )

        self._exclude_dir_names_set = set(
            exclude for exclude in config.reload_excludes if "*" not in exclude and "/" not in exclude
        )
        """Set of excluded directory names that do not contain a wildcard or path separator"""

    def __call__(self, path: Path) -> bool:
        for include_pattern in self.includes:
            if path.match(include_pattern):
                if str(path).endswith(include_pattern):
                    return True  # pragma: full coverage

                # Exclude if the pattern matches the file path
                for exclude_pattern in self.excludes:
                    if path.match(exclude_pattern):
                        return False  # pragma: full coverage

                # Exclude if any parent of the path is an excluded directory
                # Ex: `/www/xxx/yyy/z.txt` will be excluded if
                # * `/www` or `/www/xxx` is in the exclude list
                # * `xxx/yyy` is in the exclude list and the current directory is `/www`
                path_parents = path.parents
                for exclude_dir in self.exclude_dirs:
                    if exclude_dir in path_parents:
                        return False

                # Exclude if any parent directory name is an exact match to an excluded value
                # Ex: `aaa/bbb/ccc/d.txt` will be excluded if `bbb` is in the exclude list,
                #     but not `bb` or `bb*` or `bbb/**`
                if set(path.parent.parts) & self._exclude_dir_names_set:
                    return False

                return True
        return False


class WatchFilesReload(BaseReload):
    def __init__(
        self,
        config: Config,
        target: Callable[[list[socket] | None], None],
        sockets: list[socket],
    ) -> None:
        super().__init__(config, target, sockets)
        self.reloader_name = "WatchFiles"
        self.reload_dirs = []
        for directory in config.reload_dirs:
            self.reload_dirs.append(directory)

        self.watch_filter = FileFilter(config)
        self.watcher = watch(
            *self.reload_dirs,
            watch_filter=None,
            stop_event=self.should_exit,
            # using yield_on_timeout here mostly to make sure tests don't
            # hang forever, won't affect the class's behavior
            yield_on_timeout=True,
        )

    def should_restart(self) -> list[Path] | None:
        self.pause()

        changes = next(self.watcher)
        if changes:
            unique_paths = {Path(c[1]) for c in changes}
            return [p for p in unique_paths if self.watch_filter(p)]
        return None

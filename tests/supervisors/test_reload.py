from __future__ import annotations

import signal
import socket
import sys
from collections.abc import Generator
from pathlib import Path
from threading import Thread
from time import sleep
from typing import Callable

import pytest
from pytest_mock import MockerFixture

from tests.utils import as_cwd
from uvicorn.config import Config
from uvicorn.supervisors.basereload import BaseReload, _display_path
from uvicorn.supervisors.statreload import StatReload

try:
    from uvicorn.supervisors.watchfilesreload import WatchFilesReload
except ImportError:  # pragma: no cover
    WatchFilesReload = None  # type: ignore[misc,assignment]


# TODO: Investigate why this is flaky on MacOS, and Windows.
skip_non_linux = pytest.mark.skipif(sys.platform in ("darwin", "win32"), reason="Flaky on Windows and MacOS")


def run(sockets: list[socket.socket] | None) -> None:
    pass  # pragma: no cover


def sleep_touch(*paths: Path):
    sleep(0.1)
    for p in paths:
        p.touch()


@pytest.fixture
def touch_soon() -> Generator[Callable[[Path], None]]:
    threads: list[Thread] = []

    def start(*paths: Path) -> None:
        thread = Thread(target=sleep_touch, args=paths)
        thread.start()
        threads.append(thread)

    yield start

    for t in threads:
        t.join()


class TestBaseReload:
    @pytest.fixture(autouse=True)
    def setup(self, reload_directory_structure: Path, reloader_class: type[BaseReload] | None):
        if reloader_class is None:  # pragma: no cover
            pytest.skip("Needed dependency not installed")
        self.reload_path = reload_directory_structure
        self.reloader_class = reloader_class

    def _setup_reloader(self, config: Config) -> BaseReload:
        config.reload_delay = 0  # save time

        reloader = self.reloader_class(config, target=run, sockets=[])

        assert config.should_reload
        reloader.startup()
        return reloader

    def _reload_tester(
        self, touch_soon: Callable[[Path], None], reloader: BaseReload, *files: Path
    ) -> list[Path] | None:
        reloader.restart()
        if WatchFilesReload is not None and isinstance(reloader, WatchFilesReload):
            touch_soon(*files)
        else:
            assert not next(reloader)
            sleep(0.1)
            for file in files:
                file.touch()
        return next(reloader)

    @pytest.mark.parametrize("reloader_class", [StatReload, WatchFilesReload])
    def test_reloader_should_initialize(self) -> None:
        """
        A basic sanity check.

        Simply run the reloader against a no-op server, and signal for it to
        quit immediately.
        """
        with as_cwd(self.reload_path):
            config = Config(app="tests.test_config:asgi_app", reload=True)
            reloader = self._setup_reloader(config)
            reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [StatReload, pytest.param(WatchFilesReload, marks=skip_non_linux)])
    def test_reload_when_python_file_is_changed(self, touch_soon: Callable[[Path], None]):
        file = self.reload_path / "main.py"

        with as_cwd(self.reload_path):
            config = Config(app="tests.test_config:asgi_app", reload=True)
            reloader = self._setup_reloader(config)

            changes = self._reload_tester(touch_soon, reloader, file)
            assert changes == [file]

            reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [StatReload, WatchFilesReload])
    def test_should_reload_when_python_file_in_subdir_is_changed(self, touch_soon: Callable[[Path], None]):
        file = self.reload_path / "app" / "sub" / "sub.py"

        with as_cwd(self.reload_path):
            config = Config(app="tests.test_config:asgi_app", reload=True)
            reloader = self._setup_reloader(config)

            assert self._reload_tester(touch_soon, reloader, file)

            reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [WatchFilesReload])
    def test_should_not_reload_when_python_file_in_excluded_subdir_is_changed(self, touch_soon: Callable[[Path], None]):
        sub_dir = self.reload_path / "app" / "sub"
        sub_file = sub_dir / "sub.py"

        with as_cwd(self.reload_path):
            config = Config(
                app="tests.test_config:asgi_app",
                reload=True,
                reload_excludes=[str(sub_dir.relative_to(self.reload_path))],  # make it relative to current working dir
            )
            reloader = self._setup_reloader(config)

            assert not self._reload_tester(touch_soon, reloader, sub_file)

            reloader.shutdown()

    @pytest.mark.parametrize(
        "reloader_class, result", [(StatReload, False), pytest.param(WatchFilesReload, True, marks=skip_non_linux)]
    )
    def test_reload_when_pattern_matched_file_is_changed(
        self, result: bool, touch_soon: Callable[[Path], None]
    ):  # pragma: py-not-linux
        file = self.reload_path / "app" / "js" / "main.js"

        with as_cwd(self.reload_path):
            config = Config(app="tests.test_config:asgi_app", reload=True, reload_includes=["*.js"])
            reloader = self._setup_reloader(config)

            assert bool(self._reload_tester(touch_soon, reloader, file)) == result

            reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [pytest.param(WatchFilesReload, marks=skip_non_linux)])
    def test_should_not_reload_when_exclude_pattern_match_file_is_changed(
        self, touch_soon: Callable[[Path], None]
    ):  # pragma: py-not-linux
        python_file = self.reload_path / "app" / "src" / "main.py"
        css_file = self.reload_path / "app" / "css" / "main.css"
        js_file = self.reload_path / "app" / "js" / "main.js"

        with as_cwd(self.reload_path):
            config = Config(
                app="tests.test_config:asgi_app",
                reload=True,
                reload_includes=["*"],
                reload_excludes=["*.js"],
            )
            reloader = self._setup_reloader(config)

            assert self._reload_tester(touch_soon, reloader, python_file)
            assert self._reload_tester(touch_soon, reloader, css_file)
            assert not self._reload_tester(touch_soon, reloader, js_file)

            reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [StatReload, WatchFilesReload])
    def test_should_not_reload_when_dot_file_is_changed(self, touch_soon: Callable[[Path], None]):
        file = self.reload_path / ".dotted"

        with as_cwd(self.reload_path):
            config = Config(app="tests.test_config:asgi_app", reload=True)
            reloader = self._setup_reloader(config)

            assert not self._reload_tester(touch_soon, reloader, file)

            reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [StatReload, pytest.param(WatchFilesReload, marks=skip_non_linux)])
    def test_should_reload_when_directories_have_same_prefix(
        self, touch_soon: Callable[[Path], None]
    ):  # pragma: py-not-linux
        app_dir = self.reload_path / "app"
        app_file = app_dir / "src" / "main.py"
        app_first_dir = self.reload_path / "app_first"
        app_first_file = app_first_dir / "src" / "main.py"

        with as_cwd(self.reload_path):
            config = Config(
                app="tests.test_config:asgi_app",
                reload=True,
                reload_dirs=[str(app_dir), str(app_first_dir)],
            )
            reloader = self._setup_reloader(config)

            assert self._reload_tester(touch_soon, reloader, app_file)
            assert self._reload_tester(touch_soon, reloader, app_first_file)

            reloader.shutdown()

    @pytest.mark.parametrize(
        "reloader_class",
        [StatReload, pytest.param(WatchFilesReload, marks=skip_non_linux)],
    )
    def test_should_not_reload_when_only_subdirectory_is_watched(
        self, touch_soon: Callable[[Path], None]
    ):  # pragma: py-not-linux
        app_dir = self.reload_path / "app"
        app_dir_file = self.reload_path / "app" / "src" / "main.py"
        root_file = self.reload_path / "main.py"

        config = Config(
            app="tests.test_config:asgi_app",
            reload=True,
            reload_dirs=[str(app_dir)],
        )
        reloader = self._setup_reloader(config)

        assert self._reload_tester(touch_soon, reloader, app_dir_file)
        assert not self._reload_tester(touch_soon, reloader, root_file, app_dir / "~ignored")

        reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [pytest.param(WatchFilesReload, marks=skip_non_linux)])
    def test_override_defaults(self, touch_soon: Callable[[Path], None]) -> None:  # pragma: py-not-linux
        dotted_file = self.reload_path / ".dotted"
        dotted_dir_file = self.reload_path / ".dotted_dir" / "file.txt"
        python_file = self.reload_path / "main.py"

        with as_cwd(self.reload_path):
            config = Config(
                app="tests.test_config:asgi_app",
                reload=True,
                # We need to add *.txt otherwise no regular files will match
                reload_includes=[".*", "*.txt"],
                reload_excludes=["*.py"],
            )
            reloader = self._setup_reloader(config)

            assert self._reload_tester(touch_soon, reloader, dotted_file)
            assert self._reload_tester(touch_soon, reloader, dotted_dir_file)
            assert not self._reload_tester(touch_soon, reloader, python_file)

            reloader.shutdown()

    @pytest.mark.parametrize("reloader_class", [pytest.param(WatchFilesReload, marks=skip_non_linux)])
    def test_explicit_paths(self, touch_soon: Callable[[Path], None]) -> None:  # pragma: py-not-linux
        dotted_file = self.reload_path / ".dotted"
        non_dotted_file = self.reload_path / "ext" / "ext.jpg"
        python_file = self.reload_path / "main.py"

        with as_cwd(self.reload_path):
            config = Config(
                app="tests.test_config:asgi_app",
                reload=True,
                reload_includes=[".dotted", "ext/ext.jpg"],
            )
            reloader = self._setup_reloader(config)

            assert self._reload_tester(touch_soon, reloader, dotted_file)
            assert self._reload_tester(touch_soon, reloader, non_dotted_file)
            assert self._reload_tester(touch_soon, reloader, python_file)

            reloader.shutdown()

    @pytest.mark.skipif(WatchFilesReload is None, reason="watchfiles not available")
    @pytest.mark.parametrize("reloader_class", [WatchFilesReload])
    def test_watchfiles_no_changes(self) -> None:
        sub_dir = self.reload_path / "app" / "sub"

        with as_cwd(self.reload_path):
            config = Config(
                app="tests.test_config:asgi_app",
                reload=True,
                reload_excludes=[str(sub_dir.relative_to(self.reload_path))],  # make it relative to current working dir
            )
            reloader = self._setup_reloader(config)

            from watchfiles import watch

            assert isinstance(reloader, WatchFilesReload)
            # just so we can make rust_timeout 100ms
            reloader.watcher = watch(
                sub_dir,
                watch_filter=None,
                stop_event=reloader.should_exit,
                yield_on_timeout=True,
                rust_timeout=100,
            )

            assert reloader.should_restart() is None

            reloader.shutdown()


@pytest.mark.skipif(WatchFilesReload is None, reason="watchfiles not available")
def test_should_watch_cwd(mocker: MockerFixture, reload_directory_structure: Path):
    mock_watch = mocker.patch("uvicorn.supervisors.watchfilesreload.watch")

    config = Config(app="tests.test_config:asgi_app", reload=True, reload_dirs=[])
    WatchFilesReload(config, target=run, sockets=[])
    mock_watch.assert_called_once()
    assert mock_watch.call_args[0] == (Path.cwd(),)


@pytest.mark.skipif(WatchFilesReload is None, reason="watchfiles not available")
def test_should_watch_multiple_dirs(mocker: MockerFixture, reload_directory_structure: Path):
    mock_watch = mocker.patch("uvicorn.supervisors.watchfilesreload.watch")
    app_dir = reload_directory_structure / "app"
    app_first_dir = reload_directory_structure / "app_first"
    config = Config(
        app="tests.test_config:asgi_app",
        reload=True,
        reload_dirs=[str(app_dir), str(app_first_dir)],
    )
    WatchFilesReload(config, target=run, sockets=[])
    mock_watch.assert_called_once()
    assert set(mock_watch.call_args[0]) == {
        app_dir,
        app_first_dir,
    }


def test_display_path_relative(tmp_path: Path):
    with as_cwd(tmp_path):
        p = tmp_path / "app" / "foobar.py"
        # accept windows paths as wells as posix
        assert _display_path(p) in ("'app/foobar.py'", "'app\\foobar.py'")


def test_display_path_non_relative():
    p = Path("/foo/bar.py")
    assert _display_path(p) in ("'/foo/bar.py'", "'\\foo\\bar.py'")


def test_base_reloader_run(tmp_path: Path):
    calls: list[str] = []
    step = 0

    class CustomReload(BaseReload):
        def startup(self):
            calls.append("startup")

        def restart(self):
            calls.append("restart")

        def shutdown(self):
            calls.append("shutdown")

        def should_restart(self):
            nonlocal step
            step += 1
            if step == 1:
                return None
            elif step == 2:
                return [tmp_path / "foobar.py"]
            else:
                raise StopIteration()

    config = Config(app="tests.test_config:asgi_app", reload=True)
    reloader = CustomReload(config, target=run, sockets=[])
    reloader.run()

    assert calls == ["startup", "restart", "shutdown"]


def test_base_reloader_should_exit(tmp_path: Path):
    config = Config(app="tests.test_config:asgi_app", reload=True)
    reloader = BaseReload(config, target=run, sockets=[])
    assert not reloader.should_exit.is_set()
    reloader.pause()

    if sys.platform == "win32":
        reloader.signal_handler(signal.CTRL_C_EVENT, None)  # pragma: py-not-win32
    else:
        reloader.signal_handler(signal.SIGINT, None)  # pragma: py-win32

    assert reloader.should_exit.is_set()
    with pytest.raises(StopIteration):
        reloader.pause()


def test_base_reloader_closes_sockets_on_shutdown():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    config = Config(app="tests.test_config:asgi_app", reload=True)
    reloader = BaseReload(config, target=run, sockets=[sock])
    reloader.startup()
    assert sock.fileno() != -1
    reloader.shutdown()
    assert sock.fileno() == -1

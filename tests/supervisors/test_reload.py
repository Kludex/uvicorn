from __future__ import annotations

import multiprocessing
import signal
import socket
import subprocess
import sys
from collections.abc import Callable, Generator
from multiprocessing.synchronize import Event
from pathlib import Path
from threading import Thread
from time import monotonic, sleep

import pytest
from pytest_mock import MockerFixture

from tests.utils import as_cwd
from uvicorn.config import Config
from uvicorn.supervisors.basereload import BaseReload, _display_path
from uvicorn.supervisors.statreload import StatReload

try:
    from uvicorn.supervisors.watchfilesreload import FileFilter, WatchFilesReload
except ImportError:  # pragma: no cover
    WatchFilesReload = None  # type: ignore[misc,assignment]


# TODO: Investigate why this is flaky on MacOS, and Windows.
skip_non_linux = pytest.mark.skipif(sys.platform in ("darwin", "win32"), reason="Flaky on Windows and MacOS")


def run(sockets: list[socket.socket] | None) -> None:
    pass  # pragma: no cover


def create_shutdown_event() -> Event:
    return multiprocessing.get_context("spawn").Event()


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

        shutdown_event = create_shutdown_event()
        reloader = self.reloader_class(config, target=run, sockets=[], shutdown_event=shutdown_event)

        assert reloader.shutdown_event is shutdown_event
        assert config.should_reload
        reloader.startup()
        return reloader

    def _reload_tester(
        self, touch_soon: Callable[[Path], None], reloader: BaseReload, *files: Path
    ) -> list[Path] | None:
        reloader.restart()
        if WatchFilesReload is not None and isinstance(reloader, WatchFilesReload):
            touch_soon(*files)
            # Poll until the touched files are reported, ignoring unrelated churn.
            expected = set(files)
            deadline = monotonic() + 5
            seen: set[Path] = set()
            while monotonic() < deadline:
                changes = next(reloader)
                if changes:
                    seen.update(p for p in changes if p in expected)
                    if seen == expected:
                        break
            return sorted(seen) if seen else None
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
                reload_excludes=[str(sub_dir)],
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
                reload_excludes=[str(sub_dir)],
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
    WatchFilesReload(config, target=run, sockets=[], shutdown_event=create_shutdown_event())
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
    WatchFilesReload(config, target=run, sockets=[], shutdown_event=create_shutdown_event())
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
    reloader = CustomReload(config, target=run, sockets=[], shutdown_event=create_shutdown_event())
    reloader.run()

    assert calls == ["startup", "restart", "shutdown"]


def test_base_reloader_should_exit(tmp_path: Path):
    config = Config(app="tests.test_config:asgi_app", reload=True)
    reloader = BaseReload(config, target=run, sockets=[], shutdown_event=create_shutdown_event())
    assert not reloader.should_exit.is_set()
    reloader.pause()

    if sys.platform == "win32":
        reloader.signal_handler(signal.CTRL_C_EVENT, None)  # pragma: py-not-win32
    else:
        reloader.signal_handler(signal.SIGINT, None)  # pragma: py-win32

    assert reloader.should_exit.is_set()
    with pytest.raises(StopIteration):
        reloader.pause()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only process creation mode")
def test_reload_gracefully_stops_windowless_child(tmp_path: Path, unused_tcp_port: int) -> None:  # pragma: py-not-win32
    app_path = tmp_path / "app.py"
    app_path.write_text(
        """\
from __future__ import annotations

async def app(scope, receive, send):
    if scope["type"] != "lifespan":
        return

    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return
"""
    )
    # Use StatReload so watcher behavior does not affect this process-shutdown test.
    (tmp_path / "watchfiles.py").write_text("raise ImportError\n")
    log_path = tmp_path / "uvicorn.log"

    with log_path.open("w") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app:app", "--reload", "--port", str(unused_tcp_port)],
            cwd=tmp_path,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )

        try:
            deadline = monotonic() + 15
            while monotonic() < deadline:
                output = log_path.read_text()
                if "Application startup complete" in output or process.poll() is not None:
                    break
                sleep(0.1)

            assert process.poll() is None, f"Uvicorn exited before startup:\n{output}"
            assert "Application startup complete" in output, f"Uvicorn did not start:\n{output}"

            sleep(1)
            app_path.write_text(app_path.read_text() + "\n")

            deadline = monotonic() + 15
            while monotonic() < deadline:
                output = log_path.read_text()
                if output.count("Application startup complete") >= 2 or process.poll() is not None:
                    break
                sleep(0.1)

            assert process.poll() is None, f"Uvicorn exited during reload:\n{output}"
            assert output.count("Application startup complete") >= 2, f"Uvicorn did not reload:\n{output}"
            assert "Application shutdown complete" in output
        finally:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            process.kill()
            process.wait()


def test_base_reloader_closes_sockets_on_shutdown():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    config = Config(app="tests.test_config:asgi_app", reload=True)
    reloader = BaseReload(config, target=run, sockets=[sock], shutdown_event=create_shutdown_event())
    reloader.startup()
    assert sock.fileno() != -1
    reloader.shutdown()
    assert sock.fileno() == -1


@pytest.mark.skipif(WatchFilesReload is None, reason="watchfiles not available")
def test_file_filter_excluded_directory(tmp_path: Path) -> None:
    """A glob include inside an excluded directory is not watched.

    Pins the branch directly: the reload tests that exercise it through real
    file watching are skipped on Windows and macOS, which left it uncovered
    on some CI runs (see #2974).
    """
    excluded_dir = tmp_path / "vendor"
    excluded_dir.mkdir()

    config = Config(
        app="tests.test_config:asgi_app",
        reload=True,
        reload_excludes=[str(excluded_dir)],
    )
    file_filter = FileFilter(config)

    assert file_filter(tmp_path / "app.py")
    assert not file_filter(excluded_dir / "app.py")

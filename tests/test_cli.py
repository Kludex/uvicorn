import contextlib
import importlib
import os
import platform
import sys
from collections.abc import Iterator
from pathlib import Path
from textwrap import dedent
from unittest import mock

import pytest
from click.testing import CliRunner

import uvicorn
from uvicorn.config import Config
from uvicorn.main import main as cli
from uvicorn.server import Server
from uvicorn.supervisors import ChangeReload, Multiprocess

HEADERS = "Content-Security-Policy:default-src 'self'; script-src https://example.com"
main = importlib.import_module("uvicorn.main")


@contextlib.contextmanager
def load_env_var(key: str, value: str) -> Iterator[None]:
    old_environ = dict(os.environ)
    os.environ[key] = value
    yield
    os.environ.clear()
    os.environ.update(old_environ)


class App:
    pass


def test_cli_print_version() -> None:
    runner = CliRunner()

    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert (
        "Running uvicorn {version} with {py_implementation} {py_version} on {system}".format(  # noqa: UP032
            version=uvicorn.__version__,
            py_implementation=platform.python_implementation(),
            py_version=platform.python_version(),
            system=platform.system(),
        )
    ) in result.output


def test_cli_headers() -> None:
    runner = CliRunner()

    with mock.patch.object(main, "run") as mock_run:
        result = runner.invoke(cli, ["tests.test_cli:App", "--header", HEADERS])

    assert result.output == ""
    assert result.exit_code == 0
    mock_run.assert_called_once()
    assert mock_run.call_args[1]["headers"] == [
        [
            "Content-Security-Policy",
            "default-src 'self'; script-src https://example.com",
        ]
    ]


def test_cli_call_server_run() -> None:
    runner = CliRunner()

    with mock.patch.object(Server, "run") as mock_run:
        result = runner.invoke(cli, ["tests.test_cli:App"])

    assert result.exit_code == 3
    mock_run.assert_called_once()


def test_cli_call_change_reload_run() -> None:
    runner = CliRunner()

    with mock.patch.object(Config, "bind_socket") as mock_bind_socket:
        with mock.patch.object(ChangeReload, "run") as mock_run:
            result = runner.invoke(cli, ["tests.test_cli:App", "--reload"])

    assert result.exit_code == 0
    mock_bind_socket.assert_called_once()
    mock_run.assert_called_once()


def test_cli_call_multiprocess_run() -> None:
    runner = CliRunner()

    with mock.patch.object(Config, "bind_socket") as mock_bind_socket:
        with mock.patch.object(Multiprocess, "run") as mock_run:
            result = runner.invoke(cli, ["tests.test_cli:App", "--workers=2"])

    assert result.exit_code == 0
    mock_bind_socket.assert_called_once()
    mock_run.assert_called_once()


@pytest.fixture(params=(True, False))
def uds_file(tmp_path: Path, request: pytest.FixtureRequest) -> Path:  # pragma: py-win32
    file = tmp_path / "uvicorn.sock"
    should_create_file = request.param
    if should_create_file:
        file.touch(exist_ok=True)
    return file


@pytest.mark.skipif(sys.platform == "win32", reason="require unix-like system")
def test_cli_uds(uds_file: Path) -> None:  # pragma: py-win32
    runner = CliRunner()

    with mock.patch.object(Config, "bind_socket") as mock_bind_socket:
        with mock.patch.object(Multiprocess, "run") as mock_run:
            result = runner.invoke(cli, ["tests.test_cli:App", "--workers=2", "--uds", str(uds_file)])

    assert result.exit_code == 0
    assert result.output == ""
    mock_bind_socket.assert_called_once()
    mock_run.assert_called_once()
    assert not uds_file.exists()


def test_cli_incomplete_app_parameter() -> None:
    runner = CliRunner()

    result = runner.invoke(cli, ["tests.test_cli"])

    assert (
        'Error loading ASGI app. Import string "tests.test_cli" must be in format "<module>:<attribute>".'
    ) in result.output
    assert result.exit_code == 1


def test_cli_event_size() -> None:
    runner = CliRunner()

    with mock.patch.object(main, "run") as mock_run:
        result = runner.invoke(
            cli,
            ["tests.test_cli:App", "--h11-max-incomplete-event-size", str(32 * 1024)],
        )

    assert result.output == ""
    assert result.exit_code == 0
    mock_run.assert_called_once()
    assert mock_run.call_args[1]["h11_max_incomplete_event_size"] == 32768


@pytest.mark.parametrize("http_protocol", ["h11", "httptools"])
def test_env_variables(http_protocol: str):
    with load_env_var("UVICORN_HTTP", http_protocol):
        runner = CliRunner(env=os.environ)
        with mock.patch.object(main, "run") as mock_run:
            runner.invoke(cli, ["tests.test_cli:App"])
            _, kwargs = mock_run.call_args
            assert kwargs["http"] == http_protocol


def test_ignore_environment_variable_when_set_on_cli():
    with load_env_var("UVICORN_HTTP", "h11"):
        runner = CliRunner(env=os.environ)
        with mock.patch.object(main, "run") as mock_run:
            runner.invoke(cli, ["tests.test_cli:App", "--http=httptools"])
            _, kwargs = mock_run.call_args
            assert kwargs["http"] == "httptools"


def test_app_dir(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    app_dir = tmp_path / "dir" / "app_dir"
    app_file = app_dir / "main.py"
    app_dir.mkdir(parents=True)
    app_file.touch()
    app_file.write_text(
        dedent(
            """
            async def app(scope, receive, send):
                ...
            """
        )
    )
    runner = CliRunner()
    with mock.patch.object(Server, "run") as mock_run:
        result = runner.invoke(cli, ["main:app", "--app-dir", f"{str(app_dir)}"])

    assert result.exit_code == 3
    mock_run.assert_called_once()
    assert sys.path[0] == str(app_dir)


def test_set_app_via_environment_variable():
    app_path = "tests.test_cli:App"
    with load_env_var("UVICORN_APP", app_path):
        runner = CliRunner(env=os.environ)
        with mock.patch.object(main, "run") as mock_run:
            result = runner.invoke(cli)
            args, _ = mock_run.call_args
            assert result.exit_code == 0
            assert args == (app_path,)

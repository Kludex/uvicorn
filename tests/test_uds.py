from __future__ import annotations

import importlib.util
import os
import socket
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from uvicorn import run
from uvicorn.config import STARTUP_FAILURE
from uvicorn.main import main as cli
from uvicorn.supervisors import ChangeReload, Multiprocess
from uvicorn.supervisors.basereload import BaseReload

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="require unix-like system")
UVLOOP_REQUIRED = pytest.mark.skipif(importlib.util.find_spec("uvloop") is None, reason="uvloop not installed")


@pytest.mark.parametrize("mode", ["asyncio", pytest.param("uvloop", marks=UVLOOP_REQUIRED), "workers", "reload"])
@pytest.mark.parametrize("replacement", ["none", "socket", "file", "symlink", "missing"])
def test_uds_cleanup(
    short_socket_name: str, monkeypatch: pytest.MonkeyPatch, mode: str, replacement: str
) -> None:  # pragma: py-win32
    path = Path(short_socket_name)
    original = path.with_suffix(".old")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as other:

        def replace_path() -> None:
            assert path.is_socket()
            if replacement == "none":
                return
            path.rename(original)
            if replacement == "socket":
                other.bind(short_socket_name)
                other.listen()
            elif replacement == "file":
                path.write_text("sentinel")
            elif replacement == "symlink":
                target = path.with_suffix(".txt")
                target.write_text("sentinel")
                path.symlink_to(target)

        chmod = os.chmod

        def chmod_and_replace(path: str, permissions: int) -> None:
            chmod(path, permissions)
            replace_path()

        def supervise(supervisor: Multiprocess | BaseReload) -> None:
            try:
                replace_path()
            finally:
                for sock in supervisor.sockets:
                    sock.close()

        if mode in ("workers", "reload"):
            monkeypatch.setattr(Multiprocess if mode == "workers" else ChangeReload, "run", supervise)
            run(
                "tests.test_main:app",
                uds=short_socket_name,
                workers=2 if mode == "workers" else 1,
                reload=mode == "reload",
                log_level="critical",
            )
        else:
            monkeypatch.setattr(os, "chmod", chmod_and_replace)
            run(
                "tests.test_main:app",
                uds=short_socket_name,
                loop=mode,
                lifespan="off",
                limit_max_requests=0,
                log_level="critical",
            )

        if replacement in ("none", "missing"):
            assert not path.exists()
        elif replacement == "file":
            assert path.read_text() == "sentinel"
        elif replacement == "symlink":
            assert path.is_symlink()
        else:
            assert path.is_socket()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(short_socket_name)


@pytest.mark.parametrize(
    "options", [[], pytest.param(["--loop=uvloop"], marks=UVLOOP_REQUIRED), ["--workers=2"], ["--reload"]]
)
def test_uds_bind_failure_preserves_file(short_socket_name: str, options: list[str]) -> None:  # pragma: py-win32
    path = Path(short_socket_name)
    path.write_text("sentinel")

    result = CliRunner().invoke(cli, ["tests.test_main:app", "--uds", short_socket_name, "--lifespan=off", *options])

    assert result.exit_code != 0
    assert path.read_text() == "sentinel"


@pytest.mark.parametrize("options", [["--workers=2"], ["--reload"]])
def test_uds_bind_failure_preserves_socket(short_socket_name: str, options: list[str]) -> None:  # pragma: py-win32
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as owner:
        owner.bind(short_socket_name)
        owner.listen()

        result = CliRunner().invoke(cli, ["tests.test_main:app", "--uds", short_socket_name, *options])

        assert result.exit_code == STARTUP_FAILURE
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(short_socket_name)


@pytest.mark.parametrize(
    "options", [[], pytest.param(["--loop=uvloop"], marks=UVLOOP_REQUIRED), ["--workers=2"], ["--reload"]]
)
def test_uds_permission_failure_cleans_up(
    short_socket_name: str, monkeypatch: pytest.MonkeyPatch, options: list[str]
) -> None:  # pragma: py-win32
    def fail_chmod(path: str, mode: int) -> None:
        raise PermissionError("chmod failed")

    monkeypatch.setattr(os, "chmod", fail_chmod)

    result = CliRunner().invoke(cli, ["tests.test_main:app", "--uds", short_socket_name, "--lifespan=off", *options])

    assert result.exit_code != 0
    assert not Path(short_socket_name).exists()


def test_uds_disappears_during_cleanup(
    short_socket_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:  # pragma: py-win32
    remove = os.remove

    def remove_twice(path: str) -> None:
        remove(path)
        remove(path)

    def supervise(supervisor: Multiprocess) -> None:
        for sock in supervisor.sockets:
            sock.close()
        monkeypatch.setattr(os, "remove", remove_twice)

    monkeypatch.setattr(Multiprocess, "run", supervise)

    result = CliRunner().invoke(cli, ["tests.test_main:app", "--uds", short_socket_name, "--workers=2"])

    assert result.exit_code == 0
    assert not Path(short_socket_name).exists()

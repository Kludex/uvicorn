"""Test that StatReload excludes hidden / cache / venv .py files by default.

Without a fix, StatReload.iter_py_files() recursively lists every .py file
under reload_dirs, including those inside .venv/, .mypy_cache/, .git/, and
.pyc/.pyd/.pyo siblings. This causes spurious reloads on unrelated changes
(virtualenv installs, type-checker cache, git checkout operations).

WatchFilesReload has the same default exclude list (FileFilter); StatReload
should match.
"""

from pathlib import Path

from uvicorn.config import Config
from uvicorn.supervisors.statreload import StatReload


class _FakeStatReload(StatReload):
    """StatReload requires sockets/target — we just want iter_py_files()."""

    def __init__(self, config):
        self.config = config
        self.mtimes = {}
        self.reloader_name = "test"
        from threading import Event

        self.should_exit = Event()
        self.pid = 0
        self.is_restarting = False
        self.sockets = []
        self.target = lambda **kw: None


def _make_project(root: Path) -> Config:
    (root / "app.py").write_text("# app\n")
    (root / ".venv" / "lib").mkdir(parents=True)
    (root / ".venv" / "lib" / "somelib.py").write_text("# venv lib\n")
    (root / ".mypy_cache").mkdir()
    (root / ".mypy_cache" / "x.py").write_text("# cache\n")
    (root / ".git").mkdir()
    (root / ".git" / "hooks").mkdir(parents=True)
    (root / ".git" / "hooks" / "y.py").write_text("# git hook\n")
    (root / "module.pyc").write_text("not python")  # extension is .pyc, not .py
    (root / "x.pyo").write_text("not python")
    return Config(app="app", reload=True, reload_dirs=[str(root)])


def test_statreload_excludes_hidden_dirs(tmp_path):
    config = _make_project(tmp_path)
    r = _FakeStatReload(config)
    watched = {p.name for p in r.iter_py_files()}
    assert "app.py" in watched, "real app.py should still be watched"
    assert "somelib.py" not in watched, ".venv/*.py should be excluded (regression: spurious venv reloads)"
    assert "x.py" not in watched, ".mypy_cache/*.py should be excluded (regression: spurious cache reloads)"
    # y.py is inside .git — should also be excluded
    assert all(".git" not in str(p) for p in r.iter_py_files()), ".git/*.py should be excluded"


def test_statreload_includes_app_in_subdir(tmp_path):
    """Sanity: a real .py in a non-excluded subdir should be watched."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "real.py").write_text("# real\n")
    (tmp_path / ".venv" / "lib").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".venv" / "lib" / "fake.py").write_text("# fake\n")
    config = Config(app="app", reload=True, reload_dirs=[str(tmp_path)])
    r = _FakeStatReload(config)
    paths = [str(p) for p in r.iter_py_files()]
    assert any("pkg/real.py" in p for p in paths), "real .py in a subdir should still be watched"
    assert not any(".venv" in p for p in paths), "no .venv files should be watched"

"""Repro harness for https://github.com/encode/uvicorn/issues/1972 (Windows only).

Two experiments:

* swallow: start `uvicorn --reload`, touch a watched file to trigger a restart,
  then send a "user" Ctrl+C into the console at a varying delay. If the reloader
  is still alive N seconds later, the Ctrl+C was swallowed by the restart
  window in `BaseReload.signal_handler` -> reproduced.

* hang: start `uvicorn --reload` with SHUTDOWN_DELAY so graceful shutdown stalls,
  send one Ctrl+C, and check whether the parent sits forever in process.join().
  A second Ctrl+C later probes whether the child's force-exit path rescues it.

CTRL_C_EVENT broadcasts to every process attached to the console, so running
this directly would kill the CI runner agent. The driver therefore re-spawns
itself with CREATE_NEW_CONSOLE (`--inner`) and the experiment runs in that
isolated console; output comes back through a pipe.
"""

from __future__ import annotations

import argparse
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).parent
WATCHED = HERE / "watched.py"

STARTUP_LINE = "Application startup complete."
RELOAD_LINE = "Reloading..."
SHUTDOWN_LINE = "Shutting down"

JITTERS = [0.0, 0.02, 0.05, 0.1, 0.2, 0.35, 0.5, 0.75]


def log(msg: str) -> None:
    print(f"[driver +{time.monotonic() - START:8.3f}s] {msg}", flush=True)


START = time.monotonic()


class Uvicorn:
    """uvicorn subprocess sharing our console, with line-pumped output."""

    def __init__(self, extra_env: dict[str, str] | None = None) -> None:
        env = {**os.environ, "PYTHONUNBUFFERED": "1", **(extra_env or {})}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app:app", "--reload", "--port", "0"],
            cwd=HERE,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.rstrip()
            print(f"    | {line}", flush=True)
            self.lines.put(line)

    def wait_line(self, needle: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=0.1)
            except queue.Empty:
                continue
            if needle in line:
                return True
        return False

    def wait_exit(self, timeout: float) -> bool:
        try:
            self.proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def kill_tree(self) -> None:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(self.proc.pid)],
            capture_output=True,
        )
        self.proc.wait(timeout=10)


def send_console_ctrl_c() -> None:
    log("sending CTRL_C_EVENT to console")
    os.kill(0, signal.CTRL_C_EVENT)


def touch_watched() -> None:
    WATCHED.write_text(f"# {time.time_ns()}\n")


def run_swallow(iterations: int) -> int:
    reproduced = 0
    for i in range(iterations):
        jitter = JITTERS[i % len(JITTERS)]
        log(f"--- swallow iteration {i + 1}/{iterations} (jitter {jitter}s) ---")
        uv = Uvicorn()
        try:
            if not uv.wait_line(STARTUP_LINE, 60):
                log("!! server never started, skipping iteration")
                continue
            touch_watched()
            if not uv.wait_line(RELOAD_LINE, 20):
                log("!! reload never triggered, skipping iteration")
                continue
            time.sleep(jitter)
            send_console_ctrl_c()
            if uv.wait_exit(15):
                log(f"iteration {i + 1}: exited cleanly (rc={uv.proc.returncode})")
            else:
                reproduced += 1
                log(f"iteration {i + 1}: REPRODUCED - Ctrl+C swallowed (jitter {jitter}s), process still alive")
                log("probing: sending a second Ctrl+C")
                send_console_ctrl_c()
                if uv.wait_exit(10):
                    log("second Ctrl+C worked")
                else:
                    log("second Ctrl+C ALSO swallowed")
        finally:
            if uv.proc.poll() is None:
                uv.kill_tree()
    print(f"RESULT swallow: reproduced {reproduced}/{iterations}", flush=True)
    return reproduced


def run_hang(iterations: int) -> int:
    reproduced = 0
    for i in range(iterations):
        log(f"--- hang iteration {i + 1}/{iterations}: SHUTDOWN_DELAY=120 ---")
        uv = Uvicorn(extra_env={"SHUTDOWN_DELAY": "120"})
        try:
            if not uv.wait_line(STARTUP_LINE, 60):
                log("!! server never started")
                continue
            send_console_ctrl_c()
            if not uv.wait_line(SHUTDOWN_LINE, 15):
                log("signal not received at all (no 'Shutting down')")
            if uv.wait_exit(20):
                log(f"exited within 20s (rc={uv.proc.returncode}) - no hang")
            else:
                reproduced += 1
                log("REPRODUCED - parent stuck >20s after Ctrl+C (join without timeout)")
                log("probing: second Ctrl+C (child force-exit path?)")
                send_console_ctrl_c()
                if uv.wait_exit(15):
                    log("second Ctrl+C rescued it (child force_exit)")
                else:
                    log("still stuck after second Ctrl+C")
        finally:
            if uv.proc.poll() is None:
                uv.kill_tree()
    print(f"RESULT hang: reproduced {reproduced}/{iterations}", flush=True)
    return reproduced


def run_stuck_reload(iterations: int) -> int:
    reproduced = 0
    for i in range(iterations):
        log(f"--- stuck-reload iteration {i + 1}/{iterations}: SHUTDOWN_DELAY=20 ---")
        uv = Uvicorn(extra_env={"SHUTDOWN_DELAY": "20"})
        try:
            if not uv.wait_line(STARTUP_LINE, 60):
                log("!! server never started")
                continue
            touch_watched()
            if not uv.wait_line(RELOAD_LINE, 20):
                log("!! reload never triggered")
                continue
            time.sleep(1.0)  # parent is now blocked in restart() -> process.join()
            send_console_ctrl_c()  # the "user" pressing Ctrl+C
            if uv.wait_exit(10):
                log(f"exited within 10s (rc={uv.proc.returncode}) - Ctrl+C responsive during stuck restart")
            else:
                reproduced += 1
                log("REPRODUCED - Ctrl+C dead while restart is blocked on slow child shutdown")
                if uv.wait_exit(40):
                    log(f"eventually exited once child shutdown completed (rc={uv.proc.returncode})")
                else:
                    log("never exited even after the child shutdown window - fully wedged")
                    log("probing: one more Ctrl+C")
                    send_console_ctrl_c()
                    if uv.wait_exit(15):
                        log("final Ctrl+C worked")
                    else:
                        log("final Ctrl+C ALSO dead")
        finally:
            if uv.proc.poll() is None:
                uv.kill_tree()
    print(f"RESULT stuck-reload: reproduced {reproduced}/{iterations}", flush=True)
    return reproduced


def inner(args: argparse.Namespace) -> None:
    # We broadcast CTRL_C_EVENT to our own console: ignore it ourselves.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    touch_watched()
    if args.test == "swallow":
        run_swallow(args.iterations)
    elif args.test == "stuck-reload":
        run_stuck_reload(args.iterations)
    else:
        run_hang(args.iterations)


def outer(args: argparse.Namespace) -> None:
    cmd = [sys.executable, __file__, "--inner", "--test", args.test, "--iterations", str(args.iterations)]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line.rstrip(), flush=True)
    proc.wait()
    sys.exit(proc.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", choices=["swallow", "hang", "stuck-reload"], required=True)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--inner", action="store_true")
    args = parser.parse_args()

    if sys.platform != "win32":
        sys.exit("This repro only runs on Windows.")

    if args.inner:
        inner(args)
    else:
        outer(args)

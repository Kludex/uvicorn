"""
Some light wrappers around Python's multiprocessing, to deal with cleanly
starting child processes.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
from collections.abc import Callable
from multiprocessing.context import SpawnProcess
from socket import socket

from uvicorn.config import Config

multiprocessing.allow_connection_pickling()
spawn = multiprocessing.get_context("spawn")


def get_subprocess(
    config: Config,
    target: Callable[..., None],
    sockets: list[socket],
) -> tuple[SpawnProcess, multiprocessing.synchronize.Event | None]:
    """
    Called in the parent process, to instantiate a new child process instance.
    The child is not yet started at this point.

    * config - The Uvicorn configuration instance.
    * target - A callable that accepts a list of sockets. In practice this will
               be the `Server.run()` method.
    * sockets - A list of sockets to pass to the server. Sockets are bound once
                by the parent process, and then passed to the child processes.
    """
    # We pass across the stdin fileno, and reopen it in the child process.
    # This is required for some debugging environments.
    try:
        stdin_fileno = sys.stdin.fileno()
    # The `sys.stdin` can be `None`, see https://docs.python.org/3/library/sys.html#sys.__stdin__.
    except (AttributeError, OSError):
        stdin_fileno = None

    start_event: multiprocessing.synchronize.Event | None = None

    if sys.platform == "win32":  # pragma: py-not-win32
        # Create an event that will be waited on right after starting the process. This is
        # done to ensure that the child process has time to properly initialize its sockets
        start_event = spawn.Event()

    kwargs = {
        "config": config,
        "target": target,
        "sockets": sockets,
        "start_event": start_event,
        "stdin_fileno": stdin_fileno,
    }

    return spawn.Process(target=subprocess_started, kwargs=kwargs), start_event


def subprocess_started(
    config: Config,
    target: Callable[..., None],
    sockets: list[socket],
    start_event: multiprocessing.synchronize.Event | None,
    stdin_fileno: int | None,
) -> None:
    """
    Called when the child process starts.

    * config - The Uvicorn configuration instance.
    * target - A callable that accepts a list of sockets. In practice this will
               be the `Server.run()` method.
    * sockets - A list of sockets to pass to the server. Sockets are bound once
                by the parent process, and then passed to the child processes.
    * stdin_fileno - The file number of sys.stdin, so that it can be reattached
                     to the child process.
    """
    # Re-open stdin.
    if stdin_fileno is not None:
        sys.stdin = os.fdopen(stdin_fileno)  # pragma: full coverage

    # Logging needs to be setup again for each child.
    config.configure_logging()

    if sys.platform == "win32":  # pragma: py-not-win32
        assert start_event is not None

        # Windows requires that sockets are explicitly shared between processes
        from socket import fromshare

        sockets = [fromshare(sock.share(os.getpid())) for sock in sockets]

        # There seems to be a bug with `WSASocket` (which is used by `socket.share`) where when multiple
        # processes attempt to share the same socket at the same time, one of them might fail.
        # So, we can use an event to make sure that only one process will be creating sockets at a time.
        start_event.set()

    try:
        # Now we can call into `Server.run(sockets=sockets)`
        target(sockets=sockets)
    except KeyboardInterrupt:  # pragma: no cover
        # suppress the exception to avoid a traceback from subprocess.Popen
        # the parent already expects us to end, so no vital information is lost
        pass

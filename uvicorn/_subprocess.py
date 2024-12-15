"""
Some light wrappers around Python's multiprocessing, to deal with cleanly
starting child processes.
"""

from __future__ import annotations

import multiprocessing
import os
import socket
import sys
from multiprocessing.context import SpawnProcess
from typing import Callable

from uvicorn.config import Config

multiprocessing.allow_connection_pickling()
spawn = multiprocessing.get_context("spawn")


class SocketSharePickle:
    def __init__(self, sock: socket.socket):
        self._sock = sock

    def get(self) -> socket.socket:
        return self._sock


class SocketShareRebind:
    def __init__(self, sock: socket.socket):
        if not (sys.platform == "linux" and hasattr(socket, "SO_REUSEPORT")) or hasattr(socket, "SO_REUSEPORT_LB"):
            raise RuntimeError("socket_load_balance not supported")
        else:  # pragma: py-darwin pragma: py-win32
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_REUSEPORT_LB", socket.SO_REUSEPORT), 1)
            self._family = sock.family
            self._type = sock.type
            self._proto = sock.proto
            self._sockname = sock.getsockname()

    def get(self) -> socket.socket:  # pragma: py-darwin pragma: py-win32
        try:
            sock = socket.socket(family=self._family, type=self._type, proto=self._proto)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_REUSEPORT_LB", socket.SO_REUSEPORT), 1)

            sock.bind(self._sockname)
            return sock
        except BaseException:  # pragma: no cover
            sock.close()
            raise


def get_subprocess(
    config: Config,
    target: Callable[..., None],
    sockets: list[socket.socket],
) -> SpawnProcess:
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

    socket_shares: list[SocketShareRebind] | list[SocketSharePickle]
    if config.socket_load_balance:  # pragma: py-darwin pragma: py-win32
        socket_shares = [SocketShareRebind(s) for s in sockets]
    else:
        socket_shares = [SocketSharePickle(s) for s in sockets]
    kwargs = {
        "config": config,
        "target": target,
        "sockets": socket_shares,
        "stdin_fileno": stdin_fileno,
    }

    return spawn.Process(target=subprocess_started, kwargs=kwargs)


def subprocess_started(
    config: Config,
    target: Callable[..., None],
    sockets: list[SocketSharePickle] | list[SocketShareRebind],
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

    try:
        # Now we can call into `Server.run(sockets=sockets)`
        target(sockets=[s.get() for s in sockets])
    except KeyboardInterrupt:  # pragma: no cover
        # supress the exception to avoid a traceback from subprocess.Popen
        # the parent already expects us to end, so no vital information is lost
        pass

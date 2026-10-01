from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import warnings
from copy import copy
from typing import Any
from urllib.parse import urlsplit

from gunicorn.arbiter import Arbiter
from gunicorn.glogging import SafeAtoms
from gunicorn.workers.base import Worker

from uvicorn._compat import asyncio_run
from uvicorn.config import Config
from uvicorn.server import Server

warnings.warn(
    "The `uvicorn.workers` module is deprecated. Please use `uvicorn-worker` package instead.\n"
    "For more details, see https://github.com/Kludex/uvicorn-worker.",
    DeprecationWarning,
)


class GunicornAccessFormatter(logging.Formatter):
    """Format Uvicorn access records using Gunicorn's access log format."""

    def __init__(self, access_log_format: str) -> None:
        super().__init__("%(message)s")
        self.access_log_format = access_log_format

    def format(self, record: logging.LogRecord) -> str:
        if _is_uvicorn_access_record(record):
            record = copy(record)
            record.msg = self.access_log_format
            record.args = _format_record_args(record.args)  # type: ignore[arg-type]
        return super().format(record)


def _is_uvicorn_access_record(record: logging.LogRecord) -> bool:
    return bool(
        record.name == "uvicorn.access"
        and record.msg == '%s - "%s %s HTTP/%s" %d'
        and isinstance(record.args, tuple)
        and len(record.args) == 5
    )


def _format_record_args(args: tuple[Any, ...]) -> dict[str, Any]:
    client_addr, method, full_path, http_version, status_code = args
    client_host = str(client_addr).rsplit(":", 1)[0]
    parsed_path = urlsplit(str(full_path))
    path = parsed_path.path or "-"
    query = parsed_path.query
    request_line = f"{method} {full_path} HTTP/{http_version}"

    atoms = {
        "h": client_host,
        "l": "-",
        "u": "-",
        "t": "-",
        "r": request_line,
        "s": status_code,
        "m": method,
        "U": path,
        "q": query,
        "H": f"HTTP/{http_version}",
        "b": "-",
        "B": None,
        "f": "-",
        "a": "-",
        "T": 0,
        "D": 0,
        "M": 0,
        "L": "0.000000",
        "p": f"<{os.getpid()}>",
    }
    return SafeAtoms(atoms)


class UvicornWorker(Worker):
    """
    A worker class for Gunicorn that interfaces with an ASGI consumer callable,
    rather than a WSGI callable.
    """

    CONFIG_KWARGS: dict[str, Any] = {"loop": "auto", "http": "auto"}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        logger = logging.getLogger("uvicorn.error")
        logger.handlers = self.log.error_log.handlers
        logger.setLevel(self.log.error_log.level)
        logger.propagate = False

        logger = logging.getLogger("uvicorn.access")
        logger.handlers = self.log.access_log.handlers
        logger.setLevel(self.log.access_log.level)
        for handler in logger.handlers:
            handler.setFormatter(GunicornAccessFormatter(self.cfg.access_log_format))
        logger.propagate = False

        config_kwargs: dict = {
            "app": None,
            "log_config": None,
            "timeout_keep_alive": self.cfg.keepalive,
            "timeout_notify": self.timeout,
            "callback_notify": self.callback_notify,
            "limit_max_requests": self.max_requests,
            "forwarded_allow_ips": self.cfg.forwarded_allow_ips,
        }

        if self.cfg.is_ssl:
            ssl_kwargs = {
                "ssl_keyfile": self.cfg.ssl_options.get("keyfile"),
                "ssl_certfile": self.cfg.ssl_options.get("certfile"),
                "ssl_keyfile_password": self.cfg.ssl_options.get("password"),
                "ssl_version": self.cfg.ssl_options.get("ssl_version"),
                "ssl_cert_reqs": self.cfg.ssl_options.get("cert_reqs"),
                "ssl_ca_certs": self.cfg.ssl_options.get("ca_certs"),
                "ssl_ciphers": self.cfg.ssl_options.get("ciphers"),
            }
            config_kwargs.update(ssl_kwargs)

        if self.cfg.settings["backlog"].value:
            config_kwargs["backlog"] = self.cfg.settings["backlog"].value

        config_kwargs.update(self.CONFIG_KWARGS)

        self.config = Config(**config_kwargs)

    def init_signals(self) -> None:
        # Reset signals so Gunicorn doesn't swallow subprocess return codes
        # other signals are set up by Server.install_signal_handlers()
        # See: https://github.com/Kludex/uvicorn/issues/894
        for s in self.SIGNALS:
            signal.signal(s, signal.SIG_DFL)

        signal.signal(signal.SIGUSR1, self.handle_usr1)
        # Don't let SIGUSR1 disturb active requests by interrupting system calls
        signal.siginterrupt(signal.SIGUSR1, False)

    def _install_sigquit_handler(self) -> None:
        """Install a SIGQUIT handler on workers.

        - https://github.com/Kludex/uvicorn/issues/1116
        - https://github.com/benoitc/gunicorn/issues/2604
        """

        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGQUIT, self.handle_exit, signal.SIGQUIT, None)

    async def _serve(self) -> None:
        self.config.app = self.wsgi
        server = Server(config=self.config)
        self._install_sigquit_handler()
        await server.serve(sockets=self.sockets)
        if not server.started:
            sys.exit(Arbiter.WORKER_BOOT_ERROR)

    def run(self) -> None:
        return asyncio_run(self._serve(), loop_factory=self.config.get_loop_factory())

    async def callback_notify(self) -> None:
        self.notify()


class UvicornH11Worker(UvicornWorker):
    CONFIG_KWARGS = {"loop": "asyncio", "http": "h11"}

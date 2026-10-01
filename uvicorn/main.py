from __future__ import annotations

import asyncio
import logging
import os
import ssl
import sys
import warnings
from collections.abc import Callable
from configparser import RawConfigParser
from typing import IO, Any

import uvicorn.server
from uvicorn._types import ASGIApplication
from uvicorn.config import (
    LOGGING_CONFIG,
    SSL_PROTOCOL_VERSION,
    STARTUP_FAILURE,
    Config,
    HTTPProtocolType,
    InterfaceType,
    LifespanType,
    LoopFactoryType,
    WSProtocolType,
)
from uvicorn.supervisors import ChangeReload, Multiprocess

logger = logging.getLogger("uvicorn.error")


class _DeprecatedMain:
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._warn()
        from uvicorn.cli import main as cli_main

        return cli_main(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        self._warn()
        from uvicorn.cli import main as cli_main

        return getattr(cli_main, name)

    @staticmethod
    def _warn() -> None:
        warnings.warn(
            "uvicorn.main() is deprecated, use uvicorn.run() or uvicorn.cli.main() instead.",
            DeprecationWarning,
            stacklevel=3,
        )


main = _DeprecatedMain()


def run(
    app: ASGIApplication | Callable[..., Any] | str,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    uds: str | None = None,
    fd: int | None = None,
    loop: LoopFactoryType | str = "auto",
    http: type[asyncio.Protocol] | HTTPProtocolType | str = "auto",
    http2: bool = False,
    ws: type[asyncio.Protocol] | WSProtocolType | str = "auto",
    ws_max_size: int = 16777216,
    ws_max_queue: int = 32,
    ws_ping_interval: float | None = 20.0,
    ws_ping_timeout: float | None = 20.0,
    ws_per_message_deflate: bool = True,
    lifespan: LifespanType = "auto",
    interface: InterfaceType = "auto",
    reload: bool = False,
    reload_dirs: list[str] | str | None = None,
    reload_includes: list[str] | str | None = None,
    reload_excludes: list[str] | str | None = None,
    reload_delay: float = 0.25,
    workers: int | None = None,
    env_file: str | os.PathLike[str] | None = None,
    log_config: dict[str, Any] | str | os.PathLike[str] | RawConfigParser | IO[Any] | None = LOGGING_CONFIG,
    log_level: str | int | None = None,
    access_log: bool = True,
    proxy_headers: bool = True,
    server_header: bool = True,
    date_header: bool = True,
    forwarded_allow_ips: list[str] | str | None = None,
    root_path: str = "",
    limit_concurrency: int | None = None,
    backlog: int = 2048,
    limit_max_requests: int | None = None,
    limit_max_requests_jitter: int = 0,
    timeout_keep_alive: int = 5,
    timeout_graceful_shutdown: int | None = None,
    timeout_worker_healthcheck: int = 5,
    ssl_keyfile: str | os.PathLike[str] | None = None,
    ssl_certfile: str | os.PathLike[str] | None = None,
    ssl_keyfile_password: str | None = None,
    ssl_version: int = SSL_PROTOCOL_VERSION,
    ssl_cert_reqs: int = ssl.CERT_NONE,
    ssl_ca_certs: str | os.PathLike[str] | None = None,
    ssl_ciphers: str | None = None,
    ssl_context_factory: Callable[[Config, Callable[[], ssl.SSLContext]], ssl.SSLContext] | None = None,
    headers: list[tuple[str, str]] | None = None,
    use_colors: bool | None = None,
    app_dir: str | None = None,
    factory: bool = False,
    h11_max_incomplete_event_size: int | None = None,
    reset_contextvars: bool = False,
) -> None:
    if app_dir is not None:
        sys.path.insert(0, app_dir)

    config = Config(
        app,
        host=host,
        port=port,
        uds=uds,
        fd=fd,
        loop=loop,
        http=http,
        http2=http2,
        ws=ws,
        ws_max_size=ws_max_size,
        ws_max_queue=ws_max_queue,
        ws_ping_interval=ws_ping_interval,
        ws_ping_timeout=ws_ping_timeout,
        ws_per_message_deflate=ws_per_message_deflate,
        lifespan=lifespan,
        interface=interface,
        reload=reload,
        reload_dirs=reload_dirs,
        reload_includes=reload_includes,
        reload_excludes=reload_excludes,
        reload_delay=reload_delay,
        workers=workers,
        env_file=env_file,
        log_config=log_config,
        log_level=log_level,
        access_log=access_log,
        proxy_headers=proxy_headers,
        server_header=server_header,
        date_header=date_header,
        forwarded_allow_ips=forwarded_allow_ips,
        root_path=root_path,
        limit_concurrency=limit_concurrency,
        backlog=backlog,
        limit_max_requests=limit_max_requests,
        limit_max_requests_jitter=limit_max_requests_jitter,
        timeout_keep_alive=timeout_keep_alive,
        timeout_graceful_shutdown=timeout_graceful_shutdown,
        timeout_worker_healthcheck=timeout_worker_healthcheck,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        ssl_keyfile_password=ssl_keyfile_password,
        ssl_version=ssl_version,
        ssl_cert_reqs=ssl_cert_reqs,
        ssl_ca_certs=ssl_ca_certs,
        ssl_ciphers=ssl_ciphers,
        ssl_context_factory=ssl_context_factory,
        headers=headers,
        use_colors=use_colors,
        factory=factory,
        h11_max_incomplete_event_size=h11_max_incomplete_event_size,
        reset_contextvars=reset_contextvars,
    )
    if config.reload or config.workers > 1:
        if not isinstance(app, str):
            logger = logging.getLogger("uvicorn.error")
            logger.warning("You must pass the application as an import string to enable 'reload' or 'workers'.")
            sys.exit(STARTUP_FAILURE)
    else:
        config.load_app()

    server = uvicorn.server.Server(config=config)

    try:
        if config.should_reload:
            sock = config.bind_socket()
            ChangeReload(config, target=server.run, sockets=[sock]).run()
        elif config.workers > 1:
            sock = config.bind_socket()
            Multiprocess(config, sockets=[sock]).run()
        else:
            server.run()
    except KeyboardInterrupt:  # pragma: full coverage
        pass
    finally:
        if config.uds and os.path.exists(config.uds):
            os.remove(config.uds)  # pragma: py-win32

    if not server.started and not config.should_reload and config.workers == 1:
        sys.exit(STARTUP_FAILURE)


def __getattr__(name: str) -> Any:
    if name == "Server":
        warnings.warn(
            "uvicorn.main.Server is deprecated, use uvicorn.server.Server instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return uvicorn.server.Server
    if name == "ServerState":
        warnings.warn(
            "uvicorn.main.ServerState is deprecated, use uvicorn.server.ServerState instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return uvicorn.server.ServerState
    raise AttributeError(f"module {__name__} has no attribute {name}")


if __name__ == "__main__":
    main()  # pragma: no cover

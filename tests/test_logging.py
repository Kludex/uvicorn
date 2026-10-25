"""What Uvicorn writes to stdout and stderr, byte for byte.

Every test runs a real server with a real logging configuration, sends real requests, and
compares the exact output, ANSI escape codes included. The tests don't call the formatters
directly, so `uvicorn/logging.py` can be rewritten freely: anything users would see change
fails here.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import logging.config
import os
import re
import sys
from collections.abc import AsyncIterator, Iterator
from copy import deepcopy
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any

import httpx2
import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from tests.utils import run_server
from uvicorn import Config
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import LOGGING_CONFIG

pytestmark = pytest.mark.anyio

APP_LOGGER = logging.getLogger("uvicorn.error")
NOTICE, LONG_LEVEL = 23, 37
logging.addLevelName(NOTICE, "NOTICE")  # no colour assigned to it
logging.addLevelName(LONG_LEVEL, "MUCHTOOLONG")  # longer than the 8-column level prefix


def ansi(code: int, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m"


BOLD, RED, GREEN, YELLOW, BLUE, CYAN, BRIGHT_RED = 1, 31, 32, 33, 34, 36, 91


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    if scope["type"] == "lifespan":
        return
    path = scope["path"]
    if scope["type"] == "websocket":
        await receive()
        if path == "/ws":
            await send({"type": "websocket.accept"})
        await send({"type": "websocket.close", "code": 1000})
        return
    if path == "/boom":
        raise RuntimeError("boom")
    if path == "/log":
        for level in (5, logging.DEBUG, logging.INFO, NOTICE, logging.WARNING, LONG_LEVEL, logging.ERROR, 50):
            APP_LOGGER.log(level, "from app at %d", level)
        APP_LOGGER.info("from app with %s", "color_message", extra={"color_message": "from app with \x1b[36m%s\x1b[0m"})
        APP_LOGGER.info("from app without args", extra={"color_message": "from app without \x1b[36margs\x1b[0m"})
    status = int(path.strip("/")) if path.strip("/").isdigit() else 200
    await send({"type": "http.response.start", "status": status, "headers": []})
    await send({"type": "http.response.body", "body": b""})


class Stream(StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


@dataclass
class Output:
    stdout: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)


def normalize(text: str) -> list[str]:
    text = re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:PORT", text)
    # Only in "Started/Finished server process [PID]", where the PID may be wrapped in colour codes:
    # the same digits can appear in a status code, a path or a date.
    text = re.sub(rf"((?:Started|Finished) server process \[(?:\x1b\[\d+m)?){os.getpid()}\b", r"\1PID", text)
    # Traceback frames depend on file paths and the Python version: keep only the header and the
    # exception line, which are the lines the formatter produces.
    return [line for line in text.splitlines() if not line.startswith(" ")]


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    saved = deepcopy(LOGGING_CONFIG)
    yield
    # `Config(use_colors=...)` writes into the module-level LOGGING_CONFIG (#3179 fixes that);
    # undo it and point the loggers back at the real streams.
    LOGGING_CONFIG.clear()
    LOGGING_CONFIG.update(saved)
    logging.config.dictConfig(deepcopy(LOGGING_CONFIG))


@contextlib.asynccontextmanager
async def serve(*, stdout_tty: bool = False, stderr_tty: bool = False, **config: Any) -> AsyncIterator[Output]:
    """Run a server whose stdout and stderr are captured; the output is filled in on exit."""
    output = Output()
    stdout, stderr = Stream(stdout_tty), Stream(stderr_tty)
    real_streams = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = stdout, stderr  # the logging config binds `ext://sys.stdout` when Config() runs
    try:
        async with run_server(Config(app=app, **config)):
            yield output
    finally:
        sys.stdout, sys.stderr = real_streams
        output.stdout = normalize(stdout.getvalue())
        output.stderr = normalize(stderr.getvalue())


async def get(port: int, *paths: str, headers: dict[str, str] | None = None) -> None:
    async with httpx2.AsyncClient() as client:
        for path in paths:
            await client.get(f"http://127.0.0.1:{port}{path}", headers=headers)


async def raw_request(port: int, data: bytes) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    await reader.read()
    writer.close()
    await writer.wait_closed()


STARTUP = [
    "INFO:     Started server process [PID]",
    "INFO:     Waiting for application startup.",
    "INFO:     Application startup complete.",
    "INFO:     Uvicorn running on http://127.0.0.1:PORT (Press CTRL+C to quit)",
]
SHUTDOWN = [
    "INFO:     Shutting down",
    "INFO:     Waiting for application shutdown.",
    "INFO:     Application shutdown complete.",
]
EXCEPTION = [
    "ERROR:    Exception in ASGI application",
    "Traceback (most recent call last):",
    "RuntimeError: boom",
]


async def test_default_output(http_protocol_cls: type, unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, http=http_protocol_cls) as output:
        await get(unused_tcp_port, "/", "/302?q=1", "/404", "/599", "/boom")
        await raw_request(unused_tcp_port, b"GET /a%20b?q=%20x HTTP/1.0\r\n\r\n")

    assert output.stdout == [
        'INFO:     127.0.0.1:PORT - "GET / HTTP/1.1" 200 OK',
        'INFO:     127.0.0.1:PORT - "GET /302?q=1 HTTP/1.1" 302 Found',
        'INFO:     127.0.0.1:PORT - "GET /404 HTTP/1.1" 404 Not Found',
        'INFO:     127.0.0.1:PORT - "GET /599 HTTP/1.1" 599 ',
        'INFO:     127.0.0.1:PORT - "GET /boom HTTP/1.1" 500 Internal Server Error',
        'INFO:     127.0.0.1:PORT - "GET /a%20b?q=%20x HTTP/1.0" 200 OK',
    ]
    assert output.stderr == STARTUP + EXCEPTION + SHUTDOWN


async def test_default_output_on_a_terminal(unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, stdout_tty=True, stderr_tty=True) as output:
        await get(unused_tcp_port, "/", "/302", "/404", "/599", "/boom")

    request = lambda path, status, colour: (  # noqa: E731
        f'{ansi(GREEN, "INFO")}:     127.0.0.1:PORT - "{ansi(BOLD, f"GET {path} HTTP/1.1")}" {ansi(colour, status)}'
    )
    # 1xx (bright white) can't be checked here: a client can't receive one as a final response.
    assert output.stdout == [
        request("/", "200 OK", GREEN),
        request("/302", "302 Found", YELLOW),
        request("/404", "404 Not Found", RED),
        request("/599", "599 ", BRIGHT_RED),
        request("/boom", "500 Internal Server Error", BRIGHT_RED),
    ]
    info = ansi(GREEN, "INFO")
    assert output.stderr == [
        f"{info}:     Started server process [{ansi(CYAN, 'PID')}]",
        f"{info}:     Waiting for application startup.",
        f"{info}:     Application startup complete.",
        f"{info}:     Uvicorn running on {ansi(BOLD, 'http://127.0.0.1:PORT')} (Press CTRL+C to quit)",
        f"{ansi(RED, 'ERROR')}:    Exception in ASGI application",
        "Traceback (most recent call last):",
        "RuntimeError: boom",
        f"{info}:     Shutting down",
        f"{info}:     Waiting for application shutdown.",
        f"{info}:     Application shutdown complete.",
    ]


@pytest.mark.parametrize("use_colors", [False, True])
async def test_level_prefixes_and_color_message(use_colors: bool, unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, use_colors=use_colors, log_level="trace") as output:
        await get(unused_tcp_port, "/log")

    def prefix(name: str, colour: int | None) -> str:
        coloured = ansi(colour, name) if use_colors and colour else name
        return coloured + ":" + " " * (8 - len(name))

    cyan = ansi(CYAN, "{}") if use_colors else "{}"
    assert [line for line in output.stderr if "from app" in line] == [
        f"{prefix('TRACE', BLUE)} from app at 5",
        f"{prefix('DEBUG', CYAN)} from app at 10",
        f"{prefix('INFO', GREEN)} from app at 20",
        f"{prefix('NOTICE', None)} from app at 23",
        f"{prefix('WARNING', YELLOW)} from app at 30",
        f"{prefix('MUCHTOOLONG', None)} from app at 37",
        f"{prefix('ERROR', RED)} from app at 40",
        f"{prefix('CRITICAL', BRIGHT_RED)} from app at 50",
        f"{prefix('INFO', GREEN)} from app with {cyan.format('color_message')}",
        f"{prefix('INFO', GREEN)} from app without {cyan.format('args')}",
    ]


@pytest.mark.parametrize(
    ("use_colors", "tty", "coloured"),
    [(True, False, True), (False, True, False), (None, False, False), (None, True, True)],
)
async def test_use_colors(use_colors: bool | None, tty: bool, coloured: bool, unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, use_colors=use_colors, stdout_tty=tty, stderr_tty=tty) as output:
        await get(unused_tcp_port, "/")

    has_ansi = ["\x1b[" in line for line in output.stdout + output.stderr]
    assert has_ansi == [coloured] * len(has_ansi)


@pytest.mark.parametrize(("stdout_tty", "stderr_tty", "coloured"), [(True, False, True), (False, True, False)])
async def test_colours_follow_stdout_even_on_stderr(
    stdout_tty: bool, stderr_tty: bool, coloured: bool, unused_tcp_port: int
) -> None:
    # Pins today's behaviour: with `use_colors=None`, both formatters check `sys.stdout.isatty()`,
    # including the default formatter, which writes to stderr.
    async with serve(port=unused_tcp_port, stdout_tty=stdout_tty, stderr_tty=stderr_tty) as output:
        await get(unused_tcp_port, "/")

    assert output.stdout[0].startswith(ansi(GREEN, "INFO") if coloured else "INFO:")
    assert output.stderr[0].startswith(ansi(GREEN, "INFO") if coloured else "INFO:")


async def test_access_log_disabled(unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, access_log=False) as output:
        await get(unused_tcp_port, "/")

    assert output.stdout == []
    assert output.stderr == STARTUP + SHUTDOWN


async def test_log_level_warning(unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, log_level="warning") as output:
        await get(unused_tcp_port, "/log", "/boom")

    assert output.stdout == []
    assert output.stderr == [
        "WARNING:  from app at 30",
        "MUCHTOOLONG: from app at 37",
        "ERROR:    from app at 40",
        "CRITICAL: from app at 50",
        *EXCEPTION,
    ]


def log_config(access_fmt: str, default_fmt: str = "%(levelprefix)s %(message)s", **formatter: Any) -> dict[str, Any]:
    config = deepcopy(LOGGING_CONFIG)
    config["formatters"]["access"].update(fmt=access_fmt, **formatter)
    config["formatters"]["default"].update(fmt=default_fmt, **formatter)
    return config


@pytest.mark.parametrize(
    ("config", "use_colors", "access", "started"),
    [
        pytest.param(
            log_config("%(name)s|%(levelname)s|%(levelprefix)s|%(client_addr)s|%(request_line)s|%(status_code)s"),
            False,
            "uvicorn.access|INFO|INFO:    |127.0.0.1:PORT|GET /404?q=1 HTTP/1.1|404 Not Found",
            "INFO:     Started server process [PID]",
            id="percent",
        ),
        pytest.param(
            log_config("{levelprefix}{client_addr} {request_line} {status_code}", "{levelprefix}{message}", style="{"),
            False,
            "INFO:    127.0.0.1:PORT GET /404?q=1 HTTP/1.1 404 Not Found",
            "INFO:    Started server process [PID]",
            id="brace",
        ),
        pytest.param(
            log_config("$levelname $request_line $status_code", "$levelname $message", style="$"),
            False,
            "INFO GET /404?q=1 HTTP/1.1 404 Not Found",
            "INFO Started server process [PID]",
            id="dollar",
        ),
        pytest.param(
            log_config("%(message)s", "%(message)s"),
            False,
            '127.0.0.1:PORT - "GET /404?q=1 HTTP/1.1" 404',
            "Started server process [PID]",
            id="message-only",
        ),
        pytest.param(
            log_config("{levelprefix}|{request_line}|{status_code}|{message}", "{levelprefix}|{message}", style="{"),
            True,
            f"{ansi(GREEN, 'INFO')}:    |{ansi(BOLD, 'GET /404?q=1 HTTP/1.1')}|{ansi(RED, '404 Not Found')}"
            '|127.0.0.1:PORT - "GET /404?q=1 HTTP/1.1" 404',
            f"{ansi(GREEN, 'INFO')}:    |Started server process [{ansi(CYAN, 'PID')}]",
            id="brace-colours",
        ),
    ],
)
async def test_custom_formats(
    config: dict[str, Any], use_colors: bool, access: str, started: str, unused_tcp_port: int
) -> None:
    async with serve(port=unused_tcp_port, log_config=config, use_colors=use_colors) as output:
        await get(unused_tcp_port, "/404?q=1")

    assert output.stdout == [access]
    assert output.stderr[0] == started


async def test_datefmt(unused_tcp_port: int) -> None:
    config = log_config("%(asctime)s %(status_code)s", "%(asctime)s %(message)s", datefmt="%Y")
    async with serve(port=unused_tcp_port, log_config=config) as output:
        await get(unused_tcp_port, "/")

    assert re.fullmatch(r"\d{4} 200 OK", output.stdout[0])
    assert re.fullmatch(r"\d{4} Started server process \[PID\]", output.stderr[0])


RECORD_ATTRIBUTES = {*logging.LogRecord("", 0, "", 0, "", None, None).__dict__, "message"}


class JSONFormatter(logging.Formatter):
    """How JSON logging libraries usually work: unpack the access args, and add any extra attributes."""

    def format(self, record: logging.LogRecord) -> str:
        client_addr, method, path, http_version, status_code = record.args  # type: ignore[misc]
        fields = {"client": client_addr, "method": method, "path": path, "http": http_version, "status": status_code}
        fields["extra"] = sorted(set(record.__dict__) - RECORD_ATTRIBUTES)
        return json.dumps(fields)


async def test_records_shared_by_several_handlers(unused_tcp_port: int) -> None:
    config = deepcopy(LOGGING_CONFIG)
    config["formatters"]["plain"] = {"format": "%(levelname)s %(message)s"}
    config["formatters"]["json"] = {"()": JSONFormatter}
    config["handlers"]["plain"] = {"class": "logging.StreamHandler", "formatter": "plain", "stream": "ext://sys.stderr"}
    config["handlers"]["json"] = {"class": "logging.StreamHandler", "formatter": "json", "stream": "ext://sys.stderr"}
    config["loggers"]["uvicorn"]["handlers"] = ["default", "plain"]
    config["loggers"]["uvicorn.access"]["handlers"] = ["access", "plain", "json"]
    async with serve(port=unused_tcp_port, log_config=config, use_colors=True) as output:
        await get(unused_tcp_port, "/404")

    # Uvicorn's coloured formatters run first. The handlers after them must see each record as it
    # was logged: no colours, no `color_message`, no fields added by uvicorn's formatters.
    info = ansi(GREEN, "INFO")
    assert output.stdout == [
        f'{info}:     127.0.0.1:PORT - "{ansi(BOLD, "GET /404 HTTP/1.1")}" {ansi(RED, "404 Not Found")}'
    ]
    assert output.stderr == [
        f"{info}:     Started server process [{ansi(CYAN, 'PID')}]",
        "INFO Started server process [PID]",
        f"{info}:     Waiting for application startup.",
        "INFO Waiting for application startup.",
        f"{info}:     Application startup complete.",
        "INFO Application startup complete.",
        f"{info}:     Uvicorn running on {ansi(BOLD, 'http://127.0.0.1:PORT')} (Press CTRL+C to quit)",
        "INFO Uvicorn running on http://127.0.0.1:PORT (Press CTRL+C to quit)",
        'INFO 127.0.0.1:PORT - "GET /404 HTTP/1.1" 404',
        '{"client": "127.0.0.1:PORT", "method": "GET", "path": "/404", "http": "1.1", "status": 404, "extra": []}',
        f"{info}:     Shutting down",
        "INFO Shutting down",
        f"{info}:     Waiting for application shutdown.",
        "INFO Waiting for application shutdown.",
        f"{info}:     Application shutdown complete.",
        "INFO Application shutdown complete.",
    ]


ACCESS_FORMAT = "%(levelprefix)s %(request_line)s %(status_code)s"
INI_CONFIG = f"""
[loggers]
keys=root,uvicorn.access

[handlers]
keys=access

[formatters]
keys=access

[logger_root]
level=WARNING
handlers=

[logger_uvicorn.access]
level=INFO
handlers=access
qualname=uvicorn.access
propagate=0

[handler_access]
class=logging.StreamHandler
formatter=access
args=(sys.stdout,)

[formatter_access]
class=uvicorn.logging.AccessFormatter
format={ACCESS_FORMAT}
"""


@pytest.mark.parametrize("suffix", [".json", ".yaml", ".ini"])
async def test_log_config_files(suffix: str, tmp_path: Path, unused_tcp_port: int) -> None:
    path = tmp_path / f"logging{suffix}"
    if suffix == ".ini":
        path.write_text(INI_CONFIG)
    else:
        path.write_text(json.dumps(log_config(ACCESS_FORMAT)))  # JSON is valid YAML
    async with serve(port=unused_tcp_port, log_config=str(path)) as output:
        await get(unused_tcp_port, "/404")

    assert output.stdout == ["INFO:     GET /404 HTTP/1.1 404 Not Found"]


async def test_forwarded_client(unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, forwarded_allow_ips="*") as output:
        await get(unused_tcp_port, "/", headers={"x-forwarded-for": "1.2.3.4"})

    assert output.stdout == ['INFO:     1.2.3.4:0 - "GET / HTTP/1.1" 200 OK']


@pytest.mark.skipif(sys.platform == "win32", reason="require unix-like system")
async def test_unix_socket_client(short_socket_name: str) -> None:  # pragma: py-win32
    async with serve(uds=short_socket_name) as output:
        transport = httpx2.AsyncHTTPTransport(uds=short_socket_name)
        async with httpx2.AsyncClient(transport=transport) as client:
            await client.get("http://localhost/")

    assert output.stdout == ['INFO:      - "GET / HTTP/1.1" 200 OK']
    assert output.stderr[3] == f"INFO:     Uvicorn running on unix socket {short_socket_name} (Press CTRL+C to quit)"


WEBSOCKET_OUTPUT = {
    "WSProtocol": [
        'INFO:     127.0.0.1:PORT - "WebSocket /ws" [accepted]',
        'INFO:     127.0.0.1:PORT - "WebSocket /ws-reject" 403',
    ],
    # websockets-sansio also logs through the websockets library, into the same logger.
    "WebSocketsSansIOProtocol": [
        'INFO:     127.0.0.1:PORT - "WebSocket /ws" [accepted]',
        "INFO:     connection open",
        'INFO:     127.0.0.1:PORT - "WebSocket /ws-reject" 403',
        "INFO:     connection rejected (403 Forbidden)",
    ],
}


async def test_websocket_output(ws_protocol_cls: type, unused_tcp_port: int) -> None:
    async with serve(port=unused_tcp_port, ws=ws_protocol_cls) as output:
        async with connect(f"ws://127.0.0.1:{unused_tcp_port}/ws") as websocket:
            await websocket.wait_closed()
        with pytest.raises(InvalidStatus):
            async with connect(f"ws://127.0.0.1:{unused_tcp_port}/ws-reject"):
                pass  # pragma: no cover

    assert output.stdout == []
    assert output.stderr == STARTUP + WEBSOCKET_OUTPUT[ws_protocol_cls.__name__] + SHUTDOWN

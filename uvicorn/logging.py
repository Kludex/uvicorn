from __future__ import annotations

import http
import logging
import sys
import time
from copy import copy
from typing import Literal

import click

TRACE_LOG_LEVEL = 5


class ColourizedFormatter(logging.Formatter):
    """
    A custom log formatter class that:

    * Outputs the LOG_LEVEL with an appropriate color.
    * If a log call includes an `extra={"color_message": ...}` it will be used
      for formatting the output, instead of the plain text message.
    """

    level_name_colors = {
        TRACE_LOG_LEVEL: lambda level_name: click.style(str(level_name), fg="blue"),
        logging.DEBUG: lambda level_name: click.style(str(level_name), fg="cyan"),
        logging.INFO: lambda level_name: click.style(str(level_name), fg="green"),
        logging.WARNING: lambda level_name: click.style(str(level_name), fg="yellow"),
        logging.ERROR: lambda level_name: click.style(str(level_name), fg="red"),
        logging.CRITICAL: lambda level_name: click.style(str(level_name), fg="bright_red"),
    }

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
        use_colors: bool | None = None,
    ):
        if use_colors in (True, False):
            self.use_colors = use_colors
        else:
            self.use_colors = sys.stdout.isatty()
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

    def color_level_name(self, level_name: str, level_no: int) -> str:
        def default(level_name: str) -> str:
            return str(level_name)  # pragma: no cover

        func = self.level_name_colors.get(level_no, default)
        return func(level_name)

    def should_use_colors(self) -> bool:
        return True  # pragma: no cover

    def formatMessage(self, record: logging.LogRecord) -> str:
        recordcopy = copy(record)
        levelname = recordcopy.levelname
        separator = " " * (8 - len(recordcopy.levelname))
        if self.use_colors:
            levelname = self.color_level_name(levelname, recordcopy.levelno)
            if "color_message" in recordcopy.__dict__:
                recordcopy.msg = recordcopy.__dict__["color_message"]
                recordcopy.__dict__["message"] = recordcopy.getMessage()
        recordcopy.__dict__["levelprefix"] = levelname + ":" + separator
        return super().formatMessage(recordcopy)


class DefaultFormatter(ColourizedFormatter):
    def should_use_colors(self) -> bool:
        return sys.stderr.isatty()  # pragma: no cover


class AccessFormatter(ColourizedFormatter):
    status_code_colours = {
        1: lambda code: click.style(str(code), fg="bright_white"),
        2: lambda code: click.style(str(code), fg="green"),
        3: lambda code: click.style(str(code), fg="yellow"),
        4: lambda code: click.style(str(code), fg="red"),
        5: lambda code: click.style(str(code), fg="bright_red"),
    }

    def get_status_code(self, status_code: int) -> str:
        try:
            status_phrase = http.HTTPStatus(status_code).phrase
        except ValueError:
            status_phrase = ""
        status_and_phrase = f"{status_code} {status_phrase}"
        if self.use_colors:

            def default(code: int) -> str:
                return status_and_phrase  # pragma: no cover

            func = self.status_code_colours.get(status_code // 100, default)
            return func(status_and_phrase)
        return status_and_phrase

    def formatMessage(self, record: logging.LogRecord) -> str:
        recordcopy = copy(record)
        (
            client_addr,
            method,
            full_path,
            http_version,
            status_code,
        ) = recordcopy.args  # type: ignore[misc]
        status_code = self.get_status_code(int(status_code))  # type: ignore[arg-type]
        request_line = f"{method} {full_path} HTTP/{http_version}"
        if self.use_colors:
            request_line = click.style(request_line, bold=True)
        recordcopy.__dict__.update(
            {
                "client_addr": client_addr,
                "request_line": request_line,
                "status_code": status_code,
            }
        )
        return super().formatMessage(recordcopy)


class GunicornAccessFormatter(ColourizedFormatter):
    """
    A log formatter that supports gunicorn's access log format.

    Supported format atoms:
    h          - remote address
    l          - '-'
    u          - user name from Basic Auth
    t          - date of the request
    r          - status line (e.g. GET / HTTP/1.1)
    m          - request method
    U          - URL path without query string
    q          - query string
    H          - protocol
    s          - status
    B          - response length
    b          - response length or '-' (CLF format)
    f          - referer
    a          - user agent
    T          - request time in seconds
    D          - request time in microseconds
    M          - request time in milliseconds
    L          - request time in decimal seconds
    p          - process ID
    {header}i  - request header
    {header}o  - response header (not available)
    """

    status_code_colours = {
        1: lambda code: click.style(str(code), fg="bright_white"),
        2: lambda code: click.style(str(code), fg="green"),
        3: lambda code: click.style(str(code), fg="yellow"),
        4: lambda code: click.style(str(code), fg="red"),
        5: lambda code: click.style(str(code), fg="bright_red"),
    }

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
        use_colors: bool | None = None,
    ):
        if fmt is None:
            fmt = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

        self._gunicorn_fmt = fmt
        super().__init__(fmt="%(message)s", datefmt=datefmt, style=style, use_colors=use_colors)

    def get_status_code_colored(self, status_code: int) -> str:
        """Return colored status code string."""
        try:
            status_phrase = http.HTTPStatus(status_code).phrase
        except ValueError:
            status_phrase = ""
        status_and_phrase = f"{status_code} {status_phrase}"
        if self.use_colors:

            def default(code: int) -> str:
                return status_and_phrase  # pragma: no cover

            func = self.status_code_colours.get(status_code // 100, default)
            return func(status_and_phrase)
        return status_and_phrase

    def format(self, record: logging.LogRecord) -> str:
        """Format log record using gunicorn-style access log format."""
        import base64
        import binascii
        import os
        import re
        from typing import Any, Optional, cast

        recordcopy = copy(record)

        if hasattr(recordcopy, "args") and recordcopy.args and len(recordcopy.args) >= 4:
            # Extract scope, status_code, response_time, response_length from args
            args_tuple = cast(tuple[Any, ...], recordcopy.args)
            scope = cast(dict[str, Any], args_tuple[0])
            status_code = cast(int, args_tuple[1])
            response_time = cast(Optional[float], args_tuple[2])
            response_length = cast(Optional[int], args_tuple[3])

            method = cast(str, scope.get("method", ""))
            path = cast(str, scope.get("path", ""))
            http_version = cast(str, scope.get("http_version", "1.1"))
            client = scope.get("client")

            remote_addr = client[0] if client else "-"
            status_str = str(status_code)
            response_length_clf = str(response_length) if response_length and response_length > 0 else "-"
            current_time = time.strftime("[%d/%b/%Y:%H:%M:%S %z]")

            query_string_bytes = cast(bytes, scope.get("query_string", b""))
            query_string = query_string_bytes.decode("latin1")
            full_path = f"{path}?{query_string}" if query_string else path
            request_line = f"{method} {full_path} HTTP/{http_version}"
            if self.use_colors:
                request_line = click.style(request_line, bold=True)

            time_sec = response_time if response_time is not None else 0.0
            time_us = int(time_sec * 1_000_000)

            headers_dict: dict[str, str] = {}
            headers_list = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
            for header_name, header_value in headers_list:
                headers_dict[header_name.decode("latin1").lower()] = header_value.decode("latin1")

            username = "-"
            auth_header = headers_dict.get("authorization", "")
            if auth_header.lower().startswith("basic "):
                try:
                    encoded = auth_header[6:].strip()
                    decoded = base64.b64decode(encoded).decode("utf-8")
                    username = decoded.split(":", 1)[0]
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    pass

            atoms = {
                "h": remote_addr,
                "l": "-",
                "u": username,
                "t": current_time,
                "r": request_line,
                "m": method,
                "U": path,
                "q": query_string if query_string else "",
                "H": http_version,
                "s": status_str,
                "b": response_length_clf,
                "B": str(response_length) if response_length else "0",
                "D": str(time_us),
                "p": str(os.getpid()),
                "f": headers_dict.get("referer", "-"),
                "a": headers_dict.get("user-agent", "-"),
                "T": str(int(time_sec)),
                "M": str(int(time_sec * 1000)),
                "L": f"{time_sec:.6f}",
            }

            format_str = self._gunicorn_fmt

            def replace_header_i(match: re.Match[str]) -> str:
                header_name = match.group(1).lower()
                return headers_dict.get(header_name, "-")

            def replace_header_o(match: re.Match[str]) -> str:
                return "-"

            format_str = re.sub(r"%\(\{([^}]+)\}i\)s", replace_header_i, format_str)
            format_str = re.sub(r"%\(\{([^}]+)\}o\)s", replace_header_o, format_str)

            try:
                message = format_str % atoms
            except KeyError as e:
                message = f"<formatting error: missing atom {e}>"

            recordcopy.msg = message
            recordcopy.args = ()

        return super().format(recordcopy)

from __future__ import annotations

import http
import logging
import sys
from copy import copy
from typing import Any, Literal

from uvicorn._ansi import style as ansi_style

TRACE_LOG_LEVEL = 5

# "200 OK", "404 Not Found", ... for every status `http.HTTPStatus` knows.
_STATUS_PHRASES = {status.value: f"{status.value} {status.phrase}" for status in http.HTTPStatus}


class _Fields:
    """Lets the stdlib format styles, which read `obj.__dict__`, format a plain dict."""

    def __init__(self, fields: dict[str, Any]) -> None:
        self.__dict__ = fields


class ColourizedFormatter(logging.Formatter):
    """
    A custom log formatter class that:

    * Outputs the LOG_LEVEL with an appropriate color.
    * If a log call includes an `extra={"color_message": ...}` it will be used
      for formatting the output, instead of the plain text message.
    """

    level_name_colors = {
        TRACE_LOG_LEVEL: lambda level_name: ansi_style(str(level_name), fg="blue"),
        logging.DEBUG: lambda level_name: ansi_style(str(level_name), fg="cyan"),
        logging.INFO: lambda level_name: ansi_style(str(level_name), fg="green"),
        logging.WARNING: lambda level_name: ansi_style(str(level_name), fg="yellow"),
        logging.ERROR: lambda level_name: ansi_style(str(level_name), fg="red"),
        logging.CRITICAL: lambda level_name: ansi_style(str(level_name), fg="bright_red"),
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
        colour = self.level_name_colors.get(level_no)
        return level_name if colour is None else colour(level_name)

    def should_use_colors(self) -> bool:
        return True  # pragma: no cover

    def formatMessage(self, record: logging.LogRecord) -> str:
        # The record is shared with every other handler, so Uvicorn's fields never go onto it:
        # the format string reads them from a separate mapping instead.
        return super().formatMessage(_Fields(record.__dict__ | self._fields(record)))  # type: ignore[arg-type]

    def _fields(self, record: logging.LogRecord) -> dict[str, Any]:
        """The fields this formatter adds for its format string to use."""
        levelname = record.levelname
        separator = " " * (8 - len(levelname))
        fields: dict[str, Any] = {}
        if self.use_colors:
            levelname = self.color_level_name(levelname, record.levelno)
            if "color_message" in record.__dict__:
                fields["message"] = self._color_message(record)
        fields["levelprefix"] = levelname + ":" + separator
        return fields

    @staticmethod
    def _color_message(record: logging.LogRecord) -> str:
        # Rare (a few lines at startup), so a copy is fine here; it keeps any `getMessage()`
        # override on a custom record class.
        recordcopy = copy(record)
        recordcopy.msg = record.__dict__["color_message"]
        return recordcopy.getMessage()


class DefaultFormatter(ColourizedFormatter):
    def should_use_colors(self) -> bool:
        return sys.stderr.isatty()  # pragma: no cover


class AccessFormatter(ColourizedFormatter):
    status_code_colours = {
        1: lambda code: ansi_style(str(code), fg="bright_white"),
        2: lambda code: ansi_style(str(code), fg="green"),
        3: lambda code: ansi_style(str(code), fg="yellow"),
        4: lambda code: ansi_style(str(code), fg="red"),
        5: lambda code: ansi_style(str(code), fg="bright_red"),
    }

    def get_status_code(self, status_code: int) -> str:
        status_and_phrase = _STATUS_PHRASES.get(status_code) or f"{status_code} "
        if self.use_colors:
            colour = self.status_code_colours.get(status_code // 100)
            if colour is not None:
                return colour(status_and_phrase)
        return status_and_phrase

    def _fields(self, record: logging.LogRecord) -> dict[str, Any]:
        client_addr, method, full_path, http_version, status_code = record.args  # type: ignore[misc]
        request_line = f"{method} {full_path} HTTP/{http_version}"
        if self.use_colors:
            request_line = ansi_style(request_line, bold=True)
        return super()._fields(record) | {
            "client_addr": client_addr,
            "request_line": request_line,
            "status_code": self.get_status_code(int(status_code)),  # type: ignore[arg-type]
        }

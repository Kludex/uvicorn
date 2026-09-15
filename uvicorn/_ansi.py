from __future__ import annotations

_ANSI_COLORS = {
    "black": 30,
    "red": 31,
    "green": 32,
    "yellow": 33,
    "blue": 34,
    "magenta": 35,
    "cyan": 36,
    "white": 37,
    "bright_black": 90,
    "bright_red": 91,
    "bright_green": 92,
    "bright_yellow": 93,
    "bright_blue": 94,
    "bright_magenta": 95,
    "bright_cyan": 96,
    "bright_white": 97,
}


def style(text: str, fg: str | None = None, bold: bool = False) -> str:
    prefix = ""
    if fg is not None:
        prefix += f"\033[{_ANSI_COLORS[fg]}m"
    if bold:
        prefix += "\033[1m"
    return f"{prefix}{text}\033[0m"

from __future__ import annotations as _annotations

import re
import subprocess
from functools import lru_cache

from mkdocs.config import Config
from mkdocs.structure.files import Files
from mkdocs.structure.pages import Page


def on_page_content(html: str, page: Page, config: Config, files: Files) -> str:
    """Called on each page after the markdown is converted to HTML."""
    html = add_hyperlink_to_pull_request(html, page, config, files)
    return html


def add_hyperlink_to_pull_request(html: str, page: Page, config: Config, files: Files) -> str:
    """Add hyperlink on PRs mentioned on the release notes page.

    If we find "(#\\d+)" it will be added an hyperlink to https://github.com/Kludex/uvicorn/pull/$1.
    """
    if not page.file.name == "release-notes":
        return html

    return re.sub(r"\(#(\d+)\)", r"(<a href='https://github.com/Kludex/uvicorn/pull/\1'>#\1</a>)", html)


def on_page_markdown(markdown: str, page: Page, config: Config, files: Files) -> str:
    """Called on each file after it is read and before it is converted to HTML."""
    markdown = uvicorn_print_help(markdown, page)
    return markdown


def uvicorn_print_help(markdown: str, page: Page) -> str:
    return re.sub(r"{{ *uvicorn_help *}}", get_uvicorn_help(), markdown)


@lru_cache
def get_uvicorn_help():
    output = subprocess.run(["uvicorn", "--help"], capture_output=True, check=True)
    return output.stdout.decode()

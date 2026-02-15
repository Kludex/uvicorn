from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

env = {**os.environ, "COLUMNS": "150"}
help_output = subprocess.run(["uvicorn", "--help"], capture_output=True, text=True, check=True, env=env).stdout
replacement = f"<!-- uvicorn_help_output -->\n```\n{help_output}```\n<!-- /uvicorn_help_output -->"
pattern = re.compile(r"<!-- uvicorn_help_output -->\n```\n(.*?)```\n<!-- /uvicorn_help_output -->", re.DOTALL)

for path in [Path("docs/index.md"), Path("docs/deployment/index.md")]:
    content = path.read_text()
    match = pattern.search(content)
    if not match:
        print(f"ERROR: {path} is missing uvicorn_help_output markers.")
        sys.exit(1)
    if match.group(0) == replacement:
        continue
    content = content[: match.start()] + replacement + content[match.end() :]
    path.write_text(content)
    print(f"Updated {path}")

print("OK: uvicorn --help output is up to date in docs.")

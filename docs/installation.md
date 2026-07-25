**Uvicorn** is available on [PyPI](https://pypi.org/project/uvicorn/) so installation is as simple as:

=== "pip"

    ```bash
    pip install uvicorn
    ```

=== "uv"

    ```bash
    uv add uvicorn
    ```

The above will install Uvicorn with the minimal set of dependencies:

- [`h11`](https://github.com/python-hyper/h11) — Pure Python sans-io HTTP/1.1 implementation.
- [`click`](https://github.com/pallets/click) — Command line interface library.

If you are running on Python 3.10 or early versions,
[`typing_extensions`](https://github.com/python/typing_extensions) will also be installed.

## Optional Dependencies

There are many optional dependencies that can be installed to add support for various features.

Optional dependencies are grouped by feature, so you can install only what you need:

| Extra | Dependencies | Purpose |
| --- | --- | --- |
| `development` | `watchfiles` | Improved `--reload` support. |
| `dotenv` | `python-dotenv` | Support for `--env-file`. |
| `performance` | `httptools`, `uvloop` | Faster HTTP parsing and event loop, where supported. |
| `websockets` | `websockets` | WebSocket protocol support. |
| `yaml` | `PyYAML` | YAML files for `--log-config`. |

For example, to install reload and YAML configuration support:

=== "pip"
    ```bash
    pip install 'uvicorn[development,yaml]'
    ```

=== "uv"
    ```bash
    uv add 'uvicorn[development,yaml]'
    ```

If you want to install all optional dependencies at once, use the `standard` extra:

=== "pip"
    ```bash
    pip install 'uvicorn[standard]'
    ```

=== "uv"
    ```bash
    uv add 'uvicorn[standard]'
    ```

The `standard` extra combines all of the feature-specific extras and installs the following dependencies:

- **[`uvloop`](https://github.com/MagicStack/uvloop) — Fast, drop-in replacement of the built-in asyncio event loop.**

    When `uvloop` is installed, Uvicorn will use it by default.

- **[`httptools`](https://github.com/MagicStack/httptools) — Python binding for the Node.js HTTP parser.**

    When `httptools` is installed, Uvicorn will use it by default for HTTP/1.1 parsing.

    You can read this issue to understand how it compares with `h11`: [h11/issues/9](https://github.com/python-hyper/h11/issues/9).

- **[`websockets`](https://websockets.readthedocs.io/en/stable/) — WebSocket library for Python.**

    When `websockets` is installed, Uvicorn will use it by default for WebSocket handling.

    You can alternatively install **[`wsproto`](https://github.com/python-hyper/wsproto)** and set the `--ws`
    option to `wsproto` to use it instead.

- **[`watchfiles`](https://github.com/samuelcolvin/watchfiles) — Simple, modern and high performance file
    watching and code reload in python.**

    When `watchfiles` is installed, Uvicorn will use it by default for the `--reload` option.

- **[`python-dotenv`](https://github.com/theskumar/python-dotenv) — Reads key-value pairs from a `.env` file
    and adds them to the environment.**

    This is installed to allow you to use the `--env-file` option.

- **[`PyYAML`](https://github.com/yaml/pyyaml) — YAML parser and emitter for Python.**

    This is installed to allow you to provide a `.yaml` file to the `--log-config` option.

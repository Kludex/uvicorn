<p align="center">
  <img width="320" height="320" src="https://raw.githubusercontent.com/tomchristie/uvicorn/main/docs/uvicorn.png" alt='uvicorn'>
</p>

<p align="center">
<em>An ASGI web server, for Python.</em>
</p>

---

[![Build Status](https://github.com/Kludex/uvicorn/workflows/Test%20Suite/badge.svg)](https://github.com/Kludex/uvicorn/actions)
[![Package version](https://badge.fury.io/py/uvicorn.svg)](https://pypi.python.org/pypi/uvicorn)
[![Supported Python Version](https://img.shields.io/pypi/pyversions/uvicorn.svg?color=%2334D058)](https://pypl.org/project/uvicorn)
[![Discord](https://img.shields.io/discord/1051468649518616576?logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/RxKUF5JuHs)

---

**Documentation**: [https://uvicorn.dev](https://uvicorn.dev)

**Source Code**: [https://www.github.com/Kludex/uvicorn](https://www.github.com/Kludex/uvicorn)

---

Uvicorn is an ASGI web server implementation for Python.

### Logging Configuration

You can provide a custom logging configuration file using the `--log-config` flag. See the [Python logging.config documentation](https://docs.python.org/3/library/logging.config.html#logging-config-fileformat) for details on the format.

An example configuration file can be found at `examples/logging_config.ini` in the repository.

> [!WARNING]
> When you provide a custom logging configuration, Uvicorn's default loggers may be disabled. Ensure your configuration includes the `uvicorn`, `uvicorn.error`, and `uvicorn.access` loggers if you wish to maintain Uvicorn's standard output.

## Quickstart

Install using `pip`:

```shell
$ pip install uvicorn
```

This will install uvicorn with minimal (pure Python) dependencies.

```shell
$ pip install 'uvicorn[standard]'
```

This will install uvicorn with "Cython-based" dependencies (where possible) and other "optional extras".

In this context, "Cython-based" means the following:

- the event loop `uvloop` will be installed and used if possible.
- the http protocol will be handled by `httptools` if possible.

Moreover, "optional extras" means that:

- the websocket protocol will be handled by `websockets` (should you want to use `wsproto` you'd need to install it manually) if possible.
- the `--reload` flag in development mode will use `watchfiles`.
- window

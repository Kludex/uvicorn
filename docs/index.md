<p align="center">
  <img width="320" height="320" src="../../uvicorn.png" alt='uvicorn'>
</p>

<p align="center">
<em>An ASGI web server, for Python.</em>
</p>

<p align="center">
<a href="https://github.com/encode/uvicorn/actions">
    <img src="https://github.com/encode/uvicorn/workflows/Test%20Suite/badge.svg" alt="Test Suite">
</a>
<a href="https://pypi.org/project/uvicorn/">
    <img src="https://badge.fury.io/py/uvicorn.svg" alt="Package version">
</a>
<a href="https://pypi.org/project/uvicorn" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/uvicorn.svg?color=%2334D058" alt="Supported Python versions">
</a>
</p>

## Introduction

Uvicorn is an ASGI web server implementation for Python.

Until recently Python has lacked a minimal low-level server/application interface for
async frameworks. The [ASGI specification][asgi] fills this gap, and means we're now able to
start building a common set of tooling usable across all async frameworks.

Uvicorn currently supports **HTTP/1.1** and **WebSockets**.

## Quickstart

You can install Uvicorn via `pip`, as follows:

```shell
$ pip install uvicorn
```

This will install uvicorn with minimal (pure Python) dependencies.

If you want to install the "Cython-based" dependencies, and other _optional dependencies_, use the `standard` extra:

```shell
$ pip install 'uvicorn[standard]'
```

In this context, "Cython-based" means the following:

- [`uvloop`][uvloop] will be installed, and used, _if possible_. See [Event Loop][event loop] section for more details.
- [`httptools`][httptools] will be installed, and used, _if possible_. See [HTTP Parser][http parser] section for more details.

Moreover, "optional extras" means that:

- [`websockets`][websockets] will be installed, and used. See [WebSockets implementations][ws] section for more details.
- [`watchfiles`][watchfiles] will be installed, and used, _if possible_. See [Reload][reload] section.
- [`colorama`][colorama] will be installed for _colored logs_. See [Logs][logs] section.
- [`python-dotenv`][python-dotenv] will be installed, which enables you to use the `--env-file` option.
- [`PyYAML`][pyyaml] will be installed to allow you to provide a `.yaml` file to `--log-config`, if desired.

Let's create a simple [ASGI][asgi] application:

```py title="main.py"
async def app(scope, receive, send):
    assert scope['type'] == 'http'

    await send({
        'type': 'http.response.start',  # (1)!
        'status': 200,
        'headers': [
          (b'content-type', b'text/plain'),
          (b'content-length', b'13')
        ],
    })
    await send({'type': 'http.response.body', 'body': b'Hello, world!'})  # (2)!
```

1. The `http.response.start` message is sent to indicate that the response is starting.

    See [Response Start](https://asgi.readthedocs.io/en/latest/specs/www.html#response-start-send-event) for more details.

2. The `http.response.body` message is sent to indicate the response body.

    See [Response Body](https://asgi.readthedocs.io/en/latest/specs/www.html#response-body-send-event) for more details.

Run the server:

```bash
$ uvicorn main:app
```

[asgi]: https://asgi.readthedocs.io/en/latest/
<!-- TODO -->
[event loop]: https://google.com
[http parser]: https://google.com
[ws]: https://google.com
[reload]: https://google.com
[logs]: https://google.com
[uvloop]: https://github.com/MagicStack/uvloop
[httptools]: https://github.com/MagicStack/httptools
[websockets]: https://websockets.readthedocs.io/en/stable/
[watchfiles]: https://watchfiles.helpmanual.io/
[colorama]: https://github.com/tartley/colorama
[python-dotenv]: https://saurabh-kumar.com/python-dotenv/
[pyyaml]: https://pyyaml.org/wiki/PyYAMLDocumentation

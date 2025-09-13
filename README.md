<p align="center">
  <img width="320" height="320" src="https://raw.githubusercontent.com/tomchristie/uvicorn/master/docs/uvicorn.png" alt='uvicorn'>
</p>

<p align="center">
<em>An ASGI web server, for Python.</em>
</p>

---

[![Build Status](https://github.com/Kludex/uvicorn/workflows/Test%20Suite/badge.svg)](https://github.com/Kludex/uvicorn/actions)
[![Package version](https://badge.fury.io/py/uvicorn.svg)](https://pypi.python.org/pypi/uvicorn)
[![Supported Python Version](https://img.shields.io/pypi/pyversions/uvicorn.svg?color=%2334D058)](https://pypi.org/project/uvicorn)

**Documentation**: [https://www.uvicorn.org](https://www.uvicorn.org)

---

Uvicorn is an ASGI web server implementation for Python.

Until recently Python has lacked a minimal low-level server/application interface for
async frameworks. The [ASGI specification][asgi] fills this gap, and means we're now able to
start building a common set of tooling usable across all async frameworks.

Uvicorn supports HTTP/1.1 and WebSockets.

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
- windows users will have `colorama` installed for the colored logs.
- `python-dotenv` will be installed should you want to use the `--env-file` option.
- `PyYAML` will be installed to allow you to provide a `.yaml` file to `--log-config`, if desired.

Create an application, in `example.py`:

```python
async def app(scope, receive, send):
    assert scope['type'] == 'http'

    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            (b'content-type', b'text/plain'),
        ],
    })
    await send({
        'type': 'http.response.body',
        'body': b'Hello, world!',
    })
```

Run the server:

```shell
$ uvicorn example:app
```

---

## Why ASGI?

Most well established Python Web frameworks started out as WSGI-based frameworks.

WSGI applications are a single, synchronous callable that takes a request and returns a response.
This doesn’t allow for long-lived connections, like you get with long-poll HTTP or WebSocket connections,
which WSGI doesn't support well.

Having an async concurrency model also allows for options such as lightweight background tasks,
and can be less of a limiting factor for endpoints that have long periods being blocked on network
I/O such as dealing with slow HTTP requests.

---

## Alternative ASGI servers

A strength of the ASGI protocol is that it decouples the server implementation
from the application framework. This allows for an ecosystem of interoperating
webservers and application frameworks.

### Daphne

The first ASGI server implementation, originally developed to power Django Channels, is [the Daphne webserver][daphne].

It is run widely in production, and supports HTTP/1.1, HTTP/2, and WebSockets.

Any of the example applications given here can equally well be run using `daphne` instead.

```
$ pip install daphne
$ daphne app:App
```

### Hypercorn

[Hypercorn][hypercorn] was initially part of the Quart web framework, before
being separated out into a standalone ASGI server.

Hypercorn supports HTTP/1.1, HTTP/2, and WebSockets.

It also supports [the excellent `trio` async framework][trio], as an alternative to `asyncio`.

```
$ pip install hypercorn
$ hypercorn app:App
```

### Mangum

[Mangum][mangum] is an adapter for using ASGI applications with AWS Lambda & API Gateway.

### Granian

[Granian][granian] is an ASGI compatible Rust HTTP server which supports HTTP/2, TLS and WebSockets.

---

<p align="center"><i>Uvicorn is <a href="https://github.com/Kludex/uvicorn/blob/master/LICENSE.md">BSD licensed</a> code.<br/>Designed & crafted with care.</i><br/>&mdash; 🦄  &mdash;</p>

[asgi]: https://asgi.readthedocs.io/en/latest/
[daphne]: https://github.com/django/daphne
[hypercorn]: https://github.com/pgjones/hypercorn
[trio]: https://trio.readthedocs.io
[mangum]: https://github.com/jordaneremieff/mangum
[granian]: https://github.com/emmett-framework/granian

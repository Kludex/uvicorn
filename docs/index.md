<style>
  .md-typeset h1,
  .md-content__button {
    display: none;
  }
</style>

<p align="center">
  <img width="320" height="320" src="../../uvicorn.png" alt='uvicorn'>
</p>

<p align="center">
<em>An ASGI web server, for Python.</em>
</p>

<p align="center">
<a href="https://github.com/Kludex/uvicorn/actions">
    <img src="https://github.com/Kludex/uvicorn/workflows/Test%20Suite/badge.svg" alt="Test Suite">
</a>
<a href="https://pypi.org/project/uvicorn/">
    <img src="https://badge.fury.io/py/uvicorn.svg" alt="Package version">
</a>
<a href="https://pypi.org/project/uvicorn" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/uvicorn.svg?color=%2334D058" alt="Supported Python versions">
</a>
<a href="https://discord.gg/RxKUF5JuHs">
    <img src="https://img.shields.io/discord/1051468649518616576?logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2" alt="Discord">
</a>
</p>

---

**Documentation**: [https://www.uvicorn.org](https://www.uvicorn.org)<br>
**Source Code**: [https://www.github.com/Kludex/uvicorn](https://www.github.com/Kludex/uvicorn)

---

**Uvicorn** is an [ASGI](concepts/asgi.md) web server implementation for Python.

Until recently Python has lacked a minimal low-level server/application interface for
async frameworks. The [ASGI specification](https://asgi.readthedocs.io/en/latest/) fills this gap,
and means we're now able to start building a common set of tooling usable across all async frameworks.

Uvicorn currently supports **HTTP/1.1** and **WebSockets**.

## Quickstart

**Uvicorn** is available on [PyPI](https://pypi.org/project/uvicorn/) so installation is as simple as:

=== "pip"
    ```bash
    pip install uvicorn
    ```

=== "uv"
    ```bash
    uv add uvicorn
    ```

See the [installation documentation](installation.md) for more information.

---

Let's create a simple ASGI application to run with Uvicorn:

```python title="main.py"
async def app(scope, receive, send):
    assert scope['type'] == 'http'

    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            (b'content-type', b'text/plain'),
            (b'content-length', b'13'),
        ],
    })
    await send({
        'type': 'http.response.body',
        'body': b'Hello, world!',
    })
```

Then we can run it with Uvicorn:

```shell
uvicorn main:app
```

---

## Usage

The uvicorn command line tool is the easiest way to run your application.

### Command line options

```bash
{{ uvicorn_help }}
```

For more information, see the [settings documentation](settings.md).

### Running programmatically

There are several ways to run uvicorn directly from your application.

#### `uvicorn.run`

If you're looking for a programmatic equivalent of the `uvicorn` command line interface, use `uvicorn.run()`:

```py title="main.py"
import uvicorn

async def app(scope, receive, send):
    ...

if __name__ == "__main__":
    uvicorn.run("main:app", port=5000, log_level="info")
```

#### `Config` and `Server` instances

For more control over configuration and server lifecycle, use `uvicorn.Config` and `uvicorn.Server`:

```py title="main.py"
import uvicorn

async def app(scope, receive, send):
    ...

if __name__ == "__main__":
    config = uvicorn.Config("main:app", port=5000, log_level="info")
    server = uvicorn.Server(config)
    server.run()
```

If you'd like to run Uvicorn from an already running async environment, use `uvicorn.Server.serve()` instead:

```py title="main.py"
import asyncio
import uvicorn

async def app(scope, receive, send):
    ...

async def main():
    config = uvicorn.Config("main:app", port=5000, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

### Running with Gunicorn

!!! warning
    The `uvicorn.workers` module is deprecated and will be removed in a future release.

    You should use the [`uvicorn-worker`](https://github.com/Kludex/uvicorn-worker) package instead.

    ```bash
    python -m pip install uvicorn-worker
    ```

[Gunicorn](https://gunicorn.org/) is a mature, fully featured server and process manager.

Uvicorn includes a Gunicorn worker class allowing you to run ASGI applications,
with all of Uvicorn's performance benefits, while also giving you Gunicorn's
fully-featured process management.

This allows you to increase or decrease the number of worker processes on the
fly, restart worker processes gracefully, or perform server upgrades without downtime.

For production deployments we recommend using gunicorn with the uvicorn worker class.

```
gunicorn example:app -w 4 -k uvicorn.workers.UvicornWorker
```

For a [PyPy](https://pypy.org/) compatible configuration use `uvicorn.workers.UvicornH11Worker`.

For more information, see the [deployment documentation](deployment/index.md).

### Application factories

The `--factory` flag allows loading the application from a factory function, rather than an application instance directly. The factory will be called with no arguments and should return an ASGI application.

```py title="main.py"
def create_app():
    app = ...
    return app
```

```shell
uvicorn --factory main:create_app
```

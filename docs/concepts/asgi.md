## ASGI

**Uvicorn** uses the [ASGI specification](https://asgi.readthedocs.io/en/latest/) for interacting with an application.

The application should expose an async callable which takes three arguments:

* `scope` - A dictionary containing information about the incoming connection.
* `receive` - A channel on which to receive incoming messages from the server.
* `send` - A channel on which to send outgoing messages to the server.

Two common patterns you might use are either function-based applications:

```python
async def app(scope, receive, send):
    assert scope['type'] == 'http'
    ...
```

Or instance-based applications:

```python
class App:
    async def __call__(self, scope, receive, send):
        assert scope['type'] == 'http'
        ...

app = App()
```

It's good practice for applications to raise an exception on scope types
that they do not handle.

The content of the `scope` argument, and the messages expected by `receive` and `send` depend on the protocol being used.

The format for HTTP messages is described in the [ASGI HTTP Message format](https://asgi.readthedocs.io/en/latest/specs/www.html).

### HTTP Scope

An incoming HTTP request might have a connection `scope` like this:

```python
{
    'type': 'http',
    'scheme': 'http',
    'root_path': '',
    'server': ('127.0.0.1', 8000),
    'http_version': '1.1',
    'method': 'GET',
    'path': '/',
    'headers': [
        (b'host', b'127.0.0.1:8000'),
        (b'user-agent', b'curl/7.51.0'),
        (b'accept', b'*/*')
    ]
}
```

### HTTP Messages

The instance coroutine communicates back to the server by sending messages to the `send` coroutine.

```python
await send({
    'type': 'http.response.start',
    'status': 200,
    'headers': [
        [b'content-type', b'text/plain'],
    ]
})
await send({
    'type': 'http.response.body',
    'body': b'Hello, world!',
})
```

### Requests & responses

Here's an example that displays the method and path used in the incoming request:

```python
async def app(scope, receive, send):
    """
    Echo the method and path back in an HTTP response.
    """
    assert scope['type'] == 'http'

    body = f'Received {scope["method"]} request to {scope["path"]}'
    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            [b'content-type', b'text/plain'],
        ]
    })
    await send({
        'type': 'http.response.body',
        'body': body.encode('utf-8'),
    })
```

### Reading the request body

You can stream the request body without blocking the asyncio task pool,
by fetching messages from the `receive` coroutine.

```python
async def read_body(receive):
    """
    Read and return the entire body from an incoming ASGI message.
    """
    body = b''
    more_body = True

    while more_body:
        message = await receive()
        body += message.get('body', b'')
        more_body = message.get('more_body', False)

    return body


async def app(scope, receive, send):
    """
    Echo the request body back in an HTTP response.
    """
    body = await read_body(receive)
    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            (b'content-type', b'text/plain'),
            (b'content-length', str(len(body)).encode())
        ]
    })
    await send({
        'type': 'http.response.body',
        'body': body,
    })
```

### Streaming responses

You can stream responses by sending multiple `http.response.body` messages to
the `send` coroutine.

```python
import asyncio


async def app(scope, receive, send):
    """
    Send a slowly streaming HTTP response back to the client.
    """
    await send({
        'type': 'http.response.start',
        'status': 200,
        'headers': [
            [b'content-type', b'text/plain'],
        ]
    })
    for chunk in [b'Hello', b', ', b'world!']:
        await send({
            'type': 'http.response.body',
            'body': chunk,
            'more_body': True
        })
        await asyncio.sleep(1)
    await send({
        'type': 'http.response.body',
        'body': b'',
    })
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

The first ASGI server implementation, originally developed to power Django Channels, is
[the Daphne webserver](https://github.com/django/daphne).

It is run widely in production, and supports HTTP/1.1, HTTP/2, and WebSockets.

Any of the example applications given here can equally well be run using `daphne` instead.

```shell
pip install daphne
daphne app:App
```

### Hypercorn

[Hypercorn](https://github.com/pgjones/hypercorn) was initially part of the Quart web framework,
before being separated out into a standalone ASGI server.

Hypercorn supports HTTP/1.1, HTTP/2, HTTP/3 and WebSockets.

```shell
pip install hypercorn
hypercorn app:App
```

---

## ASGI frameworks

You can use Uvicorn, Daphne, or Hypercorn to run any ASGI framework.

For small services you can also write ASGI applications directly.

### Starlette

[Starlette](https://github.com/Kludex/starlette) is a lightweight ASGI framework/toolkit.

It is ideal for building high performance asyncio services, and supports both HTTP and WebSockets.

### Django Channels

The ASGI specification was originally designed for use with [Django Channels](https://channels.readthedocs.io/en/latest/).

Channels is a little different to other ASGI frameworks in that it provides
an asynchronous frontend onto a threaded-framework backend. It allows Django
to support WebSockets, background tasks, and long-running connections,
with application code still running in a standard threaded context.

### Quart

[Quart](https://pgjones.gitlab.io/quart/) is a Flask-like ASGI web framework.

### FastAPI

[**FastAPI**](https://github.com/tiangolo/fastapi) is an API framework based on **Starlette** and **Pydantic**, heavily inspired by previous server versions of **APIStar**.

You write your API function parameters with Python 3.6+ type declarations and get automatic data conversion, data validation, OpenAPI schemas (with JSON Schemas) and interactive API documentation UIs.

### BlackSheep

[BlackSheep](https://www.neoteroi.dev/blacksheep/) is a web framework based on ASGI, inspired by Flask and ASP.NET Core.

Its most distinctive features are built-in support for dependency injection, automatic binding of parameters by request handler's type annotations, and automatic generation of OpenAPI documentation and Swagger UI.

### Falcon

[Falcon](https://falconframework.org) is a minimalist REST and app backend framework for Python, with a focus on reliability, correctness, and performance at scale.

### Muffin

[Muffin](https://github.com/klen/muffin) is a fast, lightweight and asynchronous ASGI web-framework for Python 3.

### Litestar

[Litestar](https://litestar.dev) is a powerful, lightweight and flexible ASGI framework.

It includes everything that's needed to build modern APIs - from data serialization and validation to websockets, ORM integration, session management, authentication and more.

### Panther

[Panther](https://PantherPy.github.io/) is a fast & friendly web framework for building async APIs with Python 3.10+.

It has built-in Document-oriented Database, Caching System, Authentication and Permission Classes, Visual API Monitoring and also supports Websocket, Throttling, Middlewares.

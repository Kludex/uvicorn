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

Over HTTPS the scope additionally carries an `extensions` key, see
[TLS and client certificates](#tls-and-client-certificates) below.

### TLS and client certificates

For TLS connections Uvicorn implements version 0.2 of the
[ASGI TLS Extension](https://asgi.readthedocs.io/en/latest/specs/tls.html). The information is
found under `scope["extensions"]["tls"]`, for all HTTP (`h11`, `httptools`) and WebSocket
(`websockets`, `websockets-sansio`, `wsproto`) implementations.

!!! warning
    The extension is only present on connections that Uvicorn itself terminates with TLS. As
    the specification requires, the `tls` key is **absent** for plain `http://` and `ws://`
    connections — including when a proxy or load balancer terminates TLS in front of Uvicorn.
    Always probe with `scope.get("extensions", {}).get("tls")` rather than indexing directly.

| Key | Type | Value |
| --- | --- | --- |
| `server_cert` | `None` | Always `None`; CPython's `ssl` module has no API to read back the server's own certificate. |
| `client_cert_chain` | `list[str]` | PEM-encoded certificates, the client certificate first. Empty if the client sent none. |
| `client_cert_name` | `str \| None` | The Subject of the client certificate as an [RFC 4514](https://datatracker.ietf.org/doc/html/rfc4514) string, or `None`. |
| `client_cert_error` | `None` | Always `None`, see below. |
| `tls_version` | `int` | e.g. `0x0304` for TLS 1.3, `0x0303` for TLS 1.2. |
| `cipher_suite` | `int` | 16-bit suite id, e.g. `0x1302` for `TLS_AES_256_GCM_SHA384`. |
| `client_cert_dict` | `dict \| None` | **Uvicorn addition**, see [below](#the-client_cert_dict-addition). |

An example, from a connection that presented a client certificate:

```python
{
    'server_cert': None,
    'client_cert_chain': ['-----BEGIN CERTIFICATE-----\nMIIC...', '-----BEGIN CERTIFICATE-----\nMIIB...'],
    'client_cert_name': 'CN=client.example.org,O=Example Inc',
    'client_cert_error': None,
    'tls_version': 772,      # 0x0304
    'cipher_suite': 4866,    # 0x1302
    'client_cert_dict': {...},
}
```

#### When is a client certificate present?

The server only asks the client for a certificate when `--ssl-cert-reqs` is set:

| `--ssl-cert-reqs` | Client sends a certificate | Result |
| --- | --- | --- |
| `0` = `ssl.CERT_NONE` (default) | — | Never requested. `client_cert_chain` is empty. |
| `1` = `ssl.CERT_OPTIONAL` | no | Connection allowed, `client_cert_chain` is empty. |
| `1` = `ssl.CERT_OPTIONAL` | yes, valid | `client_cert_chain` is populated. |
| `2` = `ssl.CERT_REQUIRED` | yes, valid | `client_cert_chain` is populated. |
| `2` = `ssl.CERT_REQUIRED` | no, or invalid | TLS handshake fails, the application is never called. |

Validation requires a CA, so `--ssl-cert-reqs` other than `CERT_NONE` needs `--ssl-ca-certs`.

Note that `client_cert_error` is always `None` in Uvicorn: Python's `ssl` module aborts the
handshake when a certificate fails verification, so a connection with a rejected certificate
never reaches the application. The field exists for servers that can be configured to accept
such connections anyway.

!!! note
    `client_cert_chain` contains the full verified chain — the client certificate followed by
    the issuing CA certificate(s) — only on Python 3.13 and newer, which added
    `ssl.SSLObject.get_verified_chain()`. On Python 3.10 to 3.12 only the client certificate
    itself is reachable, so the list holds exactly one entry. `client_cert_chain[0]` is the
    client certificate on every version.

#### The `client_cert_dict` addition

Alongside the keys defined by the specification, Uvicorn adds `client_cert_dict`: the client
certificate already parsed, in the format of
[`ssl.SSLSocket.getpeercert()`](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.getpeercert).
It is `None` when no client certificate was presented. This saves applications from parsing
`client_cert_chain[0]` with a library such as `cryptography` for the common case of reading a
name out of the certificate.

```python
{
    'subject': ((('commonName', 'client.example.org'),), (('organizationName', 'Example Inc'),)),
    'issuer': ((('commonName', 'Example CA'),),),
    'version': 3,
    'serialNumber': '057B7C9F3F0B2A1E',
    'notBefore': 'Jan  1 00:00:00 2025 GMT',
    'notAfter': 'Jan  1 00:00:00 2026 GMT',
    'subjectAltName': (('DNS', 'client.example.org'), ('email', 'client@example.org')),
}
```

`subject` and `issuer` are tuples of relative distinguished names, each of which is itself a
tuple of `(name, value)` pairs — so they usually need flattening before use:

```python
async def app(scope, receive, send):
    tls = scope.get('extensions', {}).get('tls')
    cert = tls['client_cert_dict'] if tls else None
    if cert is None:
        common_name = None
    else:
        subject = {name: value for rdn in cert['subject'] for name, value in rdn}
        common_name = subject.get('commonName')
    ...
```

Because this key is not part of the specification, applications that need to run on other ASGI
servers should use `client_cert_chain` or `client_cert_name` instead.

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

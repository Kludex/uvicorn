**Uvicorn** has experimental support for HTTP/2, built on the [`zttp`](https://zttp.marcelotryle.com/)
parser.

!!! warning "Experimental Feature"
    HTTP/2 support is currently **experimental** and is **not enabled by default**.

## Overview

HTTP/2 introduces several key features:

- **Multiplexing**: Multiple requests and responses can be sent simultaneously over a single TCP connection
- **Header compression**: HTTP headers are compressed using HPACK, reducing overhead
- **Binary protocol**: More efficient parsing compared to HTTP/1.1's text-based format

## Enabling HTTP/2

HTTP/2 support requires the `zttp` package:

```bash
pip install zttp
```

To enable it, use the `--http2` flag:

=== "Command Line"
    ```bash
    uvicorn main:app --http2
    ```

=== "Programmatic"
    ```python
    import uvicorn

    uvicorn.run("main:app", http2=True)
    ```

## Connection Methods

### h2: HTTP/2 over TLS (Recommended)

When using HTTPS, HTTP/2 is negotiated via **ALPN** (Application-Layer Protocol Negotiation)
during the TLS handshake. This is the most common way to use HTTP/2, and the only one web
browsers support.

For testing it locally, you can generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Then create a simple ASGI application:

```python title="main.py"
async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})
```

Run Uvicorn with the `--http2` flag and the SSL certificate files:

```bash
uvicorn main:app --http2 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

You can test the connection using curl (`-k` skips certificate verification for self-signed certs):

```bash
curl -v --http2 -k https://localhost:8000/
```

### h2c: HTTP/2 Cleartext with Prior Knowledge

On cleartext connections, Uvicorn accepts clients that speak HTTP/2 directly - known as
"prior knowledge" h2c. The client opens the connection with the HTTP/2 preface instead of an
HTTP/1.1 request, and Uvicorn switches protocols on the spot. Using the same `main.py`:

```bash
uvicorn main:app --http2
```

```bash
curl -v --http2-prior-knowledge http://localhost:8000/
```

This is the mechanism proxies use for `h2c://` upstreams (e.g. Traefik and Envoy), so HTTP/2
between a proxy and Uvicorn works without TLS.

!!! warning
    The HTTP/1.1 `Upgrade: h2c` mechanism is **not** supported: an upgrade request is served
    as plain HTTP/1.1, which RFC 7540 explicitly allows. Browsers do not support h2c at all -
    they only speak HTTP/2 over TLS.

## ASGI Scope

When a request comes in over HTTP/2, the ASGI scope has `http_version` set to `"2"`:

```python
async def app(scope, receive, send):
    assert scope["type"] == "http"
    print(f"HTTP Version: {scope['http_version']}")  # "2" for HTTP/2
```

## Current Limitations

The implementation is young, and some protocol features are not complete yet:

- Request bodies are limited by the HTTP/2 flow-control window (64 KiB): the server does not
  yet replenish the window, so larger uploads stall. Use HTTP/1.1 for uploads for now.
- `SETTINGS` and `PING` frames from the client are not yet acknowledged, which strict clients
  may treat as a protocol violation on long-lived connections.
- Graceful shutdown closes the connection without sending `GOAWAY`.
- HTTP/2 server push and `Expect: 100-continue` are not supported.

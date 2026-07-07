**Uvicorn** has experimental support for HTTP/3, built on the [`zttp`](https://zttp.marcelotryle.com/)
parser and its from-scratch QUIC transport.

!!! warning "Experimental Feature"
    HTTP/3 support is currently **experimental** and is **not enabled by default**. It rides a
    young QUIC stack; do not run it in production yet.

## Overview

HTTP/3 keeps the HTTP/2 semantics - multiplexed streams, header compression, a binary framing -
but replaces the transport. Instead of running over TCP + TLS, it runs over **QUIC**, a protocol
built on **UDP** that folds the TLS 1.3 handshake, loss recovery, and per-stream flow control into
one layer. The headline wins are no head-of-line blocking across streams and a faster handshake.

Because QUIC is UDP-based, Uvicorn opens a **separate UDP socket** on the same port number as the
TCP listener. HTTP/3 is not an upgrade on an existing connection the way h2c is; clients discover
it out of band (typically via an `Alt-Svc` header on an HTTP/1.1 or HTTP/2 response) and then
connect over UDP.

## Enabling HTTP/3

HTTP/3 support requires the `zttp` (>= 0.0.14) and `cryptography` packages:

```bash
pip install "zttp>=0.0.14" cryptography
```

To enable it, use the `--http3` flag:

=== "Command Line"
    ```bash
    uvicorn main:app --http3
    ```

=== "Programmatic"
    ```python
    import uvicorn

    uvicorn.run("main:app", http3=True)
    ```

This binds a UDP endpoint on the configured host and port, alongside the usual TCP server.

## TLS certificate

QUIC always encrypts, so HTTP/3 needs a TLS certificate. zttp's QUIC stack currently signs the
handshake with a raw **P-256 (SECP256R1)** key, so the server key must be an EC P-256 key - RSA
keys are not supported yet. Generate a self-signed pair for local testing:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -x509 -new -key key.pem -out cert.pem -days 365 -subj "/CN=localhost"
```

Then run Uvicorn with the certificate:

```bash
uvicorn main:app --http3 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

If no certificate is configured, zttp falls back to an ephemeral identity. That is convenient for
experiments with a non-verifying client, but real clients will reject it.

You can exercise it with a curl built against an HTTP/3 library (`-k` skips certificate
verification for self-signed certs):

```bash
curl -v --http3-only -k https://localhost:8000/
```

## ASGI Scope

When a request comes in over HTTP/3, the ASGI scope has `http_version` set to `"3"` and `scheme`
set to `"https"` (QUIC is always encrypted):

```python
async def app(scope, receive, send):
    assert scope["type"] == "http"
    print(f"HTTP Version: {scope['http_version']}")  # "3" for HTTP/3
```

## Current Limitations

The implementation is young, and several pieces are deliberately minimal:

- **Datagrams are demultiplexed by peer address.** QUIC connection migration and NAT rebinding
  are not supported: a client that changes its address mid-connection is treated as a new one.
- **Only P-256 EC certificates** are accepted for the server key.
- **No `Alt-Svc` advertisement** is injected automatically - if you also serve HTTP/1.1 or HTTP/2,
  add the header yourself so browsers discover the HTTP/3 endpoint.
- **Bounded, not fully flow-controlled.** A request whose in-memory body exceeds an internal cap
  (~4 MiB) has its stream reset rather than being back-pressured, and the number of concurrent
  QUIC connections is capped. Prefer HTTP/1.1 for large uploads for now.
- HTTP/3 server push and `Expect: 100-continue` are not supported.

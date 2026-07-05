# HTTP/2

!!! warning
    HTTP/2 support is **experimental**. The API and behavior may change. Please
    try it out and report back.

Uvicorn can serve HTTP/2 using a Rust-backed codec provided by the
[`rh2`](https://pypi.org/project/rh2/) package, which wraps the
[`h2`](https://crates.io/crates/h2) crate (the HTTP/2 implementation behind
`hyper`). Install it with the `http2` extra:

```bash
pip install "uvicorn[http2-rh2]"
```

Enable it with the `--http2` flag (or `Config(http2=True)`):

```bash
uvicorn main:app --http2 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

When TLS is configured, `h2` is offered over ALPN alongside `http/1.1`, so
clients that support HTTP/2 negotiate it automatically and everyone else falls
back to HTTP/1.1. Cleartext prior-knowledge HTTP/2 (`h2c`, e.g.
`curl --http2-prior-knowledge`) is also detected.

## How it works

- The codec is *sans-IO*: uvicorn feeds it bytes from the socket and writes back
  whatever it produces, while the `h2` crate owns the connection state machine
  (flow control, `SETTINGS`/`PING` acknowledgement, `GOAWAY`, `RST_STREAM`).
- Each HTTP/2 stream maps to one ASGI request/response cycle, so requests are
  multiplexed over a single connection.

## Limitations

- Server push is not supported (deprecated in practice; not planned).
- Upgrade-based `h2c` (RFC 7540 section 3.2) is served as HTTP/1.1, which the
  RFC permits.

# TLS client certificates

You can use mutual TLS, or mTLS, when both sides of a connection must present a certificate.
When client verification is configured, Uvicorn verifies the client certificate during the TLS handshake.
Your ASGI application can then use the verified certificate to identify and authorize the client.

## Run an mTLS application

Create a local certificate authority, a server certificate, and a client certificate:

```bash
mkdir -p tls

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout tls/ca.key -out tls/ca.pem \
  -subj "/CN=Local development CA"

openssl req -newkey rsa:2048 -nodes \
  -keyout tls/server.key -out tls/server.csr \
  -subj "/CN=localhost"
printf '%s\n' \
  'basicConstraints=CA:FALSE' \
  'keyUsage=digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:localhost,IP:127.0.0.1' > tls/server.ext
openssl x509 -req -days 365 \
  -in tls/server.csr -CA tls/ca.pem -CAkey tls/ca.key -CAcreateserial \
  -extfile tls/server.ext -out tls/server.pem

openssl req -newkey rsa:2048 -nodes \
  -keyout tls/client.key -out tls/client.csr \
  -subj "/CN=example-client"
printf '%s\n' \
  'basicConstraints=CA:FALSE' \
  'keyUsage=digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=URI:spiffe://example.com/client' > tls/client.ext
openssl x509 -req -days 365 \
  -in tls/client.csr -CA tls/ca.pem -CAkey tls/ca.key -CAserial tls/ca.srl \
  -extfile tls/client.ext -out tls/client.pem
```

Create `app.py`:

```python
import hashlib
import json
import os

CLIENT_CERT_SHA256 = os.environ["CLIENT_CERT_SHA256"].lower()


async def app(scope, receive, send):
    assert scope["type"] == "http"

    tls = scope.get("extensions", {}).get("tls")
    client_cert = None if tls is None else tls.get("client_cert")

    if client_cert is None:
        status = 401
        content = {"detail": "Client certificate required"}
    else:
        fingerprint = hashlib.sha256(client_cert).hexdigest()
        if fingerprint != CLIENT_CERT_SHA256:
            status = 403
            content = {"detail": "Client certificate not authorized"}
        else:
            status = 200
            content = {"client": "example-client"}

    body = json.dumps(content).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
```

Start Uvicorn.
`ssl.CERT_REQUIRED` has the integer value `2`.
The option `--ssl-cert-reqs 2` rejects connections that do not present a trusted client certificate.

```bash
export CLIENT_CERT_SHA256="$(
  openssl x509 -in tls/client.pem -outform DER |
  openssl dgst -sha256 -r |
  cut -d' ' -f1
)"

uvicorn app:app \
  --host 127.0.0.1 \
  --port 8443 \
  --lifespan off \
  --ssl-certfile tls/server.pem \
  --ssl-keyfile tls/server.key \
  --ssl-ca-certs tls/ca.pem \
  --ssl-cert-reqs 2
```

Connect with the client certificate:

```bash
curl \
  --cacert tls/ca.pem \
  --cert tls/client.pem \
  --key tls/client.key \
  https://localhost:8443/
```

The application returns:

```json
{"client": "example-client"}
```

!!! warning "Keep the CA private key out of production"
    The commands above create `tls/ca.key` for local development.
    Store a production CA key outside the application host.
    Prefer a managed private CA or an offline signing process.

## Read the client certificate

Uvicorn adds TLS information to the HTTP or WebSocket scope:

```python
tls = scope.get("extensions", {}).get("tls")
client_cert = None if tls is None else tls.get("client_cert")
```

The extension has this shape:

```python
{
    "client_cert": bytes | None,
}
```

`client_cert` contains the leaf certificate in DER format.
DER is the binary certificate representation used by TLS libraries.
Uvicorn does not convert it to PEM and does not parse its subject.

This is a focused Uvicorn extension.
It does not implement the broader [ASGI TLS Extension](https://asgi.readthedocs.io/en/latest/specs/tls.html).
Check for `client_cert` before using it when your application also runs on other ASGI servers.

The value is:

- `bytes` when the client presented a certificate and the configured TLS context verified it.
- `None` when the connection uses TLS but no verified client certificate is available.
- Unavailable when the `tls` extension is absent. This happens on plaintext connections.

Uvicorn stores the certificate with the protocol's connection state after the TLS handshake.
The immutable certificate bytes are reused by requests on that connection.
This avoids parsing or encoding a certificate for every HTTP request or HTTP/2 stream.

## Parse certificate fields

Use an X.509 library when your authorization policy depends on certificate fields:

```bash
pip install cryptography
```

```python
from cryptography import x509
from cryptography.x509.oid import ExtensionOID


def client_uris(client_cert: bytes) -> list[str]:
    certificate = x509.load_der_x509_certificate(client_cert)
    alternative_names = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    return alternative_names.get_values_for_type(x509.UniformResourceIdentifier)
```

Keep X.509 parsing in the application.
Different applications use different identity fields.
Uvicorn would otherwise need to choose an identity policy and maintain a complete certificate parser.

!!! warning "Do not treat every certificate subject as an identity"
    A trusted signature does not make every subject field unique.
    Prefer a certificate fingerprint or an issuer-controlled SAN URI.
    Use the common name only when your certificate policy guarantees its meaning and uniqueness.

## Verification and authorization

TLS verification and application authorization solve different problems.

Uvicorn verifies that the client possesses the certificate's private key.
It also verifies that the certificate satisfies the configured trust policy.
The application decides what that verified certificate may access.

For example, your application can:

- Map a SHA-256 certificate fingerprint to a service account.
- Map a SAN URI to a workload or tenant.
- Require an extended key usage defined by your private PKI.
- Bind an OAuth access token to the certificate that presented it.
- Include the certificate serial and issuer in an audit event.

A certificate that fails TLS verification does not produce an ASGI scope.
The handshake fails before the application runs.

## Optional client certificates

Use `ssl.CERT_OPTIONAL` when the same listener must accept clients with and without certificates:

```python
import ssl

import uvicorn

uvicorn.run(
    "app:app",
    host="127.0.0.1",
    port=8443,
    ssl_certfile="tls/server.pem",
    ssl_keyfile="tls/server.key",
    ssl_ca_certs="tls/ca.pem",
    ssl_cert_reqs=ssl.CERT_OPTIONAL,
)
```

A client may connect without a certificate.
In that case, `client_cert` is `None`.
If a client presents a certificate, the TLS context still verifies it.

Use `ssl.CERT_REQUIRED` when every route on the listener requires mTLS.
This rejects an unauthenticated connection before it consumes application resources.

## WebSockets

The same extension is available in a WebSocket scope:

```python
async def app(scope, receive, send):
    assert scope["type"] == "websocket"

    tls = scope.get("extensions", {}).get("tls")
    client_cert = None if tls is None else tls.get("client_cert")
    if client_cert is None:
        await send({"type": "websocket.close", "code": 1008})
        return

    await receive()
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.close", "code": 1000})
```

Uvicorn exposes the same certificate for every HTTP request or WebSocket created from the TLS connection.

## TLS termination at a proxy

The extension describes the TLS connection that terminates at Uvicorn.
It does not reconstruct a certificate from HTTP headers.

When a reverse proxy terminates client TLS, Uvicorn only sees the proxy connection.
Configure the proxy to pass the verified client identity through a protected mechanism.
Validate that mechanism in trusted proxy middleware.

!!! danger "Never trust a client certificate header from the public internet"
    A client can send headers such as `X-Client-Cert` itself.
    Strip them at the edge.
    Only accept replacement values from a proxy whose connection and address you trust.

## Scope reference

| Location | Type | Meaning |
| --- | --- | --- |
| `scope["extensions"]["tls"]` | `dict` | Present when Uvicorn terminated the TLS connection. |
| `scope["extensions"]["tls"]["client_cert"]` | `bytes \| None` | Verified client leaf in DER, or `None`. |

The extension intentionally omits the TLS version, cipher suite, server certificate, parsed distinguished name,
and validation error.
Those values are not required for client authorization.
Several are also unavailable consistently across TLS implementations.

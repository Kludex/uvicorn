# TLS client certificate chains

You can use mutual TLS, or mTLS, when both sides of a connection must present a certificate.
When client verification is configured, Uvicorn verifies the client certificate during the TLS handshake.
Your ASGI application can then use the verified certificate chain to identify and authorize the client.

!!! note "Use Python 3.13 or newer"
    Python 3.13 added the public `SSLObject.get_verified_chain()` API.
    On older Python versions, Uvicorn cannot expose the verified chain and returns an empty tuple.

## Run an mTLS application

Create a local root CA, an intermediate CA, a server certificate, and a client certificate:

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
  -keyout tls/client-ca.key -out tls/client-ca.csr \
  -subj "/CN=Client intermediate CA"
printf '%s\n' \
  'basicConstraints=critical,CA:TRUE,pathlen:0' \
  'keyUsage=critical,keyCertSign,cRLSign' > tls/client-ca.ext
openssl x509 -req -days 365 \
  -in tls/client-ca.csr -CA tls/ca.pem -CAkey tls/ca.key -CAserial tls/ca.srl \
  -extfile tls/client-ca.ext -out tls/client-ca.pem

openssl req -newkey rsa:2048 -nodes \
  -keyout tls/client.key -out tls/client.csr \
  -subj "/CN=example-client"
printf '%s\n' \
  'basicConstraints=CA:FALSE' \
  'keyUsage=digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=URI:spiffe://example.com/client' > tls/client.ext
openssl x509 -req -days 365 \
  -in tls/client.csr -CA tls/client-ca.pem -CAkey tls/client-ca.key -CAcreateserial \
  -extfile tls/client.ext -out tls/client.pem
cat tls/client.pem tls/client-ca.pem > tls/client-chain.pem
```

Create `app.py`:

```python
import hashlib
import json
import os
import ssl

CLIENT_CERT_SHA256 = os.environ["CLIENT_CERT_SHA256"].lower()


async def app(scope, receive, send):
    assert scope["type"] == "http"

    tls = scope.get("extensions", {}).get("tls")
    client_cert_chain = () if tls is None else tls.get("client_cert_chain", ())

    if not client_cert_chain:
        status = 401
        content = {"detail": "Client certificate required"}
    else:
        client_cert = ssl.PEM_cert_to_DER_cert(client_cert_chain[0])
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

Connect with the client certificate and its intermediate:

```bash
curl \
  --cacert tls/ca.pem \
  --cert tls/client-chain.pem \
  --key tls/client.key \
  https://localhost:8443/
```

The application returns:

```json
{"client": "example-client"}
```

!!! warning "Keep CA private keys out of production"
    The commands above create CA keys for local development.
    Store production CA keys outside the application host.
    Prefer a managed private CA or an offline signing process.

## Read the verified chain

Uvicorn adds the chain to the HTTP or WebSocket scope:

```python
tls = scope.get("extensions", {}).get("tls")
client_cert_chain = () if tls is None else tls.get("client_cert_chain", ())
```

The extension has this shape:

```python
{
    "client_cert_chain": tuple[str, ...],
}
```

Each item is a PEM-encoded X.509 certificate.
The first item is the client leaf certificate.
The remaining items form the verified path selected by the TLS library and may include the trusted root.

```text
client_cert_chain[0]  Client leaf certificate
client_cert_chain[1]  Intermediate CA certificate
client_cert_chain[2]  Trusted root CA certificate
```

The tuple is empty when no verified chain is available.
This includes connections without a client certificate and TLS connections on Python 3.12 or older.
The `tls` extension is absent on plaintext connections.

Uvicorn implements only `client_cert_chain` from the broader
[ASGI TLS Extension](https://asgi.readthedocs.io/en/latest/specs/tls.html).
Applications must use `.get()` when they can run on other ASGI servers.

Uvicorn reads and converts the chain once after the TLS handshake.
The immutable tuple is reused by requests and HTTP/2 streams on the connection.

## Parse the leaf certificate

Use an X.509 library when your authorization policy depends on certificate fields:

```bash
pip install cryptography
```

```python
from cryptography import x509
from cryptography.x509.oid import ExtensionOID


def client_uris(client_cert_chain: tuple[str, ...]) -> list[str]:
    client_cert = x509.load_pem_x509_certificate(client_cert_chain[0].encode("ascii"))
    alternative_names = client_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    return alternative_names.get_values_for_type(x509.UniformResourceIdentifier)
```

Keep X.509 parsing in the application.
Different applications use different identity fields.
Uvicorn would otherwise need to choose an identity policy and maintain a complete certificate parser.

!!! warning "Do not treat every certificate subject as an identity"
    A trusted signature does not make every subject field unique.
    Prefer a certificate fingerprint or an issuer-controlled SAN URI.
    Use the common name only when your certificate policy guarantees its meaning and uniqueness.

## Use the issuing chain

Most applications authorize the leaf certificate.
The complete chain is useful when policy depends on the authority that issued it.

For example, your application can:

- Map an intermediate CA to a customer or tenant.
- Separate production and development issuing authorities.
- Apply certificate policies from an intermediate CA.
- Include the verified trust path in an audit event.
- Perform an additional application-specific validation.

Do not trust a root certificate because a client supplied it.
TLS verification succeeds only when the chain reaches a root configured in the server's trust store.

## Verification and authorization

TLS verification and application authorization solve different problems.

Uvicorn verifies that the client possesses the leaf certificate's private key.
It also verifies that the chain satisfies the configured trust policy.
The application decides what that verified identity may access.

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
In that case, `client_cert_chain` is empty.
If a client presents a certificate, the TLS context still verifies it.

Use `ssl.CERT_REQUIRED` when every route on the listener requires mTLS.
This rejects an unauthenticated connection before it consumes application resources.

## WebSockets

The same extension is available in a WebSocket scope:

```python
async def app(scope, receive, send):
    assert scope["type"] == "websocket"

    tls = scope.get("extensions", {}).get("tls")
    client_cert_chain = () if tls is None else tls.get("client_cert_chain", ())
    if not client_cert_chain:
        await send({"type": "websocket.close", "code": 1008})
        return

    await receive()
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.close", "code": 1000})
```

Uvicorn exposes the same immutable chain for every scope created from the TLS connection.

## TLS termination at a proxy

The extension describes the TLS connection that terminates at Uvicorn.
It does not reconstruct a certificate chain from HTTP headers.

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
| `scope["extensions"]["tls"]["client_cert_chain"]` | `tuple[str, ...]` | Verified chain in PEM format. |

The extension intentionally omits the TLS version, cipher suite, server certificate, parsed distinguished name,
and validation error.
Those values are not required for client authorization.
Several are also unavailable consistently across TLS implementations.

# Server Behavior

Uvicorn is designed with particular attention to connection and resource management, in order to provide a robust server implementation. It aims to ensure graceful behavior to either server or client errors, and resilience to poor client behavior or denial of service attacks.

## HTTP Headers

The `Server` and `Date` headers are added to all outgoing requests.

If a `Connection: Close` header is included then Uvicorn will close the connection after the response. Otherwise connections will stay open, pending the keep-alive timeout.

If a `Content-Length` header is included then Uvicorn will ensure that the content length of the response body matches the value in the header, and raise an error otherwise.

If no `Content-Length` header is included then Uvicorn will use chunked encoding for the response body, and will set a `Transfer-Encoding` header if required.

If a `Transfer-Encoding` header is included then any `Content-Length` header will be ignored.

HTTP headers are mandated to be case-insensitive. Uvicorn will always send response headers strictly in lowercase.

---

## Flow Control

Proper flow control ensures that large amounts of data do not become buffered on the transport when either side of a connection is sending data faster than its counterpart is able to handle.

### Write flow control

If the write buffer passes a high water mark, then Uvicorn ensures the ASGI `send` messages will only return once the write buffer has been drained below the low water mark.

### Read flow control

Uvicorn will pause reading from a transport once the buffered request body hits a high water mark, and will only resume once `receive` has been called, or once the response has been sent.

---

## Request and Response bodies

### Response completion

Once a response has been sent, Uvicorn will no longer buffer any remaining request body. Any later calls to `receive` will return an `http.disconnect` message.

Together with the read flow control, this behavior ensures that responses that return without reading the request body will not stream any substantial amounts of data into memory.

### Expect: 100-Continue

The `Expect: 100-Continue` header may be sent by clients to require a confirmation from the server before uploading the request body. This can be used to ensure that large request bodies are only sent once the client has confirmation that the server is willing to accept the request.

Uvicorn ensures that any required `100 Continue` confirmations are only sent if the ASGI application calls `receive` to read the request body.

Note that proxy configurations may not necessarily forward on `Expect: 100-Continue` headers. In particular, Nginx defaults to buffering request bodies, and automatically sends `100 Continues` rather than passing the header on to the upstream server.

### HEAD requests

Uvicorn will strip any response body from HTTP requests with the `HEAD` method.

Applications should generally treat `HEAD` requests in the same manner as `GET` requests, in order to ensure that identical headers are sent in both cases, and that any ASGI middleware that modifies the headers will operate identically in either case.

One exception to this might be if your application serves large file downloads, in which case you might wish to only generate the response headers.

---

## Timeouts

Uvicorn provides the following timeouts:

* Keep-Alive. Defaults to 5 seconds. Between requests, connections must receive new data within this period or be disconnected.

---

## Resource Limits

Uvicorn provides the following resource limiting:

* Concurrency (`--limit-concurrency`). Defaults to `None`. If set, this provides a maximum number of concurrent tasks *or* open connections that should be allowed. Any new requests that arrive once this limit has been reached will result in a "503 Service Unavailable" response. Setting this value to a limit that you know your servers are able to support will help ensure reliable resource usage, even against significantly over-resourced servers.
* Backlog (`--backlog`). Defaults to `2048`. The maximum number of connections the operating system will hold in the socket's accept queue before the worker accepts them. This is passed straight to the listening socket's `listen()` call.
* Max requests (`--limit-max-requests`). Defaults to `None`. If set, this provides a maximum number of HTTP requests that will be serviced before terminating a process. Together with a process manager this can be used to prevent memory leaks from impacting long running processes.

### Concurrency and backlog

`--limit-concurrency` and `--backlog` operate at different layers and do not interact. It is a common misconception that requests refused by `--limit-concurrency` are held in the `--backlog`; they are not.

**`--limit-concurrency` is an application-level gate.** When a request's headers have been fully received, Uvicorn checks whether the number of open connections *or* the number of in-flight request/response tasks has reached the limit. If so, it responds immediately with a "503 Service Unavailable" - the request is **not** queued and does **not** wait for a slot to free up. Both counts include the connection serving the current request, so a value of `N` admits at most `N - 1` *other* concurrent requests; in particular a value of `1` refuses every request. Note that the open-connection count includes idle keep-alive connections, so those also consume the budget: once the number of open connections reaches the limit, further requests are refused even if few requests are actively being processed. Because the check only runs after a connection has been accepted, `--limit-concurrency` does not stop connections from being accepted in the first place - that is governed by `--backlog`.

**`--backlog` is an OS-level socket setting.** It bounds the kernel's accept queue: connections that have completed the TCP handshake but that the worker has not yet `accept()`ed. Uvicorn accepts new connections eagerly, so under normal operation this queue stays near-empty and the setting has little observable effect. It only comes into play when connections arrive faster than the worker can accept them (for example during a large burst, or while the event loop is blocked). Once the queue is full the kernel stops accepting new connection attempts, and clients see a connection failure or timeout rather than a 503 (TCP will typically retry). Note that `--backlog` does not limit the number of connections a worker will ultimately serve - it only limits how many may sit *unaccepted* at once.

To make the distinction concrete, consider `--limit-concurrency 5` with a slow application and a burst of simultaneous requests: once the limit is reached, the excess requests receive a 503 essentially immediately - they are not held in the backlog and processed later. To instead *queue* excess load, put a reverse proxy (e.g. nginx) in front of Uvicorn, or scale out with more workers.

---

## Server Errors

Server errors will be logged at the `error` log level. All logging defaults to being written to `stdout`.

### Exceptions

If an exception is raised by an ASGI application, and a response has not yet been sent on the connection, then a `500 Server Error` HTTP response will be sent.

Uvicorn sends the headers and the status code as soon as it receives from the ASGI application. This means that if the application sends a [Response Start](https://asgi.readthedocs.io/en/latest/specs/www.html#response-start-send-event)
message with a status code of `200 OK`, and then an exception is raised, the response will still be sent with a status code of `200 OK`.

### Invalid responses

Uvicorn will ensure that ASGI applications send the correct sequence of messages, and will raise errors otherwise. This includes checking for no response sent, partial response sent, or invalid message sequences being sent.

---

## Graceful Process Shutdown

Graceful process shutdowns are particularly important during a restart period. During this period you want to:

* Start a number of new server processes to handle incoming requests, listening on the existing socket.
* Stop the previous server processes from listening on the existing socket.
* Close any connections that are not currently waiting on an HTTP response, and wait for any other connections to finalize their HTTP responses.
* Wait for any background tasks to run to completion, such as occurs when the ASGI application has sent the HTTP response, but the asyncio task has not yet run to completion.

Uvicorn handles process shutdown gracefully, ensuring that connections are properly finalized, and all tasks have run to completion. During a shutdown period Uvicorn will ensure that responses and tasks must still complete within the configured timeout periods.

---

## HTTP Pipelining

HTTP/1.1 provides support for sending multiple requests on a single connection, before having received each corresponding response. Servers are required to support HTTP pipelining, but it is now generally accepted to lead to implementation issues. It is not enabled on browsers, and may not necessarily be enabled on any proxies that the HTTP request passes through.

Uvicorn supports pipelining pragmatically. It will queue up any pipelined HTTP requests, and pause reading from the underlying transport. It will not start processing pipelined requests until each response has been dealt with in turn.

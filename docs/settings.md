# Settings

Use the following options to configure Uvicorn, when running from the command line.

## Configuration Methods

There are three ways to configure Uvicorn:

1. **Command Line**: Use command line options when running Uvicorn directly.
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

2. **Programmatic**: Use keyword arguments when running programmatically with `uvicorn.run()`.
   ```python
   uvicorn.run("main:app", host="0.0.0.0", port=8000)
   ```

    !!! note
        When using `reload=True` or `workers=NUM`, you should put `uvicorn.run` into
        an `if __name__ == '__main__'` clause in the main module.

3. **Environment Variables**: Use environment variables with the prefix `UVICORN_`.
   ```bash
   export UVICORN_HOST="0.0.0.0"
   export UVICORN_PORT="8000"
   uvicorn main:app
   ```

CLI options and the arguments for `uvicorn.run()` take precedence over environment variables.

Also note that `UVICORN_*` prefixed settings cannot be used from within an environment
configuration file. Using an environment configuration file with the `--env-file` flag is
intended for configuring the ASGI application that uvicorn runs, rather than configuring
uvicorn itself.

## Application

* `APP` - The ASGI application to run, in the format `"<module>:<attribute>"`.
* `--factory` - Treat `APP` as an application factory, i.e. a `() -> <ASGI app>` callable.
* `--app-dir <path>` - Look for APP in the specified directory by adding it to the PYTHONPATH. **Default:** *Current working directory*.

## Socket Binding

* `--host <str>` - Bind socket to this host. Use `--host 0.0.0.0` to make the application available on your local network. IPv6 addresses are supported, for example: `--host '::'`. **Default:** *'127.0.0.1'*.
* `--port <int>` - Bind to a socket with this port. If set to 0, an available port will be picked. **Default:** *8000*.
* `--uds <path>` - Bind to a UNIX domain socket, for example `--uds /tmp/uvicorn.sock`. Useful if you want to run Uvicorn behind a reverse proxy.
* `--fd <int>` - Bind to socket from this file descriptor. Useful if you want to run Uvicorn within a process manager.

## Development

* `--reload` - Enable auto-reload. Uvicorn supports two versions of auto-reloading behavior enabled by this option. **Default:** *False*.
* `--reload-dir <path>` - Specify which directories to watch for python file changes. May be used multiple times. If unused, then by default the whole current directory will be watched. If you are running programmatically use `reload_dirs=[]` and pass a list of strings.
* `--reload-delay <float>` - Delay between previous and next check if application needs to be reloaded. **Default:** *0.25*.

### Reloading without watchfiles

If Uvicorn _cannot_ load [watchfiles](https://pypi.org/project/watchfiles/) at runtime, it will periodically look for changes in modification times to all `*.py` files (and only `*.py` files) inside of its monitored directories. See the `--reload-dir` option. Specifying other file extensions is not supported unless watchfiles is installed. See the `--reload-include` and `--reload-exclude` options for details.

### Reloading with watchfiles

For more nuanced control over which file modifications trigger reloads, install `uvicorn[standard]`, which includes watchfiles as a dependency. Alternatively, install [watchfiles](https://pypi.org/project/watchfiles/) where Uvicorn can see it.

Using Uvicorn with watchfiles will enable the following options (which are otherwise ignored):

* `--reload-include <glob-pattern>` - Specify a glob pattern to [match](https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.match) files or directories which will be watched. May be used multiple times. By default the following patterns are included: `*.py`. These defaults can be overwritten by including them in `--reload-exclude`. Note, `**` is not supported in `<glob-pattern>`.
* `--reload-exclude <glob-pattern>` - Specify a glob pattern to [match](https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.match) files or directories which will be excluded from watching. May be used multiple times. If `<glob-pattern>` does not contain a `/` or `*`, it will be compared against every path part of the resolved watched file path (e.g. `--reload-exclude '__pycache__'` will exclude any file matches who have `__pycache__` as an ancestor directory). By default the following patterns are excluded: `.*, .py[cod], .sw.*, ~*`. These defaults can be overwritten by including them in `--reload-include`. Note, `**` is not supported in `<glob-pattern>`.

!!! tip
    When using Uvicorn through [WSL](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux), you might
    have to set the `WATCHFILES_FORCE_POLLING` environment variable, for file changes to trigger a reload.
    See [watchfiles documentation](https://watchfiles.helpmanual.io/api/watch/) for further details.

## Production

* `--workers <int>` - Number of worker processes. Defaults to the `$WEB_CONCURRENCY` environment variable if available, or 1. Not valid with `--reload`.
* `--env-file <path>` - Environment configuration file for the ASGI application. **Default:** *None*.

!!! note
    The `--reload` and `--workers` arguments are mutually exclusive. You cannot use both at the same time.

## Logging

* `--log-config <path>` - Logging configuration file. **Options:** *`dictConfig()` formats: .json, .yaml*. Any other format will be processed with `fileConfig()`. Set the `formatters.default.use_colors` and `formatters.access.use_colors` values to override the auto-detected behavior.
    * If you wish to use a YAML file for your logging config, you will need to include PyYAML as a dependency for your project or install uvicorn with the `[standard]` optional extras.
* `--log-level <str>` - Set the log level. **Options:** *'critical', 'error', 'warning', 'info', 'debug', 'trace'.* **Default:** *'info'*.
* `--no-access-log` - Disable access log only, without changing log level.
* `--use-colors / --no-use-colors` - Enable / disable colorized formatting of the log records. If not set, colors will be auto-detected. This option is ignored if the `--log-config` CLI option is used.

## Implementation

* `--loop <str>` - Set the event loop implementation. The uvloop implementation provides greater performance, but is not compatible with Windows or PyPy. **Options:** *'auto', 'asyncio', 'uvloop'.* **Default:** *'auto'*.
* `--http <str>` - Set the HTTP protocol implementation. The httptools implementation provides greater performance, but it not compatible with PyPy. **Options:** *'auto', 'h11', 'httptools'.* **Default:** *'auto'*.
* `--ws <str>` - Set the WebSockets protocol implementation. Either of the `websockets` and `wsproto` packages are supported. There are two versions of `websockets` supported: `websockets` and `websockets-sansio`. Use `'none'` to ignore all websocket requests. **Options:** *'auto', 'none', 'websockets', 'websockets-sansio', 'wsproto'.* **Default:** *'auto'*.
* `--ws-max-size <int>` - Set the WebSockets max message size, in bytes. Only available with the `websockets` protocol. **Default:** *16777216* (16 MB).
* `--ws-max-queue <int>` - Set the maximum length of the WebSocket incoming message queue. Only available with the `websockets` protocol. **Default:** *32*.
* `--ws-ping-interval <float>` - Set the WebSockets ping interval, in seconds. Only available with the `websockets` protocol. **Default:** *20.0*.
* `--ws-ping-timeout <float>` - Set the WebSockets ping timeout, in seconds. Only available with the `websockets` protocol. **Default:** *20.0*.
* `--ws-per-message-deflate <bool>` - Enable/disable WebSocket per-message-deflate compression. Only available with the `websockets` protocol. **Default:** *True*.
* `--lifespan <str>` - Set the Lifespan protocol implementation. **Options:** *'auto', 'on', 'off'.* **Default:** *'auto'*.
* `--h11-max-incomplete-event-size <int>` - Set the maximum number of bytes to buffer of an incomplete event. Only available for `h11` HTTP protocol implementation. **Default:** *16384* (16 KB).

## Application Interface

* `--interface <str>` - Select ASGI3, ASGI2, or WSGI as the application interface.
Note that WSGI mode always disables WebSocket support, as it is not supported by the WSGI interface.
**Options:** *'auto', 'asgi3', 'asgi2', 'wsgi'.* **Default:** *'auto'*.

!!! warning
    Uvicorn's native WSGI implementation is deprecated, you should switch
    to [a2wsgi](https://github.com/abersheeran/a2wsgi) (`pip install a2wsgi`).

## HTTP

* `--root-path <str>` - Set the ASGI `root_path` for applications submounted below a given URL path. **Default:** *""*.
* `--proxy-headers / --no-proxy-headers` - Enable/Disable X-Forwarded-Proto, X-Forwarded-For to populate remote address info. Defaults to enabled, but is restricted to only trusting connecting IPs in the `forwarded-allow-ips` configuration.
* `--forwarded-allow-ips <comma-separated-list>` - Comma separated list of IP Addresses, IP Networks, or literals (e.g. UNIX Socket path) to trust with proxy headers. Defaults to the `$FORWARDED_ALLOW_IPS` environment variable if available, or '127.0.0.1'. The literal `'*'` means trust everything.
* `--server-header / --no-server-header` - Enable/Disable default `Server` header. **Default:** *True*.
* `--date-header / --no-date-header` - Enable/Disable default `Date` header. **Default:** *True*.
* `--header <name:value>` - Specify custom default HTTP response headers as a Name:Value pair. May be used multiple times.

!!! note
    The `--no-date-header` flag doesn't have effect on the `websockets` implementation.

## HTTPS

The [SSL context](https://docs.python.org/3/library/ssl.html#ssl.SSLContext) can be configured with the following options:

* `--ssl-keyfile <path>` - The SSL key file.
* `--ssl-keyfile-password <str>` - The password to decrypt the ssl key.
* `--ssl-certfile <path>` - The SSL certificate file.
* `--ssl-version <int>` - The SSL version to use. **Default:** *ssl.PROTOCOL_TLS_SERVER*.
* `--ssl-cert-reqs <int>` - Whether client certificate is required. **Default:** *ssl.CERT_NONE*.
* `--ssl-ca-certs <str>` - The CA certificates file.
* `--ssl-ciphers <str>` - The ciphers to use. **Default:** *"TLSv1"*.

To understand more about the SSL context options, please refer to the [Python documentation](https://docs.python.org/3/library/ssl.html).

## Resource Limits

* `--limit-concurrency <int>` - Maximum number of concurrent connections or tasks to allow, before issuing HTTP 503 responses. Useful for ensuring known memory usage patterns even under over-resourced loads.
* `--limit-max-requests <int>` - Maximum number of requests to service before terminating the process. Useful when running together with a process manager, for preventing memory leaks from impacting long-running processes.
* `--backlog <int>` - Maximum number of connections to hold in backlog. Relevant for heavy incoming traffic. **Default:** *2048*.

## Timeouts

* `--timeout-keep-alive <int>` - Close Keep-Alive connections if no new data is received within this timeout. **Default:** *5*.
* `--timeout-graceful-shutdown <int>` - Maximum number of seconds to wait for graceful shutdown. After this timeout, the server will start terminating requests.

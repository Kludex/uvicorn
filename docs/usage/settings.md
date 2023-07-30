# Settings

Use the following options to configure Uvicorn, when running from the command line.

If you're running programmatically, using `uvicorn.run(...)`, then use
equivalent keyword arguments, eg. `uvicorn.run("example:app", port=5000, reload=True, access_log=False)`.
Please note that in this case, if you use `reload=True` or `workers=NUM`,
you should put `uvicorn.run` into `if __name__ == '__main__'` clause in the main module.

You can also configure Uvicorn using environment variables with the prefix `UVICORN_`.
For example, in case you want to run the app on port `5000`, just set the environment variable `UVICORN_PORT` to `5000`.

!!! note
    CLI options and the arguments for `uvicorn.run()` take precedence over environment variables.

    Also note that `UVICORN_*` prefixed settings cannot be used from within an environment configuration file. Using an environment configuration file with the `--env-file` flag is intended for configuring the ASGI application that uvicorn runs, rather than configuring uvicorn itself.

## Application

* `APP` - The ASGI application to run, in the format `"<module>:<attribute>"`.
* `--factory` - Treat `APP` as an application factory, i.e. a `() -> <ASGI app>` callable.

## Socket Binding

* `--host <str>` - Bind socket to this host. Use `--host 0.0.0.0` to make the application available on your local network. IPv6 addresses are supported, for example: `--host '::'`. **Default:** *'127.0.0.1'*.
* `--port <int>` - Bind to a socket with this port. **Default:** *8000*.
* `--uds <path>` - Bind to a UNIX domain socket, for example `--uds /tmp/uvicorn.sock`. Useful if you want to run Uvicorn behind a reverse proxy.
* `--fd <int>` - Bind to socket from this file descriptor. Useful if you want to run Uvicorn within a process manager.

## Development

* `--reload` - Enable auto-reload. Uvicorn supports two versions of auto-reloading behavior enabled by this option. There are important differences between them.
* `--reload-dir <path>` - Specify which directories to watch for python file changes. May be used multiple times. If unused, then by default the whole current directory will be watched. If you are running programmatically use `reload_dirs=[]` and pass a list of strings.

### Reloading without watchfiles

If Uvicorn _cannot_ load [watchfiles](https://pypi.org/project/watchfiles/) at runtime, it will periodically look for changes in modification times to all `*.py` files (and only `*.py` files) inside of its monitored directories. See the `--reload-dir` option. Specifying other file extensions is not supported unless watchfiles is installed. See the `--reload-include` and `--reload-exclude` options for details.

### Reloading with watchfiles

For more nuanced control over which file modifications trigger reloads, install `uvicorn[standard]`, which includes watchfiles as a dependency. Alternatively, install [watchfiles](https://pypi.org/project/watchfiles/) where Uvicorn can see it.

Using Uvicorn with watchfiles will enable the following options (which are otherwise ignored).

* `--reload-include <glob-pattern>` - Specify a glob pattern to match files or directories which will be watched. May be used multiple times. By default the following patterns are included: `*.py`. These defaults can be overwritten by including them in `--reload-exclude`.
* `--reload-exclude <glob-pattern>` - Specify a glob pattern to match files or directories which will excluded from watching. May be used multiple times. By default the following patterns are excluded: `.*, .py[cod], .sw.*, ~*`. These defaults can be overwritten by including them in `--reload-include`.

!!! tip
    When using Uvicorn through [WSL](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux), you might
    have to set the `WATCHFILES_FORCE_POLLING` environment variable, for file changes to trigger a reload.
    See [watchfiles documentation](https://watchfiles.helpmanual.io/api/watch/) for further details.

## Production

* `--workers <int>` - Use multiple worker processes. Defaults to the `$WEB_CONCURRENCY` environment variable if available, or 1.

## Logging

* `--log-config <path>` - Logging configuration file. **Options:** *`dictConfig()` formats: .json, .yaml*. Any other format will be processed with `fileConfig()`. Set the `formatters.default.use_colors` and `formatters.access.use_colors` values to override the auto-detected behavior.
    * If you wish to use a YAML file for your logging config, you will need to include PyYAML as a dependency for your project or install uvicorn with the `[standard]` optional extras.
* `--log-level <str>` - Set the log level. **Options:** *'critical', 'error', 'warning', 'info', 'debug', 'trace'.* **Default:** *'info'*.
* `--no-access-log` - Disable access log only, without changing log level.
* `--use-colors / --no-use-colors` - Enable / disable colorized formatting of the log records, in case this is not set it will be auto-detected. This option is ignored if the `--log-config` CLI option is used.


## Implementation

* `--loop <str>` - Set the event loop implementation. The uvloop implementation provides greater performance, but is not compatible with Windows or PyPy. **Options:** *'auto', 'asyncio', 'uvloop'.* **Default:** *'auto'*.
* `--http <str>` - Set the HTTP protocol implementation. The httptools implementation provides greater performance, but it not compatible with PyPy. **Options:** *'auto', 'h11', 'httptools'.* **Default:** *'auto'*.
* `--ws <str>` - Set the WebSockets protocol implementation. Either of the `websockets` and `wsproto` packages are supported. Use `'none'` to ignore all websocket requests. **Options:** *'auto', 'none', 'websockets', 'wsproto'.* **Default:** *'auto'*.
* `--ws-max-size <int>` - Set the WebSockets max message size, in bytes. Please note that this can be used only with the default `websockets` protocol.
* `--ws-max-queue <int>` - Set the maximum length of the WebSocket incoming message queue. Please note that this can be used only with the default `websockets` protocol.
* `--ws-ping-interval <float>` - Set the WebSockets ping interval, in seconds. Please note that this can be used only with the default `websockets` protocol.
* `--ws-ping-timeout <float>` - Set the WebSockets ping timeout, in seconds. Please note that this can be used only with the default `websockets` protocol.
* `--lifespan <str>` - Set the Lifespan protocol implementation. **Options:** *'auto', 'on', 'off'.* **Default:** *'auto'*.
* `--h11-max-incomplete-event-size <int>` - Set the maximum number of bytes to buffer of an incomplete event. Only available for `h11` HTTP protocol implementation. **Default:** *'16384'* (16 KB).

## Application Interface

* `--interface` - Select ASGI3, ASGI2, or WSGI as the application interface.
Note that WSGI mode always disables WebSocket support, as it is not supported by the WSGI interface.
**Options:** *'auto', 'asgi3', 'asgi2', 'wsgi'.* **Default:** *'auto'*.

!!! warning
    Uvicorn's native WSGI implementation is deprecated, you should switch
    to [a2wsgi](https://github.com/abersheeran/a2wsgi) (`pip install a2wsgi`).

## HTTP

* `--root-path <str>` - Set the ASGI `root_path` for applications submounted below a given URL path.
* `--proxy-headers` / `--no-proxy-headers` - Enable/Disable X-Forwarded-Proto, X-Forwarded-For, X-Forwarded-Port to populate remote address info. Defaults to enabled, but is restricted to only trusting
connecting IPs in the `forwarded-allow-ips` configuration.
* `--forwarded-allow-ips` <comma-separated-list> Comma separated list of IPs to trust with proxy headers. Defaults to the `$FORWARDED_ALLOW_IPS` environment variable if available, or '127.0.0.1'. A wildcard '*' means always trust.
* `--server-header` / `--no-server-header` - Enable/Disable default `Server` header.
* `--date-header` / `--no-date-header` - Enable/Disable default `Date` header.

!!! note
    The `--no-date-header` flag doesn't have effect on the `websockets` implementation.

## HTTPS

The [SSL context](https://docs.python.org/3/library/ssl.html#ssl.SSLContext) can be configured with the following options:

* `--ssl-keyfile <path>` - The SSL key file.
* `--ssl-keyfile-password <str>` - The password to decrypt the ssl key.
* `--ssl-certfile <path>` - The SSL certificate file.
* `--ssl-version <int>` - The SSL version to use.
* `--ssl-cert-reqs <int>` - Whether client certificate is required.
* `--ssl-ca-certs <str>` - The CA certificates file.
* `--ssl-ciphers <str>` - The ciphers to use.

To understand more about the SSL context options, please refer to the [Python documentation](https://docs.python.org/3/library/ssl.html).

## Resource Limits

* `--limit-concurrency <int>` - Maximum number of concurrent connections or tasks to allow, before issuing HTTP 503 responses. Useful for ensuring known memory usage patterns even under over-resourced loads.
* `--limit-max-requests <int>` - Maximum number of requests to service before terminating the process. Useful when running together with a process manager, for preventing memory leaks from impacting long-running processes.
* `--backlog <int>` - Maximum number of connections to hold in backlog. Relevant for heavy incoming traffic. **Default:** *2048*

## Timeouts

* `--timeout-keep-alive <int>` - Close Keep-Alive connections if no new data is received within this timeout. **Default:** *5*.
* `--timeout-graceful-shutdown <int>` - Maximum number of seconds to wait for graceful shutdown. After this timeout, the server will start terminating requests.

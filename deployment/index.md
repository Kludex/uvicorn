Server deployment is a complex area, that will depend on what kind of service you're deploying Uvicorn onto.

As a general rule, you probably want to:

- Run `uvicorn --reload` from the command line for local development.
- Run `gunicorn -k uvicorn.workers.UvicornWorker` for production.
- Additionally run behind Nginx for self-hosted deployments.
- Finally, run everything behind a CDN for caching support, and serious DDOS protection.

## Running from the command line

Typically you'll run `uvicorn` from the command line.

```
$ uvicorn main:app --reload --port 5000
```

The ASGI application should be specified in the form `path.to.module:instance.path`.

When running locally, use `--reload` to turn on auto-reloading.

The `--reload` and `--workers` arguments are **mutually exclusive**.

To see the complete set of available options, use `uvicorn --help`:

```
Usage: uvicorn [OPTIONS] APP

Options:
  --host TEXT                     Bind socket to this host.  [default:
                                  127.0.0.1]
  --port INTEGER                  Bind socket to this port. If 0, an available
                                  port will be picked.  [default: 8000]
  --uds TEXT                      Bind to a UNIX domain socket.
  --fd INTEGER                    Bind to socket from this file descriptor.
  --reload                        Enable auto-reload.
  --reload-dir PATH               Set reload directories explicitly, instead
                                  of using the current working directory.
  --reload-include TEXT           Set glob patterns to include while watching
                                  for files. Includes '*.py' by default; these
                                  defaults can be overridden with `--reload-
                                  exclude`. This option has no effect unless
                                  watchfiles is installed.
  --reload-exclude TEXT           Set glob patterns to exclude while watching
                                  for files. Includes '.*, .py[cod], .sw.*,
                                  ~*' by default; these defaults can be
                                  overridden with `--reload-include`. This
                                  option has no effect unless watchfiles is
                                  installed.
  --reload-delay FLOAT            Delay between previous and next check if
                                  application needs to be. Defaults to 0.25s.
                                  [default: 0.25]
  --workers INTEGER               Number of worker processes. Defaults to the
                                  $WEB_CONCURRENCY environment variable if
                                  available, or 1. Not valid with --reload.
  --loop [auto|asyncio|uvloop]    Event loop factory implementation.
                                  [default: auto]
  --http [auto|h11|httptools]     HTTP protocol implementation.  [default:
                                  auto]
  --ws [auto|websockets|websockets-sansio|wsproto]
                                  WebSocket protocol implementation.
                                  [default: auto]
  --ws-max-size INTEGER           WebSocket max size message in bytes
                                  [default: 16777216]
  --ws-max-queue INTEGER          The maximum length of the WebSocket message
                                  queue.  [default: 32]
  --ws-ping-interval FLOAT        WebSocket ping interval in seconds.
                                  [default: 20.0]
  --ws-ping-timeout FLOAT         WebSocket ping timeout in seconds.
                                  [default: 20.0]
  --ws-per-message-deflate BOOLEAN
                                  WebSocket per-message-deflate compression
                                  [default: True]
  --lifespan [auto|on|off]        Lifespan implementation.  [default: auto]
  --interface [auto|asgi3|asgi2|wsgi]
                                  Select ASGI3, ASGI2, or WSGI as the
                                  application interface.  [default: auto]
  --env-file PATH                 Environment configuration file.
  --log-config PATH               Logging configuration file. Supported
                                  formats: .ini, .json, .yaml.
  --log-level [critical|error|warning|info|debug|trace]
                                  Log level. [default: info]
  --access-log / --no-access-log  Enable/Disable access log.
  --use-colors / --no-use-colors  Enable/Disable colorized logging.
  --proxy-headers / --no-proxy-headers
                                  Enable/Disable X-Forwarded-Proto,
                                  X-Forwarded-For to populate url scheme and
                                  remote address info.
  --server-header / --no-server-header
                                  Enable/Disable default Server header.
  --date-header / --no-date-header
                                  Enable/Disable default Date header.
  --forwarded-allow-ips TEXT      Comma separated list of IP Addresses, IP
                                  Networks, or literals (e.g. UNIX Socket
                                  path) to trust with proxy headers. Defaults
                                  to the $FORWARDED_ALLOW_IPS environment
                                  variable if available, or '127.0.0.1'. The
                                  literal '*' means trust everything.
  --root-path TEXT                Set the ASGI 'root_path' for applications
                                  submounted below a given URL path.
  --limit-concurrency INTEGER     Maximum number of concurrent connections or
                                  tasks to allow, before issuing HTTP 503
                                  responses.
  --backlog INTEGER               Maximum number of connections to hold in
                                  backlog
  --limit-max-requests INTEGER    Maximum number of requests to service before
                                  terminating the process.
  --limit-max-requests-jitter INTEGER
                                  Maximum jitter to add to limit_max_requests.
                                  Staggers worker restarts to avoid all
                                  workers restarting simultaneously.
                                  [default: 0]
  --timeout-keep-alive INTEGER    Close Keep-Alive connections if no new data
                                  is received within this timeout (in
                                  seconds).  [default: 5]
  --timeout-graceful-shutdown INTEGER
                                  Maximum number of seconds to wait for
                                  graceful shutdown.
  --timeout-worker-healthcheck INTEGER
                                  Maximum number of seconds to wait for a
                                  worker to respond to a healthcheck.
                                  [default: 5]
  --ssl-keyfile TEXT              SSL key file
  --ssl-certfile TEXT             SSL certificate file
  --ssl-keyfile-password TEXT     SSL keyfile password
  --ssl-version INTEGER           SSL version to use (see stdlib ssl module's)
                                  [default: 17]
  --ssl-cert-reqs INTEGER         Whether client certificate is required (see
                                  stdlib ssl module's)  [default: 0]
  --ssl-ca-certs TEXT             CA certificates file
  --ssl-ciphers TEXT              Ciphers to use (see stdlib ssl module's)
                                  [default: TLSv1]
  --header TEXT                   Specify custom default HTTP response headers
                                  as a Name:Value pair
  --version                       Display the uvicorn version and exit.
  --app-dir TEXT                  Look for APP in the specified directory, by
                                  adding this to the PYTHONPATH. Defaults to
                                  the current working directory.  [default:
                                  ""]
  --h11-max-incomplete-event-size INTEGER
                                  For h11, the maximum number of bytes to
                                  buffer of an incomplete event.
  --factory                       Treat APP as an application factory, i.e. a
                                  () -> <ASGI app> callable.
  --help                          Show this message and exit.
```

See the [settings documentation](https://uvicorn.dev/settings/index.md) for more details on the supported options for running uvicorn.

## Running programmatically

To run directly from within a Python program, you should use `uvicorn.run(app, **config)`. For example:

main.py

```
import uvicorn

class App:
    ...

app = App()

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000, log_level="info")
```

The set of configuration options is the same as for the command line tool.

Note that the application instance itself *can* be passed instead of the app import string.

```
uvicorn.run(app, host="127.0.0.1", port=5000, log_level="info")
```

However, this style only works if you are not using multiprocessing (`workers=NUM`) or reloading (`reload=True`), so we recommend using the import string style.

Also note that in this case, you should put `uvicorn.run` into `if __name__ == '__main__'` clause in the main module.

Note

The `reload` and `workers` parameters are **mutually exclusive**.

## Using a process manager

Running Uvicorn using a process manager ensures that you can run multiple processes in a resilient manner, and allows you to perform server upgrades without dropping requests.

A process manager will handle the socket setup, start-up multiple server processes, monitor process aliveness, and listen for signals to provide for processes restarts, shutdowns, or dialing up and down the number of running processes.

### Built-in

Uvicorn includes a `--workers` option that allows you to run multiple worker processes.

```
$ uvicorn main:app --workers 4
```

Unlike gunicorn, uvicorn does not use pre-fork, but uses [`spawn`](https://docs.python.org/3/library/multiprocessing.html#contexts-and-start-methods), which allows uvicorn's multiprocess manager to still work well on Windows.

The default process manager monitors the status of child processes and automatically restarts child processes that die unexpectedly. Not only that, it will also monitor the status of the child process through the pipeline. When the child process is accidentally stuck, the corresponding child process will be killed through an unstoppable system signal or interface.

You can also manage child processes by sending specific signals to the main process. (Not supported on Windows.)

- `SIGHUP`: Work processeses are graceful restarted one after another. If you update the code, the new worker process will use the new code.
- `SIGTTIN`: Increase the number of worker processes by one.
- `SIGTTOU`: Decrease the number of worker processes by one.

### Gunicorn

Warning

The `uvicorn.workers` module is deprecated and will be removed in a future release.

You should use the [`uvicorn-worker`](https://github.com/Kludex/uvicorn-worker) package instead.

```
python -m pip install uvicorn-worker
```

Gunicorn is probably the simplest way to run and manage Uvicorn in a production setting. Uvicorn includes a gunicorn worker class that means you can get set up with very little configuration.

The following will start Gunicorn with four worker processes:

`gunicorn -w 4 -k uvicorn.workers.UvicornWorker`

The `UvicornWorker` implementation uses the `uvloop` and `httptools` implementations. To run under PyPy you'll want to use pure-python implementation instead. You can do this by using the `UvicornH11Worker` class.

`gunicorn -w 4 -k uvicorn.workers.UvicornH11Worker`

Gunicorn provides a different set of configuration options to Uvicorn, so some options such as `--limit-concurrency` are not yet supported when running with Gunicorn.

If you need to pass uvicorn's config arguments to gunicorn workers then you'll have to subclass `UvicornWorker`:

```
from uvicorn.workers import UvicornWorker

class MyUvicornWorker(UvicornWorker):
    CONFIG_KWARGS = {"loop": "asyncio", "http": "h11", "lifespan": "off"}
```

### Supervisor

To use `supervisor` as a process manager you should either:

- Hand over the socket to uvicorn using its file descriptor, which supervisor always makes available as `0`, and which must be set in the `fcgi-program` section.
- Or use a UNIX domain socket for each `uvicorn` process.

A simple supervisor configuration might look something like this:

supervisord.conf

```
[supervisord]

[fcgi-program:uvicorn]
socket=tcp://localhost:8000
command=venv/bin/uvicorn --fd 0 main:App
numprocs=4
process_name=uvicorn-%(process_num)d
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
```

Then run with `supervisord -n`.

## Running behind Nginx

Using Nginx as a proxy in front of your Uvicorn processes may not be necessary, but is recommended for additional resilience. Nginx can deal with serving your static media and buffering slow requests, leaving your application servers free from load as much as possible.

In managed environments such as `Heroku`, you won't typically need to configure Nginx, as your server processes will already be running behind load balancing proxies.

The recommended configuration for proxying from Nginx is to use a UNIX domain socket between Nginx and whatever the process manager that is being used to run Uvicorn. If using Uvicorn directly you can bind it to a UNIX domain socket using `uvicorn --uds /path/to/socket.sock <...>`.

When running your application behind one or more proxies you will want to make sure that each proxy sets appropriate headers to ensure that your application can properly determine the client address of the incoming connection, and if the connection was over `http` or `https`. For more information see [Proxies and Forwarded Headers](#proxies-and-forwarded-headers) below.

Here's how a simple Nginx configuration might look. This example includes setting proxy headers, and using a UNIX domain socket to communicate with the application server.

It also includes some basic configuration to forward websocket connections. For more info on this, check [Nginx recommendations](https://nginx.org/en/docs/http/websocket.html).

```
http {
  server {
    listen 80;
    client_max_body_size 4G;

    server_name example.com;

    location / {
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_redirect off;
      proxy_buffering off;
      proxy_pass http://uvicorn;
    }

    location /static {
      # path for static files
      root /path/to/app/static;
    }
  }

  map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
  }

  upstream uvicorn {
    server unix:/tmp/uvicorn.sock;
  }

}
```

Uvicorn's `--proxy-headers` behavior may not be sufficient for more complex proxy configurations that use different combinations of headers, or where the application is running behind more than one intermediary proxying service.

In those cases, you might want to use an ASGI middleware to set the `client` and `scheme` dependant on the request headers.

## Running behind a CDN

Running behind a content delivery network, such as Cloudflare or Cloud Front, provides a serious layer of protection against DDoS attacks. Your service will be running behind huge clusters of proxies and load balancers that are designed for handling huge amounts of traffic, and have capabilities for detecting and closing off connections from DDoS attacks.

Proper usage of cache control headers can mean that a CDN is able to serve large amounts of data without always having to forward the request on to your server.

Content Delivery Networks can also be a low-effort way to provide HTTPS termination.

## Running with HTTPS

To run uvicorn with https, a certificate and a private key are required. The recommended way to get them is using [Let's Encrypt](https://letsencrypt.org/).

For local development with https, it's possible to use [mkcert](https://github.com/FiloSottile/mkcert) to generate a valid certificate and private key.

```
$ uvicorn main:app --port 5000 --ssl-keyfile=./key.pem --ssl-certfile=./cert.pem
```

### Running gunicorn worker

It's also possible to use certificates with uvicorn's worker for gunicorn.

```
$ gunicorn --keyfile=./key.pem --certfile=./cert.pem -k uvicorn.workers.UvicornWorker main:app
```

## Proxies and Forwarded Headers

When running an application behind one or more proxies, certain information about the request is lost. To avoid this most proxies will add headers containing this information for downstream servers to read.

Uvicorn currently supports the following headers:

- `X-Forwarded-For` ([MDN Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For))
- `X-Forwarded-Proto`([MDN Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto))

Uvicorn can use these headers to correctly set the client and protocol in the request. However as anyone can set these headers you must configure which "clients" you will trust to have set them correctly.

Uvicorn can be configured to trust IP Addresses (e.g. `127.0.0.1`), IP Networks (e.g. `10.100.0.0/16`), or Literals (e.g. `/path/to/socket.sock`). When running from CLI these are configured using `--forwarded-allow-ips`.

Only trust clients you can actually trust!

Incorrectly trusting other clients can lead to malicious actors spoofing their apparent client address to your application.

For more information, check [`ProxyHeadersMiddleware`](https://github.com/Kludex/uvicorn/blob/main/uvicorn/middleware/proxy_headers.py).

### Client Port

Currently if the `ProxyHeadersMiddleware` is able to retrieve a trusted client value then the client's port will be set to `0`. This is because port information is lost when using these headers.

### UNIX Domain Sockets (UDS)

Although it is common for UNIX Domain Sockets to be used for communicating between various HTTP servers, they can mess with some of the expected received values as they will be various non-address strings or missing values.

For example:

- when NGINX itself is running behind a UDS it will add the literal `unix:` as the client in the `X-Forwarded-For` header.
- When Uvicorn is running behind a UDS the initial client will be `None`.

### Trust Everything

Rather than specifying what to trust, you can instruct Uvicorn to trust all clients using the literal `"*"`. You should only set this when you know you can trust all values within the forwarded headers (e.g. because your proxies remove the existing headers before setting their own).

# Deployment

Server deployment is a complex area, that will depend on what kind of service you're deploying Uvicorn onto.

As a general rule, you probably want to:

* Run `uvicorn --reload` from the command line for local development.
* Run `gunicorn -k uvicorn.workers.UvicornWorker` for production.
* Additionally run behind Nginx for self-hosted deployments.
* Finally, run everything behind a CDN for caching support, and serious DDOS protection.

## Running from the command line

Typically you'll run `uvicorn` from the command line.

```bash
$ uvicorn example:app --reload --port 5000
```

The ASGI application should be specified in the form `path.to.module:instance.path`.

When running locally, use `--reload` to turn on auto-reloading.

To see the complete set of available options, use `uvicorn --help`:

<!-- :cli_usage: -->
```
$ uvicorn --help
Usage: uvicorn [OPTIONS] APP

Options:
  --host TEXT                     Bind socket to this host.  [default:
                                  127.0.0.1]
  --port INTEGER                  Bind socket to this port.  [default: 8000]
  --uds TEXT                      Bind to a UNIX domain socket.
  --fd INTEGER                    Bind to socket from this file descriptor.
  --reload                        Enable auto-reload.
  --reload-dir PATH               Set reload directories explicitly, instead
                                  of using the current working directory.
  --reload-include TEXT           Set glob patterns to include while watching
                                  for files. Includes '*.py' by default, which
                                  can be overridden in reload-excludes.
  --reload-exclude TEXT           Set glob patterns to exclude while watching
                                  for files. Includes '.*, .py[cod], .sw.*,
                                  ~*' by default, which can be overridden in
                                  reload-excludes.
  --reload-delay FLOAT            Delay between previous and next check if
                                  application needs to be. Defaults to 0.25s.
                                  [default: 0.25]
  --workers INTEGER               Number of worker processes. Defaults to the
                                  $WEB_CONCURRENCY environment variable if
                                  available, or 1. Not valid with --reload.
  --loop [auto|asyncio|uvloop]    Event loop implementation.  [default: auto]
  --http [auto|h11|httptools]     HTTP protocol implementation.  [default:
                                  auto]
  --ws [auto|none|websockets|wsproto]
                                  WebSocket protocol implementation.
                                  [default: auto]
  --ws-max-size INTEGER           WebSocket max size message in bytes
                                  [default: 16777216]
  --ws-ping-interval FLOAT        WebSocket ping interval  [default: 20.0]
  --ws-ping-timeout FLOAT         WebSocket ping timeout  [default: 20.0]
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
  --access-log-format TEXT        Log format for access logger, check
                                  documentation for details.
  --use-colors / --no-use-colors  Enable/Disable colorized logging.
  --proxy-headers / --no-proxy-headers
                                  Enable/Disable X-Forwarded-Proto,
                                  X-Forwarded-For, X-Forwarded-Port to
                                  populate remote address info.
  --server-header / --no-server-header
                                  Enable/Disable default Server header.
  --date-header / --no-date-header
                                  Enable/Disable default Date header.
  --forwarded-allow-ips TEXT      Comma seperated list of IPs to trust with
                                  proxy headers. Defaults to the
                                  $FORWARDED_ALLOW_IPS environment variable if
                                  available, or '127.0.0.1'.
  --root-path TEXT                Set the ASGI 'root_path' for applications
                                  submounted below a given URL path.
  --limit-concurrency INTEGER     Maximum number of concurrent connections or
                                  tasks to allow, before issuing HTTP 503
                                  responses.
  --backlog INTEGER               Maximum number of connections to hold in
                                  backlog
  --limit-max-requests INTEGER    Maximum number of requests to service before
                                  terminating the process.
  --timeout-keep-alive INTEGER    Close Keep-Alive connections if no new data
                                  is received within this timeout.  [default:
                                  5]
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
                                  the current working directory.  [default: .]
  --factory                       Treat APP as an application factory, i.e. a
                                  () -> <ASGI app> callable.  [default: False]
  --help                          Show this message and exit.
```


See the [settings documentation](settings.md) for more details on the supported options for running uvicorn.

## Running programmatically

To run directly from within a Python program, you should use `uvicorn.run(app, **config)`. For example:

**example.py**:

```python
import uvicorn

class App:
    ...

app = App()

if __name__ == "__main__":
    uvicorn.run("example:app", host="127.0.0.1", port=5000, log_level="info")
```

The set of configuration options is the same as for the command line tool.

Note that the application instance itself *can* be passed instead of the app
import string.

```python
uvicorn.run(app, host="127.0.0.1", port=5000, log_level="info")
```

However, this style only works if you are not using multiprocessing (`workers=NUM`)
or reloading (`reload=True`), so we recommend using the import string style.

Also note that in this case, you should put `uvicorn.run` into `if __name__ == '__main__'` clause in the main module.

## Using a process manager

Running Uvicorn using a process manager ensures that you can run multiple processes in a resilient manner, and allows you to perform server upgrades without dropping requests.

A process manager will handle the socket setup, start-up multiple server processes, monitor process aliveness, and listen for signals to provide for processes restarts, shutdowns, or dialing up and down the number of running processes.

Uvicorn provides a lightweight way to run multiple worker processes, for example `--workers 4`, but does not provide any process monitoring.

### Gunicorn

Gunicorn is probably the simplest way to run and manage Uvicorn in a production setting. Uvicorn includes a gunicorn worker class that means you can get set up with very little configuration.

The following will start Gunicorn with four worker processes:

`gunicorn -w 4 -k uvicorn.workers.UvicornWorker`

The `UvicornWorker` implementation uses the `uvloop` and `httptools` implementations. To run under PyPy you'll want to use pure-python implementation instead. You can do this by using the `UvicornH11Worker` class.

`gunicorn -w 4 -k uvicorn.workers.UvicornH11Worker`

Gunicorn provides a different set of configuration options to Uvicorn, so  some options such as `--limit-concurrency` are not yet supported when running with Gunicorn.

If you need to pass uvicorn's config arguments to gunicorn workers then you'll have to subclass `UvicornWorker`:

```python
class MyUvicornWorker(UvicornWorker):
    CONFIG_KWARGS = {"loop": "asyncio", "http": "h11", "lifespan": "off"}
```

### Supervisor

To use `supervisor` as a process manager you should either:

* Hand over the socket to uvicorn using its file descriptor, which supervisor always makes available as `0`, and which must be set in the `fcgi-program` section.
* Or use a UNIX domain socket for each `uvicorn` process.

A simple supervisor configuration might look something like this:

**supervisord.conf**:

```ini
[supervisord]

[fcgi-program:uvicorn]
socket=tcp://localhost:8000
command=venv/bin/uvicorn --fd 0 example:App
numprocs=4
process_name=uvicorn-%(process_num)d
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
```

Then run with `supervisord -n`.

### Circus

To use `circus` as a process manager, you should either:

* Hand over the socket to uvicorn using its file descriptor, which circus makes available as `$(circus.sockets.web)`.
* Or use a UNIX domain socket for each `uvicorn` process.

A simple circus configuration might look something like this:

**circus.ini**:

```ini
[watcher:web]
cmd = venv/bin/uvicorn --fd $(circus.sockets.web) example:App
use_sockets = True
numprocesses = 4

[socket:web]
host = 0.0.0.0
port = 8000
```

Then run `circusd circus.ini`.

## Running behind Nginx

Using Nginx as a proxy in front of your Uvicorn processes may not be neccessary, but is recommended for additional resiliance. Nginx can deal with serving your static media and buffering slow requests, leaving your application servers free from load as much as possible.

In managed environments such as `Heroku`, you wont typically need to configure Nginx, as your server processes will already be running behind load balancing proxies.

The recommended configuration for proxying from Nginx is to use a UNIX domain socket between Nginx and whatever the process manager that is being used to run Uvicorn.
Note that when doing this you will need run Uvicorn with `--forwarded-allow-ips='*'` to ensure that the domain socket is trusted as a source from which to proxy headers.

When fronting the application with a proxy server you want to make sure that the proxy sets headers to ensure that application can properly determine the client address of the incoming connection, and if the connection was over `http` or `https`.

You should ensure that the `X-Forwarded-For` and `X-Forwarded-Proto` headers are set by the proxy, and that Uvicorn is run using the `--proxy-headers` setting. This ensure that the ASGI scope includes correct `client` and `scheme` information.

Here's how a simple Nginx configuration might look. This example includes setting proxy headers, and using a UNIX domain socket to communicate with the application server.

It also includes some basic configuration to forward websocket connections. For more info on this, check [Nginx recommendations][nginx_websocket].

```conf
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

In those cases you might want to use an ASGI middleware to set the `client` and `scheme` dependant on the request headers.

## Running behind a CDN

Running behind a content delivery network, such as Cloudflare or Cloud Front, provides a serious layer of protection against DDOS attacks. Your sevice will be running behind huge clusters of proxies and load balancers that are designed for handling huge amounts of traffic, and have capabilities for detecting and closing off connections from DDOS attacks.

Proper usage of cache control headers can mean that a CDN is able to serve large amounts of data without always having to forward the request on to your server.

Content Delivery Networks can also be a low-effort way to provide HTTPS termination.

## Running with HTTPS

To run uvicorn with https, a certificate and a private key are required.
The recommended way to get them is using [Let's Encrypt][letsencrypt].

For local development with https, it's possible to use [mkcert][mkcert]
to generate a valid certificate and private key.

```bash
$ uvicorn example:app --port 5000 --ssl-keyfile=./key.pem --ssl-certfile=./cert.pem
```

### Running gunicorn worker

It also possible to use certificates with uvicorn's worker for gunicorn

```bash
$ gunicorn --keyfile=./key.pem --certfile=./cert.pem -k uvicorn.workers.UvicornWorker example:app
```

[nginx_websocket]: https://nginx.org/en/docs/http/websocket.html
[letsencrypt]: https://letsencrypt.org/
[mkcert]: https://github.com/FiloSottile/mkcert

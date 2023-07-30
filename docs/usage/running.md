# Running Uvicorn

There are many ways you can run Uvicorn.

For this page, let's assume we have the following application:

```py title="main.py"
async def app(scope, receive, send):
    assert scope['type'] == 'http'

    await send({
        'type': 'http.response.start',  # (1)!
        'status': 200,
        'headers': [
          (b'content-type', b'text/plain'),
          (b'content-length', b'13')
        ],
    })
    await send({'type': 'http.response.body', 'body': b'Hello, world!'})  # (2)!
```

1. The `http.response.start` message is sent to indicate that the response is starting.

    See [Response Start](https://asgi.readthedocs.io/en/latest/specs/www.html#response-start-send-event) for more details.

2. The `http.response.body` message is sent to indicate the response body.

    See [Response Body](https://asgi.readthedocs.io/en/latest/specs/www.html#response-body-send-event) for more details.


## Running from the command line

The simplest way to run Uvicorn is from the command line. You can use the `uvicorn` command,
and pass it an import path to an ASGI application, like this:

```bash
$ uvicorn main:app
```

Check out the [Settings](#settings) section for a full list of options.

## Running programmatically

You can also run Uvicorn directly from Python code, using `uvicorn.run()`:

```py
if __name__ == '__main__':
    import uvicorn
    uvicorn.run("main:app")  # (1)!
```

1. The `main:app` argument is a "module:variable name" pair that points to an ASGI application.
   In this example, the `app` object is imported from the `main` module, and is the ASGI application.

Check out the [Settings](#settings) section for a full list of options.

### Using `Config` and `Server` directly

For more control over configuration and server lifecycle, use `uvicorn.Config` and `uvicorn.Server`:

```py title="main.py"
import uvicorn


async def app(scope, receive, send):
    ...


if __name__ == "__main__":
    config = uvicorn.Config("main:app", port=5000, log_level="info")
    server = uvicorn.Server(config)
    server.run()
```

If you'd like to run Uvicorn from an already running async environment, use `server.serve()` instead:

```python
import asyncio

import uvicorn


async def app(scope, receive, send):
    ...


async def main():
    config = uvicorn.Config("main:app", port=5000, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

## Running Uvicorn in an async task

You can also run Uvicorn in an async task, which allows you to run other tasks alongside it.

Let's see an example running `uvicorn` alongside a task that prints the current time every second:

```py
import asyncio

import uvicorn


async def print_every_second():
    while True:
        print(datetime.datetime.now())
        await asyncio.sleep(1)


async def main():
    asyncio.create_task(print_every_second())
    config = uvicorn.Config("main:app")
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == '__main__':
    asyncio.run(main())
```

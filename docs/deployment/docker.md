# Dockerfile

**Docker** is a popular choice for modern application deployment. However, creating a good Dockerfile from scratch can be challenging. This guide provides a **solid foundation** that works well for most Python projects.

While the example below won't fit every use case, it offers an excellent starting point that you can adapt to your specific needs.


## Quickstart

For this example, we'll need to install [`docker`](https://docs.docker.com/get-docker/),
[docker-compose](https://docs.docker.com/compose/install/) and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/).

Then, let's create a new project with `uv`:

```bash
uv init app
```

This will create a new project with a basic structure:

```bash
app/
├── main.py
├── pyproject.toml
└── README.md
```

On `main.py`, let's create a simple ASGI application:

```python title="main.py"
async def app(scope, receive, send):
    body = "Hello, world!"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/plain"],
                [b"content-length", len(body)],
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body.encode("utf-8"),
        }
    )
```

We need to include `uvicorn` in the dependencies:

```bash
uv add uvicorn
```

This will also create a `uv.lock` file. :sunglasses:

??? tip "What is `uv.lock`?"

    `uv.lock` is a `uv` specific lockfile. A lockfile is a file that contains the exact versions of the dependencies
    that were installed when the `uv.lock` file was created.

    This allows for deterministic builds and consistent deployments.

Just to make sure everything is working, let's run the application:

```bash
uv run uvicorn main:app
```

You should see the following output:

```bash
INFO:     Started server process [62727]
INFO:     Waiting for application startup.
INFO:     ASGI 'lifespan' protocol appears unsupported.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

## Dockerfile

We'll create a **cache-aware Dockerfile** that optimizes build times. The key strategy is to install dependencies first, then copy the project files. This approach leverages Docker's caching mechanism to significantly speed up rebuilds.

```dockerfile title="Dockerfile"
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Change the working directory to the `app` directory
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project

# Copy the project into the image
ADD . /app

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

# Run with uvicorn
CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

A common question is **"how many workers should I run?"**. The image above uses a single Uvicorn worker.
The recommended approach is to let your orchestration system manage the number of deployed containers rather than
relying on the process manager inside the container.

You can read more about this in the
[Decouple applications](https://docs.docker.com/build/building/best-practices/#decouple-applications) section
of the Docker documentation.

!!! warning "For production, create a non-root user!"
    When running in production, you should create a non-root user and run the container as that user.

To make sure it works, let's build the image and run it:

```bash
docker build -t my-app .
docker run -p 8000:8000 my-app
```

For more information on using uv with Docker, refer to the
[official uv Docker integration guide](https://docs.astral.sh/uv/guides/integration/docker/).

## Docker Compose

When running in development, it's often useful to have a way to hot-reload the application when code changes.

Let's create a `docker-compose.yml` file to run the application:

```yaml title="docker-compose.yml"
services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - UVICORN_RELOAD=true
    volumes:
      - .:/app
    tty: true
```

You can run the application with `docker compose up` and it will automatically rebuild the image when code changes.

Now you have a fully working development environment! :tada:

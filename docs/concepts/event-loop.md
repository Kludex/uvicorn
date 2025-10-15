# Event Loop

Uvicorn provides two event loop implementations that you can choose from using the [`--loop`](../settings.md#implementation) option:

```bash
uvicorn main:app --loop <auto|asyncio|uvloop|winloop>
```

By default, Uvicorn uses `--loop auto`, which automatically selects:

1. **uvloop** / **winloop** - If [uvloop](https://github.com/MagicStack/uvloop) (on Unix) or [winloop](https://github.com/Vizonex/Winloop) (on Windows) is installed, Uvicorn will use it for maximum performance
2. **asyncio** - If uvloop/winloop is not available, Uvicorn falls back to Python's built-in asyncio event loop

Both `uvloop` and `winloop` are based on libuv and are not compatible with PyPy.

On Windows, the asyncio implementation uses [`ProactorEventLoop`][asyncio.ProactorEventLoop] if running with multiple workers,
otherwise it uses the standard [`SelectorEventLoop`][asyncio.SelectorEventLoop] for better performance.

??? info "Why does `SelectorEventLoop` not work with multiple processes on Windows?"
    If you want to know more about it, you can read the issue [#cpython/122240](https://github.com/python/cpython/issues/122240).

## Custom Event Loop

You can use custom event loop implementations by specifying a module path and function name using the colon notation:

```bash
uvicorn main:app --loop <module>:<function>
```

The function should return a callable that creates a new event loop instance.

### rloop

[rloop](https://github.com/gi0baro/rloop) is an experimental AsyncIO event loop implemented in Rust on top of the [mio](https://github.com/tokio-rs/mio) crate. It aims to provide high performance through Rust's systems programming capabilities.

You can install it with:

=== "pip"
    ```bash
    pip install rloop
    ```
=== "uv"
    ```bash
    uv add rloop
    ```

You can run `uvicorn` with `rloop` with the following command:

```bash
uvicorn main:app --loop rloop:new_event_loop
```

!!! warning "Experimental"
    rloop is currently **experimental** and **not suited for production usage**. It is only available on **Unix systems**.

### Winloop

[Winloop](https://github.com/Vizonex/Winloop) brings uvloop-like performance to Windows. Both winloop and uvloop are based on libuv, but winloop provides a Windows-compatible implementation with significant performance improvements over the standard Windows event loop policies.

Winloop is now a built-in option in Uvicorn. You can install it with:

=== "pip"
    ```bash
    pip install winloop
    ```
=== "uv"
    ```bash
    uv add winloop
    ```

You can explicitly use Winloop with the following command:

```bash
uvicorn main:app --loop winloop
```

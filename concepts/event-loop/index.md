# Event Loop

Uvicorn provides two event loop implementations that you can choose from using the [`--loop`](https://uvicorn.dev/settings/#implementation) option:

```
uvicorn main:app --loop <auto|asyncio|uvloop>
```

By default, Uvicorn uses `--loop auto`, which automatically selects:

1. **uvloop** - If [uvloop](https://github.com/MagicStack/uvloop) is installed, Uvicorn will use it for maximum performance
1. **asyncio** - If uvloop is not available, Uvicorn falls back to Python's built-in asyncio event loop

Since `uvloop` is not compatible with Windows or PyPy, it is not available on these platforms.

On Windows, the asyncio implementation uses ProactorEventLoop if running with multiple workers, otherwise it uses the standard SelectorEventLoop for better performance.

Why does `SelectorEventLoop` not work with multiple processes on Windows?

If you want to know more about it, you can read the issue [#cpython/122240](https://github.com/python/cpython/issues/122240).

## Custom Event Loop

You can use custom event loop implementations by specifying a module path and function name using the colon notation:

```
uvicorn main:app --loop <module>:<function>
```

The function should return a callable that creates a new event loop instance.

### rloop

[rloop](https://github.com/gi0baro/rloop) is an experimental AsyncIO event loop implemented in Rust on top of the [mio](https://github.com/tokio-rs/mio) crate. It aims to provide high performance through Rust's systems programming capabilities.

You can install it with:

```
pip install rloop
```

```
uv add rloop
```

You can run `uvicorn` with `rloop` with the following command:

```
uvicorn main:app --loop rloop:new_event_loop
```

Experimental

rloop is currently **experimental** and **not suited for production usage**. It is only available on **Unix systems**.

### Winloop

[Winloop](https://github.com/Vizonex/Winloop) is an alternative library that brings uvloop-like performance to Windows. Since uvloop is based on libuv and doesn't support Windows, Winloop provides a Windows-compatible implementation with significant performance improvements over the standard Windows event loop policies.

You can install it with:

```
pip install winloop
```

```
uv add winloop
```

You can run `uvicorn` with `Winloop` with the following command:

```
uvicorn main:app --loop winloop:new_event_loop
```

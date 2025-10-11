# Event Loop

The event loop is the core of Python's asynchronous programming. It manages and executes asynchronous tasks, handles I/O operations, and coordinates the execution of concurrent code without using threads.

In the context of Uvicorn, the event loop is responsible for handling incoming HTTP requests, managing WebSocket connections, and executing your ASGI application's asynchronous code.

## How Uvicorn Selects the Event Loop

Uvicorn provides two event loop implementations that you can choose from using the `--loop` option:

```bash
uvicorn main:app --loop auto
```

By default, Uvicorn uses `--loop auto`, which automatically selects the best available event loop implementation:

1. **First choice: uvloop** - If [uvloop](https://github.com/MagicStack/uvloop) is installed, Uvicorn will use it for maximum performance
2. **Fallback: asyncio** - If uvloop is not available, Uvicorn falls back to Python's built-in asyncio event loop

On Windows, the asyncio implementation uses `ProactorEventLoop` for better I/O performance, while on Unix systems it uses `SelectorEventLoop`.

## Built-in Event Loop Options

Uvicorn includes three built-in event loop options:

### auto (Default)

Automatically selects the best available event loop. Prefers uvloop if installed, otherwise uses asyncio.

```bash
uvicorn main:app --loop auto
```

### asyncio

Uses Python's standard library asyncio event loop. This is guaranteed to be available but may have lower performance compared to uvloop.

```bash
uvicorn main:app --loop asyncio
```

### uvloop

Uses the [uvloop](https://github.com/MagicStack/uvloop) event loop, which is a fast drop-in replacement for asyncio's event loop. It's implemented on top of libuv (the same library that powers Node.js) and provides 2-4x performance improvement over the standard asyncio event loop.

```bash
uvicorn main:app --loop uvloop
```

!!! note
    uvloop is not compatible with Windows or PyPy. On these platforms, use `asyncio` or one of the alternative implementations below.

## Custom Event Loop Implementations

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

You can use it by specifying the module path and function name:

```bash
uvicorn main:app --loop rloop:new_event_loop
```

!!! warning "Experimental"
    rloop is currently **experimental** and **not suited for production usage**. It is only available on **Unix systems**.

### winloop

[winloop](https://github.com/Vizonex/Winloop) is an alternative library that brings uvloop-like performance to Windows. Since uvloop is based on libuv and doesn't support Windows, winloop provides a Windows-compatible implementation with significant performance improvements over the standard Windows event loop policies.

You can install it with:

=== "pip"
    ```bash
    pip install winloop
    ```
=== "uv"
    ```bash
    uv add winloop
    ```

You can use it by specifying the module path and function name:

```bash
uvicorn main:app --loop winloop:new_event_loop
```

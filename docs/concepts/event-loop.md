By default, Uvicorn automatically selects the best available event loop:

- **uvloop** if available (preferred for performance)
- **asyncio** as a fallback in case uvloop is not installed

This is the recommended setting for most applications since it provides better performance when
possible while maintaining compatibility.

### uvloop

[uvloop](https://github.com/MagicStack/uvloop) is a fast, drop-in replacement for asyncio's event loop,
built on top of libuv. It provides significant performance improvements over the standard asyncio event loop.

Note that `uvloop` is not available on Windows.

### asyncio

The standard Python asyncio event loop. This is the fallback option that works on all platforms.

### Custom Event Loop

You can specify a custom event loop factory using the `--loop` option.

As an example, let's use [`rloop`](https://github.com/gi0baro/rloop), an AsyncIO selector event loop implemented in Rust.

```bash
uvicorn app:app --loop=rloop:new_event_loop
```

As mentioned by `rloop`'s README, the package is experimental, and it doesn't give the best performance on every system.

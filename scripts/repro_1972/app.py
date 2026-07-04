"""Minimal ASGI app for the #1972 repro. SHUTDOWN_DELAY simulates an app whose
graceful shutdown takes a long time (open connections, slow lifespan teardown)."""

from __future__ import annotations

import asyncio
import os


async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                delay = float(os.environ.get("SHUTDOWN_DELAY", "0"))
                if delay:
                    print(f"[app] shutdown requested, sleeping {delay}s", flush=True)
                    await asyncio.sleep(delay)
                await send({"type": "lifespan.shutdown.complete"})
                return
    elif scope["type"] == "http":
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

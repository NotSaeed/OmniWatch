"""
Ephemeral in-memory challenge state store for WebAuthn ceremonies.

Challenges are one-time-use: pop() atomically reads and removes the entry.
Entries that exceed CHALLENGE_TTL_S are treated as missing (expired) on read.

This is appropriate for a single-process FastAPI app. A Redis store would be
needed for multi-process deployment, but that is out of scope for this demo.
"""

import asyncio
import time
from typing import Any

CHALLENGE_TTL_S: int = 300   # WebAuthn recommends ≤ 5 min

_store: dict[str, tuple[Any, float]] = {}
_lock  = asyncio.Lock()


async def put(key: str, state: Any) -> None:
    """Store challenge state. Overwrites any existing entry for the same key."""
    async with _lock:
        _store[key] = (state, time.monotonic())


async def pop(key: str) -> Any | None:
    """
    Retrieve and atomically remove challenge state.
    Returns None if missing or if the entry has expired (TTL exceeded).
    Expired entries are silently discarded — callers must treat None as failure.
    """
    async with _lock:
        entry = _store.pop(key, None)
    if entry is None:
        return None
    state, ts = entry
    if time.monotonic() - ts > CHALLENGE_TTL_S:
        return None           # expired — treat as if it never existed
    return state

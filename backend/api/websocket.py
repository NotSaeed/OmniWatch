"""WebSocket connection manager — broadcasts new alerts and playbook events to the dashboard."""

import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        logger.info("WebSocket connected — %d active", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)
        logger.info("WebSocket disconnected — %d active", len(self._connections))

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """Send a JSON payload to every connected client. Silently drops dead connections."""
        dead: set[WebSocket] = set()
        message = json.dumps(payload, default=str)
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        self._connections -= dead


# Module-level singleton used across routes and background tasks
manager = ConnectionManager()

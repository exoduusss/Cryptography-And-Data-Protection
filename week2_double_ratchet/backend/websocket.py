"""WebSocket Connection Manager for untrusted message relaying.

Educational reference implementation.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("relay.websocket")


class ConnectionManager:
    """Manages active user WebSocket connections for message dispatch."""

    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections[user_id] = websocket
        logger.info(f"User '{user_id}' connected via WebSocket")

    def disconnect(self, user_id: str) -> None:
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            logger.info(f"User '{user_id}' disconnected")

    async def send_to_user(self, recipient_id: str, message: dict[str, Any]) -> bool:
        """Send message directly to active recipient WebSocket if connected."""
        ws = self.active_connections.get(recipient_id)
        if ws is not None:
            await ws.send_json(message)
            return True
        return False

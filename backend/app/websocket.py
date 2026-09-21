"""WebSocket event bus for real-time scan streaming.

Manages WebSocket connections per scan and broadcasts events
(log lines, progress updates, findings, assets) to all connected clients.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("intellivapt.ws")


@dataclass
class ScanEvent:
    """A single event emitted during a scan."""

    event: str  # "log", "progress", "status", "finding", "asset", "stage"
    data: Any

    def to_json(self) -> str:
        return json.dumps({"event": self.event, "data": self.data})


class ScanEventBus:
    """Manages WebSocket connections and broadcasts scan events.

    Thread-safe: the scanner runs in a background thread and calls
    ``broadcast_sync`` which schedules the actual send onto the asyncio
    event loop.
    """

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Store the main asyncio event loop for thread-safe broadcasting."""
        self._loop = loop

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        """Accept a WebSocket connection and register it for a scan."""
        await ws.accept()
        self._connections[scan_id].append(ws)
        logger.info("WS connected for scan %s (total: %d)", scan_id, len(self._connections[scan_id]))

    def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        """Remove a WebSocket from the scan's connection list."""
        conns = self._connections.get(scan_id, [])
        if ws in conns:
            conns.remove(ws)
        if not conns:
            self._connections.pop(scan_id, None)
        logger.info("WS disconnected for scan %s", scan_id)

    async def _broadcast(self, scan_id: str, event: ScanEvent) -> None:
        """Send an event to all WebSocket clients for a given scan."""
        conns = self._connections.get(scan_id, [])
        if not conns:
            return

        payload = event.to_json()
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(scan_id, ws)

    def broadcast_sync(self, scan_id: str, event_type: str, data: Any) -> None:
        """Thread-safe broadcast — schedules the send on the asyncio loop.

        Call this from the scanner background thread.
        """
        if self._loop is None or self._loop.is_closed():
            return

        event = ScanEvent(event=event_type, data=data)
        asyncio.run_coroutine_threadsafe(self._broadcast(scan_id, event), self._loop)

    # -----------------------------------------------------------------------
    # Convenience helpers for the scanner
    # -----------------------------------------------------------------------

    def emit_log(self, scan_id: str, message: str) -> None:
        self.broadcast_sync(scan_id, "log", {"message": message})

    def emit_progress(self, scan_id: str, progress: int, stage: str = "") -> None:
        self.broadcast_sync(scan_id, "progress", {"progress": progress, "stage": stage})

    def emit_status(self, scan_id: str, status: str) -> None:
        self.broadcast_sync(scan_id, "status", {"status": status})

    def emit_finding(self, scan_id: str, finding: dict) -> None:
        self.broadcast_sync(scan_id, "finding", finding)

    def emit_asset(self, scan_id: str, asset: dict) -> None:
        self.broadcast_sync(scan_id, "asset", asset)

    def emit_stage(self, scan_id: str, stage: str, step: int, total: int) -> None:
        self.broadcast_sync(scan_id, "stage", {"stage": stage, "step": step, "total": total})


# ---------------------------------------------------------------------------
# Global singleton — imported by scanner.py and main.py
# ---------------------------------------------------------------------------
scan_event_bus = ScanEventBus()

"""
detection_engine/notification_bus.py

Minimal in-process pub/sub for live incident notifications.

No new index, no new external dependency. The incident_engine pushes
events here; the FastAPI SSE endpoint drains them. Nothing else needs
to know this file exists.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("detection_engine.notification_bus")


class NotificationBus:
    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Call once at FastAPI startup so sync code can push events safely."""
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    def publish(self, event: dict[str, Any]) -> None:
        """
        Safe to call from sync code (incident_engine runs outside the
        event loop, e.g. in a worker thread or sync request path).
        """
        event.setdefault("emitted_at", datetime.now(timezone.utc).isoformat())

        if not self._subscribers:
            return  # no dashboard connected — drop silently, not an error

        if self._loop is None:
            log.warning("NotificationBus.publish called before bind_loop(); dropping event")
            return

        for q in list(self._subscribers):
            self._loop.call_soon_threadsafe(self._put_nowait_safe, q, event)

    @staticmethod
    def _put_nowait_safe(q: asyncio.Queue, event: dict) -> None:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("Subscriber queue full — dropping oldest notification")
            try:
                q.get_nowait()
                q.put_nowait(event)
            except Exception:
                pass


# Module-level singleton — imported by both incident_engine.py and the API layer
notification_bus = NotificationBus()
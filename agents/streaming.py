"""
Live Streaming Agent Output — StreamingEventBus.

Provides an in-process publish/subscribe event bus for broadcasting agent
state changes in real-time.  Events are serialised as JSON and can be
consumed by async generators (WebSocket handlers, CLI printers, tests).

A SQLite-backed event queue lets *late subscribers* replay events they
missed while not yet connected.

Usage::

    from agents.streaming import StreamingEventBus, emit

    bus = StreamingEventBus()

    # Publisher (agent / tool)
    await bus.publish("scan_123", {"type": "file_scanned", "file": "auth.py"})

    # Subscriber (WebSocket / CLI)
    async for event in bus.subscribe("scan_123"):
        print(event)

    # Module-level convenience
    await emit("scan_123", {"type": "scan_completed"})

Standard event types (not enforced, but documented here for consistency):
    scan_started     — scan kicked off
    file_scanned     — one file processed
    finding_found    — a finding was produced
    tool_executed    — an agent tool completed
    step_completed   — a durable-workflow step completed
    scan_completed   — the overall scan is done
    error_occurred   — an error event
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from typing import Any, AsyncGenerator, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Default bus (module-level singleton) ──────────────────────────────────────

_default_bus: Optional["StreamingEventBus"] = None


def get_default_bus() -> "StreamingEventBus":
    """Return (and lazily create) the module-level default StreamingEventBus."""
    global _default_bus
    if _default_bus is None:
        _default_bus = StreamingEventBus()
    return _default_bus


async def emit(scan_id: str, event: Dict[str, Any]) -> None:
    """Publish *event* to the default bus for *scan_id*."""
    await get_default_bus().publish(scan_id, event)


# ── SQLite queue schema ───────────────────────────────────────────────────────

_QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_queue (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT    NOT NULL,
    payload    TEXT    NOT NULL,
    created_at REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_eq_scan ON event_queue(scan_id, id);
"""

# Maximum events to keep per scan_id in the SQLite queue
_MAX_QUEUE_EVENTS = 10_000


# ── StreamingEventBus ─────────────────────────────────────────────────────────


class StreamingEventBus:
    """
    In-process pub/sub event bus with optional SQLite persistence for late
    subscribers.

    Thread safety: ``publish`` and ``subscribe`` are safe to call from any
    asyncio task.  The SQLite store uses WAL mode and is safe for concurrent
    access from multiple threads/processes.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        # channel_name → set of asyncio.Queue
        self._queues: Dict[str, List[asyncio.Queue]] = {}  # type: ignore[type-arg]
        self._lock = asyncio.Lock()
        # Optional SQLite persistence
        if db_path:
            self._db_path: Optional[str] = db_path
            self._conn: Optional[sqlite3.Connection] = sqlite3.connect(
                db_path, check_same_thread=False
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_QUEUE_SCHEMA)
            self._conn.commit()
        else:
            self._db_path = None
            self._conn = None

    # ── publish ───────────────────────────────────────────────────────

    async def publish(self, scan_id: str, event: Dict[str, Any]) -> None:
        """
        Publish *event* to all current subscribers for *scan_id*.

        A ``timestamp`` field is injected automatically if absent.
        The event is also persisted to SQLite (when a db_path was provided)
        so late subscribers can replay missed events.
        """
        if "timestamp" not in event:
            event = {**event, "timestamp": _iso_now()}
        if "scan_id" not in event:
            event = {**event, "scan_id": scan_id}

        payload = json.dumps(event)
        logger.debug(
            "StreamingEventBus.publish: scan_id=%s type=%s", scan_id, event.get("type")
        )

        # Persist to SQLite
        if self._conn is not None:
            try:
                self._conn.execute(
                    "INSERT INTO event_queue (scan_id, payload, created_at) VALUES (?, ?, ?)",
                    (scan_id, payload, time.time()),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                logger.warning("StreamingEventBus: sqlite write failed: %s", exc)

        # Deliver to in-process subscribers
        async with self._lock:
            queues = list(self._queues.get(scan_id, []))

        for q in queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    "StreamingEventBus: subscriber queue full for scan_id=%s", scan_id
                )

    def publish_sync(self, scan_id: str, event: Dict[str, Any]) -> None:
        """
        Synchronous publish — safe to call from non-async code.

        Events are persisted to SQLite (if configured) and delivered to any
        current in-process subscribers.
        """
        if "timestamp" not in event:
            event = {**event, "timestamp": _iso_now()}
        if "scan_id" not in event:
            event = {**event, "scan_id": scan_id}
        payload = json.dumps(event)
        for queue in list(self._queues.get(scan_id, [])):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    "StreamingEventBus: subscriber queue full for scan_id=%s", scan_id
                )
        if self._conn is not None:
            try:
                self._conn.execute(
                    "INSERT INTO event_queue (scan_id, payload, created_at) VALUES (?, ?, ?)",
                    (scan_id, payload, time.time()),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                logger.warning("StreamingEventBus: sqlite write (sync) failed: %s", exc)

    # ── subscribe ─────────────────────────────────────────────────────

    async def subscribe(
        self,
        scan_id: str,
        replay_from_db: bool = False,
        max_size: int = 1000,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Async generator that yields events for *scan_id* as they arrive.

        Parameters
        ----------
        scan_id:
            The scan/channel identifier to subscribe to.
        replay_from_db:
            If ``True`` and a SQLite db_path was provided at construction
            time, replay all previously-persisted events before yielding
            live ones.
        max_size:
            Internal queue capacity.  When full, new events are dropped with
            a warning.

        Yields
        ------
        dict
            Deserialized event objects.

        Notes
        -----
        Call ``await bus.close_channel(scan_id)`` (or publish a
        ``{"type": "scan_completed"}`` sentinel) to signal to subscribers
        that the stream is finished.  This generator will stop when it
        receives a ``None`` sentinel via ``_close_queue``.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=max_size)  # type: ignore[type-arg]

        async with self._lock:
            if scan_id not in self._queues:
                self._queues[scan_id] = []
            self._queues[scan_id].append(q)

        try:
            # Replay persisted events
            if replay_from_db and self._conn is not None:
                rows = self._conn.execute(
                    "SELECT payload FROM event_queue WHERE scan_id = ? ORDER BY id",
                    (scan_id,),
                ).fetchall()
                for (payload,) in rows:
                    try:
                        yield json.loads(payload)
                    except (json.JSONDecodeError, Exception):  # noqa: BLE001
                        pass

            # Yield live events
            while True:
                event = await q.get()
                if event is None:  # sentinel — channel closed
                    break
                yield event
        finally:
            async with self._lock:
                try:
                    self._queues.get(scan_id, []).remove(q)
                except ValueError:
                    pass

    async def close_channel(self, scan_id: str) -> None:
        """
        Signal all subscribers for *scan_id* that the stream is done.

        Sends a ``None`` sentinel through every subscriber queue.
        """
        async with self._lock:
            queues = list(self._queues.get(scan_id, []))
        for q in queues:
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass

    # ── query persisted events ────────────────────────────────────────

    def get_events(self, scan_id: str, since_id: int = 0) -> List[Dict[str, Any]]:
        """
        Return persisted events for *scan_id* since *since_id* (exclusive).

        Useful for polling / REST fallback when WebSockets aren't available.
        """
        if self._conn is None:
            return []
        rows = self._conn.execute(
            "SELECT id, payload FROM event_queue WHERE scan_id = ? AND id > ? ORDER BY id",
            (scan_id, since_id),
        ).fetchall()
        events = []
        for row_id, payload in rows:
            try:
                obj = json.loads(payload)
                obj["_event_id"] = row_id
                events.append(obj)
            except (json.JSONDecodeError, Exception):  # noqa: BLE001
                pass
        return events

    def close(self) -> None:
        """Close the SQLite connection (if open)."""
        if self._conn:
            self._conn.close()
            self._conn = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _iso_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Convenience event constructors ────────────────────────────────────────────


def scan_started_event(scan_id: str, path: str, total_files: int) -> Dict[str, Any]:
    return {
        "type": "scan_started",
        "scan_id": scan_id,
        "path": path,
        "total_files": total_files,
    }


def file_scanned_event(
    scan_id: str, file: str, current: int, total: int
) -> Dict[str, Any]:
    return {
        "type": "file_scanned",
        "scan_id": scan_id,
        "file": file,
        "progress": {"current": current, "total": total},
    }


def finding_found_event(
    scan_id: str,
    agent: str,
    severity: str,
    file: str,
    line: int,
    issue: str,
    current: int,
    total: int,
) -> Dict[str, Any]:
    return {
        "type": "finding_found",
        "scan_id": scan_id,
        "finding": {
            "agent": agent,
            "severity": severity,
            "file": file,
            "line": line,
            "issue": issue,
        },
        "progress": {"current": current, "total": total},
    }


def step_completed_event(scan_id: str, step_name: str, attempt: int) -> Dict[str, Any]:
    return {
        "type": "step_completed",
        "scan_id": scan_id,
        "step_name": step_name,
        "attempt": attempt,
    }


def scan_completed_event(scan_id: str, total_findings: int) -> Dict[str, Any]:
    return {
        "type": "scan_completed",
        "scan_id": scan_id,
        "total_findings": total_findings,
    }


def error_occurred_event(
    scan_id: str, error: str, step: Optional[str] = None
) -> Dict[str, Any]:
    return {"type": "error_occurred", "scan_id": scan_id, "error": error, "step": step}

"""
Durable Workflow Steps — Multi-Hour Scan Resilience.

Provides a `@durable_step` decorator and `@durable_workflow` decorator that
persist each step's inputs, outputs, and status to SQLite. On failure, a
workflow can resume from the last completed step instead of restarting from
scratch.

Usage::

    from agents.durability import durable_step, durable_workflow

    @durable_step(max_retries=3, backoff="exponential")
    async def scan_files(project_path: str):
        return await cli_scan(project_path)

    @durable_step(max_retries=2)
    async def apply_fixes(findings: list):
        return await healing_agent.run(findings)

    @durable_workflow(name="full_scan_and_heal")
    async def full_workflow(project_path: str):
        findings = await scan_files(project_path)
        fixed   = await apply_fixes(findings)
        return fixed
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
import random
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default database path; can be overridden via ``DurabilityDB(path=...)``.
_DEFAULT_DB_PATH = Path.home() / ".rushingtech" / "durability.db"

# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_STEPS_TABLE = """
CREATE TABLE IF NOT EXISTS steps (
    step_id      TEXT    NOT NULL,
    workflow_id  TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'pending',
    inputs       TEXT,
    outputs      TEXT,
    started_at   REAL,
    completed_at REAL,
    error        TEXT,
    attempt      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (step_id, workflow_id)
);
"""

_VALID_STATUSES = {"pending", "running", "completed", "failed"}


# ── Database ──────────────────────────────────────────────────────────────────


class DurabilityDB:
    """Thin wrapper around SQLite for durable-step persistence."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = Path(path) if path else _DEFAULT_DB_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    # ── connection management ──────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_CREATE_STEPS_TABLE)
            self._conn.commit()
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── step CRUD ─────────────────────────────────────────────────────

    def upsert_step(
        self,
        *,
        step_id: str,
        workflow_id: str,
        status: str,
        inputs: Optional[Any] = None,
        outputs: Optional[Any] = None,
        started_at: Optional[float] = None,
        completed_at: Optional[float] = None,
        error: Optional[str] = None,
        attempt: int = 0,
    ) -> None:
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO steps
                (step_id, workflow_id, status, inputs, outputs,
                 started_at, completed_at, error, attempt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(step_id, workflow_id) DO UPDATE SET
                status       = excluded.status,
                inputs       = excluded.inputs,
                outputs      = excluded.outputs,
                started_at   = COALESCE(excluded.started_at, steps.started_at),
                completed_at = excluded.completed_at,
                error        = excluded.error,
                attempt      = excluded.attempt
            """,
            (
                step_id,
                workflow_id,
                status,
                _serialize(inputs),
                _serialize(outputs),
                started_at,
                completed_at,
                error,
                attempt,
            ),
        )
        conn.commit()

    def get_step(self, step_id: str, workflow_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM steps WHERE step_id = ? AND workflow_id = ?",
            (step_id, workflow_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "step_id": row["step_id"],
            "workflow_id": row["workflow_id"],
            "status": row["status"],
            "inputs": _deserialize(row["inputs"]),
            "outputs": _deserialize(row["outputs"]),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "error": row["error"],
            "attempt": row["attempt"],
        }

    def list_steps(self, workflow_id: str) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM steps WHERE workflow_id = ? ORDER BY started_at",
            (workflow_id,),
        ).fetchall()
        return [
            {
                "step_id": r["step_id"],
                "workflow_id": r["workflow_id"],
                "status": r["status"],
                "inputs": _deserialize(r["inputs"]),
                "outputs": _deserialize(r["outputs"]),
                "started_at": r["started_at"],
                "completed_at": r["completed_at"],
                "error": r["error"],
                "attempt": r["attempt"],
            }
            for r in rows
        ]

    def delete_workflow(self, workflow_id: str) -> None:
        conn = self._get_conn()
        conn.execute("DELETE FROM steps WHERE workflow_id = ?", (workflow_id,))
        conn.commit()


# ── Serialization helpers ─────────────────────────────────────────────────────


def _serialize(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return json.dumps(str(value))


def _deserialize(text: Optional[str]) -> Any:
    if text is None:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


# ── Backoff helpers ───────────────────────────────────────────────────────────


def _compute_backoff(attempt: int, backoff: str, base: float = 1.0) -> float:
    """Return the number of seconds to wait before the next attempt."""
    if backoff == "exponential":
        delay = base * (2 ** attempt) + random.uniform(0, 0.5)
    elif backoff == "linear":
        delay = base * (attempt + 1)
    else:  # "none" or unknown
        delay = 0.0
    return delay


# ── Active workflow context ───────────────────────────────────────────────────

# Thread-local storage is insufficient for asyncio; we use a module-level
# dict keyed by running-task identity instead.
_current_workflow: Dict[int, "_WorkflowContext"] = {}


class _WorkflowContext:
    def __init__(self, workflow_id: str, db: DurabilityDB, resume_from: Optional[str] = None) -> None:
        self.workflow_id = workflow_id
        self.db = db
        self.resume_from = resume_from  # step name to resume *at*
        self.resuming = resume_from is not None
        self.step_counters: Dict[str, int] = {}  # for disambiguating repeated calls


def _get_current_context() -> Optional["_WorkflowContext"]:
    task = _current_task_id()
    return _current_workflow.get(task)


def _current_task_id() -> int:
    """Return a stable identifier for the current asyncio Task (or 0 for sync)."""
    try:
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        return id(task) if task is not None else id(loop)
    except RuntimeError:
        return 0


# ── Decorators ────────────────────────────────────────────────────────────────


def durable_step(
    func: Optional[Callable] = None,
    *,
    max_retries: int = 3,
    backoff: str = "exponential",
    db: Optional[DurabilityDB] = None,
    db_path: Optional[str] = None,
) -> Callable:
    """
    Decorator that makes an async (or sync) function a durable step.

    When called inside a ``@durable_workflow``, the step result is persisted to
    SQLite so that if the workflow is re-run with ``resume_from=<step_name>``,
    already-completed steps are not re-executed — their cached output is
    returned immediately.

    Outside of a ``@durable_workflow`` context the decorator is transparent:
    the function runs normally without any persistence overhead.
    """

    def decorator(fn: Callable) -> Callable:
        step_name = fn.__name__

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx = _get_current_context()
            if ctx is None:
                # No workflow context — run transparently.
                if inspect.iscoroutinefunction(fn):
                    return await fn(*args, **kwargs)
                return fn(*args, **kwargs)

            _db = db or ctx.db or DurabilityDB(path=db_path)
            workflow_id = ctx.workflow_id

            # disambiguate if the same step is called multiple times
            ctx.step_counters[step_name] = ctx.step_counters.get(step_name, 0)
            call_index = ctx.step_counters[step_name]
            ctx.step_counters[step_name] += 1
            unique_step_id = f"{step_name}#{call_index}" if call_index > 0 else step_name

            # Check for existing completed result (checkpoint resume)
            existing = _db.get_step(unique_step_id, workflow_id)
            if existing and existing["status"] == "completed":
                logger.info("durable_step: resuming %s from checkpoint", unique_step_id)
                return existing["outputs"]

            # Determine inputs for persistence
            bound_inputs: Dict[str, Any] = {}
            try:
                sig = inspect.signature(fn)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                bound_inputs = dict(bound.arguments)
            except Exception:  # noqa: BLE001
                pass

            attempt = (existing or {}).get("attempt", 0)
            last_error: Optional[str] = None

            for retry_num in range(max_retries + 1):
                attempt += 1
                _db.upsert_step(
                    step_id=unique_step_id,
                    workflow_id=workflow_id,
                    status="running",
                    inputs=bound_inputs,
                    started_at=time.time(),
                    attempt=attempt,
                )
                try:
                    if inspect.iscoroutinefunction(fn):
                        result = await fn(*args, **kwargs)
                    else:
                        result = fn(*args, **kwargs)
                    _db.upsert_step(
                        step_id=unique_step_id,
                        workflow_id=workflow_id,
                        status="completed",
                        inputs=bound_inputs,
                        outputs=result,
                        completed_at=time.time(),
                        attempt=attempt,
                    )
                    logger.info("durable_step: %s completed (attempt %d)", unique_step_id, attempt)
                    return result
                except Exception as exc:  # noqa: BLE001
                    last_error = str(exc)
                    logger.warning(
                        "durable_step: %s failed attempt %d/%d — %s",
                        unique_step_id,
                        attempt,
                        max_retries + 1,
                        last_error,
                    )
                    _db.upsert_step(
                        step_id=unique_step_id,
                        workflow_id=workflow_id,
                        status="failed",
                        inputs=bound_inputs,
                        error=last_error,
                        completed_at=time.time(),
                        attempt=attempt,
                    )
                    if retry_num < max_retries:
                        delay = _compute_backoff(retry_num, backoff)
                        if delay > 0:
                            await asyncio.sleep(delay)
                    else:
                        raise

            # Should not reach here.
            raise RuntimeError(f"durable_step {unique_step_id} exhausted retries: {last_error}")

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            """Sync variant — runs async_wrapper in a new event loop."""
            return asyncio.run(async_wrapper(*args, **kwargs))

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    if func is not None:
        # Called as @durable_step without arguments.
        return decorator(func)
    return decorator


def durable_workflow(
    func: Optional[Callable] = None,
    *,
    name: Optional[str] = None,
    db: Optional[DurabilityDB] = None,
    db_path: Optional[str] = None,
    resume_from: Optional[str] = None,
) -> Callable:
    """
    Decorator that wraps an async workflow function with durable context.

    All ``@durable_step`` calls made inside the workflow share the same
    ``workflow_id`` and persistence database.  Pass ``resume_from=<step_name>``
    to skip already-completed steps on re-run.
    """

    def decorator(fn: Callable) -> Callable:
        workflow_name = name or fn.__name__

        @functools.wraps(fn)
        async def async_wrapper(
            *args: Any,
            workflow_id: Optional[str] = None,
            resume_from: Optional[str] = resume_from,
            _db: Optional[DurabilityDB] = None,
            **kwargs: Any,
        ) -> Any:
            _wf_id = workflow_id or f"{workflow_name}_{int(time.time() * 1000)}"
            _wf_db = _db or db or DurabilityDB(path=db_path)
            ctx = _WorkflowContext(_wf_id, _wf_db, resume_from=resume_from)
            task_id = _current_task_id()
            _current_workflow[task_id] = ctx
            try:
                if inspect.iscoroutinefunction(fn):
                    return await fn(*args, **kwargs)
                return fn(*args, **kwargs)
            finally:
                _current_workflow.pop(task_id, None)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            return asyncio.run(async_wrapper(*args, **kwargs))

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator


# ── Convenience helpers ───────────────────────────────────────────────────────


def list_workflow_steps(workflow_id: str, db: Optional[DurabilityDB] = None) -> List[Dict[str, Any]]:
    """Return all persisted steps for a workflow, ordered by start time."""
    _db = db or DurabilityDB()
    return _db.list_steps(workflow_id)


def reset_workflow(workflow_id: str, db: Optional[DurabilityDB] = None) -> None:
    """Delete all persisted steps for a workflow so it runs from scratch."""
    _db = db or DurabilityDB()
    _db.delete_workflow(workflow_id)


# Alias for convenience: `DurableStep` is the decorator itself.
DurableStep = durable_step

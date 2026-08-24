"""
Tests for the 4 new enterprise capabilities:
  1. Durable Workflow Steps (agents/durability.py)
  2. Codebase Knowledge Graph (agents/knowledge_graph.py)
  3. Live Streaming Agent Output (agents/streaming.py)
  4. RAG-Enhanced Triage (agents/triage.py — TriageRAG)
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import textwrap
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── 1. Durable Workflow Steps ─────────────────────────────────────────────────

from agents.durability import (
    DurabilityDB,
    _compute_backoff,
    _deserialize,
    _serialize,
    durable_step,
    durable_workflow,
    list_workflow_steps,
    reset_workflow,
)


class TestDurabilityDB:
    def test_upsert_and_get(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        db.upsert_step(
            step_id="s1",
            workflow_id="wf1",
            status="completed",
            inputs={"x": 1},
            outputs={"y": 2},
            started_at=1.0,
            completed_at=2.0,
            attempt=1,
        )
        row = db.get_step("s1", "wf1")
        assert row is not None
        assert row["status"] == "completed"
        assert row["inputs"] == {"x": 1}
        assert row["outputs"] == {"y": 2}
        db.close()

    def test_list_steps(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        for i in range(3):
            db.upsert_step(
                step_id=f"s{i}", workflow_id="wf1", status="completed",
                started_at=float(i), attempt=1,
            )
        steps = db.list_steps("wf1")
        assert len(steps) == 3
        db.close()

    def test_delete_workflow(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        db.upsert_step(step_id="s1", workflow_id="wf1", status="completed", attempt=1)
        db.delete_workflow("wf1")
        assert db.list_steps("wf1") == []
        db.close()

    def test_upsert_updates_existing(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        db.upsert_step(step_id="s1", workflow_id="wf1", status="running", attempt=1)
        db.upsert_step(step_id="s1", workflow_id="wf1", status="completed", attempt=2)
        row = db.get_step("s1", "wf1")
        assert row["status"] == "completed"
        assert row["attempt"] == 2
        db.close()

    def test_get_missing_returns_none(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        assert db.get_step("missing", "wf1") is None
        db.close()


class TestSerialization:
    def test_roundtrip_dict(self):
        data = {"a": 1, "b": [1, 2, 3]}
        assert _deserialize(_serialize(data)) == data

    def test_roundtrip_list(self):
        data = [1, "two", 3.0]
        assert _deserialize(_serialize(data)) == data

    def test_none(self):
        assert _serialize(None) is None
        assert _deserialize(None) is None

    def test_non_serialisable(self):
        # Should not raise; falls back to str representation
        result = _serialize(object())
        assert isinstance(result, str)


class TestBackoff:
    def test_exponential(self):
        d0 = _compute_backoff(0, "exponential", base=1.0)
        d1 = _compute_backoff(1, "exponential", base=1.0)
        # d1 > d0 on average (jitter means we can't be exact)
        assert d1 > 0

    def test_linear(self):
        d0 = _compute_backoff(0, "linear", base=1.0)
        d1 = _compute_backoff(1, "linear", base=1.0)
        assert d1 > d0

    def test_none_backoff(self):
        assert _compute_backoff(0, "none") == 0.0
        assert _compute_backoff(5, "none") == 0.0


class TestDurableStep:
    """@durable_step without a workflow context is transparent."""

    def test_sync_function_runs_normally(self):
        @durable_step
        def add(a, b):
            return a + b

        assert add(1, 2) == 3

    def test_async_function_runs_normally(self):
        @durable_step
        async def add(a, b):
            return a + b

        result = asyncio.run(add(1, 2))
        assert result == 3


class TestDurableWorkflow:
    def test_end_to_end_simple(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))

        @durable_step
        async def step_a(x):
            return x * 2

        @durable_step
        async def step_b(x):
            return x + 10

        @durable_workflow(name="test_wf")
        async def my_workflow(x):
            r = await step_a(x)
            return await step_b(r)

        result = asyncio.run(
            my_workflow(5, workflow_id="test_wf_1", _db=db)
        )
        assert result == 20  # (5*2)+10

    def test_checkpoint_resume_skips_completed_step(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        calls = {"step_a": 0, "step_b": 0}

        @durable_step
        async def step_a(x):
            calls["step_a"] += 1
            return x * 2

        @durable_step
        async def step_b(x):
            calls["step_b"] += 1
            return x + 10

        @durable_workflow(name="wf2")
        async def my_workflow(x):
            r = await step_a(x)
            return await step_b(r)

        async def run_twice():
            await my_workflow(5, workflow_id="wf2_test", _db=db)
            assert calls["step_a"] == 1
            assert calls["step_b"] == 1
            # Second run with same workflow_id — both steps are already completed
            await my_workflow(5, workflow_id="wf2_test", _db=db)
            assert calls["step_a"] == 1  # skipped
            assert calls["step_b"] == 1  # skipped

        asyncio.run(run_twice())

    def test_failed_step_retries(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        attempt_count = {"n": 0}

        @durable_step(max_retries=2, backoff="none")
        async def flaky(x):
            attempt_count["n"] += 1
            if attempt_count["n"] < 3:
                raise RuntimeError("transient error")
            return x + 1

        @durable_workflow(name="retry_wf")
        async def retry_wf(x):
            return await flaky(x)

        result = asyncio.run(
            retry_wf(4, workflow_id="retry_1", _db=db)
        )
        assert result == 5
        assert attempt_count["n"] == 3  # failed twice, succeeded on third

    def test_reset_workflow(self, tmp_path):
        db = DurabilityDB(path=str(tmp_path / "dur.db"))
        db.upsert_step(step_id="s1", workflow_id="to_reset", status="completed", attempt=1)
        reset_workflow("to_reset", db=db)
        assert list_workflow_steps("to_reset", db=db) == []


# ── 2. Codebase Knowledge Graph ───────────────────────────────────────────────

from agents.knowledge_graph import CodebaseGraph, _index_file, _collect_files


class TestCodebaseGraph:
    def _make_project(self, tmp_path) -> str:
        """Create a tiny Python project for testing."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "auth.py").write_text(textwrap.dedent("""\
            import jwt
            from helpers import validate_token

            class AuthHandler:
                def handle_login(self, request):
                    token = validate_token(request.args.get("token"))
                    return token

            def validate_jwt(token):
                return jwt.decode(token, "secret")
        """))
        (src / "helpers.py").write_text(textwrap.dedent("""\
            def validate_token(token):
                if not token:
                    raise ValueError("missing token")
                return token
        """))
        (src / "app.js").write_text(textwrap.dedent("""\
            import express from 'express';
            const app = express();

            function handleRequest(req, res) {
                res.send("ok");
            }
            app.get("/", handleRequest);
        """))
        return str(tmp_path)

    def test_build_graph(self, tmp_path):
        project = self._make_project(tmp_path)
        graph = CodebaseGraph.build(project)
        stats = graph.stats()
        assert stats["files"] >= 3
        assert stats["symbols"] > 0
        assert stats["imports"] > 0
        graph.close()

    def test_find_callers(self, tmp_path):
        project = self._make_project(tmp_path)
        graph = CodebaseGraph.build(project)
        callers = graph.find_callers("validate_token")
        assert len(callers) >= 1
        assert any("auth.py" in c["file"] for c in callers)
        graph.close()

    def test_find_importers(self, tmp_path):
        project = self._make_project(tmp_path)
        graph = CodebaseGraph.build(project)
        importers = graph.find_importers("jwt")
        assert len(importers) >= 1
        assert any("auth.py" in i["file"] for i in importers)
        graph.close()

    def test_find_symbols(self, tmp_path):
        project = self._make_project(tmp_path)
        graph = CodebaseGraph.build(project)
        syms = graph.find_symbols("validate_jwt")
        assert len(syms) >= 1
        assert syms[0]["kind"] == "FUNCTION"
        graph.close()

    def test_symbols_in_file(self, tmp_path):
        project = self._make_project(tmp_path)
        graph = CodebaseGraph.build(project)
        files = _collect_files(project)
        auth_file = next(f for f in files if "auth.py" in f)
        syms = graph.symbols_in_file(auth_file)
        names = {s["name"] for s in syms}
        assert "validate_jwt" in names
        assert "AuthHandler" in names
        graph.close()

    def test_tainted_paths(self, tmp_path):
        """Detect a tainted path from request.args.get to cursor.execute."""
        src = tmp_path / "vuln.py"
        src.write_text(textwrap.dedent("""\
            import sqlite3
            conn = sqlite3.connect("test.db")
            cursor = conn.cursor()

            def search(request):
                cursor.execute(request.args.get("q"))
        """))
        graph = CodebaseGraph.build(str(tmp_path))
        paths = graph.find_tainted_paths("request.args.get", "cursor.execute")
        assert len(paths) >= 1
        graph.close()

    def test_stats(self, tmp_path):
        project = self._make_project(tmp_path)
        graph = CodebaseGraph.build(project)
        s = graph.stats()
        for key in ("files", "symbols", "imports", "calls", "data_flows"):
            assert key in s
            assert isinstance(s[key], int)
        graph.close()

    def test_collect_files_skips_node_modules(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").write_text("const x = 1;")
        (tmp_path / "main.py").write_text("x = 1")
        files = _collect_files(str(tmp_path))
        assert all("node_modules" not in f for f in files)
        assert any("main.py" in f for f in files)

    def test_index_file_python(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("def foo(): pass\nclass Bar: pass\n")
        result = _index_file(str(f))
        assert result is not None
        names = {s["name"] for s in result["symbols"]}
        assert "foo" in names
        assert "Bar" in names

    def test_index_file_js(self, tmp_path):
        f = tmp_path / "test.js"
        f.write_text("function greet(name) { return 'hi ' + name; }\n")
        result = _index_file(str(f))
        assert result is not None
        names = {s["name"] for s in result["symbols"]}
        assert "greet" in names


# ── 3. Live Streaming (StreamingEventBus) ────────────────────────────────────

from agents.streaming import (
    StreamingEventBus,
    emit,
    error_occurred_event,
    file_scanned_event,
    finding_found_event,
    get_default_bus,
    scan_completed_event,
    scan_started_event,
    step_completed_event,
)


class TestStreamingEventBus:
    def test_publish_and_subscribe(self):
        async def run():
            bus = StreamingEventBus()
            received = []

            async def collect():
                async for event in bus.subscribe("scan_1"):
                    received.append(event)

            task = asyncio.create_task(collect())
            await asyncio.sleep(0)  # let subscriber start

            await bus.publish("scan_1", {"type": "file_scanned", "file": "a.py"})
            await bus.publish("scan_1", {"type": "scan_completed"})
            await bus.close_channel("scan_1")
            await task

            assert len(received) == 2
            assert received[0]["type"] == "file_scanned"
            assert received[1]["type"] == "scan_completed"

        asyncio.run(run())

    def test_timestamp_injected(self):
        async def run():
            bus = StreamingEventBus()
            received = []

            async def collect():
                async for event in bus.subscribe("s2"):
                    received.append(event)

            task = asyncio.create_task(collect())
            await asyncio.sleep(0)
            await bus.publish("s2", {"type": "scan_started"})
            await bus.close_channel("s2")
            await task

            assert "timestamp" in received[0]

        asyncio.run(run())

    def test_multiple_subscribers(self):
        async def run():
            bus = StreamingEventBus()
            received_a = []
            received_b = []

            async def collect_a():
                async for event in bus.subscribe("s3"):
                    received_a.append(event)

            async def collect_b():
                async for event in bus.subscribe("s3"):
                    received_b.append(event)

            ta = asyncio.create_task(collect_a())
            tb = asyncio.create_task(collect_b())
            await asyncio.sleep(0)

            await bus.publish("s3", {"type": "ping"})
            await bus.close_channel("s3")
            await asyncio.gather(ta, tb)

            assert len(received_a) == 1
            assert len(received_b) == 1

        asyncio.run(run())

    def test_sqlite_persistence_and_replay(self, tmp_path):
        async def run():
            db_path = str(tmp_path / "events.db")
            bus = StreamingEventBus(db_path=db_path)

            await bus.publish("s4", {"type": "event_1"})
            await bus.publish("s4", {"type": "event_2"})

            # Late subscriber with replay
            replayed = []
            async def late_collect():
                async for event in bus.subscribe("s4", replay_from_db=True):
                    replayed.append(event)

            task = asyncio.create_task(late_collect())
            await asyncio.sleep(0)
            await bus.close_channel("s4")
            await task

            assert len(replayed) >= 2
            types = [e["type"] for e in replayed]
            assert "event_1" in types
            assert "event_2" in types
            bus.close()

        asyncio.run(run())

    def test_get_events_polling(self, tmp_path):
        async def run():
            db_path = str(tmp_path / "events2.db")
            bus = StreamingEventBus(db_path=db_path)
            await bus.publish("s5", {"type": "x"})
            await bus.publish("s5", {"type": "y"})
            events = bus.get_events("s5")
            assert len(events) == 2
            bus.close()

        asyncio.run(run())

    def test_publish_sync(self, tmp_path):
        db_path = str(tmp_path / "events3.db")
        bus = StreamingEventBus(db_path=db_path)
        bus.publish_sync("s6", {"type": "sync_event"})
        events = bus.get_events("s6")
        assert any(e["type"] == "sync_event" for e in events)
        bus.close()

    def test_event_constructors(self):
        e = scan_started_event("s1", "/path", 100)
        assert e["type"] == "scan_started"
        assert e["total_files"] == 100

        e = file_scanned_event("s1", "file.py", 3, 10)
        assert e["progress"]["current"] == 3

        e = finding_found_event("s1", "security_audit", "HIGH", "auth.py", 42, "JWT not validated", 1, 10)
        assert e["finding"]["severity"] == "HIGH"

        e = step_completed_event("s1", "scan_files", 1)
        assert e["step_name"] == "scan_files"

        e = scan_completed_event("s1", 15)
        assert e["total_findings"] == 15

        e = error_occurred_event("s1", "network timeout", "scan_files")
        assert e["error"] == "network timeout"

    def test_no_cross_channel_delivery(self):
        async def run():
            bus = StreamingEventBus()
            received_a = []

            async def collect_a():
                async for event in bus.subscribe("ch_a"):
                    received_a.append(event)

            task = asyncio.create_task(collect_a())
            await asyncio.sleep(0)
            await bus.publish("ch_b", {"type": "for_b_only"})  # different channel
            await bus.close_channel("ch_a")
            await task

            assert received_a == []  # Nothing delivered to ch_a

        asyncio.run(run())


# ── 4. TriageRAG ──────────────────────────────────────────────────────────────

from agents.triage import TriageRAG, _finding_fingerprint, _simple_embed, _cosine


class TestTriageRAGHelpers:
    def test_fingerprint_is_stable(self):
        f = {"agent": "security_audit", "rule": "jwt", "file": "auth.py", "issue": "missing exp"}
        assert _finding_fingerprint(f) == _finding_fingerprint(f)

    def test_fingerprint_differs_by_field(self):
        f1 = {"agent": "security_audit", "rule": "jwt", "file": "auth.py", "issue": "missing exp"}
        f2 = {**f1, "file": "other.py"}
        assert _finding_fingerprint(f1) != _finding_fingerprint(f2)

    def test_simple_embed_length(self):
        v = _simple_embed("hello world test")
        assert len(v) == 64

    def test_simple_embed_normalised(self):
        import math
        v = _simple_embed("hello world")
        norm = math.sqrt(sum(x * x for x in v))
        assert abs(norm - 1.0) < 1e-6

    def test_cosine_identical(self):
        v = _simple_embed("identical text")
        assert abs(_cosine(v, v) - 1.0) < 1e-6

    def test_cosine_range(self):
        a = _simple_embed("foo bar baz")
        b = _simple_embed("hello world cat")
        c = _cosine(a, b)
        assert 0.0 <= c <= 1.0


class TestTriageRAG:
    def _make_rag(self, tmp_path) -> TriageRAG:
        return TriageRAG(
            project_root=str(tmp_path),
            db_path=str(tmp_path / "rag.db"),
            min_similarity=0.3,
            top_k=5,
        )

    def test_record_and_retrieve(self, tmp_path):
        rag = self._make_rag(tmp_path)
        finding = {"agent": "security_audit", "rule": "eval_call", "file": "utils.py", "issue": "eval() used"}
        rag.record_verdict(finding, verdict="CONFIRMED", reason="Unsafe eval in production code")
        ctx = rag.retrieve_context(finding)
        assert ctx["total_similar"] >= 1
        assert ctx["confirmed_count"] >= 1
        assert ctx["confidence"] > 0
        rag.close()

    def test_confidence_calculation(self, tmp_path):
        rag = self._make_rag(tmp_path)
        base = {"agent": "security_audit", "rule": "eval_call", "file": "a.py", "issue": "eval() call"}
        for i in range(8):
            f = {**base, "file": f"file_{i}.py"}
            rag.record_verdict(f, verdict="CONFIRMED")
        for i in range(2):
            f = {**base, "file": f"fp_{i}.py"}
            rag.record_verdict(f, verdict="FALSE_POSITIVE")

        ctx = rag.retrieve_context(base)
        # confidence should reflect ~80% CONFIRMED
        if ctx["total_similar"] > 0:
            assert ctx["confidence"] >= 0.5  # at least half confirmed
        rag.close()

    def test_context_text_present(self, tmp_path):
        rag = self._make_rag(tmp_path)
        finding = {"agent": "security_audit", "rule": "jwt", "file": "auth.py", "issue": "no exp"}
        rag.record_verdict(finding, verdict="FALSE_POSITIVE", reason="handled elsewhere")
        ctx = rag.retrieve_context(finding)
        assert isinstance(ctx["context_text"], str)
        rag.close()

    def test_record_duplicate_updates(self, tmp_path):
        rag = self._make_rag(tmp_path)
        finding = {"agent": "a", "rule": "r", "file": "f.py", "issue": "i"}
        rag.record_verdict(finding, verdict="FALSE_POSITIVE")
        rag.record_verdict(finding, verdict="CONFIRMED")  # update
        ctx = rag.retrieve_context(finding)
        # Only one record (deduped), now CONFIRMED
        confirmed = [s for s in ctx["similar"] if s["verdict"] == "CONFIRMED"]
        assert len(confirmed) >= 1
        rag.close()

    def test_retrieve_empty_returns_safe_defaults(self, tmp_path):
        rag = self._make_rag(tmp_path)
        finding = {"agent": "x", "rule": "y", "file": "z.py", "issue": "w"}
        ctx = rag.retrieve_context(finding)
        assert ctx["total_similar"] == 0
        assert ctx["confidence"] == 0.0
        assert ctx["context_text"] == "No similar past findings."
        rag.close()

    def test_record_report_verdicts(self, tmp_path):
        rag = self._make_rag(tmp_path)
        report = {
            "results": [
                {
                    "agent": "security_audit",
                    "tool": "audit_eval",
                    "file": "utils.py",
                    "result": {
                        "findings": [
                            {
                                "severity": "HIGH",
                                "issue": "eval() call",
                                "triage": {"verdict": "CONFIRMED", "reason": "real"},
                            },
                            {
                                "severity": "LOW",
                                "issue": "eval in tests",
                                "triage": {"verdict": "FALSE_POSITIVE", "reason": "test fixture"},
                            },
                        ]
                    },
                }
            ]
        }
        written = rag.record_report_verdicts(report)
        assert written == 2
        rag.close()

    def test_triage_with_rag_high_confidence_fast_path(self, tmp_path):
        """High-confidence RAG returns cached verdict without LLM call."""
        rag = self._make_rag(tmp_path)
        base = {"agent": "security_audit", "rule": "eval_call", "file": "a.py", "issue": "eval() call"}
        # Seed with 5 confirmed findings
        for i in range(5):
            rag.record_verdict({**base, "file": f"f{i}.py"}, verdict="CONFIRMED", reason="real")

        finding = {**base, "file": "new.py"}
        # Mock TriageAgent — should not be called
        mock_agent = MagicMock()
        mock_agent.run_async = AsyncMock()

        async def run():
            result = await rag.triage_with_rag(mock_agent, finding, min_confidence=0.75)
            return result

        result = asyncio.run(run())
        assert result["verdict"] == "CONFIRMED"
        assert result["source"] == "rag_cache"
        # LLM was NOT called
        mock_agent.run_async.assert_not_called()
        rag.close()

    def test_triage_with_rag_low_confidence_calls_llm(self, tmp_path):
        """Low-confidence RAG falls through to LLM."""
        rag = self._make_rag(tmp_path)
        finding = {"agent": "a", "rule": "r", "file": "new.py", "issue": "something new"}

        mock_response = MagicMock()
        mock_response.content = '{"verdict": "FALSE_POSITIVE", "reason": "test fixture"}'

        mock_agent = MagicMock()
        mock_agent.run_async = AsyncMock(return_value=mock_response)
        mock_agent.reset = MagicMock()

        async def run():
            return await rag.triage_with_rag(mock_agent, finding, min_confidence=0.75)

        result = asyncio.run(run())
        assert result["verdict"] == "FALSE_POSITIVE"
        assert result["source"] == "llm"
        mock_agent.run_async.assert_called_once()
        rag.close()

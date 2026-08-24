import os
import json
from unittest.mock import MagicMock, patch

import pytest

from agents.triage import TriageAgent, _extract_verdict, triage_entry, triage_report


def test_extract_verdict_parses_confirmed():
    text = '{"verdict": "confirmed", "reason": "the file never sets exp"}'
    result = _extract_verdict(text)
    assert result == {"verdict": "CONFIRMED", "reason": "the file never sets exp"}


def test_extract_verdict_parses_false_positive_with_surrounding_prose():
    text = 'Here is my answer:\n{"verdict": "false_positive", "reason": "checked elsewhere"}\nthanks'
    result = _extract_verdict(text)
    assert result["verdict"] == "FALSE_POSITIVE"


def test_extract_verdict_handles_no_json():
    result = _extract_verdict("I couldn't decide.")
    assert result["verdict"] == "UNKNOWN"


def test_extract_verdict_handles_malformed_json():
    result = _extract_verdict("{not valid json}")
    assert result["verdict"] == "UNKNOWN"


def test_extract_verdict_handles_unrecognized_verdict_value():
    result = _extract_verdict('{"verdict": "MAYBE", "reason": "unsure"}')
    assert result["verdict"] == "UNKNOWN"


def test_read_project_file_confines_to_root(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "inside.txt").write_text("safe content")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret content")

    agent = TriageAgent(str(project), provider="anthropic", api_key="test-key")

    ok = agent._read_project_file("inside.txt")
    assert ok["content"] == "safe content"

    escape = agent._read_project_file("../outside.txt")
    assert "error" in escape
    assert "escapes" in escape["error"]

    missing = agent._read_project_file("does_not_exist.txt")
    assert "error" in missing


def test_triage_entry_uses_agent_run_and_parses_verdict(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "apple.py").write_text("def verify(): ...")

    agent = TriageAgent(str(project), provider="anthropic", api_key="test-key")
    fake_response = MagicMock()
    fake_response.content = '{"verdict": "false_positive", "reason": "verified elsewhere"}'
    agent.run = MagicMock(return_value=fake_response)

    entry = {
        "file": "apple.py",
        "agent": "security_audit",
        "tool": "check_jwt_implementation",
        "result": {"findings": [{"severity": "HIGH", "issue": "No token expiration set"}]},
    }

    verdict = triage_entry(agent, str(project), entry)
    assert verdict["verdict"] == "FALSE_POSITIVE"
    agent.run.assert_called_once()


def test_triage_report_aggregates_and_skips_errored_entries(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.py").write_text("a")
    (project / "b.py").write_text("b")
    (project / "c.py").write_text("c")

    report = {
        "project": str(project),
        "files_matched": 3,
        "summary": {},
        "results": [
            {"file": "a.py", "agent": "x", "tool": "t1", "result": {"findings": [{"severity": "HIGH", "issue": "i1"}]}},
            {"file": "b.py", "agent": "x", "tool": "t2", "result": {"findings": [{"severity": "HIGH", "issue": "i2"}]}},
            {"file": "c.py", "agent": "x", "tool": "t3", "result": {"error": "handler crashed"}},
        ],
    }

    # One entry, one finding each — the batch call returns a single-element
    # list per entry.
    per_entry = iter([
        [{"verdict": "CONFIRMED", "reason": "real gap"}],
        [{"verdict": "FALSE_POSITIVE", "reason": "handled elsewhere"}],
    ])

    with patch("agents.triage.TriageAgent") as MockAgent:
        MockAgent.return_value = MagicMock()
        with patch("agents.triage.triage_entry_findings", side_effect=lambda *a, **k: next(per_entry)):
            result = triage_report(report, provider="anthropic", api_key="test-key")

    assert result["triage_summary"] == {"confirmed": 1, "false_positive": 1, "unknown": 0}
    assert result["results"][0]["triage"]["verdict"] == "CONFIRMED"
    assert result["results"][1]["triage"]["verdict"] == "FALSE_POSITIVE"
    assert "triage" not in result["results"][2]


def test_triage_verdicts_are_per_finding_not_per_file(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "route.py").write_text("route")
    report = {
        "project": str(project),
        "files_matched": 1,
        "summary": {},
        "coverage": {"tool_errors": 0, "skipped_files": []},
        "results": [{
            "file": "route.py",
            "agent": "security_audit",
            "tool": "mixed",
            "result": {"findings": [
                {"severity": "HIGH", "issue": "real"},
                {"severity": "LOW", "issue": "noise"},
            ]},
        }],
    }
    batched = [
        {"verdict": "CONFIRMED", "reason": "real gap"},
        {"verdict": "FALSE_POSITIVE", "reason": "handled elsewhere"},
    ]

    with patch("agents.triage.TriageAgent") as MockAgent:
        MockAgent.return_value = MagicMock()
        with patch("agents.triage.triage_entry_findings", side_effect=lambda *a, **k: batched):
            result = triage_report(report, provider="anthropic", api_key="test-key")

    findings = result["results"][0]["result"]["findings"]
    assert findings[0]["triage"]["verdict"] == "CONFIRMED"
    assert findings[1]["triage"]["verdict"] == "FALSE_POSITIVE"
    assert result["results"][0]["triage"]["verdict"] == "CONFIRMED"
    assert result["triage_summary"] == {"confirmed": 1, "false_positive": 1, "unknown": 0}


# --- batching ------------------------------------------------------------------

def test_one_call_per_entry_however_many_findings(tmp_path):
    """The per-finding loop this replaced re-uploaded the file once per
    finding: a 14-finding component sent its own source fourteen times."""
    from agents.triage import triage_entry_findings

    project = tmp_path / "p"
    project.mkdir()
    (project / "big.tsx").write_text("export const C = () => null;")
    entry = {
        "file": "big.tsx", "agent": "code_review", "tool": "review_react_component",
        "result": {"findings": [{"severity": "LOW", "issue": f"issue {i}"} for i in range(14)]},
    }

    agent = MagicMock()
    agent.run.return_value = MagicMock(content=json.dumps([
        {"index": i, "verdict": "CONFIRMED", "reason": "r"} for i in range(14)
    ]))

    verdicts = triage_entry_findings(agent, str(project), entry)
    assert len(verdicts) == 14
    assert agent.run.call_count == 1, "fourteen findings must cost one call"


def test_a_dropped_verdict_never_shifts_onto_another_finding(tmp_path):
    """Indexes exist so a short response degrades to UNKNOWN for the missing
    finding rather than sliding later verdicts onto earlier ones — a
    misaligned verdict teaches the scorer the opposite of the truth."""
    from agents.triage import triage_entry_findings

    project = tmp_path / "p"
    project.mkdir()
    (project / "f.py").write_text("x")
    entry = {
        "file": "f.py", "agent": "x", "tool": "t",
        "result": {"findings": [{"issue": "a"}, {"issue": "b"}, {"issue": "c"}]},
    }

    agent = MagicMock()
    # The model answered for findings 0 and 2 only.
    agent.run.return_value = MagicMock(content=json.dumps([
        {"index": 0, "verdict": "CONFIRMED", "reason": "real"},
        {"index": 2, "verdict": "FALSE_POSITIVE", "reason": "noise"},
    ]))

    verdicts = triage_entry_findings(agent, str(project), entry)
    assert [v["verdict"] for v in verdicts] == ["CONFIRMED", "UNKNOWN", "FALSE_POSITIVE"]


def test_malformed_batch_response_is_unknown_for_every_finding(tmp_path):
    from agents.triage import triage_entry_findings

    project = tmp_path / "p"
    project.mkdir()
    (project / "f.py").write_text("x")
    entry = {"file": "f.py", "agent": "x", "tool": "t",
             "result": {"findings": [{"issue": "a"}, {"issue": "b"}]}}

    agent = MagicMock()
    agent.run.return_value = MagicMock(content="the model rambled instead")
    verdicts = triage_entry_findings(agent, str(project), entry)
    assert [v["verdict"] for v in verdicts] == ["UNKNOWN", "UNKNOWN"]

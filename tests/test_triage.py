import os
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

    verdicts = iter([
        {"verdict": "CONFIRMED", "reason": "real gap"},
        {"verdict": "FALSE_POSITIVE", "reason": "handled elsewhere"},
    ])

    with patch("agents.triage.TriageAgent") as MockAgent:
        MockAgent.return_value = MagicMock()
        with patch("agents.triage.triage_entry", side_effect=lambda *a, **k: next(verdicts)):
            result = triage_report(report, provider="anthropic", api_key="test-key")

    assert result["triage_summary"] == {"confirmed": 1, "false_positive": 1, "unknown": 0}
    assert result["results"][0]["triage"]["verdict"] == "CONFIRMED"
    assert result["results"][1]["triage"]["verdict"] == "FALSE_POSITIVE"
    assert "triage" not in result["results"][2]

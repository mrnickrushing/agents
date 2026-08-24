"""Per-rule precision and the trust demotion — the scanner earning belief.

The design rule under test: a rule that measured verdicts show to be mostly
wrong keeps running, but its findings stop spending HIGH-severity attention
until it earns it back. And precision over a handful of verdicts is noise,
not a measurement — unscored rules are never demoted.
"""

import json
import os

import pytest

from agents.cli import TRUST_MIN_VERDICTS, TRUST_THRESHOLD, load_rule_trust, rule_precision
from agents.evolution import EvolutionStore


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "evolution.db")


def _seed(db_path, rule_tool, verdicts):
    """Record one finding per verdict for agent 'security_audit'."""
    with EvolutionStore(db_path) as store:
        report = {
            "project": "/tmp/proj",
            "project_key": "proj",
            "results": [{
                "file": f"f{i}.py", "agent": "security_audit", "tool": rule_tool,
                "source_hash": "h" * 40,
                "result": {"findings": [{"severity": "HIGH", "issue": f"issue {i}"}]},
            } for i in range(len(verdicts))],
        }
        store.record_scan(report, detector_version="test")   # attaches finding ids
        for entry, verdict in zip(report["results"], verdicts):
            fid = entry["result"]["findings"][0]["finding_id"]
            store.add_feedback(fid, verdict, "test")


def test_precision_groups_by_rule_and_counts_verdicts(db):
    _seed(db, "audit_xss_patterns", ["CONFIRMED", "CONFIRMED", "FALSE_POSITIVE"])
    rows = rule_precision(db)
    assert len(rows) == 1
    r = rows[0]
    assert r["rule"] == "security_audit.audit_xss_patterns"
    assert r["confirmed"] == 2 and r["false_positive"] == 1
    assert r["precision"] == pytest.approx(2 / 3)


def test_too_few_verdicts_are_not_scored(db):
    _seed(db, "audit_xss_patterns", ["FALSE_POSITIVE"] * (TRUST_MIN_VERDICTS - 1))
    rows = rule_precision(db)
    assert rows[0]["scored"] is False


def test_enough_verdicts_score(db):
    _seed(db, "audit_xss_patterns", ["FALSE_POSITIVE"] * TRUST_MIN_VERDICTS)
    rows = rule_precision(db)
    assert rows[0]["scored"] is True
    assert rows[0]["precision"] == 0.0
    assert rows[0]["precision"] < TRUST_THRESHOLD


def test_load_rule_trust_missing_file_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTS_STATE_DIR", str(tmp_path / "nowhere"))
    assert load_rule_trust() == {}


def test_scan_demotes_findings_of_untrusted_rules(tmp_path, monkeypatch):
    """End to end: a trust file naming a rule turns its findings INFO, keeps
    the original severity visible, and says why."""
    state = tmp_path / "state"
    state.mkdir()
    (state / "rule_trust.json").write_text(json.dumps({
        "demoted": {"config_audit.audit_dockerfile": 0.2},
    }))
    monkeypatch.setenv("AGENTS_STATE_DIR", str(state))
    # Also point the evolution DB somewhere disposable.
    monkeypatch.setenv("AGENTS_EVOLUTION_DB", str(tmp_path / "evo.db"))

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text("FROM python:3.13-slim\nCMD ['x']\n")   # rootful

    from agents.cli import _run_scan
    report = _run_scan(str(proj), ["config_audit"])
    findings = [
        f for entry in report["results"]
        for f in entry.get("result", {}).get("findings", [])
    ]
    assert findings, "the rootful Dockerfile should still be found"
    for f in findings:
        assert f["severity"] == "INFO"
        assert f["pre_demotion_severity"] == "HIGH"
        assert "precision 20%" in f["demoted"]


def test_scan_untouched_when_no_trust_file(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENTS_EVOLUTION_DB", str(tmp_path / "evo.db"))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text("FROM python:3.13-slim\nCMD ['x']\n")

    from agents.cli import _run_scan
    report = _run_scan(str(proj), ["config_audit"])
    sevs = {
        f["severity"] for entry in report["results"]
        for f in entry.get("result", {}).get("findings", [])
    }
    assert "HIGH" in sevs

"""Per-rule precision and the trust demotion — the scanner earning belief.

The design rule under test: a rule that measured verdicts show to be mostly
wrong keeps running, but its findings stop spending HIGH-severity attention
until it earns it back. And precision over a handful of verdicts is noise,
not a measurement — unscored rules are never demoted.
"""

import json

import pytest

from agents.cli import (
    TRUST_MIN_VERDICTS,
    TRUST_THRESHOLD,
    load_rule_trust,
    rule_precision,
)
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
            "results": [
                {
                    "file": f"f{i}.py",
                    "agent": "security_audit",
                    "tool": rule_tool,
                    "source_hash": "h" * 40,
                    "result": {
                        "findings": [{"severity": "HIGH", "issue": f"issue {i}"}]
                    },
                }
                for i in range(len(verdicts))
            ],
        }
        store.record_scan(report, detector_version="test")  # attaches finding ids
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
    (state / "rule_trust.json").write_text(
        json.dumps(
            {
                "demoted": {"config_audit.audit_dockerfile": 0.2},
            }
        )
    )
    monkeypatch.setenv("AGENTS_STATE_DIR", str(state))
    # Also point the evolution DB somewhere disposable.
    monkeypatch.setenv("AGENTS_EVOLUTION_DB", str(tmp_path / "evo.db"))

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text("FROM python:3.13-slim\nCMD ['x']\n")  # rootful

    from agents.cli import _run_scan

    report = _run_scan(str(proj), ["config_audit"])
    findings = [
        f
        for entry in report["results"]
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
        f["severity"]
        for entry in report["results"]
        for f in entry.get("result", {}).get("findings", [])
    }
    assert "HIGH" in sevs


def test_a_verdict_is_counted_once_however_many_scans_recorded_the_finding(db):
    """findings carries one row per (finding, scan). The obvious join
    multiplies every verdict by the rescan count — two real verdicts read as
    twelve after six scans, enough to push a rule past the scoring threshold
    and demote it on a single opinion. Caught by noticing a rule claimed 12
    verdicts while the feedback table held 2.
    """
    from agents.evolution import EvolutionStore

    report = {
        "project": "/tmp/proj",
        "project_key": "proj",
        "results": [
            {
                "file": "a.py",
                "agent": "security_audit",
                "tool": "audit_xss_patterns",
                "source_hash": "h" * 40,
                "result": {"findings": [{"severity": "HIGH", "issue": "same finding"}]},
            }
        ],
    }
    with EvolutionStore(db) as store:
        # The identical finding, recorded by six separate scans.
        for _ in range(6):
            import copy

            store.record_scan(copy.deepcopy(report), detector_version="test")
        fid = store.connection.execute(
            "SELECT finding_id FROM findings LIMIT 1"
        ).fetchone()["finding_id"]
        store.add_feedback(fid, "FALSE_POSITIVE", "one human opinion")

    rows = rule_precision(db)
    assert len(rows) == 1
    r = rows[0]
    assert r["verdicts"] == 1, f"one verdict, six scans — got {r['verdicts']}"
    assert r["false_positive"] == 1
    assert r["scored"] is False, "a single opinion must never be enough to demote"


def test_any_confirmed_wins_over_earlier_dismissals(db):
    """Resolution matches evolution.py: confirming something once settles it."""
    from agents.evolution import EvolutionStore

    report = {
        "project": "/tmp/proj",
        "project_key": "proj",
        "results": [
            {
                "file": "a.py",
                "agent": "security_audit",
                "tool": "audit_sql_injection",
                "source_hash": "h" * 40,
                "result": {"findings": [{"severity": "HIGH", "issue": "x"}]},
            }
        ],
    }
    with EvolutionStore(db) as store:
        store.record_scan(report, detector_version="test")
        fid = report["results"][0]["result"]["findings"][0]["finding_id"]
        store.add_feedback(fid, "FALSE_POSITIVE", "dismissed first")
        store.add_feedback(fid, "CONFIRMED", "then confirmed")

    r = rule_precision(db)[0]
    assert r["confirmed"] == 1 and r["false_positive"] == 0

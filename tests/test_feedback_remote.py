"""Verdicts recorded from the dashboard or the CLI: they hide dismissed
findings, keep the attention counts honest, and are remembered by future
scans through the evolution store."""

import subprocess
import sys
import threading
from wsgiref.simple_server import make_server

import pytest

pytest.importorskip("flask")

from agents.server import create_app, record_webhook_result  # noqa: E402

TOKEN = "tok"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _seed(db):
    findings = [
        {
            "severity": "HIGH",
            "issue": "OAuth flow has no visible state parameter validation",
            "fix": "x",
            "file": "a.tsx",
            "line": 1,
        },
        {
            "severity": "LOW",
            "issue": "Upload flow has no visible malware scanning step",
            "fix": "y",
            "file": "b.tsx",
            "line": 2,
        },
    ]
    record_webhook_result(
        db,
        {"action": "scanned", "repo": "nick/app", "pr_number": 1, "findings": findings},
    )


@pytest.fixture
def app(tmp_path):
    db = str(tmp_path / "evolution.db")
    _seed(db)
    return create_app(db_path=db, webhook_secret="", dashboard_token=TOKEN)


def test_dismissing_hides_the_finding_and_fixes_the_counts(app):
    client = app.test_client()
    rows = client.get("/api/findings", headers=AUTH).get_json()["findings"]
    assert {r["verdict"] for r in rows} == {None}
    high = next(r for r in rows if r["severity"] == "HIGH")
    before = client.get("/api/summary", headers=AUTH).get_json()
    assert before["by_severity"] == {"HIGH": 1, "LOW": 1} and before["dismissed"] == 0

    r = client.post(
        "/api/feedback",
        json={
            "finding_id": high["finding_id"],
            "verdict": "dismiss",
            "reason": "useCallback, not OAuth",
        },
        headers=AUTH,
    )
    assert r.status_code == 200
    assert r.get_json()["verdict"] == "FALSE_POSITIVE"
    assert r.get_json()["by"] == "token"

    after = client.get("/api/summary", headers=AUTH).get_json()
    assert after["by_severity"] == {"LOW": 1} and after["dismissed"] == 1
    rows = client.get("/api/findings", headers=AUTH).get_json()["findings"]
    dismissed = next(r for r in rows if r["finding_id"] == high["finding_id"])
    assert dismissed["verdict"] == "FALSE_POSITIVE"
    assert dismissed["verdict_reason"] == "useCallback, not OAuth"
    assert dismissed["verdict_source"] == "human"


def test_feedback_validation(app):
    client = app.test_client()
    assert client.post("/api/feedback", json={}, headers=AUTH).status_code == 400
    assert (
        client.post(
            "/api/feedback",
            json={"finding_id": "agf_nope", "verdict": "dismiss", "reason": "r"},
            headers=AUTH,
        ).status_code
        == 404
    )
    rows = client.get("/api/findings", headers=AUTH).get_json()["findings"]
    assert (
        client.post(
            "/api/feedback",
            json={
                "finding_id": rows[0]["finding_id"],
                "verdict": "maybe",
                "reason": "r",
            },
            headers=AUTH,
        ).status_code
        == 400
    )
    assert client.post("/api/feedback", json={}).status_code == 401


def test_cli_remote_feedback_records_a_verdict(app):
    server = make_server("127.0.0.1", 0, app)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = app.test_client()
        rows = client.get("/api/findings", headers=AUTH).get_json()["findings"]
        target = rows[0]["finding_id"]
        out = subprocess.run(
            [
                sys.executable,
                "-m",
                "agents.cli",
                "remote-feedback",
                target,
                "confirm",
                "--reason",
                "real",
                "--url",
                f"http://127.0.0.1:{port}",
                "--token",
                TOKEN,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert out.returncode == 0, out.stderr
        assert out.stdout.startswith(f"CONFIRMED {target}")
        rows = client.get("/api/findings", headers=AUTH).get_json()["findings"]
        assert (
            next(r for r in rows if r["finding_id"] == target)["verdict"] == "CONFIRMED"
        )
    finally:
        server.shutdown()

"""The hosted service: health/readiness, webhook wiring, and the dashboard
reading the evolution store's real schema."""

import hashlib
import hmac
import json

import pytest

pytest.importorskip("flask")

from agents.evolution import EvolutionStore  # noqa: E402
from agents.server import create_app, record_webhook_result  # noqa: E402
from agents.web import AgentsDashboard  # noqa: E402

SECRET = "webhook-test-secret"
LEAKED_KEY = "q7Xv93LmZp2RtK8wYb4NcJ6HsD1fG0aE"


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


def _pr_payload(body_text: str) -> dict:
    return {
        "action": "opened",
        "pull_request": {
            "number": 7,
            "body": body_text,
            "head": {"sha": "abc123"},
        },
        "repository": {"full_name": "mrnickrushing/example"},
    }


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    return create_app(
        db_path=str(tmp_path / "state" / "evolution.db"), webhook_secret=SECRET
    )


def test_health_and_ready(app):
    client = app.test_client()
    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json()["status"] == "ok"
    assert health.get_json()["version"]

    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.get_json()["status"] == "ready"


def test_ready_reports_unusable_database(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    app = create_app(db_path=str(blocker / "evolution.db"), webhook_secret=SECRET)
    response = app.test_client().get("/ready")
    assert response.status_code == 503
    assert response.get_json()["status"] == "unavailable"


def test_webhook_unconfigured_returns_503(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    app = create_app(db_path=str(tmp_path / "evolution.db"), webhook_secret="")
    response = app.test_client().post("/webhook", data=b"{}")
    assert response.status_code == 503
    assert "GITHUB_WEBHOOK_SECRET" in response.get_json()["error"]


def test_webhook_rejects_bad_signature(app):
    body = json.dumps(_pr_payload("hello")).encode()
    response = app.test_client().post(
        "/webhook",
        data=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": "sha256=deadbeef",
        },
    )
    assert response.status_code == 401


def test_webhook_scan_lands_in_dashboard(app):
    client = app.test_client()
    body = json.dumps(_pr_payload(f'api_key = "{LEAKED_KEY}"')).encode()
    response = client.post(
        "/webhook",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-1",
            "X-Hub-Signature-256": _sign(body),
        },
    )
    assert response.status_code == 200
    result = response.get_json()
    assert result["action"] == "scanned"
    assert result["findings_count"] >= 1
    assert result["recorded"] is True
    assert result["scan_id"].startswith("ags_")
    # No GITHUB_TOKEN in the test environment, so nothing is posted upstream.
    assert result["summary_comment_posted"] is False

    summary = client.get("/api/summary").get_json()
    assert summary["total_scans"] == 1
    assert summary["total_findings"] >= 1

    findings = client.get("/api/findings").get_json()["findings"]
    assert findings
    assert findings[0]["file_path"] == "pull/7.diff"
    assert findings[0]["detector"] == "security_audit.audit_hardcoded_secrets"
    assert findings[0]["project"] == "/github/mrnickrushing/example"
    assert findings[0]["scanned_at"]

    # Redelivery of the same GitHub delivery id is acknowledged, not re-scanned.
    duplicate = client.post(
        "/webhook",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-1",
            "X-Hub-Signature-256": _sign(body),
        },
    )
    assert duplicate.get_json()["action"] == "duplicate"
    assert client.get("/api/summary").get_json()["total_scans"] == 1


def test_record_webhook_result_ignores_non_scans(tmp_path):
    db = str(tmp_path / "evolution.db")
    assert record_webhook_result(db, {"action": "ignored"}) is None


def test_dashboard_reads_evolution_schema(tmp_path):
    """Regression: the dashboard used to query columns the evolution store
    never had (file_path/detector/scanned_at) and silently showed nothing."""
    db = str(tmp_path / "evolution.db")
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hi')\n")
    report = {
        "project": str(project),
        "results": [
            {
                "file": "app.py",
                "agent": "security_audit",
                "tool": "check_jwt_implementation",
                "result": {
                    "findings": [{"severity": "HIGH", "issue": "boom", "fix": "fix it"}]
                },
            }
        ],
    }
    with EvolutionStore(db) as store:
        store.record_scan(report, detector_version="test")

    dashboard = AgentsDashboard(db_path=db)
    assert dashboard.get_summary()["total_findings"] == 1
    assert dashboard.get_summary()["by_severity"] == {"HIGH": 1}
    findings = dashboard.get_findings()["findings"]
    assert len(findings) == 1
    assert findings[0]["issue"] == "boom"
    assert findings[0]["file_path"] == "app.py"
    assert findings[0]["detector"] == "security_audit.check_jwt_implementation"

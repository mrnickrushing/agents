"""The hosted service: health/readiness, webhook wiring, and the dashboard
reading the evolution store's real schema."""

import hashlib
import hmac
import json

import pytest

pytest.importorskip("flask")

from agents.evolution import EvolutionStore  # noqa: E402
from agents.server import (  # noqa: E402
    PR_BODY_FILE,
    create_app,
    record_webhook_result,
    scan_pull_request_diff,
    split_unified_diff,
)
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
            "html_url": "https://github.com/mrnickrushing/example/pull/7",
            "title": "Add config",
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
    # No diff could be fetched (no diff_url), so the PR body was scanned.
    assert findings[0]["file_path"] == PR_BODY_FILE
    assert findings[0]["line"] == 1
    # The offending line is shown, but never the credential itself.
    assert findings[0]["snippet"].startswith("api_key")
    assert LEAKED_KEY not in findings[0]["snippet"]
    assert "git history" in findings[0]["why"]
    assert findings[0]["detector"] == "security_audit.audit_hardcoded_secrets"
    assert findings[0]["project"] == "/github/mrnickrushing/example"
    assert findings[0]["project_label"] == "mrnickrushing/example"
    assert findings[0]["pull_request"] == {
        "repo": "mrnickrushing/example",
        "number": 7,
        "url": "https://github.com/mrnickrushing/example/pull/7",
        "title": "Add config",
        "head_sha": "abc123",
    }
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


DIFF = """diff --git a/README.md b/README.md
index 1..2 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # Example
+Nothing secret here.
 Done.
diff --git a/src/config.ts b/src/config.ts
index 3..4 100644
--- a/src/config.ts
+++ b/src/config.ts
@@ -10,4 +10,6 @@ export const settings = {
   retries: 3,
-  api_key: process.env.API_KEY,
+  // hardcoded for now
+  api_key: "%s",
   timeout: 30,
 };
""" % LEAKED_KEY


def test_split_unified_diff_keeps_only_added_lines_with_new_file_numbers():
    sections = split_unified_diff(DIFF)
    assert [s["path"] for s in sections] == ["README.md", "src/config.ts"]
    assert sections[0]["text"] == "Nothing secret here."
    assert sections[0]["lines"] == [2]
    assert sections[1]["lines"] == [11, 12]


def test_scan_pull_request_diff_attributes_file_and_line():
    findings = scan_pull_request_diff(DIFF)
    assert findings, "the added api_key line should be flagged"
    assert all(f["file"] == "src/config.ts" for f in findings)
    assert {f["line"] for f in findings} == {12}


def test_mask_secrets_keeps_shape_but_hides_value():
    from agents.server import mask_secrets

    masked = mask_secrets(f'api_key: "{LEAKED_KEY}",')
    assert LEAKED_KEY not in masked
    assert masked.startswith('api_key: "q7Xv…aE"')
    assert mask_secrets("retries: 3") == "retries: 3"


def test_scan_pull_request_diff_falls_back_to_body_pseudo_file():
    findings = scan_pull_request_diff(f'api_key = "{LEAKED_KEY}"')
    assert findings and findings[0]["file"] == PR_BODY_FILE


def test_record_webhook_result_groups_findings_by_file(tmp_path):
    db = str(tmp_path / "evolution.db")
    result = {
        "action": "scanned",
        "repo": "o/r",
        "pr_number": 3,
        "findings": scan_pull_request_diff(DIFF),
    }
    scan_id = record_webhook_result(
        db,
        result,
        pull_request={"url": "https://github.com/o/r/pull/3", "head_sha": "h"},
    )
    assert scan_id
    rows = AgentsDashboard(db_path=db).get_findings()["findings"]
    assert {r["file_path"] for r in rows} == {"src/config.ts"}
    assert rows[0]["line"] == 12
    assert rows[0]["pull_request"]["url"] == "https://github.com/o/r/pull/3"
    assert rows[0]["snippet"] and LEAKED_KEY not in rows[0]["snippet"]
    assert rows[0]["why"]


def test_dashboard_page_renders_the_review_layout(app):
    html = app.test_client().get("/").get_data(as_text=True)
    for marker in (
        "Needs attention",
        "Why this matters",
        "How to fix",
        "/api/findings",
    ):
        assert marker in html
    summary = app.test_client().get("/api/summary").get_json()
    assert set(summary) >= {
        "total_scans",
        "total_findings",
        "by_severity",
        "last_scan_at",
        "projects",
    }


def test_home_screen_assets_for_iphone(app):
    client = app.test_client()
    page = client.get("/").get_data(as_text=True)
    assert "viewport-fit=cover" in page
    assert 'rel="apple-touch-icon"' in page and 'rel="manifest"' in page
    manifest = client.get("/manifest.webmanifest")
    assert manifest.status_code == 200
    assert manifest.get_json()["display"] == "standalone"
    icon = client.get("/apple-touch-icon.png")
    assert icon.status_code == 200
    assert icon.mimetype == "image/png"
    assert icon.data.startswith(b"\x89PNG")

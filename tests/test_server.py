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


def test_inline_scripts_parse():
    """The dashboard's JavaScript lives inside a Python string; a stray
    escape (`'\\n'` becoming a real newline) once broke the whole page. Parse
    every inline script with node when it is available."""
    import re
    import shutil
    import subprocess

    from agents.web import _HTML, _LOGIN_HTML

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    for name, html in (("dashboard", _HTML), ("login", _LOGIN_HTML)):
        scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
        if not scripts:
            continue
        path = tmp_script = None
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write("\n".join(scripts))
            path = tmp_script = fh.name
        result = subprocess.run(
            [node, "--check", path], capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"{name}: {result.stderr[-800:]}"
        assert tmp_script


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


# ── Running agents from the web ──────────────────────────────────────────

TOKEN = "dashboard-test-token"


@pytest.fixture
def run_app(tmp_path):
    return create_app(
        db_path=str(tmp_path / "evolution.db"),
        webhook_secret="",
        dashboard_token=TOKEN,
    )


def test_agent_catalog_lists_every_cli_agent(run_app):
    from agents.cli import AGENTS

    d = (
        run_app.test_client()
        .get("/api/agents", headers={"Authorization": f"Bearer {TOKEN}"})
        .get_json()
    )
    assert d["runs_enabled"] is True
    assert {a["key"] for a in d["agents"]} == set(AGENTS)
    sec = next(a for a in d["agents"] if a["key"] == "security_audit")
    tool = next(t for t in sec["tools"] if t["name"] == "audit_hardcoded_secrets")
    assert "code" in tool["parameters"]["properties"]


def test_run_endpoints_are_disabled_without_a_token(tmp_path, monkeypatch):
    monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
    app = create_app(
        db_path=str(tmp_path / "e.db"), webhook_secret="", dashboard_token=""
    )
    client = app.test_client()
    assert client.get("/api/agents").get_json()["runs_enabled"] is False
    assert client.get("/api/me").get_json()["sign_in_required"] is False
    assert client.post("/api/run", json={}).status_code == 503
    assert client.post("/api/scan", json={}).status_code == 503


def test_run_endpoints_reject_a_bad_token(run_app):
    client = run_app.test_client()
    assert client.post("/api/run", json={}).status_code == 401
    r = client.post("/api/run", json={}, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_run_one_check_from_the_web(run_app):
    client = run_app.test_client()
    r = client.post(
        "/api/run",
        json={
            "agent": "security_audit",
            "tool": "audit_hardcoded_secrets",
            "args": {"code": f'api_key = "{LEAKED_KEY}"', "ignored": "x"},
        },
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert r.status_code == 200
    findings = r.get_json()["result"]["findings"]
    assert findings and findings[0]["why"]
    bad = client.post(
        "/api/run",
        json={"agent": "security_audit", "tool": "audit_hardcoded_secrets", "args": {}},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert bad.status_code == 400 and "missing required" in bad.get_json()["error"]
    unknown = client.post(
        "/api/run",
        json={"agent": "nope", "tool": "x", "args": {}},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert unknown.status_code == 400


def test_clone_errors_say_what_to_do():
    from agents.server import friendly_clone_error

    prompt = "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
    assert "private" in friendly_clone_error(prompt, "u", "u", None)
    assert "cannot read it" in friendly_clone_error(prompt, "u", "u", "tok")
    assert "branch or tag" in friendly_clone_error(
        "fatal: Remote branch nope not found in upstream origin", "u", "u", None
    )
    secret_url = "https://x-access-token:SECRET@github.com/o/r.git"
    out = friendly_clone_error(
        f"weird failure at {secret_url}",
        secret_url,
        "https://github.com/o/r.git",
        "SECRET",
    )
    assert "SECRET" not in out and "github.com/o/r.git" in out


def test_normalize_repo_accepts_urls_and_rejects_junk():
    from agents.server import normalize_repo

    assert normalize_repo("https://github.com/Owner/Repo.git") == "Owner/Repo"
    assert normalize_repo("github.com/o/r/") == "o/r"
    for junk in ("", "o", "o/r/x", "../../etc", "o/r;rm", "--flag/x"):
        with pytest.raises(ValueError):
            normalize_repo(junk)


def test_scan_job_clones_scans_and_records(run_app, tmp_path, monkeypatch):
    import subprocess
    import time as _time

    # A local stand-in for GitHub: a git repo with a leaked key.
    origin = tmp_path / "origin"
    origin.mkdir()
    (origin / "config.py").write_text(f'API_KEY = "{LEAKED_KEY}"\n')
    subprocess.run(["git", "init", "-q"], cwd=origin, check=True)
    subprocess.run(["git", "add", "."], cwd=origin, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=origin,
        check=True,
    )

    def fake_clone(repo, ref, destination, token=None):
        subprocess.run(["git", "clone", "-q", str(origin), destination], check=True)
        return "deadbeefcafe"

    monkeypatch.setattr("agents.server._clone_repository", fake_clone)
    client = run_app.test_client()
    r = client.post(
        "/api/scan",
        json={"repo": "mrnickrushing/example", "agents": ["security_audit"]},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert r.status_code == 202
    job_id = r.get_json()["job"]["id"]
    auth = {"Authorization": f"Bearer {TOKEN}"}
    for _ in range(100):
        job = client.get(f"/api/jobs/{job_id}", headers=auth).get_json()["job"]
        if job["status"] in ("done", "failed"):
            break
        _time.sleep(0.1)
    assert job["status"] == "done", job
    assert job["result"]["findings"] >= 1
    assert job["result"]["files_scanned"] >= 1
    assert job["result"]["head_sha"] == "deadbeefcafe"

    findings = client.get("/api/findings", headers=auth).get_json()["findings"]
    assert findings[0]["project_label"] == "mrnickrushing/example"
    assert findings[0]["file_path"] == "config.py"
    assert findings[0]["repository"]["head_sha"] == "deadbeefcafe"
    assert findings[0]["source"] == "web-scan"
    assert client.get("/api/jobs", headers=auth).get_json()["jobs"][0]["id"] == job_id


def test_scan_rejects_bad_input(run_app):
    client = run_app.test_client()
    h = {"Authorization": f"Bearer {TOKEN}"}
    assert client.post("/api/scan", json={"repo": "junk"}, headers=h).status_code == 400
    assert (
        client.post(
            "/api/scan", json={"repo": "o/r", "ref": "-x"}, headers=h
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/scan", json={"repo": "o/r", "agents": ["nope"]}, headers=h
        ).status_code
        == 400
    )


def test_github_pseudo_root_matches_a_real_clone(tmp_path):
    import subprocess

    from agents.evolution import project_key

    clone = tmp_path / "clone"
    clone.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=clone, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/Owner/Repo.git"],
        cwd=clone,
        check=True,
    )
    assert project_key(str(clone)) == project_key("/github/owner/repo")

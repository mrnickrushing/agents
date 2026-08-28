"""Getting findings out of the dashboard and into whoever fixes them:
the per-repository filter, the Markdown hand-off, and the CLI pull."""

import json
import subprocess
import sys

import pytest

from agents.web import findings_markdown

pytest.importorskip("flask")

from agents.server import create_app, record_webhook_result  # noqa: E402
from agents.web import AgentsDashboard  # noqa: E402

LEAKED_KEY = "q7Xv93LmZp2RtK8wYb4NcJ6HsD1fG0aE"


def _record(db, repo, number):
    findings = [
        {
            "severity": "CRITICAL",
            "issue": "Hardcoded API Key detected",
            "fix": "Move it to an environment variable.",
            "file": "src/config.ts",
            "line": 12,
            "snippet": 'api_key: "q7Xv…aE"',
            "why": "It stays in git history.",
        }
    ]
    record_webhook_result(
        db,
        {"action": "scanned", "repo": repo, "pr_number": number, "findings": findings},
        pull_request={
            "url": f"https://github.com/{repo}/pull/{number}",
            "head_sha": "abc",
        },
    )


def test_findings_can_be_filtered_to_one_repository(tmp_path):
    db = str(tmp_path / "evolution.db")
    _record(db, "nick/app", 1)
    _record(db, "nick/site", 2)
    dash = AgentsDashboard(db_path=db)
    assert len(dash.get_findings()["findings"]) == 2
    only = dash.get_findings(project="nick/site")["findings"]
    assert [f["project_label"] for f in only] == ["nick/site"]
    assert dash.get_findings(project="nobody/nothing")["findings"] == []


def test_api_findings_accepts_project_and_caps_limit(tmp_path):
    db = str(tmp_path / "evolution.db")
    _record(db, "nick/app", 1)
    _record(db, "nick/site", 2)
    app = create_app(db_path=db, webhook_secret="", dashboard_token="")
    client = app.test_client()
    rows = client.get("/api/findings?project=nick/app&limit=99999").get_json()[
        "findings"
    ]
    assert [r["project_label"] for r in rows] == ["nick/app"]


def test_markdown_handoff_groups_by_repository_with_line_reason_fix_and_id(tmp_path):
    db = str(tmp_path / "evolution.db")
    _record(db, "nick/app", 7)
    rows = AgentsDashboard(db_path=db).get_findings()["findings"]
    text = findings_markdown(rows, title="# test")
    assert text.startswith("# test")
    assert "## nick/app (PR #7: https://github.com/nick/app/pull/7)" in text
    assert "- **CRITICAL** `src/config.ts:12` — Hardcoded API Key detected" in text
    assert '  - line: `api_key: "q7Xv…aE"`' in text
    assert "  - why: It stays in git history." in text
    assert "  - fix: Move it to an environment variable." in text
    assert "detector: security_audit.audit_hardcoded_secrets · id: agf_" in text
    assert LEAKED_KEY not in text


def test_cli_remote_findings_pulls_from_a_dashboard(tmp_path, monkeypatch):
    """The CLI end of the hand-off, against a real HTTP server."""
    import threading
    from wsgiref.simple_server import make_server

    db = str(tmp_path / "evolution.db")
    _record(db, "nick/app", 3)
    app = create_app(db_path=db, webhook_secret="", dashboard_token="tok")
    server = make_server("127.0.0.1", 0, app)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = {**__import__("os").environ, "AGENTS_DASHBOARD_TOKEN": "tok"}
        out = subprocess.run(
            [
                sys.executable,
                "-m",
                "agents.cli",
                "remote-findings",
                "--url",
                f"http://127.0.0.1:{port}",
                "--project",
                "nick/app",
                "--json",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert out.returncode == 0, out.stderr
        rows = json.loads(out.stdout)
        assert rows and rows[0]["project_label"] == "nick/app"

        markdown = subprocess.run(
            [
                sys.executable,
                "-m",
                "agents.cli",
                "remote-findings",
                "--url",
                f"http://127.0.0.1:{port}",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert "## nick/app (PR #3" in markdown.stdout

        denied = subprocess.run(
            [
                sys.executable,
                "-m",
                "agents.cli",
                "remote-findings",
                "--url",
                f"http://127.0.0.1:{port}",
            ],
            capture_output=True,
            text=True,
            env={k: v for k, v in env.items() if k != "AGENTS_DASHBOARD_TOKEN"},
            timeout=60,
        )
        assert denied.returncode != 0 and "token is required" in denied.stderr
    finally:
        server.shutdown()


def test_dismissed_findings_are_left_out_of_the_handoff():
    # Regression: /api/findings returns dismissed findings so the board can
    # offer its "show dismissed" toggle, but the Markdown hand-off has no such
    # toggle — it used to list them anyway, so dismissing a false positive
    # changed nothing and the same finding came back in every hand-off.
    findings = [
        {
            "severity": "HIGH",
            "issue": "Real problem",
            "file_path": "src/a.ts",
            "project_label": "nick/app",
            "finding_id": "agf_real",
        },
        {
            "severity": "HIGH",
            "issue": "Known false positive",
            "file_path": "src/b.ts",
            "project_label": "nick/app",
            "finding_id": "agf_dismissed",
            "verdict": "FALSE_POSITIVE",
            "verdict_reason": "Parameterized fragment, not user input",
        },
    ]
    markdown = findings_markdown(findings)
    assert "Real problem" in markdown
    assert "Known false positive" not in markdown
    assert "fix these 1 finding(s)" in markdown


def test_confirmed_and_unreviewed_findings_still_appear():
    findings = [
        {
            "severity": "HIGH",
            "issue": "Confirmed problem",
            "file_path": "src/a.ts",
            "project_label": "nick/app",
            "verdict": "CONFIRMED",
        },
        {
            "severity": "LOW",
            "issue": "Unreviewed problem",
            "file_path": "src/b.ts",
            "project_label": "nick/app",
        },
    ]
    markdown = findings_markdown(findings)
    assert "Confirmed problem" in markdown
    assert "Unreviewed problem" in markdown
    assert "fix these 2 finding(s)" in markdown


def test_dismissed_findings_are_shown_when_explicitly_requested():
    findings = [
        {
            "severity": "HIGH",
            "issue": "Known false positive",
            "file_path": "src/b.ts",
            "project_label": "nick/app",
            "verdict": "FALSE_POSITIVE",
        }
    ]
    assert "Known false positive" in findings_markdown(findings, include_dismissed=True)

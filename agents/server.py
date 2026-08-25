"""
Hosted service — the dashboard, the GitHub webhook receiver, and health
endpoints on one WSGI app, so a single Railway service (or one `docker run`)
serves all of it.

    agents serve                       # binds HOST:PORT (0.0.0.0:8000 by default)
    python -m agents.server --port 8000

Environment:
    PORT / HOST             bind address (Railway injects PORT)
    AGENTS_DB               evolution.db path (default: the XDG state dir,
                            the same file `agents scan` records into)
    GITHUB_WEBHOOK_SECRET   enables POST /webhook; unset, that route answers 503
    GITHUB_TOKEN            lets the receiver fetch PR diffs and post summaries

Routes:
    GET  /                    dashboard UI
    GET  /api/summary         counts for the dashboard cards
    GET  /api/findings        most recent findings (?limit=)
    GET  /api/events          Server-Sent Events live feed
    GET  /health              liveness — 200 once the process is up
    GET  /ready               readiness — opens the evolution DB read/write
    POST /webhook             GitHub pull_request events (HMAC-SHA256 verified)

A webhook scan is recorded into the same evolution store the dashboard reads,
so a PR event shows up on the dashboard and in the SSE feed without any other
process involved.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional

from agents import __version__
from agents.evolution import EvolutionStore
from agents.github_integration import GitHubIntegration, register_webhook_routes
from agents.web import AgentsDashboard, _default_db_path

logger = logging.getLogger(__name__)

WEBHOOK_AGENT = "security_audit"
WEBHOOK_TOOL = "audit_hardcoded_secrets"


def resolve_db_path(db_path: Optional[str] = None) -> str:
    """Explicit argument, then AGENTS_DB, then the standard XDG location."""
    return db_path or os.environ.get("AGENTS_DB") or _default_db_path()


PR_BODY_FILE = "(pull request description)"

_DIFF_HEADER = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")


def split_unified_diff(diff: str) -> List[Dict[str, Any]]:
    """Split a unified diff into the *added* text of each file.

    Returns one dict per file: ``path``, ``text`` (the added lines joined, in
    order) and ``lines`` (for each of those lines, its line number in the new
    file). Only added lines are scanned — a secret already present in the
    surrounding context predates the PR and should not be pinned on it.
    """
    files: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    new_line = 0
    for raw in diff.splitlines():
        header = _DIFF_HEADER.match(raw)
        if header:
            current = {"path": header.group("b"), "added": [], "lines": []}
            files.append(current)
            new_line = 0
            continue
        if current is None:
            continue
        hunk = _HUNK_HEADER.match(raw)
        if hunk:
            new_line = int(hunk.group("start"))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            current["added"].append(raw[1:])
            current["lines"].append(new_line)
            new_line += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
        else:
            new_line += 1
    return [
        {"path": f["path"], "text": "\n".join(f["added"]), "lines": f["lines"]}
        for f in files
        if f["added"]
    ]


def scan_pull_request_diff(diff: str) -> List[Dict[str, Any]]:
    """The static check the webhook runs on a PR (no API key needed).

    Each finding carries ``file`` and ``line`` in the PR's new-file
    coordinates. Text that is not a unified diff (the PR description, used
    when the diff could not be fetched) is scanned as one pseudo-file.
    """
    from agents.security_audit import SecurityAuditAgent

    handler = getattr(SecurityAuditAgent(), f"_{WEBHOOK_TOOL}")
    sections = split_unified_diff(diff) or [
        {"path": PR_BODY_FILE, "text": diff, "lines": None}
    ]
    findings: List[Dict[str, Any]] = []
    for section in sections:
        for finding in handler(section["text"]).get("findings", []):
            finding = dict(finding)
            finding["file"] = section["path"]
            local = finding.get("line")
            if section["lines"] is not None and isinstance(local, int):
                if 1 <= local <= len(section["lines"]):
                    finding["line"] = section["lines"][local - 1]
            findings.append(finding)
    return findings


def record_webhook_result(
    db_path: str,
    result: Dict[str, Any],
    pull_request: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Persist a webhook scan into the evolution store.

    The report shape mirrors what `agents scan` records so the dashboard,
    `agents history`, and `agents feedback` all see webhook findings the same
    way they see local ones. The project identity is the repository (not a
    filesystem path) so every PR of one repo shares a finding history; the
    PR itself (number, URL, title, head SHA) is kept on the report for the
    dashboard to link to.
    """
    if result.get("action") != "scanned":
        return None
    repo = result.get("repo") or "unknown/unknown"
    pr_number = result.get("pr_number", 0)
    head_sha = str((pull_request or {}).get("head_sha") or result.get("head_sha") or "")
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for finding in result.get("findings", []):
        by_file.setdefault(str(finding.get("file") or PR_BODY_FILE), []).append(
            dict(finding)
        )
    report: Dict[str, Any] = {
        "project": f"/github/{repo}",
        "source": "github-webhook",
        "pull_request": {
            "repo": repo,
            "number": pr_number,
            "url": (pull_request or {}).get("url")
            or f"https://github.com/{repo}/pull/{pr_number}",
            "title": (pull_request or {}).get("title", ""),
            "head_sha": head_sha,
        },
        "results": [
            {
                "file": path,
                "agent": WEBHOOK_AGENT,
                "tool": WEBHOOK_TOOL,
                "source_hash": head_sha or "unavailable",
                "result": {"findings": findings},
            }
            for path, findings in by_file.items()
        ],
    }
    with EvolutionStore(db_path) as store:
        return store.record_scan(report, detector_version=__version__)


def create_app(db_path: Optional[str] = None, webhook_secret: Optional[str] = None):
    """Build the WSGI app. `webhook_secret=None` reads GITHUB_WEBHOOK_SECRET;
    an empty string disables the webhook route explicitly."""
    try:
        from flask import jsonify
    except ImportError as exc:  # pragma: no cover - exercised by the import guard
        raise ImportError(
            "Install the web extra: pip install 'rushingtech-agents[web]'"
        ) from exc

    resolved_db = resolve_db_path(db_path)
    dashboard = AgentsDashboard(db_path=resolved_db)
    app = dashboard.create_flask_app()
    app.config["AGENTS_DB"] = resolved_db

    @app.get("/health")
    def health():
        return jsonify(
            {"status": "ok", "service": "rushingtech-agents", "version": __version__}
        )

    @app.get("/ready")
    def ready():
        try:
            with EvolutionStore(resolved_db) as store:
                store.connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()
        except (OSError, sqlite3.Error) as exc:
            return (
                jsonify(
                    {
                        "status": "unavailable",
                        "database": resolved_db,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                ),
                503,
            )
        return jsonify({"status": "ready", "database": resolved_db})

    secret = (
        os.environ.get("GITHUB_WEBHOOK_SECRET")
        if webhook_secret is None
        else webhook_secret
    )
    integration = GitHubIntegration(webhook_secret=secret) if secret else None

    def on_result(payload: Dict[str, Any], result: Dict[str, Any]) -> None:
        pr = payload.get("pull_request") or {}
        head = pr.get("head") or {}
        if head.get("sha"):
            result["head_sha"] = head["sha"]
        meta = {
            "url": pr.get("html_url"),
            "title": pr.get("title", ""),
            "head_sha": head.get("sha", ""),
        }
        try:
            scan_id = record_webhook_result(resolved_db, result, pull_request=meta)
        except (OSError, sqlite3.Error) as exc:
            logger.error("webhook scan could not be recorded: %s", exc)
            result["recorded"] = False
            return
        if scan_id:
            result["recorded"] = True
            result["scan_id"] = scan_id
            dashboard.publish_event(
                f"scan_complete {result.get('repo')}#{result.get('pr_number')}: "
                f"{result.get('findings_count', 0)} finding(s)"
            )

    register_webhook_routes(
        app, integration, scan_fn=scan_pull_request_diff, on_result=on_result
    )
    return app


def serve(
    host: str = "0.0.0.0",  # noqa: S104 - a hosted service must accept external traffic
    port: int = 8000,
    db_path: Optional[str] = None,
    threads: int = 8,
) -> None:
    """Run the service under gunicorn (one worker, threaded).

    A single worker on purpose: the dashboard's SSE fan-out and the webhook
    delivery de-duplication are in-process state. Threads give concurrency
    for long-lived SSE connections without splitting that state.
    """
    app = create_app(db_path=db_path)
    try:
        import gunicorn.app.base  # type: ignore
    except ImportError:
        logger.warning(
            "gunicorn is not installed; using Flask's development server "
            "(pip install 'rushingtech-agents[web]' for the production server)"
        )
        app.run(host=host, port=port, threaded=True)
        return

    class _Server(gunicorn.app.base.BaseApplication):  # type: ignore[misc]
        def __init__(self, application, options: Dict[str, Any]) -> None:
            self._application = application
            self._options = options
            super().__init__()

        def load_config(self) -> None:
            for key, value in self._options.items():
                self.cfg.set(key, value)

        def load(self):
            return self._application

    _Server(
        app,
        {
            "bind": f"{host}:{port}",
            "workers": 1,
            "threads": threads,
            "worker_class": "gthread",
            "timeout": 120,
            "accesslog": "-",
            "errorlog": "-",
        },
    ).run()


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="rushingtech-agents hosted service (dashboard + GitHub webhook)"
    )
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    parser.add_argument(
        "--db", default=None, help="Path to evolution.db (default: $AGENTS_DB or XDG)"
    )
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    serve(host=args.host, port=args.port, db_path=args.db, threads=args.threads)


if __name__ == "__main__":
    _main()

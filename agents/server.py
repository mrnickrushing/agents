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

import hmac
import logging
import os
import queue
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from agents import __version__, webauth
from agents.evolution import EvolutionStore
from agents.github_integration import GitHubIntegration, register_webhook_routes
from agents.web import AgentsDashboard, _default_db_path, render_login
from agents.webauth import SESSION_COOKIE, OAuthConfig, SessionStore

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
        source_lines = section["text"].split("\n")
        for finding in handler(section["text"]).get("findings", []):
            finding = dict(finding)
            finding["file"] = section["path"]
            local = finding.get("line")
            if isinstance(local, int) and 1 <= local <= len(source_lines):
                finding["snippet"] = mask_secrets(source_lines[local - 1].strip())
                if section["lines"] is not None:
                    finding["line"] = section["lines"][local - 1]
            finding.setdefault("why", explain_finding(WEBHOOK_TOOL, finding))
            findings.append(finding)
    return _dedupe_entropy(findings)


def _dedupe_entropy(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The entropy heuristic fires on the same line as a typed secret match;
    keep only the typed (CRITICAL) finding for that file:line."""
    typed = {
        (f.get("file"), f.get("line"))
        for f in findings
        if not str(f.get("issue", "")).startswith("High-entropy")
    }
    return [
        f
        for f in findings
        if not (
            str(f.get("issue", "")).startswith("High-entropy")
            and (f.get("file"), f.get("line")) in typed
        )
    ]


_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-/+=]{16,}")


def mask_secrets(text: str) -> str:
    """Keep the shape of a line but never echo a credential back out.

    Any run of 16+ token characters (keys, JWT segments, passwords) is
    reduced to its first four and last two characters.
    """

    def _mask(match: "re.Match[str]") -> str:
        value = match.group(0)
        return f"{value[:4]}…{value[-2:]}"

    return _LONG_TOKEN.sub(_mask, text)[:240]


# Plain-language rationale per detector, so a finding says *why* it is a
# problem and not only what pattern matched. Keyed by tool name; a more
# specific entry keyed by "tool:issue-prefix" wins when present.
RATIONALE: Dict[str, str] = {
    "audit_hardcoded_secrets": (
        "A credential in source is readable by anyone with repository access, "
        "every CI runner, and every fork — and it stays in git history after "
        "the line is removed. Treat it as leaked: rotate it, then load it from "
        "an environment variable or secret manager."
    ),
    "audit_hardcoded_secrets:High-entropy": (
        "This string has the randomness profile of a generated key or token. "
        "If it is one, it is now in git history; if it is not (a hash, an "
        "asset id), dismiss the finding so it stops being reported."
    ),
    "audit_hardcoded_secrets:******": (
        "A token that appears in a log line or comment ends up in log storage "
        "and error trackers, which usually have wider access than the code."
    ),
    "check_jwt_implementation": (
        "A JWT that is decoded without verification, signed with a weak or "
        "shared secret, or never expires lets anyone mint or replay sessions."
    ),
    "audit_cors_config": (
        "A permissive CORS policy lets any website make credentialed requests "
        "to this API from a victim's browser."
    ),
    "analyze_helmet_config": (
        "Missing security headers leave the browser to defaults that allow "
        "clickjacking, MIME sniffing, and inline script injection."
    ),
    "audit_sql_injection": (
        "Request input interpolated into a query lets an attacker change the "
        "query's meaning — reading, altering, or deleting data."
    ),
    "audit_xss_patterns": (
        "Untrusted HTML rendered without escaping runs attacker JavaScript in "
        "every visitor's session."
    ),
    "review_webhook_handler": (
        "A webhook that skips signature verification or idempotency accepts "
        "forged or replayed events — money and entitlements follow."
    ),
    "audit_railway_config": (
        "Railway probes the healthcheck path before routing traffic; a path no "
        "route serves fails every deploy."
    ),
}


def explain_finding(tool: str, finding: Dict[str, Any]) -> str:
    issue = str(finding.get("issue") or "")
    for key, text in RATIONALE.items():
        if ":" in key:
            k_tool, prefix = key.split(":", 1)
            if k_tool == tool and issue.startswith(prefix):
                return text
    return RATIONALE.get(tool, "")


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


# ── Running agents from the web ──────────────────────────────────────────
#
# Both entry points below are gated by DASHBOARD_TOKEN: the page is public,
# and cloning repositories / running detectors on demand must not be.

MAX_ARG_CHARS = 512_000
_CATALOG: List[Dict[str, Any]] = []
_CATALOG_LOCK = threading.Lock()


def agent_catalog() -> List[Dict[str, Any]]:
    """Every CLI-registered agent with its tools and parameter schemas."""
    with _CATALOG_LOCK:
        if _CATALOG:
            return _CATALOG
        from agents.cli import AGENTS

        for key, cls in sorted(AGENTS.items()):
            agent = cls()
            tools = []
            for tool in agent._tools:
                schema = tool.get("parameters") or tool.get("input_schema") or {}
                tools.append(
                    {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": schema,
                    }
                )
            doc = (cls.__doc__ or "").strip().splitlines()
            _CATALOG.append(
                {
                    "key": key,
                    "name": cls.__name__,
                    "description": doc[0] if doc else "",
                    "tools": tools,
                }
            )
        return _CATALOG


def run_tool(agent_key: str, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Call one tool handler with schema-checked arguments (the web form of
    `agents run <agent> <tool>`). Findings gain a `why` like webhook ones."""
    from agents.cli import AGENTS

    cls = AGENTS.get(agent_key)
    if cls is None:
        raise ValueError(f"unknown agent: {agent_key}")
    agent = cls()
    handler = agent._tool_handlers.get(tool_name)
    if handler is None:
        raise ValueError(f"unknown tool {tool_name!r} for agent {agent_key!r}")
    spec = next((tl for tl in agent._tools if tl["name"] == tool_name), {})
    schema = spec.get("parameters") or spec.get("input_schema") or {}
    allowed = set((schema.get("properties") or {}).keys())
    missing = [name for name in schema.get("required", []) if name not in args]
    if missing:
        raise ValueError(f"missing required argument(s): {', '.join(missing)}")
    kwargs: Dict[str, Any] = {}
    for name, value in (args or {}).items():
        if name not in allowed:
            continue
        if isinstance(value, str) and len(value) > MAX_ARG_CHARS:
            raise ValueError(f"argument {name!r} is too large")
        kwargs[name] = value
    result = handler(**kwargs)
    if isinstance(result, dict) and isinstance(result.get("findings"), list):
        findings = [f for f in result["findings"] if isinstance(f, dict)]
        for finding in findings:
            finding.setdefault("why", explain_finding(tool_name, finding))
        if tool_name == WEBHOOK_TOOL:
            findings = _dedupe_entropy(findings)
        result["findings"] = findings
        result["total_issues"] = len(findings)
    return result


_REPO_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,120}$")


def normalize_repo(value: str) -> str:
    """Accept `owner/name`, `github.com/owner/name`, or a full URL."""
    slug = (value or "").strip()
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if slug.lower().startswith(prefix):
            slug = slug[len(prefix) :]
    slug = slug.strip("/").removesuffix(".git")
    if not _REPO_RE.match(slug) or ".." in slug:
        raise ValueError("repository must look like owner/name on github.com")
    return slug


def _clone_repository(
    repo: str, ref: Optional[str], destination: str, token: Optional[str] = None
) -> str:
    """Shallow-clone `repo` at `ref` into `destination`; returns the head SHA.

    The signed-in person's GitHub token (or GITHUB_TOKEN as a fallback) is
    passed as the HTTPS credential so private repositories work; it never
    reaches the recorded report (the evolution store strips credentials from
    remote URLs)."""
    public_url = f"https://github.com/{repo}.git"
    token = token or os.environ.get("GITHUB_TOKEN")
    url = public_url
    if token:
        url = public_url.replace("https://", f"https://x-access-token:{token}@", 1)
    command = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags"]
    if ref:
        command += ["--branch", ref]
    command += ["--", url, destination]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    proc = subprocess.run(
        command, capture_output=True, text=True, timeout=180, env=env, check=False
    )
    if proc.returncode != 0:
        message = proc.stderr.strip().replace(url, public_url)
        raise RuntimeError(message[-400:] or "git clone failed")
    head = subprocess.run(
        ["git", "-C", destination, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    ).stdout.strip()
    return head


class ScanJobs:
    """One worker thread; scans run one at a time so a small container is
    never asked to clone and analyse several repositories at once."""

    MAX_QUEUED = 5
    KEEP = 50

    def __init__(self, db_path: str, publish) -> None:
        self._db_path = db_path
        self._publish = publish
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._tokens: Dict[str, str] = {}  # never exposed through the API
        self._order: List[str] = []
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._lock = threading.Lock()
        self._worker: Optional[threading.Thread] = None

    def submit(
        self,
        repo: str,
        ref: Optional[str],
        agents: List[str],
        token: Optional[str] = None,
        requested_by: str = "",
    ) -> Dict[str, Any]:
        from agents.cli import AGENTS

        repo = normalize_repo(repo)
        ref = (ref or "").strip() or None
        if ref and (not _REF_RE.match(ref) or ".." in ref):
            raise ValueError("branch or tag name is not valid")
        unknown = [a for a in agents if a not in AGENTS]
        if unknown:
            raise ValueError(f"unknown agent(s): {', '.join(unknown)}")
        with self._lock:
            queued = sum(1 for j in self._jobs.values() if j["status"] == "queued")
            if queued >= self.MAX_QUEUED:
                raise RuntimeError("too many scans queued; try again in a minute")
            job = {
                "id": f"job_{uuid.uuid4().hex[:12]}",
                "repo": repo,
                "ref": ref,
                "agents": list(agents),
                "status": "queued",
                "requested_by": requested_by,
                "submitted_at": time.time(),
                "started_at": None,
                "finished_at": None,
                "progress": "queued",
                "result": None,
                "error": None,
            }
            self._jobs[job["id"]] = job
            if token:
                self._tokens[job["id"]] = token
            self._order.append(job["id"])
            for stale in self._order[: -self.KEEP]:
                self._jobs.pop(stale, None)
                self._tokens.pop(stale, None)
            self._order = self._order[-self.KEEP :]
            self._ensure_worker()
        self._queue.put(job["id"])
        return dict(job)

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def recent(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                dict(self._jobs[i]) for i in reversed(self._order) if i in self._jobs
            ]

    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(
                target=self._loop, name="agents-scan-worker", daemon=True
            )
            self._worker.start()

    def _loop(self) -> None:
        while True:
            job_id = self._queue.get()
            job = self._jobs.get(job_id)
            if job is None:
                continue
            try:
                self._run(job)
            except Exception as exc:  # noqa: BLE001 - reported on the job
                logger.exception("scan job %s failed", job_id)
                job.update(
                    status="failed",
                    error=f"{type(exc).__name__}: {exc}",
                    finished_at=time.time(),
                )
                self._publish(f"scan_failed {job['repo']}: {exc}")

    def _run(self, job: Dict[str, Any]) -> None:
        from agents.cli import _run_scan
        from agents.evolution import _source_hash, attach_finding_ids

        job.update(status="running", started_at=time.time(), progress="cloning")
        self._publish(f"scan_started {job['repo']}")
        workdir = tempfile.mkdtemp(prefix="agents-scan-")
        token = self._tokens.pop(job["id"], None)
        try:
            clone_dir = os.path.join(workdir, "repo")
            head = _clone_repository(job["repo"], job["ref"], clone_dir, token=token)
            job["progress"] = "scanning"
            report = _run_scan(clone_dir, job["agents"] or None)
            attach_finding_ids(report)
            for entry in report.get("results", []):
                entry["source_hash"] = _source_hash(
                    clone_dir, str(entry.get("file", ""))
                )
            report["project"] = f"/github/{job['repo']}"
            report["source"] = "web-scan"
            report["repository"] = {
                "repo": job["repo"],
                "ref": job["ref"],
                "head_sha": head,
            }
            job["progress"] = "recording"
            with EvolutionStore(self._db_path) as store:
                store.apply_feedback(report)
                scan_id = store.record_scan(report, detector_version=__version__)
            counts: Dict[str, int] = {}
            total = 0
            for entry in report.get("results", []):
                for finding in entry.get("result", {}).get("findings", []):
                    if isinstance(finding, dict):
                        total += 1
                        sev = str(finding.get("severity", "INFO"))
                        counts[sev] = counts.get(sev, 0) + 1
            job.update(
                status="done",
                finished_at=time.time(),
                progress="done",
                result={
                    "scan_id": scan_id,
                    "head_sha": head,
                    "files_scanned": report.get("files_scanned"),
                    "findings": total,
                    "by_severity": counts,
                },
            )
            self._publish(f"scan_complete {job['repo']}: {total} finding(s)")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


def create_app(
    db_path: Optional[str] = None,
    webhook_secret: Optional[str] = None,
    dashboard_token: Optional[str] = None,
    oauth: Optional[OAuthConfig] = None,
    session_db_path: Optional[str] = None,
    public: Optional[bool] = None,
):
    """Build the WSGI app. `webhook_secret=None` reads GITHUB_WEBHOOK_SECRET
    and `dashboard_token=None` reads DASHBOARD_TOKEN; an empty string
    disables that feature explicitly. `oauth=None` reads the GitHub OAuth
    App settings from the environment.

    Once any sign-in method is configured the whole dashboard requires it;
    `public=True` (or DASHBOARD_PUBLIC=1) keeps the findings readable by
    anyone while still gating the run/scan endpoints."""
    from urllib.parse import quote

    try:
        from flask import g, jsonify, redirect, request, session
        from werkzeug.middleware.proxy_fix import ProxyFix
    except ImportError as exc:  # pragma: no cover - exercised by the import guard
        raise ImportError(
            "Install the web extra: pip install 'rushingtech-agents[web]'"
        ) from exc
    import secrets as _secrets

    resolved_db = resolve_db_path(db_path)
    dashboard = AgentsDashboard(db_path=resolved_db)
    app = dashboard.create_flask_app()
    app.config["AGENTS_DB"] = resolved_db
    # Railway/Cloudflare terminate TLS; trust their forwarded scheme/host so
    # the OAuth callback URL and Secure cookies are built for https.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.secret_key = os.environ.get("SESSION_SECRET") or _secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="agents_oauth",
    )

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

    token = (
        os.environ.get("DASHBOARD_TOKEN")
        if dashboard_token is None
        else dashboard_token
    )
    oauth_config = OAuthConfig() if oauth is None else oauth
    sessions = SessionStore(
        session_db_path or webauth.default_session_db_path(resolved_db)
    )
    app.config["SESSIONS"] = sessions
    jobs = ScanJobs(resolved_db, dashboard.publish_event)
    app.config["SCAN_JOBS"] = jobs
    runs_enabled = bool(token) or oauth_config.enabled
    repo_cache: Dict[str, Any] = {}
    if public is None:
        public = os.environ.get("DASHBOARD_PUBLIC", "").lower() in ("1", "true", "yes")
    require_sign_in = runs_enabled and not public
    app.config["REQUIRE_SIGN_IN"] = require_sign_in

    # Reachable without signing in: probes, the GitHub webhook, the sign-in
    # flow itself, and the home-screen assets the sign-in page references.
    public_paths = {
        "/health",
        "/ready",
        "/webhook",
        "/login",
        "/auth/login",
        "/auth/callback",
        "/auth/token",
        "/auth/logout",
        "/api/me",
        "/manifest.webmanifest",
        "/apple-touch-icon.png",
    }

    @app.before_request
    def gate():
        if not require_sign_in or request.path in public_paths:
            return None
        if principal() is not None:
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "sign in first"}), 401
        return redirect("/login")

    def login_redirect(message: str):
        return redirect("/login?error=" + quote(message))

    # ── who is asking? ──────────────────────────────────────────────
    def principal() -> Optional[Dict[str, Any]]:
        """The signed-in person (cookie session) or the bearer token."""
        session_id = request.cookies.get(SESSION_COOKIE)
        current = sessions.get(session_id)
        if current:
            if webauth.token_needs_refresh(current):
                # GitHub App user tokens expire in 8 hours; the session is
                # good for 30 days, so renew quietly with the refresh token.
                try:
                    fresh = webauth.refresh_access_token(
                        oauth_config, current["refresh_token"]
                    )
                    sessions.update_tokens(session_id, fresh)
                    current = {
                        **current,
                        **fresh,
                        "github_token": fresh["access_token"],
                    }
                except (OSError, ValueError, PermissionError) as exc:
                    logger.warning("GitHub token refresh failed: %s", exc)
            return {"kind": "session", **current}
        header = request.headers.get("Authorization", "")
        supplied = header[7:] if header.startswith("Bearer ") else ""
        if token and supplied and hmac.compare_digest(supplied, token):
            return {
                "kind": "bearer",
                "login": "token",
                "github_token": os.environ.get("GITHUB_TOKEN") or "",
            }
        return None

    def denied():
        if not runs_enabled:
            return (
                jsonify(
                    {
                        "error": "running checks from the web is disabled: set "
                        "GITHUB_OAUTH_CLIENT_ID/SECRET (sign in) or DASHBOARD_TOKEN"
                    }
                ),
                503,
            )
        who = principal()
        if who is None:
            return jsonify({"error": "sign in first"}), 401
        if who["kind"] == "session" and request.method == "POST":
            # Cookie-authenticated writes must come from this page: a custom
            # header (never sent by a plain form) and a same-site origin.
            origin = request.headers.get("Origin") or ""
            if request.headers.get("X-Requested-With") != "fetch" or (
                origin and origin.rstrip("/") != request.host_url.rstrip("/")
            ):
                return jsonify({"error": "cross-site request refused"}), 403
        g.principal = who
        return None

    def callback_url() -> str:
        return request.host_url.rstrip("/") + "/auth/callback"

    # ── sign in ─────────────────────────────────────────────────────
    def start_session(user: Dict[str, Any], tokens: Any):
        session_id = sessions.create(user, tokens)
        response = redirect("/")
        response.set_cookie(
            SESSION_COOKIE,
            session_id,
            max_age=webauth.SESSION_TTL,
            httponly=True,
            secure=request.scheme == "https",
            samesite="Lax",
            path="/",
        )
        return response

    @app.get("/login")
    def login_page():
        if sessions.get(request.cookies.get(SESSION_COOKIE)):
            return redirect("/")
        from flask import Response

        return Response(
            render_login(
                version=__version__,
                sign_in_enabled=oauth_config.enabled,
                token_enabled=bool(token),
                error=request.args.get("error", "")[:300],
            ),
            mimetype="text/html",
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/auth/token")
    def auth_token():
        """Access-token sign-in from the page's form: a session for the
        browser instead of an Authorization header on every request."""
        if not token:
            return login_redirect("Access-token sign-in is not enabled")
        supplied = (request.form.get("token") or "").strip()
        if not supplied or not hmac.compare_digest(supplied, token):
            return login_redirect("That access token is not right")
        return start_session(
            {"login": "token", "name": "Access token", "avatar_url": ""},
            os.environ.get("GITHUB_TOKEN") or "",
        )

    @app.get("/auth/login")
    def auth_login():
        if not oauth_config.enabled:
            return (
                jsonify({"error": "sign-in is not configured on this service"}),
                503,
            )
        state = _secrets.token_urlsafe(24)
        session["oauth_state"] = state
        return redirect(webauth.authorize_url(oauth_config, callback_url(), state))

    @app.get("/auth/callback")
    def auth_callback():
        if not oauth_config.enabled:
            return login_redirect("Sign-in is not configured on this service")
        expected = session.pop("oauth_state", None)
        state = request.args.get("state", "")
        code = request.args.get("code", "")
        if not expected or not code or not hmac.compare_digest(expected, state):
            return login_redirect(
                "The sign-in link expired or was tampered with — try again"
            )
        try:
            tokens = webauth.normalize_tokens(
                webauth.exchange_code(oauth_config, code, callback_url())
            )
            user = webauth.fetch_user(tokens["access_token"])
        except (OSError, ValueError, PermissionError) as exc:
            logger.warning("GitHub sign-in failed: %s", exc)
            return login_redirect("GitHub did not complete the sign-in — try again")
        if not oauth_config.allows(user.get("login", "")):
            return login_redirect(
                f"@{user.get('login')} is not on this dashboard's allow list"
            )
        return start_session(user, tokens)

    @app.post("/auth/logout")
    def auth_logout():
        sessions.delete(request.cookies.get(SESSION_COOKIE))
        response = jsonify({"signed_in": False})
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/api/me")
    def api_me():
        who = sessions.get(request.cookies.get(SESSION_COOKIE))
        return jsonify(
            {
                "signed_in": bool(who),
                "login": who["login"] if who else None,
                "name": who["name"] if who else None,
                "avatar_url": who["avatar_url"] if who else None,
                "sign_in_enabled": oauth_config.enabled,
                "token_enabled": bool(token),
                "sign_in_required": require_sign_in,
            }
        )

    @app.get("/api/repos")
    def api_repos():
        refusal = denied()
        if refusal:
            return refusal
        github_token = g.principal.get("github_token")
        if not github_token:
            return (
                jsonify(
                    {
                        "error": "no GitHub access: sign in with GitHub, or set "
                        "GITHUB_TOKEN on the service"
                    }
                ),
                503,
            )
        cache_key = g.principal["login"]
        cached = repo_cache.get(cache_key)
        if cached and cached["at"] > time.time() - 120:
            return jsonify({"repos": cached["repos"], "cached": True})
        try:
            repos = webauth.list_repositories(github_token)
        except (OSError, ValueError) as exc:
            return jsonify({"error": f"GitHub did not answer: {exc}"}), 502
        repo_cache[cache_key] = {"at": time.time(), "repos": repos}
        hint = ""
        if not repos and g.principal["kind"] == "session":
            hint = (
                "GitHub returned no repositories for this sign-in. If the app you "
                "created is a GitHub App (client id starts with 'Iv'), install it on "
                "your account with Contents: read access — GitHub Apps only see "
                "repositories they are installed on."
            )
        return jsonify({"repos": repos, "cached": False, "hint": hint})

    @app.get("/api/branches")
    def api_branches():
        refusal = denied()
        if refusal:
            return refusal
        try:
            repo = normalize_repo(request.args.get("repo", ""))
            branches = webauth.list_branches(g.principal.get("github_token"), repo)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"error": f"GitHub did not answer: {exc}"}), 502
        return jsonify({"repo": repo, "branches": branches})

    @app.get("/api/agents")
    def api_agents():
        return jsonify(
            {
                "agents": agent_catalog(),
                "runs_enabled": runs_enabled,
                "sign_in_enabled": oauth_config.enabled,
            }
        )

    @app.post("/api/run")
    def api_run():
        refusal = denied()
        if refusal:
            return refusal
        body = request.get_json(silent=True) or {}
        try:
            result = run_tool(
                str(body.get("agent", "")),
                str(body.get("tool", "")),
                body.get("args") or {},
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except TypeError as exc:
            return jsonify({"error": f"bad arguments: {exc}"}), 400
        return jsonify({"result": result})

    @app.post("/api/scan")
    def api_scan():
        refusal = denied()
        if refusal:
            return refusal
        body = request.get_json(silent=True) or {}
        try:
            job = jobs.submit(
                str(body.get("repo", "")),
                body.get("ref"),
                [str(a) for a in (body.get("agents") or [])],
                token=g.principal.get("github_token") or None,
                requested_by=str(g.principal.get("login", "")),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 429
        return jsonify({"job": job}), 202

    @app.get("/api/jobs")
    def api_jobs():
        return jsonify({"jobs": jobs.recent()})

    @app.get("/api/jobs/<job_id>")
    def api_job(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            return jsonify({"error": "unknown job"}), 404
        return jsonify({"job": job})

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

"""
GitHub Integration — webhook handlers and PR comment formatting.

Handles GitHub App webhook events for pull_request.opened,
pull_request.synchronize, and pull_request.labeled.  Formats
scan findings as rich PR review comments.

Usage (as a Flask/FastAPI plugin):
    from agents.github_integration import GitHubIntegration
    integration = GitHubIntegration(webhook_secret="...")
    integration.handle_event(event_type, payload, scan_fn)

CLI (run the webhook server):
    python -m agents.github_integration --port 8001
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import urllib.request
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🔴",
    "MEDIUM": "🟠",
    "LOW": "🟡",
    "INFO": "ℹ️",
}

# Severities that block merge by default
_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}


class GitHubIntegration:
    """
    GitHub App integration layer.

    Validates webhook signatures, dispatches PR events to the scan pipeline,
    and formats findings into rich PR review comments.
    """

    def __init__(
        self,
        webhook_secret: Optional[str] = None,
        block_on_severities: Optional[set] = None,
    ) -> None:
        self.webhook_secret = webhook_secret
        self.block_on_severities = block_on_severities or set(_BLOCKING_SEVERITIES)

    # ── Signature verification ────────────────────────────────────────

    def verify_signature(self, payload_bytes: bytes, signature_header: str) -> bool:
        """Verify GitHub's X-Hub-Signature-256 webhook signature."""
        if not self.webhook_secret:
            return False
        if not signature_header.startswith("sha256="):
            return False
        expected = (
            "sha256="
            + hmac.new(
                self.webhook_secret.encode("utf-8"),
                payload_bytes,
                hashlib.sha256,
            ).hexdigest()
        )
        return hmac.compare_digest(expected, signature_header)

    # ── Event dispatch ────────────────────────────────────────────────

    def handle_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        scan_fn: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """
        Dispatch a GitHub webhook event.

        Parameters
        ----------
        event_type:
            Value of the X-GitHub-Event header (e.g. "pull_request").
        payload:
            Parsed JSON webhook payload.
        scan_fn:
            Callable that accepts a diff/code string and returns a list of
            finding dicts.  If None, returns a no-op result.
        """
        if event_type != "pull_request":
            return {
                "action": "ignored",
                "reason": f"Unsupported event type: {event_type}",
            }

        action = payload.get("action", "")
        if action not in {"opened", "synchronize", "labeled"}:
            return {"action": "ignored", "reason": f"Unhandled PR action: {action}"}

        if action == "labeled":
            label = payload.get("label", {}).get("name", "")
            if label not in {"agents-scan", "security-review"}:
                return {
                    "action": "ignored",
                    "reason": f"Label '{label}' not an opt-in label",
                }

        pr = payload.get("pull_request", {})
        diff = _fetch_pr_diff(pr) or pr.get("body", "") or ""
        repo = payload.get("repository", {}).get("full_name", "unknown/unknown")
        pr_number = pr.get("number", 0)

        findings: List[Dict[str, Any]] = []
        if scan_fn is not None:
            try:
                findings = scan_fn(diff)
            except Exception as exc:  # noqa: BLE001
                logger.error("scan_fn raised: %s", exc)
                return {"action": "error", "reason": str(exc)}

        comments = [format_pr_comment(f, repo=repo) for f in findings]
        should_block = any(
            f.get("severity", "INFO") in self.block_on_severities for f in findings
        )

        return {
            "action": "scanned",
            "repo": repo,
            "pr_number": pr_number,
            "findings_count": len(findings),
            "should_block_merge": should_block,
            "comments": comments,
            "findings": findings,
        }

    # ── Org config ────────────────────────────────────────────────────

    @staticmethod
    def load_org_config(agents_yaml_content: str) -> Dict[str, Any]:
        """
        Parse an ``agents.yml`` config file from ``.github/agents.yml``.

        Supported keys:
            block_severities: [CRITICAL, HIGH]
            agents: [security_audit, auth_security]
            severity_threshold: HIGH
        """
        try:
            import yaml  # type: ignore

            return yaml.safe_load(agents_yaml_content) or {}
        except Exception:  # noqa: BLE001
            return {}


# ── Comment formatting ─────────────────────────────────────────────────────


def format_pr_comment(
    finding: Dict[str, Any],
    repo: str = "",
    file_path: str = "",
    line: Optional[int] = None,
) -> str:
    """Return a markdown PR review comment string for a finding."""
    severity = finding.get("severity", "INFO")
    emoji = _SEVERITY_EMOJI.get(severity, "ℹ️")
    issue = finding.get("issue", "Security finding detected")
    fix = finding.get("fix", "")
    detector = finding.get("detector", finding.get("rule", "agents-scan"))
    file_ref = f"**File**: {file_path}" if file_path else ""
    line_ref = f" (Line {line})" if line else ""

    lines = [
        f"{emoji} **{severity} Issue Detected** (`{detector}`)",
        "",
    ]
    if file_ref:
        lines.append(f"{file_ref}{line_ref}  ")
    lines += [
        f"**Issue**: {issue}  ",
    ]
    if fix:
        lines += [
            "",
            "**Suggested fix**:",
            fix,
        ]
    lines += [
        "",
        "_Generated by [rushingtech-agents](https://github.com/mrnickrushing/agents)_",
    ]
    return "\n".join(lines)


def format_scan_summary(
    findings: List[Dict[str, Any]], repo: str = "", pr_number: int = 0
) -> str:
    """Return a top-level PR summary comment."""
    if not findings:
        return (
            "✅ **agents-scan**: No issues detected.\n\n"
            "_All scanned patterns passed — keep up the great work!_"
        )

    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    summary_lines = [
        f"## 🔍 agents-scan found {len(findings)} issue(s)",
        "",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            emoji = _SEVERITY_EMOJI.get(sev, "ℹ️")
            summary_lines.append(f"- {emoji} **{sev}**: {counts[sev]}")

    summary_lines += [
        "",
        "> Review each inline comment for details and suggested fixes.",
    ]
    return "\n".join(summary_lines)


def _fetch_pr_diff(pr: Dict[str, Any]) -> str:
    url = pr.get("diff_url")
    token = os.getenv("GITHUB_TOKEN")
    if not url or not token:
        return ""
    headers = {
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "rushingtech-agents",
        "Authorization": f"Bearer {token}",
    }
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.read(2_000_000).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _post_pr_summary(payload: Dict[str, Any], result: Dict[str, Any]) -> bool:
    token = os.getenv("GITHUB_TOKEN")
    comments_url = (payload.get("pull_request") or {}).get("comments_url")
    if not token or not comments_url:
        return False
    body = format_scan_summary(
        result.get("findings", []),
        repo=result.get("repo", ""),
        pr_number=result.get("pr_number", 0),
    )
    request = urllib.request.Request(
        comments_url,
        data=json.dumps({"body": body}).encode(),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "rushingtech-agents",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return 200 <= response.status < 300
    except (OSError, ValueError):
        return False


def _default_scan_fn(diff: str) -> List[Dict[str, Any]]:
    from agents.security_audit import SecurityAuditAgent

    return SecurityAuditAgent()._audit_hardcoded_secrets(diff).get("findings", [])


def register_webhook_routes(
    app,
    integration: Optional[GitHubIntegration],
    scan_fn: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
    on_result: Optional[Callable[[Dict[str, Any], Dict[str, Any]], None]] = None,
):
    """Mount POST /webhook on an existing Flask app.

    `integration=None` mounts a route that answers 503 with a clear reason,
    so a deployment without GITHUB_WEBHOOK_SECRET still serves everything
    else and says why the webhook is off instead of 404ing.

    `on_result(payload, result)` runs after a scan (before the response) —
    the hosted service uses it to record findings and push SSE events.
    """
    from flask import jsonify, request

    processed_deliveries: set[str] = set()
    scan = scan_fn or _default_scan_fn

    @app.post("/webhook")
    def webhook():
        if integration is None or not integration.webhook_secret:
            return (
                jsonify(
                    {
                        "error": "webhook disabled: GITHUB_WEBHOOK_SECRET is not configured"
                    }
                ),
                503,
            )
        raw = request.get_data(cache=True)
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not integration.verify_signature(raw, signature):
            return jsonify({"error": "invalid signature"}), 401
        delivery_id = request.headers.get("X-GitHub-Delivery", "")
        if delivery_id and delivery_id in processed_deliveries:
            return jsonify({"action": "duplicate", "delivery_id": delivery_id})
        payload = request.get_json(silent=True) or {}

        event = request.headers.get("X-GitHub-Event", "")
        result = integration.handle_event(event, payload, scan)
        if result.get("action") == "scanned":
            result["summary_comment_posted"] = _post_pr_summary(payload, result)
            if on_result is not None:
                on_result(payload, result)
        if delivery_id:
            processed_deliveries.add(delivery_id)
            if len(processed_deliveries) > 10_000:
                processed_deliveries.pop()
        return jsonify(result)

    return app


def create_flask_app(integration: GitHubIntegration):
    try:
        from flask import Flask
    except ImportError as exc:
        raise ImportError(
            "Install the web extra: pip install 'rushingtech-agents[web]'"
        ) from exc

    app = Flask("agents-github-integration")
    return register_webhook_routes(app, integration)


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="GitHub webhook receiver for rushingtech-agents"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise SystemExit("GITHUB_WEBHOOK_SECRET is required")
    create_flask_app(GitHubIntegration(webhook_secret=secret)).run(
        host=args.host, port=args.port
    )


if __name__ == "__main__":
    _main()

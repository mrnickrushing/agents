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
import re
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
            return True  # No secret configured — skip verification
        if not signature_header.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(
            self.webhook_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
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
            return {"action": "ignored", "reason": f"Unsupported event type: {event_type}"}

        action = payload.get("action", "")
        if action not in {"opened", "synchronize", "labeled"}:
            return {"action": "ignored", "reason": f"Unhandled PR action: {action}"}

        if action == "labeled":
            label = payload.get("label", {}).get("name", "")
            if label not in {"agents-scan", "security-review"}:
                return {"action": "ignored", "reason": f"Label '{label}' not an opt-in label"}

        pr = payload.get("pull_request", {})
        diff = pr.get("body", "") or ""  # PR description as fallback; real usage fetches diff via API
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


def format_scan_summary(findings: List[Dict[str, Any]], repo: str = "", pr_number: int = 0) -> str:
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

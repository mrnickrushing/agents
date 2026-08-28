"""Flow audit agent for async/state-machine reliability checks."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent


def _serialises_writes(code: str) -> bool:
    """True when the file shows a mechanism that runs writes one at a time.

    A serialising queue is the idiomatic JavaScript mutex — `x = x.then(...)`
    appends each task to a chain — and none of lock/mutex/transaction appears
    anywhere near one, so a relay client that funnels every tmux action
    through `actionQueue` read as unguarded (cyberlab-terminal, 2026-08-28).

    The seed matters: without it, an incidental `result = result.then(
    normalize)` on a fetch would vouch for unrelated writes elsewhere in the
    file. A real queue starts from an already-resolved promise. And a
    concurrency limiter only serialises at one — `pLimit(5)` deliberately
    permits five writes at once.
    """
    if re.search(r"lock|mutex|transaction|FOR UPDATE", code, re.IGNORECASE):
        return True
    for seed in re.finditer(r"\b(\w+)\s*=\s*Promise\.resolve\s*\(\s*\)", code):
        name = re.escape(seed.group(1))
        if re.search(rf"\b{name}\s*=\s*{name}\s*\.then\b", code):
            return True
    return bool(re.search(r"\bpLimit\s*\(\s*1\s*\)|\bconcurrency\s*:\s*1\b", code))


class FlowAuditAgent(BaseAgent):
    name = "flow_audit"
    description = "Audits async/state-machine flow logic for auth, payments, uploads, and concurrency risks."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "audit_flow_logic",
                "description": "Detects state-machine edge cases, missing idempotency, OAuth state gaps, and async cleanup hazards.",
                "parameters": {
                    "type": "object",
                    "properties": {"code": {"type": "string"}},
                    "required": ["code"],
                },
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"audit_flow_logic": self._audit_flow_logic}

    def _audit_flow_logic(self, code: str) -> Dict[str, Any]:
        findings = []
        # An OAuth flow, not React's useCallback or any function named
        # `callback`: the protocol's own vocabulary has to be present.
        if re.search(
            r"\boauth\b|redirect_uri|\bauthoriz(?:e|ation)[_ ]?(?:url|endpoint|code)"
            r"|['\"][^'\"]*/callback['\"]|client_secret",
            code,
            re.IGNORECASE,
        ):
            if not re.search(r"\bstate\b", code):
                findings.append(
                    {
                        "severity": "HIGH",
                        "issue": "OAuth flow has no visible state parameter validation",
                        "fix": "Generate, persist, validate, and expire OAuth state values.",
                    }
                )
            elif not re.search(r"expire|ttl|max_age|timestamp", code, re.IGNORECASE):
                findings.append(
                    {
                        "severity": "LOW",
                        "issue": "OAuth state exists but no visible timeout/expiry handling",
                        "fix": "Expire state tokens after a short TTL (e.g., 10 minutes).",
                    }
                )
        if re.search(
            r"webhook|payment|invoice|subscription", code, re.IGNORECASE
        ) and not re.search(r"idempotenc|event\.id|dedup", code, re.IGNORECASE):
            findings.append(
                {
                    "severity": "HIGH",
                    "issue": "Payment/subscription flow has no visible idempotency guard",
                    "fix": "Persist event/request IDs and skip duplicate processing.",
                }
            )
        # A server accepting uploads — not a mobile app reading its own files
        # through expo-file-system or a `File` type annotation.
        if re.search(
            r"multer|formidable|busboy|multipart/form-data|req\.files?\b"
            r"|UploadFile|FileField|upload_to\s*=|\.upload\(|putObject|put_object",
            code,
        ):
            if not re.search(r"cleanup|finally|unlink|delete", code, re.IGNORECASE):
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "issue": "Upload workflow has no visible cleanup on failure",
                        "fix": "Wrap upload pipeline in try/finally and delete partial artifacts on failure.",
                    }
                )
            if not re.search(r"scan|clam|virus|malware", code, re.IGNORECASE):
                findings.append(
                    {
                        "severity": "LOW",
                        "issue": "Upload flow has no visible malware scanning step",
                        "fix": "Scan uploaded files before durable storage/serving.",
                    }
                )
        if re.search(r"retry|attempt", code, re.IGNORECASE) and not re.search(
            r"exponential|2\s*\*\*|Math\.pow|backoff", code, re.IGNORECASE
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Retry logic has no visible exponential backoff",
                    "fix": "Use bounded exponential backoff with jitter to avoid retry storms.",
                }
            )
        # Parallel *writes* without a guard; parallel reads (the common
        # `Promise.all([load(), load()])`) are fine.
        if (
            re.search(r"Promise\.all|asyncio\.gather|Thread|concurrent", code)
            and re.search(
                r"\.(?:update|upsert|insert|save|write|delete|destroy|increment)\w*\("
                r"|\bUPDATE\s+\w+\s+SET\b|\bINSERT\s+INTO\b",
                code,
            )
            and not _serialises_writes(code)
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Concurrent state updates with no visible lock/transaction guard",
                    "fix": "Protect critical state transitions with row locks, mutexes, or transactional checks.",
                }
            )
        # JavaScript `try {` / `catch (` count as handling too, not only
        # Python's `try:`/`except` and promise `.catch(`.
        if re.search(r"new Promise|async ", code) and not re.search(
            r"\.catch\(|\bexcept\b|\btry\s*[:{]|\bcatch\s*\(", code
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Async flow may create unhandled rejection/exception paths",
                    "fix": "Attach .catch()/try-except handling for every async side effect.",
                }
            )
        return {"findings": findings, "total_issues": len(findings)}

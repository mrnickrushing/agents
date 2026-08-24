"""Flow audit agent for async/state-machine reliability checks."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent


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
        if re.search(r"oauth|authorize|callback", code, re.IGNORECASE):
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
        if re.search(r"upload|multipart|file", code, re.IGNORECASE):
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
        if re.search(
            r"Promise\.all|asyncio\.gather|Thread|concurrent", code
        ) and not re.search(r"lock|mutex|transaction|FOR UPDATE", code, re.IGNORECASE):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Concurrent state updates with no visible lock/transaction guard",
                    "fix": "Protect critical state transitions with row locks, mutexes, or transactional checks.",
                }
            )
        if re.search(r"new Promise|async ", code) and not re.search(
            r"\.catch\(|except|try\s*:", code
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Async flow may create unhandled rejection/exception paths",
                    "fix": "Attach .catch()/try-except handling for every async side effect.",
                }
            )
        return {"findings": findings, "total_issues": len(findings)}

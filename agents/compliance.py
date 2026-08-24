"""
Compliance Audit Agent — maps code patterns to SOC2, HIPAA, GDPR, PCI-DSS controls.

ComplianceAuditAgent runs the existing detector tool handlers and synthesises
results into a compliance report that shows which controls are ✅ met,
⚠️ partial, or ❌ missing.

Usage:
    from agents.compliance import ComplianceAuditAgent
    agent = ComplianceAuditAgent()
    result = agent._audit_compliance(code, standard="SOC2")
    print(result["report"])

CLI:
    python -m agents.cli run compliance audit_compliance \
        --arg standard=SOC2 --file code=src/auth.ts
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent

# ---------------------------------------------------------------------------
# Control definitions
# Each control maps to a list of detector checks.  A check is either:
#   - a plain regex pattern (str) that is applied to the code directly, or
#   - a dict {pattern, negate} where negate=True means *absence* of the
#     pattern is the positive evidence (e.g. "no hardcoded secrets found").
# ---------------------------------------------------------------------------

_FRAMEWORKS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "SOC2": {
        "CC6.1": {
            "name": "Logical Access Control",
            "description": "Only authorized users can access systems and data.",
            "checks": [
                {
                    "pattern": r"jwt\.(sign|verify)\(",
                    "negate": False,
                    "label": "JWT auth present",
                },
                {
                    "pattern": r"oauth|AppleAuthentication|google.*oauth",
                    "negate": False,
                    "label": "OAuth integration present",
                },
                {
                    "pattern": r"x-api-key|requireApiKey|INTERNAL_API_KEY",
                    "negate": False,
                    "label": "API key gate present",
                },
            ],
            "remediation": "Implement OAuth2 or JWT with proper validation on every protected route.",
        },
        "CC6.2": {
            "name": "Cryptography",
            "description": "Sensitive data is encrypted in transit and at rest.",
            "checks": [
                {
                    "pattern": r"https://|ssl:|tls:",
                    "negate": False,
                    "label": "TLS/HTTPS references",
                },
                {
                    "pattern": r"bcrypt|argon2|hashlib\.pbkdf2|sha256",
                    "negate": False,
                    "label": "Password hashing present",
                },
                {
                    "pattern": r"(?i)http://(?!localhost|127\.0\.0\.1)",
                    "negate": True,
                    "label": "No plaintext HTTP to remote hosts",
                },
            ],
            "remediation": "Use TLS for all external connections; hash passwords with bcrypt/argon2.",
        },
        "CC6.7": {
            "name": "Transmission Integrity",
            "description": "Data transmitted over networks is protected.",
            "checks": [
                {
                    "pattern": r"stripe\.webhooks\.constructEvent|svix.*verify",
                    "negate": False,
                    "label": "Webhook signature verification",
                },
                {
                    "pattern": r"hsts|Strict-Transport-Security",
                    "negate": False,
                    "label": "HSTS header present",
                },
            ],
            "remediation": "Verify webhook signatures; enforce HSTS on all HTTP responses.",
        },
        "CC7.2": {
            "name": "Monitoring & Alerting",
            "description": "Security events are monitored and alerted on.",
            "checks": [
                {
                    "pattern": r"sentry_sdk\.init\(|Sentry\.init\(",
                    "negate": False,
                    "label": "Sentry error monitoring",
                },
                {
                    "pattern": r"sendDefaultPii\s*:\s*false",
                    "negate": False,
                    "label": "Sentry PII scrubbing configured",
                },
                {
                    "pattern": r"/health|/ping|/status",
                    "negate": False,
                    "label": "Health endpoint present",
                },
            ],
            "remediation": "Configure Sentry with sendDefaultPii: false and a beforeSend PII hook.",
        },
        "CC8.1": {
            "name": "Change Management",
            "description": "Production changes are authorized and tested.",
            "checks": [
                {
                    "pattern": r"\.github/workflows|ci\.yml|ci\.yaml",
                    "negate": False,
                    "label": "CI pipeline present",
                },
                {
                    "pattern": r"test\s*:|scripts.*test",
                    "negate": False,
                    "label": "Test scripts defined",
                },
            ],
            "remediation": "Require CI checks and passing tests before merging to the main branch.",
        },
    },
    "HIPAA": {
        "164.312(a)(1)": {
            "name": "Access Control",
            "description": "Unique user identification; emergency access; automatic logoff; encryption.",
            "checks": [
                {
                    "pattern": r"jwt\.(sign|verify)\(|Bearer\b",
                    "negate": False,
                    "label": "User authentication tokens",
                },
                {
                    "pattern": r"exp\s*:|exp:\s*\d|expiresIn\s*:",
                    "negate": False,
                    "label": "Token expiry set",
                },
                {
                    "pattern": r"logout|signOut|revoke",
                    "negate": False,
                    "label": "Session termination",
                },
            ],
            "remediation": "Implement unique user IDs, expiring tokens, and session revocation.",
        },
        "164.312(b)": {
            "name": "Audit Controls",
            "description": "Record and examine ePHI system activity.",
            "checks": [
                {
                    "pattern": r"audit_log|auditLog|logger\.(info|warn|error)",
                    "negate": False,
                    "label": "Audit logging present",
                },
                {
                    "pattern": r"winston|pino|structlog",
                    "negate": False,
                    "label": "Structured logging library",
                },
            ],
            "remediation": "Log all access to ePHI with user ID, timestamp, and action.",
        },
        "164.312(e)(2)(ii)": {
            "name": "Encryption in Transit",
            "description": "Encrypt ePHI in transit.",
            "checks": [
                {
                    "pattern": r"https://|ssl:|tls:",
                    "negate": False,
                    "label": "HTTPS/TLS references",
                },
                {
                    "pattern": r"(?i)http://(?!localhost|127\.0\.0\.1)",
                    "negate": True,
                    "label": "No HTTP to remote endpoints",
                },
            ],
            "remediation": "Use HTTPS for all data transmission; disable HTTP fallback.",
        },
    },
    "GDPR": {
        "Art.25": {
            "name": "Data Protection by Design",
            "description": "Privacy-by-default must be implemented from the start.",
            "checks": [
                {
                    "pattern": r"sensitive_data|@sensitive|pii|personally.identifiable",
                    "negate": False,
                    "label": "PII tagging present",
                },
                {
                    "pattern": r"sendDefaultPii\s*:\s*false|beforeSend",
                    "negate": False,
                    "label": "PII scrubbing in error reporting",
                },
            ],
            "remediation": "Tag PII fields; configure error reporters to strip sensitive data.",
        },
        "Art.32": {
            "name": "Security of Processing",
            "description": "Appropriate technical and organisational measures to ensure security.",
            "checks": [
                {
                    "pattern": r"bcrypt|argon2|sha256",
                    "negate": False,
                    "label": "Password/data hashing",
                },
                {
                    "pattern": r"jwt\.(sign|verify)\(|oauth",
                    "negate": False,
                    "label": "Authentication present",
                },
                {
                    "pattern": r"https://|tls:",
                    "negate": False,
                    "label": "Transport encryption",
                },
            ],
            "remediation": "Encrypt personal data in transit and at rest; enforce authentication.",
        },
        "Art.33": {
            "name": "Breach Notification Readiness",
            "description": "Ability to detect and report breaches within 72 hours.",
            "checks": [
                {
                    "pattern": r"sentry_sdk\.init\(|Sentry\.init\(|pagerduty|opsgenie|alertmanager",
                    "negate": False,
                    "label": "Incident monitoring present",
                },
                {
                    "pattern": r"audit_log|access_log|security.log",
                    "negate": False,
                    "label": "Audit trail logging",
                },
            ],
            "remediation": "Configure incident alerting and maintain access logs with sufficient retention.",
        },
    },
    "PCI-DSS": {
        "Req.2": {
            "name": "Secure Configurations",
            "description": "Do not use vendor-supplied defaults for system passwords.",
            "checks": [
                {
                    "pattern": r"(?i)password\s*[:=]\s*['\"](?:admin|password|1234|default|changeme)",
                    "negate": True,
                    "label": "No default passwords",
                },
                {
                    "pattern": r"helmet\(|cors\(",
                    "negate": False,
                    "label": "Security headers configured",
                },
            ],
            "remediation": "Change all default credentials and harden HTTP security headers.",
        },
        "Req.6": {
            "name": "Secure Software Development",
            "description": "Protect systems against known vulnerabilities.",
            "checks": [
                {
                    "pattern": r"npm\s+audit|safety\s+check|trivy|snyk",
                    "negate": False,
                    "label": "Dependency vulnerability scanning",
                },
                {
                    "pattern": r"z\.object\(|Joi\.object\(|validate\(|sanitize\(",
                    "negate": False,
                    "label": "Input validation present",
                },
            ],
            "remediation": "Integrate dependency scanning in CI; validate all user inputs.",
        },
        "Req.8": {
            "name": "Identity & Access Management",
            "description": "Identify users and authenticate before granting access.",
            "checks": [
                {
                    "pattern": r"jwt\.(sign|verify)\(|passport|OAuth2",
                    "negate": False,
                    "label": "Authentication library",
                },
                {
                    "pattern": r"rate.?limit|throttle|rateLimit",
                    "negate": False,
                    "label": "Brute-force protection",
                },
                {
                    "pattern": r"bcrypt|argon2",
                    "negate": False,
                    "label": "Password hashing present",
                },
            ],
            "remediation": "Use strong authentication, rate limiting, and proper password hashing.",
        },
    },
}


class ComplianceAuditAgent(BaseAgent):
    """
    Maps code patterns to SOC2, HIPAA, GDPR, PCI-DSS compliance controls.

    Runs deterministic checks (no LLM required) and produces a structured
    report showing which controls are fully met, partially met, or missing.
    """

    name = "compliance"
    description = "Maps code patterns to SOC2/HIPAA/GDPR/PCI-DSS compliance controls."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "audit_compliance",
                "description": "Audit code against a compliance framework (SOC2/HIPAA/GDPR/PCI-DSS).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Source code or config to audit",
                        },
                        "standard": {
                            "type": "string",
                            "enum": ["SOC2", "HIPAA", "GDPR", "PCI-DSS"],
                            "description": "Compliance framework to check against",
                        },
                    },
                    "required": ["code", "standard"],
                },
            },
            {
                "name": "list_frameworks",
                "description": "List supported compliance frameworks and their controls.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "audit_compliance": self._audit_compliance,
            "list_frameworks": self._list_frameworks,
        }

    # ── Tool handlers ─────────────────────────────────────────────────

    def _audit_compliance(self, code: str, standard: str = "SOC2") -> Dict[str, Any]:
        """Run compliance checks against ``code`` for the given ``standard``."""
        framework = _FRAMEWORKS.get(standard.upper())
        if framework is None:
            return {
                "error": f"Unknown standard '{standard}'. Supported: {', '.join(_FRAMEWORKS)}",
                "findings": [],
            }

        results: List[Dict[str, Any]] = []
        total_met = 0
        total_partial = 0
        total_missing = 0

        for control_id, control in framework.items():
            checks_passed: List[str] = []
            checks_failed: List[str] = []

            for check in control["checks"]:
                pattern = check["pattern"]
                negate = check.get("negate", False)
                label = check["label"]
                matched = bool(re.search(pattern, code, re.IGNORECASE | re.DOTALL))
                positive = (not matched) if negate else matched
                if positive:
                    checks_passed.append(label)
                else:
                    checks_failed.append(label)

            total = len(control["checks"])
            passed = len(checks_passed)

            if passed == total:
                status = "MET"
                severity = None
                total_met += 1
            elif passed == 0:
                status = "MISSING"
                severity = "HIGH"
                total_missing += 1
            else:
                status = "PARTIAL"
                severity = "MEDIUM"
                total_partial += 1

            entry: Dict[str, Any] = {
                "control_id": control_id,
                "name": control["name"],
                "description": control["description"],
                "status": status,
                "checks_passed": checks_passed,
                "checks_failed": checks_failed,
            }
            if severity:
                entry["severity"] = severity
                entry["remediation"] = control["remediation"]
            results.append(entry)

        findings = [
            {
                "severity": r["severity"],
                "issue": f"{standard} {r['control_id']} ({r['name']}): {r['status']}",
                "fix": r.get("remediation", ""),
            }
            for r in results
            if r.get("severity")
        ]

        return {
            "standard": standard,
            "controls": results,
            "findings": findings,
            "summary": {
                "total": len(results),
                "met": total_met,
                "partial": total_partial,
                "missing": total_missing,
            },
            "total_issues": len(findings),
        }

    def _list_frameworks(self) -> Dict[str, Any]:
        """Return all supported frameworks and their controls."""
        out: Dict[str, Any] = {}
        for std, framework in _FRAMEWORKS.items():
            out[std] = {cid: ctrl["name"] for cid, ctrl in framework.items()}
        return {"frameworks": out}

"""
Incident Postmortem Agent — analyses past incidents, maps them to detector
coverage, and suggests structural prevention changes.

PostmortemAgent takes a plain-text incident description (or structured dict),
queries the evolution store for similar historical findings, and synthesises:

- Which existing detectors would have caught it
- Which detectors need enhancement
- Structural code changes that prevent recurrence
- Prevention confidence rating

Usage:
    from agents.postmortem import PostmortemAgent
    agent = PostmortemAgent()
    result = agent._analyze_incident(incident_text, code)
    print(result["prevention_confidence"])
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent

# ---------------------------------------------------------------------------
# Pattern library: incident keyword → detectors that would cover it
# ---------------------------------------------------------------------------

_DETECTOR_COVERAGE: List[Dict[str, Any]] = [
    {
        "keywords": [
            "n+1",
            "n plus 1",
            "query inside loop",
            "connection pool",
            "connection leak",
        ],
        "detector": "database_architect.review_n_plus_one",
        "description": "Detects loops with DB queries inside",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": ["sql injection", "raw query", "string interpolation", "query raw"],
        "detector": "security_audit.audit_sql_injection",
        "description": "Detects unsanitised SQL queries",
        "severity": "CRITICAL",
        "enhancement": None,
    },
    {
        "keywords": [
            "jwt",
            "token not validated",
            "missing exp",
            "algorithm confusion",
        ],
        "detector": "auth_security.review_refresh_token_rotation",
        "description": "Detects JWT algorithm confusion and missing expiry",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": ["rate limit", "brute force", "too many requests", "429"],
        "detector": "api_architect.review_rate_limit_contract",
        "description": "Detects missing rate-limit response contracts",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": ["webhook", "idempotency", "duplicate event", "replay"],
        "detector": "flow_audit.audit_flow_logic",
        "description": "Detects missing idempotency guards on payment/webhook flows",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": [
            "health check",
            "404 health",
            "healthcheck",
            "health endpoint missing",
        ],
        "detector": "infra_monitor.audit_health_check_endpoint",
        "description": "Detects shallow health checks (doesn't verify DB pool)",
        "severity": "MEDIUM",
        "enhancement": "Add connection pool saturation check to health endpoint",
    },
    {
        "keywords": ["retry", "thundering herd", "no backoff", "retry storm"],
        "detector": "flow_audit.audit_flow_logic",
        "description": "Detects retry logic with no exponential backoff",
        "severity": "MEDIUM",
        "enhancement": "Add jitter and exponential backoff to all retry loops",
    },
    {
        "keywords": ["cors", "cross-origin", "origin header"],
        "detector": "security_audit.audit_cors_config",
        "description": "Detects permissive CORS configurations",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": [
            "hardcoded secret",
            "api key",
            "password in code",
            "committed secret",
        ],
        "detector": "security_audit.audit_hardcoded_secrets",
        "description": "Detects hardcoded credentials in source code",
        "severity": "CRITICAL",
        "enhancement": None,
    },
    {
        "keywords": ["file upload", "malicious upload", "path traversal"],
        "detector": "security_audit.audit_file_upload",
        "description": "Detects missing upload validation",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": ["xss", "dangerouslysetinnerhtml", "innerhtml", "script injection"],
        "detector": "security_audit.audit_xss_patterns",
        "description": "Detects XSS injection points",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": ["migration", "drop column", "alter table", "schema change"],
        "detector": "database_architect.review_migration_safety",
        "description": "Detects unsafe migration operations",
        "severity": "HIGH",
        "enhancement": None,
    },
    {
        "keywords": ["sentry", "error reporting", "unhandled exception", "crash"],
        "detector": "infra_monitor.review_sentry_setup",
        "description": "Detects missing or misconfigured Sentry error tracking",
        "severity": "MEDIUM",
        "enhancement": None,
    },
]

# Structural code changes recommended by incident type
_STRUCTURAL_RECOMMENDATIONS: List[Dict[str, Any]] = [
    {
        "keywords": ["n+1", "connection pool", "query inside loop"],
        "title": "Circuit Breaker Pattern",
        "confidence": "HIGH",
        "description": "Prevents cascade when database becomes slow",
        "code_example": "@circuit_breaker(failure_threshold=5, timeout=60)\nasync def fetch_user(user_id): ...",
        "effort": "2 hours",
    },
    {
        "keywords": ["n+1", "connection pool", "slow query"],
        "title": "Alert on Slow Queries",
        "confidence": "HIGH",
        "description": "Alert before pool exhaustion via query timing",
        "code_example": "# Set DB query timeout alert: any query > 100ms",
        "effort": "1 hour",
    },
    {
        "keywords": ["retry", "thundering herd", "backoff"],
        "title": "Exponential Backoff with Jitter",
        "confidence": "HIGH",
        "description": "Prevents retry storms from cascading",
        "code_example": "delay = min(base * 2**attempt + random.uniform(0, 1), max_delay)",
        "effort": "1 hour",
    },
    {
        "keywords": ["webhook", "idempotency", "duplicate"],
        "title": "Idempotency Key Tracking",
        "confidence": "HIGH",
        "description": "Prevents duplicate processing of events",
        "code_example": "if await db.exists('processed_events', event_id=event.id):\n    return 200",
        "effort": "2 hours",
    },
    {
        "keywords": ["jwt", "token", "auth"],
        "title": "Token Rotation & Revocation",
        "confidence": "HIGH",
        "description": "Limits blast radius of token theft",
        "code_example": "# Store refresh token hash; revoke entire family on reuse detection",
        "effort": "3 hours",
    },
]


class PostmortemAgent(BaseAgent):
    """
    Analyses incident descriptions, maps them to existing detector coverage,
    identifies gaps, and recommends structural prevention changes.
    """

    name = "postmortem"
    description = "Analyses incidents, identifies detector coverage gaps, and recommends structural prevention changes."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "analyze_incident",
                "description": "Analyze an incident description against detector coverage.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "incident_text": {
                            "type": "string",
                            "description": "Plain-text incident description or structured JSON",
                        },
                        "code": {
                            "type": "string",
                            "description": "Relevant source code (optional)",
                        },
                    },
                    "required": ["incident_text"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"analyze_incident": self._analyze_incident}

    # ── Tool handlers ─────────────────────────────────────────────────

    def _analyze_incident(
        self,
        incident_text: str,
        code: str = "",
    ) -> Dict[str, Any]:
        """
        Parse an incident description and return detector coverage + recommendations.
        """
        lower = incident_text.lower()

        # Match detectors
        covered: List[Dict[str, Any]] = []
        covered_with_enhancement: List[Dict[str, Any]] = []
        not_covered_keywords: List[str] = []

        matched_detectors: set = set()
        for entry in _DETECTOR_COVERAGE:
            if any(kw in lower for kw in entry["keywords"]):
                if entry["detector"] in matched_detectors:
                    continue
                matched_detectors.add(entry["detector"])
                if entry["enhancement"]:
                    covered_with_enhancement.append(
                        {
                            "detector": entry["detector"],
                            "description": entry["description"],
                            "enhancement": entry["enhancement"],
                            "severity": entry["severity"],
                        }
                    )
                else:
                    covered.append(
                        {
                            "detector": entry["detector"],
                            "description": entry["description"],
                            "severity": entry["severity"],
                        }
                    )

        # Gaps: keywords that appear in the incident but match no detector
        all_detector_keywords = {kw for e in _DETECTOR_COVERAGE for kw in e["keywords"]}
        incident_words = set(re.findall(r"\b\w+\b", lower))
        unmatched_technical = incident_words & {
            "async",
            "concurrent",
            "race",
            "deadlock",
            "cache",
            "redis",
            "queue",
            "worker",
            "cron",
            "scheduler",
            "timeout",
        }
        for word in sorted(unmatched_technical):
            if word not in " ".join(all_detector_keywords):
                not_covered_keywords.append(word)

        # Structural recommendations
        recommendations: List[Dict[str, Any]] = []
        seen_titles: set = set()
        for rec in _STRUCTURAL_RECOMMENDATIONS:
            if any(kw in lower for kw in rec["keywords"]):
                if rec["title"] not in seen_titles:
                    recommendations.append(rec)
                    seen_titles.add(rec["title"])

        # Prevention confidence
        total_signals = len(covered) + len(covered_with_enhancement)
        gap_signals = len(not_covered_keywords)
        if total_signals == 0:
            prevention_confidence = 0
        else:
            prevention_confidence = min(
                100,
                int(
                    (total_signals / max(total_signals + gap_signals, 1)) * 100
                    + len(recommendations) * 5
                ),
            )

        findings = []
        for gap in not_covered_keywords:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": f"No detector covers '{gap}' pattern found in incident",
                    "fix": f"Consider adding a detector for '{gap}' failure mode.",
                }
            )

        return {
            "detectors_would_catch": covered,
            "detectors_need_enhancement": covered_with_enhancement,
            "coverage_gaps": not_covered_keywords,
            "structural_recommendations": recommendations,
            "prevention_confidence": prevention_confidence,
            "findings": findings,
            "total_issues": len(findings),
            "summary": (
                f"{len(covered)} detector(s) would have caught this incident; "
                f"{len(covered_with_enhancement)} need enhancement; "
                f"{len(not_covered_keywords)} gap(s) identified."
            ),
        }

"""
Infra Monitor Agent — Sentry setup, health-check depth, and alert design.

Complements RailwayDeployAgent's deployment_checklist (which just asks "is
Sentry configured?") with a real review of *how* it's configured, plus
whether a health-check endpoint actually verifies dependencies or just
unconditionally returns 200.

Usage:
    from agents import InfraMonitorAgent
    agent = InfraMonitorAgent(api_key="sk-...")
    result = agent.run("Review my Sentry init call")
    print(result.content)
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class InfraMonitorAgent(BaseAgent):
    """
    Observability specialist: Sentry configuration, health checks, alerting.
    """

    name = "infra_monitor"
    description = "Reviews Sentry setup (DSN handling, sampling, PII), health-check depth, and designs alert rules."
    model = "gpt-5"

    system_prompt = """\
You are an observability specialist for solo full-stack operators running on Railway/Vercel with Sentry for error monitoring.

YOUR DOMAIN:

1. SENTRY SETUP
   - DSN loaded from an env var/settings object, never hardcoded (it's not secret, but hardcoding it makes per-environment routing impossible)
   - environment tag set (dev/staging/production) so events can be filtered
   - tracesSampleRate set deliberately — 1.0 (sample everything) is fine for low-traffic apps but gets expensive and noisy as traffic grows
   - PII handling explicit: sendDefaultPii/send_default_pii off (or scrubbed via beforeSend) for apps handling sensitive data — this stack includes health data, financial/security data, and message content depending on the app

2. HEALTH CHECKS
   - A /health endpoint that unconditionally returns 200 tells you the process is alive, not that the app actually works — it should check the dependencies that matter (DB connection, Redis if used)
   - Distinguish liveness (is the process running) from readiness (can it actually serve traffic)

3. ALERTING
   - Error rate spikes, not just individual errors
   - Latency (p95/p99) on critical paths, especially AI/LLM calls which can silently degrade
   - Payment failure rate (Stripe) — a payment-processing outage is often invisible to generic error-rate alerts if failures return non-500 responses
   - Cost-relevant alerts for anything metered (AI API spend, SMS, email sends)

When reviewing, cite the exact config field that's missing or risky and give the exact fix.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_sentry_setup",
                "description": "Review a Sentry.init()/sentry_sdk.init() call for DSN handling, sampling, and PII configuration.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Sentry initialization code"},
                        "handles_sensitive_data": {"type": "boolean", "description": "Whether this app handles health/financial/security-sensitive data"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_health_check_endpoint",
                "description": "Audit a health-check endpoint for whether it actually verifies dependencies (DB/Redis) or just unconditionally returns 200.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The health-check route handler code"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_error_boundary_coverage",
                "description": "Review a React root layout for error boundary coverage.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The root layout/App component code"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "generate_alert_rules",
                "description": "Generate suggested alert rules for a given service.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "service_type": {"type": "string", "enum": ["web_api", "mobile_backend", "saas_platform"]},
                        "has_stripe": {"type": "boolean"},
                        "has_ai": {"type": "boolean", "description": "Whether the service makes LLM/AI API calls"},
                    },
                    "required": ["service_type"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_sentry_setup": self._review_sentry_setup,
            "audit_health_check_endpoint": self._audit_health_check_endpoint,
            "review_error_boundary_coverage": self._review_error_boundary_coverage,
            "generate_alert_rules": self._generate_alert_rules,
        }

    def _review_sentry_setup(self, code: str, handles_sensitive_data: bool = True) -> Dict[str, Any]:
        """Review Sentry initialization config."""
        findings = []

        if not re.search(r"sentry_sdk\.init\(|Sentry\.init\(", code):
            return {"findings": [], "total_issues": 0, "note": "No Sentry.init() call found in this snippet"}

        if re.search(r"dsn\s*[:=]\s*[\"']https://[a-f0-9]+@", code, re.IGNORECASE):
            findings.append({"severity": "LOW", "issue": "DSN appears hardcoded as a literal string rather than loaded from env/settings — not secret, but makes per-environment routing (dev vs prod projects) harder to manage", "fix": "Load the DSN from an environment variable / settings object instead of a literal string"})

        if not re.search(r"environment\s*[:=]", code):
            findings.append({"severity": "LOW", "issue": "No environment tag set — events from dev/staging/production will be mixed together in Sentry", "fix": "Set environment: process.env.NODE_ENV (Node) or environment=settings.ENVIRONMENT (Python)"})

        if not re.search(r"traces?_?sample_?rate\s*[:=]", code, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "No tracesSampleRate set — performance tracing is likely off entirely (or defaulting in a way that's not explicit)", "fix": "Set tracesSampleRate explicitly (e.g. 0.1 for production, 1.0 is fine for low-traffic apps)"})
        elif re.search(r"traces?_?sample_?rate\s*[:=]\s*1(\.0)?\b", code, re.IGNORECASE):
            findings.append({"severity": "INFO", "issue": "tracesSampleRate is 1.0 (sampling every transaction) — fine for low traffic, but will get expensive/noisy as traffic grows", "fix": "Consider lowering to 0.1-0.2 once traffic increases"})

        if handles_sensitive_data:
            pii_off = re.search(r"send_?default_?pii\s*[:=]\s*false", code, re.IGNORECASE)
            has_before_send = "beforeSend" in code
            if not pii_off and not has_before_send:
                findings.append({"severity": "HIGH", "issue": "This app handles sensitive data but Sentry has no explicit sendDefaultPii=false or beforeSend scrubbing — request bodies/user data could end up in Sentry events", "fix": "Set sendDefaultPii: false, and/or add a beforeSend hook to strip sensitive fields before events are sent"})

        return {"findings": findings, "total_issues": len(findings)}

    def _audit_health_check_endpoint(self, code: str) -> Dict[str, Any]:
        """Audit whether a health check verifies real dependencies."""
        findings = []

        if not re.search(r"/health|/healthz|/ping|/status", code):
            return {"findings": [], "total_issues": 0, "note": "No health-check route found in this snippet"}

        checks_db = bool(re.search(r"\bdb\.(query|execute|ping)|pool\.query|session\.execute|SELECT 1", code, re.IGNORECASE))
        checks_redis = bool(re.search(r"redis\.ping|redis\.get|redisClient\.", code, re.IGNORECASE))
        uses_redis_elsewhere = bool(re.search(r"createClient\(|redis://|REDIS_URL", code, re.IGNORECASE))

        if not checks_db:
            findings.append({"severity": "MEDIUM", "issue": "Health check doesn't appear to verify the database connection — it can return 200 while the DB is unreachable", "fix": "Run a trivial query (SELECT 1) against the DB in the health check and return 503 if it fails/times out"})
        if uses_redis_elsewhere and not checks_redis:
            findings.append({"severity": "LOW", "issue": "Redis is used elsewhere in this service but the health check doesn't verify it", "fix": "Add a redis.ping() check if Redis is required for the service to function"})

        return {"findings": findings, "total_issues": len(findings)}

    def _review_error_boundary_coverage(self, code: str) -> Dict[str, Any]:
        """Review error boundary coverage in a React root layout."""
        findings = []

        if not re.search(r"ErrorBoundary|componentDidCatch|error\.tsx|error\.jsx", code):
            findings.append({"severity": "MEDIUM", "issue": "No ErrorBoundary found — an uncaught render error will blank the whole screen instead of showing a fallback UI", "fix": "Wrap the app (or key sections) in an ErrorBoundary (Sentry.ErrorBoundary if using Sentry, or a custom one) with a fallback UI"})

        return {"findings": findings, "total_issues": len(findings)}

    def _generate_alert_rules(self, service_type: str = "web_api", has_stripe: bool = False, has_ai: bool = False) -> Dict[str, Any]:
        """Generate suggested alert rules."""
        rules = [
            {"name": "Error rate spike", "condition": "Error rate > 5% of requests over 5 minutes", "severity": "HIGH"},
            {"name": "p95 latency", "condition": "p95 response time > 2s over 5 minutes on any critical route", "severity": "MEDIUM"},
            {"name": "Health check failing", "condition": "Health check endpoint returns non-200 for > 2 consecutive checks", "severity": "CRITICAL"},
        ]
        if has_stripe:
            rules.append({"name": "Payment failure rate", "condition": "Stripe webhook processing failures > 3 in 10 minutes (payment outages often don't surface as generic 500 errors)", "severity": "CRITICAL"})
        if has_ai:
            rules.append({"name": "AI call failure/latency", "condition": "LLM API error rate > 10% or p95 latency > 10s (silent degradation is common with third-party AI APIs)", "severity": "HIGH"})
            rules.append({"name": "AI spend anomaly", "condition": "Daily AI API spend exceeds 2x the trailing 7-day average", "severity": "MEDIUM"})
        if service_type == "mobile_backend":
            rules.append({"name": "Push notification delivery failure rate", "condition": "Expo push delivery failures > 10% over 1 hour", "severity": "MEDIUM"})

        return {"service_type": service_type, "rules": rules, "total_rules": len(rules)}

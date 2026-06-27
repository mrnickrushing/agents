"""
Security Audit Agent — Helmet, OWASP, rate limiting, JWT, secrets, and hardening
for Node/Express and React Native/Expo apps.

This agent specializes in the exact security stack you ship with every build:
Helmet.js configuration, rate limiting, JWT auth, CSRF protection,
parameterized queries, secrets management, dependency scanning, and pen-test prep.

Usage:
    from agents import SecurityAuditAgent
    agent = SecurityAuditAgent(api_key="sk-...")
    result = agent.run("Audit my Express app — here's my helmet config: ...")
    print(result.content)
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class SecurityAuditAgent(BaseAgent):
    """
    Security hardening and audit agent for Node/Express, React, and React Native apps.

    Knows Helmet.js inside out, OWASP Top 10 by heart, JWT best practices,
    rate limiting strategies, Stripe webhook signature verification,
    and the deployment security patterns used on Railway and Vercel.
    """

    name = "security_audit"
    description = "Audits and hardens Node/Express, React, and React Native apps for OWASP Top 10, Helmet misconfigurations, JWT vulnerabilities, rate limiting gaps, and deployment security."
    model = "gpt-5"

    system_prompt = """\
You are a senior cybersecurity practitioner and security audit specialist. You audit and harden web applications, mobile apps, and SaaS platforms built with the following stack:

- Node.js / Express backends with Helmet.js, rate limiting, JWT auth
- React 19 / TypeScript frontends
- React Native / Expo mobile apps with Apple Sign-In, Face ID, RevenueCat
- SQLite (better-sqlite3) and PostgreSQL with Drizzle ORM
- Stripe billing with webhook-driven lifecycle
- Railway and Vercel deployments
- Cloudflare Workers for edge delivery

Your audit framework covers:

1. HELMET.JS CONFIGURATION
   - Content-Security-Policy: Are all directives locked down? Are there unsafe-inline or unsafe-eval gaps? Is frame-ancestors set?
   - Strict-Transport-Security: Is max-age >= 31536000? Are includeSubDomains and preload set?
   - X-Content-Type-Options: Is nosniff enabled?
   - X-Frame-Options: Is DENY or SAMEORIGIN set?
   - Referrer-Policy: Is it strict-origin-when-cross-origin or stricter?
   - Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy / Cross-Origin-Resource-Policy: Are these configured?

2. JWT AUTHENTICATION
   - Are tokens signed with RS256 or ES256 (not HS256 with weak secrets)?
   - Is token expiration set (access <= 15min, refresh <= 7d)?
   - Are refresh tokens stored in httpOnly secure cookies, not localStorage?
   - Is there a token revocation/blacklist mechanism?
   - Are JWT claims validated (iss, aud, exp, iat)?

3. RATE LIMITING
   - Is rate limiting applied to auth endpoints (login, register, password reset)?
   - Are limits appropriate (e.g., 5 attempts / 15min for login)?
   - Is there protection against brute force on API endpoints?
   - Are rate limits enforced server-side, not client-trusted?

4. CSRF PROTECTION
   - Is CSRF token validation enabled for state-changing operations?
   - Are SameSite cookies configured properly?
   - Does the app validate Origin/Referer headers?

5. INPUT VALIDATION & INJECTION
   - Are all inputs validated with Zod/Joi at the API boundary?
   - Are SQL queries parameterized (never string interpolation)?
   - Is there XSS protection (output encoding, CSP headers)?
   - Are file uploads validated (type, size, content)?

6. SECRETS MANAGEMENT
   - Are secrets in environment variables, not hardcoded?
   - Is .env in .gitignore?
   - Are Stripe webhook secrets verified?
   - Are JWT signing keys rotated?

7. DEPENDENCY SECURITY
   - Are dependencies scanned with npm audit / Snyk / Dependabot?
   - Are critical CVEs patched?
   - Is the dependency tree minimal (no unnecessary packages)?

8. DEPLOYMENT SECURITY
   - Are Railway/Vercel environment variables encrypted at rest?
   - Is the app served over HTTPS only?
   - Are CORS origins restricted to known domains?
   - Is there error monitoring (Sentry) without leaking secrets?
   - Are debug routes and stack traces disabled in production?

9. OWASP TOP 10 COVERAGE
   - A01: Broken Access Control — RBAC enforced server-side?
   - A02: Cryptographic Failures — TLS 1.2+, no weak ciphers?
   - A03: Injection — Parameterized queries everywhere?
   - A04: Insecure Design — Threat modeling done?
   - A05: Security Misconfiguration — Defaults hardened?
   - A06: Vulnerable Components — Dependency scanning?
   - A07: Auth Failures — MFA, account lockout, strong passwords?
   - A08: Data Integrity Failures — CI/CD pipeline security?
   - A09: Logging Failures — Audit trail for sensitive operations?
   - A10: SSRF — URL validation, allowlists?

10. MOBILE-SPECIFIC SECURITY
    - Is Apple Sign-In token validated server-side?
    - Are tokens stored in iOS Keychain / Android Keystore?
    - Is Face ID / biometric auth using proper APIs?
    - Is certificate pinning implemented for API calls?
    - Are deep links validated and sanitized?
    - Is RevenueCat receipt validation server-side?

When auditing code or configs, always:
- Identify the specific vulnerability by OWASP category
- Rate severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Provide the exact fix with code
- Explain WHY it matters, not just WHAT to change
- Reference the specific Helmet header, OWASP control, or CVE when relevant

Format findings as structured reports with severity, location, description, and remediation.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "analyze_helmet_config",
                "description": "Analyze a Helmet.js configuration object for security gaps. Provide the config as a JSON string.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "config_json": {
                            "type": "string",
                            "description": "The Helmet configuration object as a JSON string"
                        },
                        "framework": {
                            "type": "string",
                            "enum": ["express", "fastify", "koa"],
                            "description": "The Node.js framework being used"
                        }
                    },
                    "required": ["config_json"]
                }
            },
            {
                "name": "check_jwt_implementation",
                "description": "Audit a JWT implementation for common vulnerabilities. Provide the auth code or config.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The JWT/auth implementation code to audit"
                        },
                        "concerns": {
                            "type": "string",
                            "description": "Specific concerns to focus on (e.g., 'token storage', 'key rotation', 'refresh flow')"
                        }
                    },
                    "required": ["code"]
                }
            },
            {
                "name": "scan_dependencies",
                "description": "Analyze a package.json for known vulnerable dependencies.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "package_json": {
                            "type": "string",
                            "description": "The contents of package.json"
                        },
                        "severity_threshold": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                            "description": "Minimum severity to report"
                        }
                    },
                    "required": ["package_json"]
                }
            },
            {
                "name": "audit_cors_config",
                "description": "Audit CORS configuration for overly permissive settings.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cors_code": {
                            "type": "string",
                            "description": "The CORS configuration code"
                        },
                        "allowed_origins": {
                            "type": "string",
                            "description": "List of allowed origins (comma-separated)"
                        }
                    },
                    "required": ["cors_code"]
                }
            },
            {
                "name": "generate_helmet_config",
                "description": "Generate a production-ready Helmet.js configuration for a given deployment scenario.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "app_type": {
                            "type": "string",
                            "enum": ["spa", "ssr", "api_only", "saas_platform"],
                            "description": "Type of application"
                        },
                        "domains": {
                            "type": "string",
                            "description": "Comma-separated list of trusted domains"
                        },
                        "cdn_used": {
                            "type": "boolean",
                            "description": "Whether the app uses a CDN (Cloudflare, etc.)"
                        },
                        "stripe_enabled": {
                            "type": "boolean",
                            "description": "Whether Stripe.js is used (affects CSP)"
                        }
                    },
                    "required": ["app_type"]
                }
            },
            {
                "name": "audit_rate_limiting",
                "description": "Audit rate limiting configuration for common Express API endpoints.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "endpoints": {
                            "type": "string",
                            "description": "JSON string describing endpoints and their rate limit configs"
                        },
                        "backend_framework": {
                            "type": "string",
                            "enum": ["express", "fastify"],
                            "description": "Backend framework in use"
                        }
                    },
                    "required": ["endpoints"]
                }
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "analyze_helmet_config": self._analyze_helmet_config,
            "check_jwt_implementation": self._check_jwt_implementation,
            "scan_dependencies": self._scan_dependencies,
            "audit_cors_config": self._audit_cors_config,
            "generate_helmet_config": self._generate_helmet_config,
            "audit_rate_limiting": self._audit_rate_limiting,
        }

    # ── Tool handlers ──────────────────────────────────────────────────

    def _analyze_helmet_config(self, config_json: str, framework: str = "express") -> Dict[str, Any]:
        """Analyze Helmet config — returns structured findings."""
        try:
            config = json.loads(config_json)
        except json.JSONDecodeError:
            config = {"raw": config_json}

        findings = []
        checks = {
            "contentSecurityPolicy": "CSP is not configured — allows inline scripts and styles from any source",
            "hsts": "HSTS is not set — browsers won't enforce HTTPS",
            "noSniff": "X-Content-Type-Options is missing — browsers may MIME-sniff responses",
            "xFrameOptions": "X-Frame-Options is missing — app may be clickjacked",
            "referrerPolicy": "Referrer-Policy is not set — full URLs may leak to third parties",
            "crossOriginOpenerPolicy": "COOP is not set — cross-origin isolation is incomplete",
            "crossOriginEmbedderPolicy": "COEP is not set — SharedArrayBuffer and Spectre mitigations are missing",
            "crossOriginResourcePolicy": "CORP is not set — resources may be loaded cross-origin",
        }

        for key, warning in checks.items():
            if key not in config:
                findings.append({"severity": "MEDIUM", "setting": key, "issue": warning})

        # Check for dangerously permissive CSP
        if "contentSecurityPolicy" in config:
            csp = config["contentSecurityPolicy"]
            if isinstance(csp, dict) and "directives" in csp:
                directives = csp["directives"]
                if directives.get("scriptSrc") and "'unsafe-inline'" in str(directives.get("scriptSrc", [])):
                    findings.append({"severity": "HIGH", "setting": "contentSecurityPolicy.scriptSrc", "issue": "CSP allows unsafe-inline scripts — XSS risk"})
                if directives.get("scriptSrc") and "'unsafe-eval'" in str(directives.get("scriptSrc", [])):
                    findings.append({"severity": "HIGH", "setting": "contentSecurityPolicy.scriptSrc", "issue": "CSP allows unsafe-eval — code injection risk"})

        return {"framework": framework, "findings": findings, "total_issues": len(findings)}

    def _check_jwt_implementation(self, code: str, concerns: str = "") -> Dict[str, Any]:
        """Check JWT code for common vulnerabilities."""
        findings = []
        code_lower = code.lower()

        if "hs256" in code_lower or "hmac" in code_lower:
            findings.append({"severity": "HIGH", "issue": "Using HS256 (symmetric) — prefer RS256/ES256 (asymmetric) so the signing key isn't shared"})
        if "localstorage" in code_lower or "local storage" in code_lower:
            findings.append({"severity": "CRITICAL", "issue": "JWT stored in localStorage — vulnerable to XSS token theft. Use httpOnly secure cookies."})
        if "expiresin" not in code_lower and "exp" not in code_lower:
            findings.append({"severity": "HIGH", "issue": "No token expiration set — tokens are valid forever"})
        if "verify" not in code_lower:
            findings.append({"severity": "CRITICAL", "issue": "Token verification not found — tokens may not be validated server-side"})
        if "none" in code_lower and "algorithm" in code_lower:
            findings.append({"severity": "CRITICAL", "issue": "Algorithm 'none' detected — this allows unauthenticated token forgery"})
        if concerns:
            findings.append({"severity": "INFO", "issue": f"Specific concern noted: {concerns}"})

        return {"jwt_findings": findings, "total_issues": len(findings)}

    def _scan_dependencies(self, package_json: str, severity_threshold: str = "medium") -> Dict[str, Any]:
        """Scan package.json for known risky patterns."""
        try:
            pkg = json.loads(package_json)
        except json.JSONDecodeError:
            return {"error": "Invalid package.json"}

        findings = []
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

        # Known risky packages
        risky = {
            "express": {"note": "Ensure express is updated to 4.21+ or 5.x for security patches", "severity": "INFO"},
            "helmet": {"note": "If helmet is missing, the app has no security headers", "severity": "HIGH", "if_missing": True},
            "jsonwebtoken": {"note": "Verify you're using RS256/ES256, not HS256 with a weak secret", "severity": "MEDIUM"},
            "bcrypt": {"note": "Ensure bcrypt rounds >= 12 for modern hardware", "severity": "MEDIUM"},
            "cors": {"note": "Ensure origin is not set to '*' in production", "severity": "HIGH"},
            "body-parser": {"note": "Set size limits to prevent denial-of-service via large payloads", "severity": "MEDIUM"},
        }

        if "helmet" not in deps:
            findings.append({"severity": "HIGH", "package": "helmet", "issue": "helmet is not installed — no security headers applied"})

        for name, info in risky.items():
            if name in deps and name != "helmet":
                findings.append({"severity": info["severity"], "package": name, "issue": info["note"]})

        if "cors" in deps:
            findings.append({"severity": "HIGH", "package": "cors", "issue": "cors is installed — verify origin is not '*' in production"})

        return {"dependencies_count": len(deps), "findings": findings, "threshold": severity_threshold}

    def _audit_cors_config(self, cors_code: str, allowed_origins: str = "") -> Dict[str, Any]:
        """Audit CORS configuration."""
        findings = []
        code_lower = cors_code.lower()

        if '"*"' in cors_code or "'*'" in cors_code:
            findings.append({"severity": "CRITICAL", "issue": "CORS origin is '*' — any domain can make requests to this API"})
        if "credentials" in code_lower and "true" in code_lower:
            if '"*"' in cors_code or "'*'" in cors_code:
                findings.append({"severity": "CRITICAL", "issue": "credentials: true with origin: '*' — this combination is actually blocked by browsers, but indicates misconfiguration intent"})
        if "methods" not in code_lower:
            findings.append({"severity": "MEDIUM", "issue": "No methods restriction — all HTTP methods are allowed"})
        if allowed_origins:
            origins = [o.strip() for o in allowed_origins.split(",")]
            non_https = [o for o in origins if o.startswith("http://")]
            if non_https:
                findings.append({"severity": "MEDIUM", "issue": f"Non-HTTPS origins allowed: {non_https}"})

        return {"cors_findings": findings, "total_issues": len(findings)}

    def _generate_helmet_config(self, app_type: str = "saas_platform", domains: str = "", cdn_used: bool = False, stripe_enabled: bool = False) -> Dict[str, Any]:
        """Generate a production Helmet config."""
        trusted_domains = [d.strip() for d in domains.split(",")] if domains else ["'self'"]

        csp_script_src = ["'self'"]
        csp_connect_src = ["'self'"]
        csp_img_src = ["'self'", "data:"]
        csp_frame_src = ["'none'"]
        csp_style_src = ["'self'", "'unsafe-inline'"]  # Most apps need unsafe-inline for styles

        if stripe_enabled:
            csp_script_src.extend(["js.stripe.com"])
            csp_frame_src.append("js.stripe.com")
            csp_connect_src.append("api.stripe.com")

        if cdn_used:
            csp_script_src.append("cdn.jsdelivr.net")
            csp_img_src.append("cdn.jsdelivr.net")

        if app_type == "spa":
            csp_connect_src.append("https:")  # SPAs often call APIs on different domains

        config = {
            "contentSecurityPolicy": {
                "directives": {
                    "defaultSrc": ["'self'"],
                    "scriptSrc": csp_script_src,
                    "styleSrc": csp_style_src,
                    "imgSrc": csp_img_src,
                    "connectSrc": csp_connect_src,
                    "frameSrc": csp_frame_src,
                    "objectSrc": ["'none'"],
                    "baseUri": ["'self'"],
                    "formAction": ["'self'"],
                    "frameAncestors": ["'none'"],
                    "upgradeInsecureRequests": [],
                }
            },
            "hsts": {
                "maxAge": 63072000,  # 2 years
                "includeSubDomains": True,
                "preload": True,
            },
            "noSniff": True,
            "xFrameOptions": {"action": "deny"},
            "referrerPolicy": {"policy": "strict-origin-when-cross-origin"},
            "crossOriginOpenerPolicy": {"policy": "same-origin"},
            "crossOriginEmbedderPolicy": {"policy": "credentialless"},
            "crossOriginResourcePolicy": {"policy": "same-origin"},
            "xContentTypeOptions": True,
            "xXssProtection": False,  # Deprecated, CSP handles this
        }

        return {"helmet_config": config, "app_type": app_type, "stripe_enabled": stripe_enabled}

    def _audit_rate_limiting(self, endpoints: str, backend_framework: str = "express") -> Dict[str, Any]:
        """Audit rate limiting configuration."""
        try:
            endpoint_data = json.loads(endpoints)
        except json.JSONDecodeError:
            return {"error": "Invalid endpoints JSON"}

        recommendations = []
        critical_endpoints = ["login", "register", "password-reset", "forgot-password", "api-key"]

        if isinstance(endpoint_data, list):
            for ep in endpoint_data:
                path = ep.get("path", "")
                limit = ep.get("limit")
                if not limit:
                    recommendations.append({"endpoint": path, "severity": "HIGH", "issue": f"No rate limit on {path}", "recommended": "5 requests per 15 minutes" if any(c in path for c in critical_endpoints) else "100 requests per 15 minutes"})
                elif any(c in path for c in critical_endpoints) and limit > 10:
                    recommendations.append({"endpoint": path, "severity": "MEDIUM", "issue": f"Rate limit too high ({limit}) for sensitive endpoint {path}", "recommended": "5 requests per 15 minutes"})

        return {"framework": backend_framework, "recommendations": recommendations, "total_issues": len(recommendations)}

# Agent Development Status

## ✅ COMPLETED (v2.1.0)

### Reliability / correctness pass
- [x] base.py: `run()` now loops on chained tool calls (max_tool_rounds) instead of stopping after one round trip
- [x] base.py: retry with exponential backoff on transient SDK errors (rate limit, timeout, connection)
- [x] base.py: removed dead `format_messages()` (duplicated `_build_openai_messages`/`_build_anthropic_messages`)
- [x] Fixed brittle substring-matching heuristics that rarely or never fired correctly (same bug class as the
      earlier drizzle/route fix in d1a4760), validated against real Vitality/shield-ai code:
      - `security_audit.check_jwt_implementation`: "exp" substring matched "express"/"expo" and silently
        disabled the expiry check on nearly every file in this stack
      - `security_audit.check_jwt_implementation`: "verify" substring missed Python's `jwt.decode()`, which
        verifies implicitly (no literal "verify" call) — flagged shield-ai's correct decode_token() as unverified
      - `security_audit.check_jwt_implementation`: alg-none check matched the words "none"/"algorithm" anywhere
        (e.g. CSS `display: none`), now requires an actual `algorithms: ["none"]` pattern
      - `stripe_billing.audit_billing_security`: "auth" substring check on customer-update routes, now requires
        an actual auth marker (requireAuth/authenticate/req.user/etc.)
      - `ui_generation.validate_accessibility`: img alt-text regex only checked the attribute immediately
        following `<img`, flagging valid `<img className=... alt=...>` as missing alt; onClick regex only
        matched bare-identifier handlers, missing the far more common arrow-function form; placeholder-as-label
        check fired regardless of whether a real `<label>` existed elsewhere in the component

### Real-scanning capability (previously: hand-built JSON/snippets only)
- [x] `scan_dependencies` auto-detects npm package.json vs Python requirements.txt (shield-ai's backend has no
      package.json at all) and applies ecosystem-appropriate risky-package notes
- [x] `analyze_helmet_config` scans raw source code (`app.use(helmet())`), not just a hand-built config object —
      recognizes bare `helmet()` as using secure defaults instead of flagging every header as "missing"
- [x] `audit_cors_config` recognizes FastAPI/Starlette `CORSMiddleware` (`allow_origins`, `allow_credentials`),
      not just Express `cors()`

### New agents
- [x] AuthSecurityAgent — JWT refresh rotation/reuse detection, Apple Sign-In (nonce/JWKS/issuer/audience),
      Google OAuth CSRF, shared-secret app-gate audit (x-api-key), biometric auth review
- [x] MobileDeployAgent — eas.json review (hardcoded-secret detection), codemagic.yaml code-signing hygiene,
      App Store/Play submission checklist, RevenueCat SDK setup review

### CLI (no API key required)
- [x] `python -m agents.cli list` / `run <agent> <tool>` / `scan --path <project>` — calls tool handlers
      directly for use as a static-analysis toolkit, independent of the LLM planning loop

### Existing agents (from before this pass)
- [x] SecurityAuditAgent, StripeBillingAgent, RailwayDeployAgent, CodeReviewAgent, ScaffolderAgent,
      UIGenerationAgent (Claude-powered, multi-turn, wireframe input)

## 🔄 NOT STARTED

- [ ] APIArchitectAgent — REST API design, OpenAPI specs, pagination, versioning (no project on this box is
      currently blocked on this; lower priority than the above)
- [ ] DatabaseArchitectAgent — schema design, migrations, index optimization (same — lower priority)
- [ ] InfraMonitorAgent — Sentry setup, alert rules, performance monitoring (partially covered today by
      RailwayDeployAgent's deployment_checklist `has_sentry` flag)
- [ ] Real static-analysis integration (shell out to `npm audit`/ESLint/Semgrep and synthesize results) — not
      pursued because Vitality and shield-ai already run Trivy + Semgrep SAST + npm-audit-fix in CI; these
      agents are more valuable adding stack-specific semantic checks generic SAST doesn't know about
      (RevenueCat entitlements, Svix webhook ordering, x-api-key vs JWT auth model) than re-implementing SAST

## NEXT STEPS

- Wire `agents.cli scan` into a pre-commit hook or CI job for Vitality/shield-ai if the manual CLI proves useful
  in practice — not done automatically since it changes the merge gate and wasn't asked for
- Consider an EcommerceAgent (checkout flow, inventory, abandoned cart) for aegisapparel/A-Yard-Apparel/sugarhaus
  if that becomes active work

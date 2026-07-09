# Agent Development Status

## ✅ COMPLETED (v2.2.0)

### New agents
- [x] APIArchitectAgent — pagination affordances, error response shape consistency, status code correctness,
      OpenAPI stub generation
- [x] DatabaseArchitectAgent — index coverage (Drizzle + SQLAlchemy 2.0 `Mapped[]` style), migration safety
      against populated tables (Alembic `add_column`/`drop_column` + raw `ALTER TABLE`), N+1 query detection,
      missing unique constraints
- [x] InfraMonitorAgent — Sentry setup review (DSN/sampling/PII), health-check depth (DB connectivity, not just
      "process is alive"), React error boundary coverage, alert rule generation

### UI Generation Agent, upgraded in parallel on another branch
- [x] Upgraded UIGenerationAgent into a full design-systems-first agent: added `generate_design_system`
      tool (color theory/palette + type/spacing/radius/elevation/motion tokens) and rewrote the system
      prompt around visual craft (hierarchy, micro-interactions, dark-mode-as-first-class-palette,
      restrained use of gradients/glassmorphism), not just component scaffolding
- [x] Replaced the generic `ui-component-generator` Claude Code subagent with `ui-designer` — a
      super-capable visual design persona, mirrored into both this repo and studyit's `.claude/agents/`

### SecurityAuditAgent: implemented the tools the README already promised but the code never delivered
- [x] `audit_sql_injection`, `audit_xss_patterns`, `audit_csrf_protection`, `audit_input_validation`,
      `audit_file_upload`, `audit_websocket_auth` — all validated against real code, calibrated to distinguish
      direct request-input interpolation (CRITICAL) from ambiguous opaque-variable interpolation (MEDIUM,
      "verify") rather than asserting a vulnerability the tool can't actually confirm from static text alone

### CodeReviewAgent tools wired into `cli.py scan` (existed but were never exercised by the scanner)
- [x] `review_express_route`, `review_react_component`, `review_drizzle_schema`, `review_zod_validation`,
      `review_expo_integration` (push_notifications/healthkit/location)

### More heuristic bugs found and fixed during this pass (same bug classes as v2.1.0, found by re-validating
against real Vitality/shield-ai code after each new check, same discipline as the CodeReviewAgent d1a4760 fix)
- [x] `code_review._review_expo_integration`: case-mismatch bug (`"getPermissionsAsync" not in code_lower` —
      comparing a mixed-case literal against an all-lowercase string can never match) made the push-notification
      permission check, the RevenueCat CustomerInfo check, and the location-cleanup check all fire far more
      often than intended, in one case unconditionally
- [x] `auth_security._review_oauth_flow`: "expo" matched inside "export" (JS keyword); lookaround fix, then found
      it needed line-scoping too (a settings file mentioning "Expo push notifications" in an unrelated comment
      falsely implicated an unrelated `client_secret` field elsewhere in the same file)
- [x] `auth_security._audit_shared_secret_auth`: `===`/`==` timing-safe-compare check wasn't scoped to lines
      actually mentioning the secret, so an unrelated `hostname === 'localhost'` comparison 40 lines away read as
      an insecure secret compare
- [x] `auth_security._review_refresh_token_rotation`: persistence-verb regex matched `create_refresh_token(`
      (a token-*generation* function name) as if it were a database persistence call
- [x] `security_audit._audit_sql_injection`: bare SQL keywords ("update"/"select") matched ordinary English
      prose in f-strings; also initially flagged two textbook-correct parameterized-query patterns (bulk insert
      via generated placeholder lists, dynamic WHERE-clause composition from static fragments) as CRITICAL
      injection — now requires actual SQL statement shape and downgrades to MEDIUM/"verify" for opaque-variable
      interpolation instead of asserting CRITICAL without evidence the value is user-controlled
- [x] `security_audit.check_jwt_implementation`: "hmac" alone flagged Python's `hmac.compare_digest` (a
      *correct*, recommended timing-safe comparison) as evidence of weak HS256 JWT signing
- [x] `database_architect`: two nested-parens truncation bugs (`op.add_column(...)` and SQLAlchemy `Column(...)`
      regexes stopped at the first inner `)`, silently missing the actual unsafe/unindexed case entirely);
      DROP COLUMN check fired on every migration's idiomatic `downgrade()` (which is supposed to drop what
      upgrade added); index/constraint checks didn't handle SQLAlchemy 2.0's `Mapped[]` annotation style at all
      (silent 100% false-negative on this stack's actual model files); constraint check's `\w*email\w*` matched
      `email_enabled` (a boolean) and `sender_email`/`reply_to_email` (legitimately non-unique per-row fields)
- [x] `api_architect._review_error_response_shape`: compared *all* `res.json()` call shapes in a file (business
      responses included) against a low distinctness threshold — flagged nearly every route file with 3+
      endpoints, since different endpoints legitimately return different data; rescoped to only compare the
      shape of the error value itself (string vs nested object)
- [x] CLI: `review_express_route`'s trigger (`router\.get\(` etc.) coincidentally matches FastAPI's
      `@router.get(...)` decorator syntax — was telling Python/FastAPI routes to "Add Zod validation" (a JS-only
      library). Added a per-tool file-extension allowlist so JS-specific tools can't fire on Python files even
      when the trigger regex happens to match

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

- [ ] Real static-analysis integration (shell out to `npm audit`/ESLint/Semgrep and synthesize results) — not
      pursued because Vitality and shield-ai already run Trivy + Semgrep SAST + npm-audit-fix in CI; these
      agents are more valuable adding stack-specific semantic checks generic SAST doesn't know about
      (RevenueCat entitlements, Svix webhook ordering, x-api-key vs JWT auth model) than re-implementing SAST

## NEXT STEPS

- Wire `agents.cli scan` into a pre-commit hook or CI job for Vitality/shield-ai if the manual CLI proves useful
  in practice — not done automatically since it changes the merge gate and wasn't asked for
- Consider an EcommerceAgent (checkout flow, inventory, abandoned cart) for aegisapparel/A-Yard-Apparel/sugarhaus
  if that becomes active work

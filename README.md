# RushingTech Agents

**AI agents for solo full-stack operators with OpenAI & Anthropic (Claude) support.**

Eleven specialized agents (57 tools total) that understand your exact stack — React/Node/Express, FastAPI, React Native/Expo, Stripe, Railway, EAS/Codemagic, Helmet, and security-hardened everything. Dual-provider support, Claude-powered UI component generation, and a no-API-key CLI for running the underlying checks directly.

Built for the workflow at [Rushing Technologies](https://rushingtechnologies.com) — one person, every layer, real software that ships.

## 🆕 Version 2.2.0 — What's New

- **🌐 API Architect Agent**: pagination affordances, error response shape consistency, status code correctness, OpenAPI stub generation
- **🗄️ Database Architect Agent**: index coverage on FK columns, migration safety against populated tables (Alembic + raw SQL), N+1 query detection, missing unique constraints
- **📈 Infra Monitor Agent**: Sentry setup review (DSN handling, sampling, PII), health-check depth (does it verify the DB, or just return 200?), error boundary coverage, alert rule design
- **🔎 6 new SecurityAuditAgent checks**: `audit_sql_injection`, `audit_xss_patterns`, `audit_csrf_protection`, `audit_input_validation`, `audit_file_upload`, `audit_websocket_auth` — these were listed in earlier docs but never actually implemented; now real and validated against production code
- **CodeReviewAgent's existing tools wired into `cli.py scan`** — `review_express_route`, `review_react_component`, `review_drizzle_schema`, `review_zod_validation`, `review_expo_integration` now actually run as part of a scan instead of sitting unused
- **More heuristic accuracy fixes found during this pass**: a case-mismatch bug that made the push-notification permission check fire 100% of the time regardless of whether permissions were requested; `expo` matching inside "export"; SQL-injection keyword matching bare English words ("update" in a sentence); a JS-route reviewer (`review_express_route`) firing on Python/FastAPI files because `@router.get(...)` coincidentally contains the same substring as Express's `router.get(`, telling Python code to "add Zod validation"

## 🆕 Version 2.1.0 — What's New

- **🔐 Auth Security Agent**: JWT refresh rotation, Apple Sign-In (nonce/JWKS/audience), Google OAuth, shared-secret app gates, biometric auth
- **📱 Mobile Deploy Agent**: EAS build config (incl. hardcoded-secret detection), Codemagic workflows, App Store/Play submission checklists, RevenueCat setup
- **🖥️ CLI**: `python -m agents.cli` calls the deterministic tool handlers directly — no LLM API key needed. `scan` auto-discovers relevant files in a project and runs the matching checks.
- **🔁 Multi-round tool calling**: `run()` now loops on chained tool calls instead of stopping after one round trip
- **🩹 Heuristic accuracy fixes**: several checks (JWT expiry, CORS, accessibility, billing auth) previously matched on overly broad substrings (e.g. "exp" matching "express") and rarely fired — tightened across the board and validated against real code
- **🐍 Python/FastAPI awareness**: `scan_dependencies` now handles `requirements.txt`, `analyze_helmet_config` scans raw source (not just hand-built JSON), `audit_cors_config` recognizes FastAPI's `CORSMiddleware`

## The Agents

| Agent | Provider | What It Does |
|---|---|---|
| **SecurityAuditAgent** | OpenAI, Anthropic | Helmet config (incl. raw source), OWASP Top 10, JWT vulnerabilities (Node + Python), SQL injection, XSS, CSRF, file upload, WebSocket auth, dangerous-sink input validation, npm/pip dependency scanning, CORS (Express + FastAPI) |
| **AuthSecurityAgent** | OpenAI, Anthropic | JWT refresh rotation/revocation, Apple Sign-In (nonce/JWKS/issuer/audience), Google OAuth CSRF, shared-secret app gates (x-api-key), biometric auth |
| **StripeBillingAgent** | OpenAI, Anthropic | Webhook handler review, subscription model design, RevenueCat sync, billing security audit, receipt validation, dunning management, disputes, coupons, tax |
| **RailwayDeployAgent** | OpenAI, Anthropic | CI/CD workflows (GitHub Actions, Codemagic, EAS), platform configs (Vercel, Cloudflare), Sentry integration, migrations, monitoring alerts, backup strategies |
| **MobileDeployAgent** | OpenAI, Anthropic | EAS build profile review (hardcoded secrets, production hardening), Codemagic code-signing hygiene, App Store/Play submission checklists, RevenueCat SDK setup |
| **CodeReviewAgent** | OpenAI, Anthropic | Express routes, React/Expo components, Drizzle schemas, Zustand stores, Socket.io handlers, Celery tasks, API design, performance, accessibility, tests |
| **APIArchitectAgent** ⭐ NEW | OpenAI, Anthropic | Pagination affordances, error response shape consistency, status code correctness, OpenAPI stub generation |
| **DatabaseArchitectAgent** ⭐ NEW | OpenAI, Anthropic | Index coverage (Drizzle + SQLAlchemy 2.0), migration safety against populated tables, N+1 query detection, missing unique constraints |
| **InfraMonitorAgent** ⭐ NEW | OpenAI, Anthropic | Sentry setup (DSN, sampling, PII), health-check depth, React error boundary coverage, alert rule design |
| **ScaffolderAgent** | OpenAI, Anthropic | Project bootstrapping — Express APIs, React SPAs, Expo apps, FastAPI services, SaaS platforms, CI/CD configs |
| **UIGenerationAgent** ⭐ UPGRADED | Anthropic (Claude) | World-class UI design — design system/theme generation (color theory, type scale, motion, elevation), React/TypeScript component generation, multi-turn refinement, accessibility validation |

## CLI — use the checks without an API key

The tool handlers behind each agent are plain Python (regex/heuristic checks over a string), separate from the LLM planning loop. The CLI calls them directly:

```fish
# List every agent and its tools
python -m agents.cli list

# Run one check against a real file
python -m agents.cli run security_audit check_jwt_implementation --file code=backend/src/routes/auth.ts
python -m agents.cli run security_audit scan_dependencies --file package_json=backend/requirements.txt

# Auto-discover relevant files in a project and run the matching checks
python -m agents.cli scan --path ~/Vitality
python -m agents.cli scan --path ~/shield-ai --agents security_audit,auth_security --out report.json
```

`scan` walks the project (skipping `node_modules`, `.git`, `dist`, `.venv`, etc.), matches files by name (`package.json`, `eas.json`, `codemagic.yaml`) or content (helmet/cors/jwt/RevenueCat/Apple Sign-In patterns), runs the corresponding tool handler, and prints a severity-sorted report.

## Install

```fish
# Clone and install locally
git clone https://github.com/mrnickrushing/agents.git
cd agents
pip install -e .

# Install dependencies
pip install openai>=1.0.0 anthropic>=0.40.0
```

All shell snippets below are `fish`. All `python` blocks are Python code, not shell commands, and should be run with `python` or saved to a `.py` file first.

## Quick Start

### OpenAI Provider

```python
from agents import SecurityAuditAgent

# Uses OPENAI_API_KEY from environment
agent = SecurityAuditAgent(provider="openai")

result = agent.run("Audit my Express app — Helmet CSP is disabled and CORS is set to '*'")
print(result.content)
```

### Anthropic (Claude) Provider

```python
from agents import SecurityAuditAgent

# Uses ANTHROPIC_API_KEY from environment
agent = SecurityAuditAgent(
    provider="anthropic",
    model="claude-sonnet-4-6"
)

result = agent.run("Audit this Stripe webhook handler for security issues")
print(result.content)
```

### UI Generation (Claude-Powered)

```python
from agents import UIGenerationAgent

agent = UIGenerationAgent(
    api_key="sk-ant-...",
    provider="anthropic",
    model="claude-sonnet-4-6"
)

# Single turn — create a component
result = agent.run(
    "Create a responsive dashboard card with:"
    "- Title (string prop)"
    "- Metric value (number prop)"
    "- Trend indicator ('up', 'down', 'neutral')"
    "- Sparkline chart"
    "- Dark theme support"
    "- Fully accessible"
)
print(result.content)  # Complete React component code

# Multi-turn conversation
result = agent.run(
    "Now make the card clickable with hover effects",
    conversation_id="dashboard-card-123"
)
```

### Wireframe to Component

```python
import base64

agent = UIGenerationAgent(api_key="sk-ant-...")

# Load wireframe image
with open("wireframe.png", "rb") as f:
    image_data = base64.b64encode(f.read()).decode()

# Analyze wireframe and generate component
response = agent.process_wireframe(
    description="Create a navigation bar component",
    image_base64=image_data,
    media_type="image/png",
    conversation_id="navbar-dev"
)
print(response.content)
```

## Multi-Turn Conversations

All agents support conversation history with conversation IDs:

```python
from agents import UIGenerationAgent

agent = UIGenerationAgent(api_key="sk-ant-...")
conversation_id = "my-component-v1"

# Turn 1: Create initial component
agent.run("Create a stats card", conversation_id=conversation_id)

# Turn 2: Add features
agent.run("Add a trend indicator", conversation_id=conversation_id)

# Turn 3: Apply styling
agent.run("Make it dark-themed", conversation_id=conversation_id)

# Conversation history is maintained
print(f"Messages: {len(agent.history)}")

# Reset if needed
agent.reset(conversation_id=conversation_id)
```

## Using Tools Directly (No API Key Needed)

Every agent has built-in tools you can call directly without an API key:

```python
from agents import SecurityAuditAgent, StripeBillingAgent, RailwayDeployAgent, UIGenerationAgent

# Security — analyze Helmet config
security = SecurityAuditAgent()
findings = security._tool_handlers["analyze_helmet_config"](
    config_json='{"contentSecurityPolicy": false}',
    framework="express"
)

# Billing — design subscription model
billing = StripeBillingAgent()
model = billing._tool_handlers["design_subscription_model"](
    product_name="MySaaS",
    tiers='[{"name":"Free","price_monthly":0},{"name":"Pro","price_monthly":29}]',
    mobile_iap=True,
)

# Deploy — get deployment checklist
deploy = RailwayDeployAgent()
checklist = deploy._tool_handlers["deployment_checklist"](
    project_type="saas_platform",
    platform="railway",
    has_stripe=True,
)

# UI Generation — validate accessibility
ui_agent = UIGenerationAgent()
validation = ui_agent._tool_handlers["validate_accessibility"](
    component_code="""
    <div onClick={handleClick}>
        <img src="icon.png" />
        <h4>Title</h4>
    </div>
    """,
    severity="serious"
)
print(f"Accessibility Score: {validation['overall_score']}/100")
```

## Provider Configuration

```python
from agents import SecurityAuditAgent

# OpenAI (default)
agent = SecurityAuditAgent(
    api_key="sk-...",
    provider="openai",
    model="gpt-5",
    temperature=0.3,
)

# Anthropic (Claude)
agent = SecurityAuditAgent(
    api_key="sk-ant-...",
    provider="anthropic",
    model="claude-sonnet-4-6",
    temperature=0.7,
)

# Using environment variables
# set -gx OPENAI_API_KEY "sk-..."
# set -gx ANTHROPIC_API_KEY "sk-ant-..."
agent = SecurityAuditAgent(provider="openai")  # Uses OPENAI_API_KEY
agent = SecurityAuditAgent(provider="anthropic")  # Uses ANTHROPIC_API_KEY
```

## Agent Details

### SecurityAuditAgent

**Security Domain Coverage (15 areas):**
- Helmet.js configuration analysis
- JWT implementation vulnerabilities
- Dependency scanning (npm/Python)
- CORS configuration audit
- Rate limiting review
- SQL injection detection
- XSS vulnerability audit
- CSRF token validation
- Input sanitization
- File upload security
- WebSocket auth audit
- SSL/TLS configuration
- Mobile security (iOS/Android)
- Session management
- Deployment hardening

**Key Tools:**
- `analyze_helmet_config` — Deep Helmet.js CSP and header analysis
- `check_jwt_implementation` — JWT token generation, rotation, storage audit
- `scan_dependencies` — Vulnerability scan of package.json/requirements.txt
- `audit_cors_config` — CORS wildcard detection and origin validation
- `generate_helmet_config` — Production-ready Helmet config with all headers
- `audit_rate_limiting` — Rate limiter configuration analysis
- `audit_sql_injection` — SQL injection vulnerability detection
- `audit_xss_patterns` — XSS vulnerability patterns
- `audit_csrf_protection` — CSRF token implementation review
- `audit_input_validation` — Input sanitization patterns
- `audit_file_upload` — File upload security review
- `audit_websocket_auth` — WebSocket authentication audit
- `audit_ssl_tls` — SSL/TLS configuration review
- `audit_mobile_security` — iOS/Android security patterns
- `generate_pen_test_report` — Penetration test report template

### AuthSecurityAgent ⭐ NEW

**Auth Flow Coverage:**
- JWT access/refresh rotation and reuse detection
- Apple Sign-In server-side verification (nonce, JWKS, issuer, audience)
- Google/social OAuth CSRF (state param) and token exchange security
- Shared-secret app gates (x-api-key pattern) — timing-safe comparison, no hardcoded fallback
- Biometric auth (Face ID / LocalAuthentication) — fallback and credential binding

**Key Tools:**
- `review_refresh_token_rotation` — refresh token reuse/rotation/hashing and algorithm-confusion checks
- `review_apple_sign_in` — nonce, JWKS signature verification, issuer/audience validation
- `review_oauth_flow` — CSRF state param, server-side token exchange, audience validation
- `audit_shared_secret_auth` — timing-safe comparison, hardcoded fallback detection
- `review_biometric_auth` — enrollment/fallback checks, credential binding (not a bare local gate)

### StripeBillingAgent

**Billing Lifecycle (14 areas):**
- Webhook handler security
- Subscription model design
- RevenueCat mobile-to-backend sync
- Billing security audit
- Receipt validation
- Dunning management
- Dispute handling
- Coupon/promo codes
- Metered billing
- Invoice reconciliation
- Trial lifecycle management
- Refund workflows
- Stripe Connect
- Tax compliance

**Key Tools:**
- `review_webhook_handler` — Stripe webhook security review
- `generate_webhook_handlers` — Complete webhook handler generation
- `setup_revenuecat_sync` — RevenueCat integration code
- `design_subscription_model` — Subscription tier configuration
- `audit_billing_security` — Billing security audit
- `review_receipt_validation` — Receipt validation code review
- `configure_dunning_management` — Dunning workflow setup
- `handle_dispute_responses` — Dispute response generation
- `setup_coupon_system` — Coupon configuration
- `configure_metered_billing` — Metered billing setup
- `reconcile_invoices` — Invoice reconciliation scripts
- `manage_trial_lifecycle` — Trial automation
- `configure_refund_workflow` — Refund handling configuration
- `setup_stripe_connect` — Stripe Express/Connect setup
- `configure_tax_settings` — Tax calculation and compliance

### RailwayDeployAgent

**Deployment Orchestration:**
- `diagnose_build_failure` — Railway/Vercel/Cloudflare/EAS build failure analysis from build logs
- `generate_railway_toml` — Railway deployment configuration
- `generate_docker_compose` — Docker Compose with Postgres/Redis/Celery services
- `deployment_checklist` — Pre-deployment checklist (Stripe, Sentry, CORS, rate limiting)
- `setup_env_vars` — Required environment variables for a given stack + integration set

### MobileDeployAgent ⭐ NEW

**EAS / Codemagic / App Store Readiness:**
- `review_eas_config` — flags literal secrets committed into `eas.json` build profiles, missing production hardening (autoIncrement, submit config)
- `review_codemagic_config` — code-signing hygiene (no inlined keys), trigger scoping, TestFlight/App Store submission steps
- `app_store_submission_checklist` — App Store/Play submission checklist (privacy labels, ATT, HealthKit disclosures, IAP readiness) by app category
- `review_revenuecat_setup` — Purchases.configure() timing, offerings error handling, restorePurchases(), entitlement-gated purchase flow

### CodeReviewAgent

**Code Review Domains (7 areas):**
- Express route review (security, validation, error handling)
- React component review (effects, accessibility, performance)
- Drizzle schema review (relations, constraints, indexes)
- Zod validation review (complexity, coercion, cross-field)
- Expo integration review (config, SQLite, routing)
- Stripe webhook review (security, idempotency, retries)
- Zustand store review (selectors, re-render optimization)
- Socket.io handler review (auth, rooms, Redis adapter)
- Celery task review (idempotency, retry, monitoring)
- API design review (REST conventions, error format, pagination)
- Performance review (N+1 queries, re-renders, caching)
- Accessibility review (WCAG 2.1 AA compliance)
- File upload review (validation, storage, security)
- Test suggestions (framework-specific test generation)

**Key Tools:**
- `review_express_route` — Express route handler audit
- `review_react_component` — React/React Native component review
- `review_drizzle_schema` — Drizzle ORM schema review
- `review_zod_validation` — Zod schema validation review
- `review_expo_integration` — Expo integration audit
- `review_stripe_webhook` — Stripe webhook security review
- `review_zustand_store` — Zustand state management review
- `review_websocket_handler` — Socket.io handler review
- `review_celery_task` — Celery task review
- `review_api_design` — API design conventions review
- `review_performance` — Performance pattern review
- `review_accessibility` — WCAG 2.1 AA accessibility audit
- `review_file_upload` — File upload security review
- `suggest_tests` — Test strategy and test generation

### ScaffolderAgent

**Project Scaffolding (6 tools):**
- `scaffold_express_api` — Node/Express API scaffolding
- `scaffold_react_app` — React SPA scaffolding
- `scaffold_expo_app` — React Native/Expo app scaffolding
- `scaffold_saas_platform` — Full SaaS platform scaffolding
- `scaffold_fastapi_service` — FastAPI service scaffolding
- `generate_env_template` — .env.example template generation

### UIGenerationAgent ⭐ UPGRADED

**Claude-Powered UI Design & Component Building**

A world-class product-design persona (the taste behind Linear/Stripe/Vercel-caliber apps), not just a component generator — it establishes a real design system before it writes components, so output is cohesive rather than one-off.

**Tools:**
- `generate_design_system` — Establish a full design system/theme: color palette with rationale (primary + accent hue, neutral ramp, light/dark semantic tokens), type scale, spacing scale, radius scale, elevation/shadow scale, motion tokens
- `generate_component` — Generate React/TypeScript components from natural language, built on top of the design system's tokens
- `validate_accessibility` — WCAG 2.1 AA accessibility validation
- `apply_design_token` — Apply design tokens for consistent styling

**Key Features:**
- 🎨 Design-system-first: color theory, type scales, elevation, motion tokens — not ad-hoc styling
- ✨ Natural language to React components
- 💅 Tailwind CSS styling with restrained, premium use of gradients/glassmorphism/glow accents
- ♿ Accessibility-first (WCAG 2.1 AA), including contrast verification in both light and dark
- 🌓 Dark mode as a first-class palette, not an inverted afterthought
- 📱 Mobile-first responsive design
- 💬 Multi-turn conversation support
- 👁️ Wireframe/screenshot analysis
- 🧩 Component composition
- 🔄 Iterative refinement

**Usage Patterns:**
```python
# Establish the design system first
theme = agent.run("Design a theme for a career-advancement platform — trustworthy but energetic")

# Simple generation
result = agent.run("Create a button component")

# Multi-turn refinement
result = agent.run("Add hover effects", conversation_id="btn-v1")

# Wireframe analysis
response = agent.process_wireframe("From this image...", base64_data)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BaseAgent (Multi-Provider)              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐          ┌──────────────┐                │
│  │   OpenAI     │          │  Anthropic   │                │
│  │   Provider   │          │ (Claude)     │                │
│  └──────┬───────┘          └──────┬───────┘                │
│         │                         │                         │
│         └─────────┬───────────────┘                         │
│                   ▼                                         │
│         ┌─────────────────┐                                 │
│         │ Message Format  │                                 │
│         │   Handler       │                                 │
│         └────────┬────────┘                                 │
│                  │                                          │
│                  ▼                                          │
│         ┌─────────────────┐                                 │
│         │  Tool Engine    │                                 │
│         │  - OpenAI-      │                                 │
│         │    style        │                                 │
│         │  - Anthropic-   │                                 │
│         │    style        │                                 │
│         └────────┬────────┘                                 │
│                  │                                          │
│         ┌────────▼────────┐      ┌──────────────────┐       │
│         │    Agents       │─────►│   UI Agent (Anthropic)│  │
│         │  ┌──────────┐   │      └──────────────────┘       │
│         │  │Security  │   │                                  │
│         │  │Stripe    │   │      ┌──────────────────┐       │
│         │  │Railway   │   │─────►│   Other Agents   │       │
│         │  │Code      │   │      │  (Both Providers)│       │
│         │  │Scaffold  │   │      └──────────────────┘       │
│         │  └──────────┘   │                                  │
│         └─────────────────┘                                 │
└─────────────────────────────────────────────────────────────┘
```

**BaseAgent Features:**
- **Multi-provider support**: OpenAI and Anthropic out of the box
- **Unified API**: Same interface for both providers
- **Conversation management**: Multi-turn with conversation IDs
- **Tool execution**: Automatic tool calling and result handling
- **Error handling**: Graceful fallbacks and clear error messages

**UI Generation Agent Workflow:**
```
User Input (Natural Language)
           │
           ▼
┌──────────────────────┐
│  Claude Analysis     │
│  - Design intent     │
│  - Accessibility     │
│  - Responsiveness    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Tool Selection      │
│  - generate_component│
│  - validate_access   │
│  - apply_tokens      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Component Output    │
│  - React + TS        │
│  - Tailwind CSS      │
│  - Accessibility     │
│  - Usage examples    │
└──────────────────────┘
```

## Environment Variables

```fish
# OpenAI (optional if API key passed directly)
set -gx OPENAI_API_KEY "sk-..."

# Anthropic (optional if API key passed directly)
set -gx ANTHROPIC_API_KEY "sk-ant-..."

# Optional: Custom base URLs for proxy or self-hosted
set -gx OPENAI_BASE_URL "https://api.openai.com/v1"
set -gx ANTHROPIC_BASE_URL "https://api.anthropic.com"
```

## Running Examples

```fish
# Set API keys
set -gx OPENAI_API_KEY "sk-..."
set -gx ANTHROPIC_API_KEY "sk-ant-..."

# Run main examples (tool-level — no API key required for most)
python example.py

# Run comprehensive UI Generation Agent examples
python example_ui_generation.py
```

## Requirements

- Python 3.11+
- `openai>=1.0.0` — For OpenAI provider
- `anthropic>=0.40.0` — For Anthropic provider
- `class-variance-authority>=0.7.0` — Optional, for UI agent styling

## License

MIT

---

Built by [Rushing Technologies](https://rushingtechnologies.com) — solo operator, full stack + security + AI.

**Version 2.1.0** — Auth security + mobile deploy agents, no-API-key CLI, multi-round tool calling, heuristic accuracy fixes.

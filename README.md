# RushingTech Agents

**AI agents for solo full-stack operators with OpenAI & Anthropic (Claude) support.**

Six specialized agents that understand your exact stack — React/Node/Express, React Native/Expo, Stripe, Railway, Helmet, and security-hardened everything. Now with dual-provider support and Claude-powered UI component generation.

Built for the workflow at [Rushing Technologies](https://rushingtechnologies.com) — one person, every layer, real software that ships.

## 🆕 Version 2.0.0 — What's New

- **✨ Multi-Provider Support**: All agents now work with both OpenAI and Anthropic
- **🎨 UI Generation Agent**: Claude-powered component builder with multi-turn conversations
- **🔧 Expanded Tooling**: SecurityAudit (15 domains), StripeBilling (14 tools), RailwayDeploy (14 tools), CodeReview (14 tools)
- **💬 Conversation Support**: Multi-turn conversations with conversation IDs
- **👁️ Vision Input**: Wireframe/screenshot analysis for UI components

## The Agents

| Agent | Provider | What It Does |
|---|---|---|
| **SecurityAuditAgent** | OpenAI, Anthropic | Helmet config, OWASP Top 10, JWT vulnerabilities, rate limiting gaps, dependency scanning, deployment security, mobile hardening, WebSocket auth |
| **StripeBillingAgent** | OpenAI, Anthropic | Webhook handler review, subscription model design, RevenueCat sync, billing security audit, receipt validation, dunning management, disputes, coupons, tax |
| **RailwayDeployAgent** | OpenAI, Anthropic | CI/CD workflows (GitHub Actions, Codemagic, EAS), platform configs (Vercel, Cloudflare), Sentry integration, migrations, monitoring alerts, backup strategies |
| **CodeReviewAgent** | OpenAI, Anthropic | Express routes, React/Expo components, Drizzle schemas, Zustand stores, Socket.io handlers, Celery tasks, API design, performance, accessibility, tests |
| **ScaffolderAgent** | OpenAI, Anthropic | Project bootstrapping — Express APIs, React SPAs, Expo apps, FastAPI services, SaaS platforms, CI/CD configs |
| **UIGenerationAgent** ⭐ NEW | Anthropic (Claude) | React/TypeScript component generation from natural language, multi-turn refinement, accessibility validation, design tokens |

## Install

```bash
# Clone and install locally
git clone https://github.com/mrnickrushing/rushingtech-agents.git
cd rushingtech-agents
pip install -e .

# Install dependencies
pip install openai>=1.0.0 anthropic>=0.40.0
```

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
    model="claude-3-5-sonnet-20241022"
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
    model="claude-3-5-sonnet-20241022"
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
    model="gpt-4o",
    temperature=0.3,
)

# Anthropic (Claude)
agent = SecurityAuditAgent(
    api_key="sk-ant-...",
    provider="anthropic",
    model="claude-3-5-sonnet-20241022",
    temperature=0.7,
)

# Using environment variables
# export OPENAI_API_KEY="sk-..."
# export ANTHROPIC_API_KEY="sk-ant-..."
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

**Deployment Orchestration (14 tools):**

**CI/CD & Build:**
- `diagnose_build_failure` — Railway/Vercel/Cloudflare/EAS build failure analysis
- `generate_github_actions` — CI/CD workflows (node_ci, python_ci, deployment pipelines)
- `generate_codemagic_config` — React Native iOS/Android build configs
- `generate_eas_config` — Expo managed workflow build configs

**Platform Configs:**
- `generate_railway_toml` — Railway deployment configuration
- `generate_vercel_config` — Vercel deployment configuration
- `generate_cloudflare_workers` — Cloudflare Workers + Hono config

**Infrastructure:**
- `generate_docker_compose` — Docker Compose with health checks and Celery
- `generate_migration_runner` — Zero-downtime migration scripts
- `setup_sentry_integration` — Sentry error monitoring setup
- `setup_monitoring_alerts` — Health checks and alert rules
- `setup_backup_strategy` — Backup and disaster recovery
- `setup_ssl_domain` — SSL/TLS and domain configuration
- `deployment_checklist` — Pre-deployment checklist

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

### UIGenerationAgent ⭐ NEW

**Claude-Powered UI Component Building**

**Tools:**
- `generate_component` — Generate React/TypeScript components from natural language
- `validate_accessibility` — WCAG 2.1 AA accessibility validation
- `apply_design_token` — Apply design tokens for consistent styling

**Key Features:**
- ✨ Natural language to React components
- 🎨 Tailwind CSS styling
- ♿ Accessibility-first (WCAG 2.1 AA)
- 🌓 Dark mode support
- 📱 Mobile-first responsive design
- 💬 Multi-turn conversation support
- 👁️ Wireframe/screenshot analysis
- 🧩 Component composition
- 🔄 Iterative refinement

**Usage Patterns:**
```python
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

```bash
# OpenAI (optional if API key passed directly)
export OPENAI_API_KEY="sk-..."

# Anthropic (optional if API key passed directly)
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional: Custom base URLs for proxy or self-hosted
export OPENAI_BASE_URL="https://api.openai.com/v1"
export ANTHROPIC_BASE_URL="https://api.anthropic.com"
```

## Running Examples

```bash
# Set API keys
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

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

**Version 2.0.0** — Multi-provider support with Claude-powered UI generation.

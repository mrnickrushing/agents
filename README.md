# RushingTech Agents

**OpenAI-compatible AI agents for solo full-stack operators.** Five specialized agents that understand your exact stack — React/Node/Express, React Native/Expo, Stripe, Railway, Helmet, and security-hardened everything.

Built for the workflow at [Rushing Technologies](https://rushingtechnologies.com) — one person, every layer, real software that ships.

## The Agents

| Agent | What It Does |
|---|---|
| **SecurityAuditAgent** | Helmet config, OWASP Top 10, JWT vulnerabilities, rate limiting gaps, dependency scanning, deployment security, mobile-specific hardening |
| **StripeBillingAgent** | Webhook handler review, subscription model design, RevenueCat sync, billing security audit, receipt validation |
| **RailwayDeployAgent** | Build failure diagnosis, railway.toml generation, Docker Compose, deployment checklists, environment variable management |
| **CodeReviewAgent** | Express route review, React/React Native component review, Drizzle schema review, Zod validation review, Expo integration review |
| **ScaffolderAgent** | Project bootstrapping — Express APIs, React SPAs, Expo apps, FastAPI services, full SaaS platforms, .env templates |

## Install

```bash
# Clone and install locally
git clone https://github.com/mrnickrushing/rushingtech-agents.git
cd rushingtech-agents
pip install -e .

# Or just copy the agents/ directory into your project
cp -r agents/ /your/project/
```

## Quick Start

```python
from agents import SecurityAuditAgent

# Uses OPENAI_API_KEY from environment
agent = SecurityAuditAgent()

# Full OpenAI chat completion — sends to GPT-4o with security specialist system prompt
result = agent.run("Audit my Express app — Helmet CSP is disabled and CORS is set to '*'")
print(result.content)
```

## Using Tools Directly (No API Key Needed)

Every agent has built-in tools you can call directly without an OpenAI API key:

```python
from agents import SecurityAuditAgent, StripeBillingAgent, RailwayDeployAgent

# Security — analyze Helmet config
security = SecurityAuditAgent()
findings = security._tool_handlers["analyze_helmet_config"](
    config_json='{"contentSecurityPolicy": false, "hsts": {"maxAge": 86400}}',
    framework="express"
)

# Security — generate a production Helmet config
config = security._tool_handlers["generate_helmet_config"](
    app_type="saas_platform",
    domains="yourdomain.com,app.yourdomain.com",
    stripe_enabled=True,
    cdn_used=True,
)

# Stripe — design a subscription model
billing = StripeBillingAgent()
model = billing._tool_handlers["design_subscription_model"](
    product_name="MySaaS",
    tiers='[{"name":"Free","price_monthly":0},{"name":"Pro","price_monthly":29}]',
    mobile_iap=True,
)

# Railway — get deployment checklist
deploy = RailwayDeployAgent()
checklist = deploy._tool_handlers["deployment_checklist"](
    project_type="saas_platform",
    platform="railway",
    has_stripe=True,
    has_sentry=True,
)
```

## Using with OpenAI (Full Agent Mode)

Each agent constructs a complete OpenAI chat completion payload with:

- **System prompt** — deep domain expertise in your stack
- **Tools** — OpenAI function calling definitions for structured operations
- **Tool execution** — automatic tool call handling and re-submission
- **Conversation history** — maintained across calls

```python
from agents import CodeReviewAgent

agent = CodeReviewAgent(api_key="sk-...", model="gpt-4o")

# The agent sends your message + system prompt + tools to OpenAI
# If GPT-4o decides to use a tool, it executes and resubmits automatically
result = agent.run("""
Review this Express route:
router.post('/api/stripe/webhook', async (req, res) => {
    const event = req.body;
    if (event.type === 'customer.subscription.deleted') {
        await db.updateSubscription(event.data.object.id, 'canceled');
    }
    res.send();
});
""")
print(result.content)
```

## OpenAI-Compatible Payload

You can also get the raw payload and send it to any OpenAI-compatible endpoint:

```python
from agents import SecurityAuditAgent

agent = SecurityAuditAgent()

# Build the payload
payload = agent.format_payload(
    user_input="Audit this app for security issues",
    context="Express app with Helmet, JWT auth, Stripe billing"
)

# Send to any OpenAI-compatible API
import requests
response = requests.post(
    "https://api.openai.com/v1/chat/completions",
    headers={"Authorization": f"Bearer {agent.api_key}"},
    json=payload,
)
```

Works with any OpenAI-compatible API:
- OpenAI (`https://api.openai.com/v1`)
- Azure OpenAI
- Anthropic via proxy
- Local LLMs (Ollama, LM Studio, etc.)

## Custom Configuration

```python
from agents import SecurityAuditAgent

agent = SecurityAuditAgent(
    api_key="sk-...",           # Or set OPENAI_API_KEY env var
    model="gpt-4o",             # Any OpenAI model
    temperature=0.2,            # Lower for more precise, higher for creative
    base_url="https://api.openai.com/v1",  # Or any compatible endpoint
)

# Reset conversation history
agent.reset()

# Access conversation history
print(agent.history)
```

## Agent Details

### SecurityAuditAgent

**Tools:**
- `analyze_helmet_config` — Analyze Helmet.js config for security gaps
- `check_jwt_implementation` — Audit JWT code for vulnerabilities
- `scan_dependencies` — Scan package.json for risky dependencies
- `audit_cors_config` — Audit CORS configuration
- `generate_helmet_config` — Generate production Helmet config
- `audit_rate_limiting` — Audit rate limiting configuration

### StripeBillingAgent

**Tools:**
- `review_webhook_handler` — Review Stripe webhook handler code
- `generate_webhook_handlers` — Generate webhook handlers for subscription events
- `setup_revenuecat_sync` — Generate RevenueCat receipt validation code
- `design_subscription_model` — Design Stripe subscription tiers and pricing
- `audit_billing_security` — Audit Stripe/RevenueCat integration for vulnerabilities

### RailwayDeployAgent

**Tools:**
- `diagnose_build_failure` — Diagnose Railway/Vercel build failures from logs
- `generate_railway_toml` — Generate railway.toml configuration
- `generate_docker_compose` — Generate Docker Compose for local dev
- `deployment_checklist` — Generate pre-deployment checklist
- `setup_env_vars` — List required environment variables for a project type

### CodeReviewAgent

**Tools:**
- `review_express_route` — Review Express route handlers
- `review_react_component` — Review React/React Native components
- `review_drizzle_schema` — Review Drizzle ORM schemas
- `review_zod_validation` — Review Zod validation schemas
- `review_expo_integration` — Review Expo integration code
- `review_stripe_webhook` — Review Stripe webhook handlers

### ScaffolderAgent

**Tools:**
- `scaffold_express_api` — Scaffold Node/Express API project
- `scaffold_react_app` — Scaffold React SPA project
- `scaffold_expo_app` — Scaffold React Native/Expo app
- `scaffold_saas_platform` — Scaffold full SaaS platform
- `scaffold_fastapi_service` — Scaffold FastAPI service
- `generate_env_template` — Generate .env.example template

## Running Examples

```bash
export OPENAI_API_KEY="sk-..."
python example.py
```

The examples demonstrate both direct tool usage (no API key needed) and full OpenAI chat completion mode.

## Requirements

- Python 3.11+
- `openai>=1.0.0` (for full agent mode — tools work without it)

## License

MIT

---

Built by [Rushing Technologies](https://rushingtechnologies.com) — solo operator, full stack + security.

"""
RushingTech Agents — Usage Examples

Run any of these examples after setting OPENAI_API_KEY:
    export OPENAI_API_KEY="sk-..."
    python example.py
"""

import os
import json

# ── Import the agents ──────────────────────────────────────────────
from agents import (
    SecurityAuditAgent,
    StripeBillingAgent,
    RailwayDeployAgent,
    CodeReviewAgent,
    ScaffolderAgent,
)


def example_security_audit():
    """Security Audit Agent — audit Helmet config and generate a production-ready one."""
    agent = SecurityAuditAgent()  # Uses OPENAI_API_KEY env var

    # Example: Analyze a Helmet config
    helmet_config = json.dumps({
        "contentSecurityPolicy": False,  # Disabled!
        "hsts": {"maxAge": 86400},  # Only 1 day
        "noSniff": True,
    })

    print("=" * 60)
    print("SECURITY AUDIT AGENT")
    print("=" * 60)

    # Use the tool directly for structured output
    result = agent._tool_handlers["analyze_helmet_config"](
        config_json=helmet_config,
        framework="express"
    )
    print("\n📋 Helmet Config Analysis:")
    print(json.dumps(result, indent=2))

    # Generate a production Helmet config
    config = agent._tool_handlers["generate_helmet_config"](
        app_type="saas_platform",
        domains="yourdomain.com,app.yourdomain.com",
        stripe_enabled=True,
        cdn_used=True,
    )
    print("\n🔒 Generated Production Helmet Config:")
    print(json.dumps(config, indent=2))

    # Or use the full agent with OpenAI
    # response = agent.run("Audit my Express app — Helmet CSP is disabled and HSTS is only 1 day")
    # print(response.content)


def example_stripe_billing():
    """Stripe Billing Agent — review webhooks and design subscription models."""
    agent = StripeBillingAgent()

    print("\n" + "=" * 60)
    print("STRIPE BILLING AGENT")
    print("=" * 60)

    # Design a subscription model
    model = agent._tool_handlers["design_subscription_model"](
        product_name="CyberCore Academy",
        tiers=json.dumps([
            {"name": "Free", "price_monthly": 0, "price_yearly": 0, "features": ["5 modules", "basic progress"], "trial_days": 0},
            {"name": "Pro", "price_monthly": 29, "price_yearly": 290, "features": ["all modules", "badges", "simulations", "admin panel"], "trial_days": 14},
            {"name": "Enterprise", "price_monthly": 99, "price_yearly": 990, "features": ["everything in Pro", "SOC 2 mapping", "NIST CSF", "HIPAA", "cohort management"], "trial_days": 30},
        ]),
        mobile_iap=True,
    )
    print("\n💳 Subscription Model:")
    print(json.dumps(model, indent=2))

    # Review a webhook handler
    review = agent._tool_handlers["review_webhook_handler"](
        code="""
        app.post('/stripe/webhook', async (req, res) => {
            const event = req.body;
            if (event.type === 'customer.subscription.deleted') {
                await db.updateSubscription(event.data.object.id, 'canceled');
            }
            res.send();
        });
        """,
        events_handled="customer.subscription.deleted"
    )
    print("\n🚨 Webhook Handler Review:")
    print(json.dumps(review, indent=2))


def example_railway_deploy():
    """Railway Deploy Agent — generate configs and diagnose failures."""
    agent = RailwayDeployAgent()

    print("\n" + "=" * 60)
    print("RAILWAY DEPLOY AGENT")
    print("=" * 60)

    # Generate railway.toml
    config = agent._tool_handlers["generate_railway_toml"](
        project_type="node_express",
        start_command="node dist/index.js",
        healthcheck_path="/health",
        needs_postgres=True,
        needs_redis=True,
    )
    print("\n🚂 railway.toml:")
    print(config["railway_toml"])

    # Get deployment checklist
    checklist = agent._tool_handlers["deployment_checklist"](
        project_type="saas_platform",
        platform="railway",
        has_stripe=True,
        has_sentry=True,
    )
    print("\n✅ Deployment Checklist:")
    for item in checklist["checklist"]:
        status = "🔴" if item["critical"] else "🟡"
        print(f"  {status} Step {item['step']}: {item['item']}")

    # Get required env vars
    env_vars = agent._tool_handlers["setup_env_vars"](
        project_type="saas_full_stack",
        integrations="stripe,sentry,resend,redis"
    )
    print("\n🔐 Required Environment Variables:")
    for var in env_vars["required_env_vars"]:
        print(f"  • {var}")


def example_code_review():
    """Code Review Agent — review Express routes and React components."""
    agent = CodeReviewAgent()

    print("\n" + "=" * 60)
    print("CODE REVIEW AGENT")
    print("=" * 60)

    # Review an Express route
    review = agent._tool_handlers["review_express_route"](
        code="""
        router.post('/api/users', async (req, res) => {
            const { email, password } = req.body;
            const user = await db.insert(users).values({ email, password }).returning();
            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
            res.json({ token, user });
        });
        """,
        route_path="POST /api/users",
        auth_required=False,
    )
    print("\n🔍 Route Review (POST /api/users):")
    print(json.dumps(review, indent=2))

    # Review an Expo integration
    expo_review = agent._tool_handlers["review_expo_integration"](
        code="""
        import * as AppleAuthentication from 'expo-apple-authentication';
        
        async function signIn() {
            const credential = await AppleAuthentication.signInAsync({
                requestedScopes: [AppleAuthentication.AppleAuthenticationScope.FULL_NAME, AppleAuthentication.AppleAuthenticationScope.EMAIL],
            });
            // Send credential.identityToken to backend
            const response = await api.post('/auth/apple', { token: credential.identityToken });
            return response.data;
        }
        """,
        integration_type="apple_sign_in",
    )
    print("\n📱 Apple Sign-In Review:")
    print(json.dumps(expo_review, indent=2))


def example_scaffolder():
    """Scaffolder Agent — generate project structures."""
    agent = ScaffolderAgent()

    print("\n" + "=" * 60)
    print("SCAFFOLDER AGENT")
    print("=" * 60)

    # Scaffold a full SaaS platform
    scaffold = agent._tool_handlers["scaffold_saas_platform"](
        project_name="next-big-thing",
        tiers="free,pro,enterprise",
        mobile_app=True,
        email=True,
    )
    print("\n🏗️ SaaS Platform: next-big-thing")
    print(f"  Architecture: {json.dumps(scaffold['architecture'], indent=4)}")
    print(f"\n  Files to create ({len(scaffold['file_structure'])}):")
    for f in scaffold["file_structure"]:
        print(f"    📄 {f}")

    # Generate .env.example
    env = agent._tool_handlers["generate_env_template"](
        project_type="saas_full_stack",
        integrations="stripe,sentry,resend,redis,apns"
    )
    print("\n📝 .env.example:")
    for line in env["env_template"]:
        print(f"  {line}")


def example_openai_chat():
    """Use any agent with the full OpenAI chat completions interface."""
    agent = SecurityAuditAgent()

    print("\n" + "=" * 60)
    print("OPENAI CHAT COMPLETIONS INTERFACE")
    print("=" * 60)

    # Get the raw payload — send to any OpenAI-compatible endpoint
    payload = agent.format_payload(
        user_input="Audit my Express app for security vulnerabilities",
        context="The app uses Helmet with CSP disabled, JWT stored in localStorage, and CORS set to '*'"
    )
    print("\n📤 Chat Completion Payload:")
    print(f"  Model: {payload['model']}")
    print(f"  Messages: {len(payload['messages'])}")
    print(f"  Tools: {len(payload.get('tools', []))} functions defined")
    print(f"  Temperature: {payload['temperature']}")

    # You can also send this payload to any OpenAI-compatible API:
    # import requests
    # response = requests.post(
    #     "https://api.openai.com/v1/chat/completions",
    #     headers={"Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}"},
    #     json=payload,
    # )


if __name__ == "__main__":
    # Run all examples (tool-level — no API key needed)
    example_security_audit()
    example_stripe_billing()
    example_railway_deploy()
    example_code_review()
    example_scaffolder()
    example_openai_chat()

    print("\n" + "=" * 60)
    print("✅ All examples complete!")
    print("=" * 60)
    print("\nTo use with OpenAI, set your API key and call agent.run():")
    print('  export OPENAI_API_KEY="sk-..."')
    print('  agent = SecurityAuditAgent()')
    print('  result = agent.run("Audit my app")')
    print('  print(result.content)')

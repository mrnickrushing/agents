"""
RushingTech Agents — Usage Examples

Run any of these examples after setting API keys:
    export OPENAI_API_KEY="sk-..."
    export ANTHROPIC_API_KEY="sk-ant-..."
    python example.py
"""

import os
import json

# ── Import ALL agents including the new UI Generation Agent ─────
from agents import (
    SecurityAuditAgent,
    StripeBillingAgent,
    RailwayDeployAgent,
    CodeReviewAgent,
    ScaffolderAgent,
    UIGenerationAgent,  # NEW: Claude-powered UI component generator
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
    print("\n💰 Subscription Model:")
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
    print("\n⚠️  Webhook Handler Review:")
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
    print("\n🏗️  SaaS Platform: next-big-thing")
    print(f"  Architecture: {json.dumps(scaffold['architecture'], indent=4)}")


def example_ui_generation():
    """UI Generation Agent — Claude-powered component creation with multi-turn conversation."""
    
    print("\n" + "=" * 60)
    print("UI GENERATION AGENT (CLAUDE-POWERED)")
    print("=" * 60)
    
    # Initialize with Anthropic API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n⚠️  Set ANTHROPIC_API_KEY to run this example:")
        print("  export ANTHROPIC_API_KEY='sk-ant-...'")
        print("\nShowing pattern instead:")
        
        # Show usage pattern
        pattern = """
# Initialize UI Generation Agent with Claude
from agents import UIGenerationAgent

agent = UIGenerationAgent(
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    provider="anthropic",
    model="claude-3-5-sonnet-20241022",
    temperature=0.7
)

# Example 1: Single-turn component generation
response = agent.run(
    "Create a responsive dashboard card component with:"
    "- A title (string prop)"
    "- A metric value (number prop)"
    "- A trend indicator ('up', 'down', or 'neutral')"
    "- A mini sparkline chart"
    "- Dark theme support"
    "- Clickable with hover effects"
    "- Fully accessible (keyboard navigation, screen reader support)"
)
print(response.content)

# Example 2: Multi-turn conversation
conversation_id = "dashboard-card-dev"

response1 = agent.run(
    "Create a user profile card with avatar, name, and bio",
    conversation_id=conversation_id
)

response2 = agent.run(
    "Now add a 'Follow' button with loading state ability",
    conversation_id=conversation_id
)

# Conversation history is maintained
print(f"Messages in conversation: {len(agent.history)}")

# Example 3: Wireframe to component
import base64

with open("wireframe.png", "rb") as f:
    image_base64 = base64.b64encode(f.read()).decode()

response = agent.process_wireframe(
    description="Create a navigation bar component",
    image_base64=image_base64,
    media_type="image/png",
    conversation_id="navbar-dev"
)
"""
        print(pattern)
        return
    
    # Run actual example if API key is present
    agent = UIGenerationAgent(
        api_key=api_key,
        provider="anthropic",
        model="claude-3-5-sonnet-20241022",
        temperature=0.7
    )
    
    print("\n🎨 Creating a dashboard card component...")
    
    response = agent.run(
        "Create a responsive dashboard card component with:"
        "- A title (string prop)"
        "- A metric value (number prop)"
        "- A trend indicator ('up', 'down', or 'neutral')"
        "- A mini sparkline chart shown as a visual indicator"
        "- Dark theme support"
        "- Clickable with hover effects"
        "- Fully accessible (keyboard navigation, screen reader support)"
    )
    
    print("\nGenerated Component:")
    print(response.content)
    print(f"\nModel: {response.model}")
    print(f"Tokens: {response.usage}")
    
    # Multi-turn example
    print("\n" + "-" * 60)
    print("Multi-turn conversation example:")
    print("-" * 60)
    
    conversation_id = "card-refinement"
    
    print("\nTurn 1: Create a basic card")
    response1 = agent.run("Create a simple stats card with title and value", conversation_id=conversation_id)
    print(f"✓ Generated (messages: {len(agent.history)})")
    
    print("\nTurn 2: Add trend indicator")
    response2 = agent.run("Now add a trend arrow that shows up/down/neutral", conversation_id=conversation_id)
    print(f"✓ Updated (messages: {len(agent.history)})")
    
    print("\nTurn 3: Make it darker theme")
    response3 = agent.run("Update the styling for a dark theme", conversation_id=conversation_id)
    print(f"✓ Styled (messages: {len(agent.history)})")
    
    print(f"\nFinal conversation length: {len(agent.history)} messages")


def example_multi_provider():
    """Demonstrate using agents with both OpenAI and Anthropic providers."""
    
    print("\n" + "=" * 60)
    print("MULTI-PROVIDER SUPPORT")
    print("=" * 60)
    
    # OpenAI provider (default)
    print("\n🤖 Using OpenAI:")
    openai_agent = SecurityAuditAgent(
        api_key=os.getenv("OPENAI_API_KEY"),
        provider="openai"
    )
    print(f"  Provider: {openai_agent.provider}")
    print(f"  Model: {openai_agent.model}")
    
    # Anthropic provider
    print("\n🧠 Using Anthropic (Claude):")
    anthropic_agent = SecurityAuditAgent(
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        provider="anthropic",
        model="claude-3-5-sonnet-20241022"
    )
    print(f"  Provider: {anthropic_agent.provider}")
    print(f"  Model: {anthropic_agent.model}")
    
    # UI Generation is Anthropic by default
    print("\n🎨 UI Generation Agent:")
    ui_agent = UIGenerationAgent(
        api_key=os.getenv("ANTHROPIC_API_KEY")
    )
    print(f"  Provider: {ui_agent.provider}")
    print(f"  Model: {ui_agent.model}")
    
    print("\n💡 Tip: Pass provider='openai' or provider='anthropic' to any agent!")


def example_openai_chat():
    """Use any agent with the full chat completions interface."""
    agent = SecurityAuditAgent()

    print("\n" + "=" * 60)
    print("CHAT COMPLETIONS INTERFACE")
    print("=" * 60)

    # Get the raw payload — send to any OpenAI-compatible endpoint
    payload = agent.format_payload(
        user_input="Audit my Express app for security vulnerabilities",
        context="The app uses Helmet with CSP disabled, JWT stored in localStorage, and CORS set to '*'"
    )
    print("\n📤 Chat Completion Payload:")
    print(f"  Model: {payload['model']}")
    print(f"  Provider: {agent.provider}")
    print(f"  Messages: {len(payload['messages'])}")
    print(f"  Tools: {len(payload.get('tools', []))} functions defined")


if __name__ == "__main__":
    # Run all examples (tool-level — no API key needed for most)
    example_security_audit()
    example_stripe_billing()
    example_railway_deploy()
    example_code_review()
    example_scaffolder()
    example_ui_generation()  # NEW: UI Generation Agent example
    example_multi_provider()  # NEW: Multi-provider demonstration
    example_openai_chat()

    print("\n" + "=" * 60)
    print("✅ All examples complete!")
    print("=" * 60)
    print("\nTo use with APIs, set your keys and call agent.run():")
    print('  export OPENAI_API_KEY="sk-..."')
    print('  export ANTHROPIC_API_KEY="sk-ant-..."')
    print('  agent = SecurityAuditAgent(provider="openai")')
    print('  result = agent.run("Audit my app")')
    print('  print(result.content)')
    print('\nFor UI generation:')
    print('  ui_agent = UIGenerationAgent(provider="anthropic")')
    print('  result = ui_agent.run("Create a dashboard card")')
    print('  print(result.content)')

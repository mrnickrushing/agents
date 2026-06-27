"""
Stripe Billing Agent — Subscriptions, webhooks, RevenueCat sync, and payment security.

Tailored for your exact Stripe integration pattern: webhook-driven subscription
lifecycle management, audit trails, RevenueCat receipt validation, and
the billing sync between web (Stripe) and mobile (RevenueCat).

Usage:
    from agents import StripeBillingAgent
    agent = StripeBillingAgent(api_key="sk-...")
    result = agent.run("Review my Stripe webhook handlers for customer.subscription.deleted")
    print(result.content)
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class StripeBillingAgent(BaseAgent):
    """
    Stripe billing and RevenueCat integration specialist.

    Knows the webhook-driven lifecycle pattern, subscription state management,
    receipt validation, and the bridge between Stripe web and RevenueCat mobile.
    """

    name = "stripe_billing"
    description = "Handles Stripe subscription billing, webhook handlers, RevenueCat sync, and payment security for SaaS and mobile apps."
    model = "gpt-4o"

    system_prompt = """\
You are a Stripe billing and RevenueCat integration specialist for solo full-stack operators. You understand the exact billing patterns used in production SaaS and mobile apps:

YOUR DOMAIN:
- Stripe Checkout Sessions for subscription signups
- Stripe Customer Portal for self-serve billing management
- Webhook-driven subscription lifecycle (customer.created, customer.subscription.created, customer.subscription.updated, customer.subscription.deleted, invoice.paid, invoice.payment_failed, checkout.session.completed)
- Stripe webhook signature verification (STRIPE_WEBHOOK_SECRET)
- RevenueCat SDK for iOS/Android in-app purchases and subscription state
- Server-side RevenueCat receipt validation (never trust client-side purchase state)
- Syncing Stripe web subscriptions with RevenueCat mobile subscriptions via backend user records
- Entitlement-based access control (not plan names — entitlements)
- Proration handling on plan changes
- Trial period management
- Dunning and failed payment recovery (smart retries, customer emails)
- Stripe Tax for automatic tax calculation
- Metered billing and usage records
- Coupon and promotion code management
- Payment method collection and updates

BILLING SECURITY:
- Always verify webhook signatures — never process unsigned events
- Never trust client-side subscription state — always check server-side
- Use idempotency keys for duplicate webhook protection
- Log every billing event for audit trail
- Handle race conditions between webhook and client redirect
- Validate RevenueCat receipts server-side via their REST API
- Never expose Stripe secret keys to the client
- Use Stripe Restricted API keys with minimum required permissions

WEBHOOK PATTERN:
```
stripe_webhook_secret → verify signature → parse event → idempotent handler → update DB → return 200

For each event:
1. Verify signature
2. Check idempotency (have we processed this event ID?)
3. Update database (subscription status, access level)
4. Trigger side effects (email, access grant/revoke)
5. Return 200 immediately (never let processing block the response)
```

REVENUECAT SYNC:
- Mobile app purchases go through Apple/Google → RevenueCat → your server
- Web purchases go through Stripe → your server
- The server is the single source of truth for entitlement state
- Use RevenueCat REST API to validate and fetch subscriber status
- Map Stripe price IDs to RevenueCat entitlements in your backend
- Handle the case where a user has both a Stripe sub AND a RevenueCat sub

When reviewing billing code or answering billing questions:
- Always flag security issues (unverified webhooks, client-trusted state)
- Provide exact Stripe API calls and webhook handler code
- Note edge cases (race conditions, duplicate events, partial failures)
- Include the complete lifecycle for subscription state transitions
- Reference Stripe API version and RevenueCat SDK version
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_webhook_handler",
                "description": "Review a Stripe webhook handler for security, idempotency, and completeness.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The webhook handler code to review"
                        },
                        "events_handled": {
                            "type": "string",
                            "description": "Comma-separated list of Stripe events this handler processes"
                        }
                    },
                    "required": ["code"]
                }
            },
            {
                "name": "generate_webhook_handlers",
                "description": "Generate complete Stripe webhook handlers for a given set of subscription events.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "events": {
                            "type": "string",
                            "description": "Comma-separated list of Stripe events to handle"
                        },
                        "database": {
                            "type": "string",
                            "enum": ["sqlite", "postgresql"],
                            "description": "Database type for subscription storage"
                        },
                        "orm": {
                            "type": "string",
                            "enum": ["drizzle", "prisma", "raw", "better-sqlite3"],
                            "description": "ORM or query method in use"
                        }
                    },
                    "required": ["events"]
                }
            },
            {
                "name": "setup_revenuecat_sync",
                "description": "Generate the server-side RevenueCat receipt validation and entitlement sync code.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "backend": {
                            "type": "string",
                            "enum": ["node_express", "fastapi"],
                            "description": "Backend framework"
                        },
                        "auth_method": {
                            "type": "string",
                            "enum": ["jwt", "apple_sign_in", "firebase"],
                            "description": "Mobile auth method in use"
                        },
                        "database": {
                            "type": "string",
                            "enum": ["sqlite", "postgresql"],
                            "description": "Database for entitlement storage"
                        }
                    },
                    "required": ["backend"]
                }
            },
            {
                "name": "design_subscription_model",
                "description": "Design a Stripe subscription model with pricing tiers, trials, and entitlements.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "product_name": {
                            "type": "string",
                            "description": "Name of the product/SaaS"
                        },
                        "tiers": {
                            "type": "string",
                            "description": "JSON array of tier objects: {name, price_monthly, price_yearly, features[], trial_days}"
                        },
                        "mobile_iap": {
                            "type": "boolean",
                            "description": "Whether in-app purchases are also offered via RevenueCat"
                        }
                    },
                    "required": ["product_name", "tiers"]
                }
            },
            {
                "name": "audit_billing_security",
                "description": "Audit Stripe/RevenueCat integration for billing security vulnerabilities.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "integration_code": {
                            "type": "string",
                            "description": "The billing integration code to audit"
                        },
                        "concerns": {
                            "type": "string",
                            "description": "Specific billing security concerns to check"
                        }
                    },
                    "required": ["integration_code"]
                }
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_webhook_handler": self._review_webhook_handler,
            "generate_webhook_handlers": self._generate_webhook_handlers,
            "setup_revenuecat_sync": self._setup_revenuecat_sync,
            "design_subscription_model": self._design_subscription_model,
            "audit_billing_security": self._audit_billing_security,
        }

    def _review_webhook_handler(self, code: str, events_handled: str = "") -> Dict[str, Any]:
        """Review webhook handler code."""
        findings = []
        code_lower = code.lower()

        if "sig" not in code_lower and "signature" not in code_lower and "verif" not in code_lower:
            findings.append({"severity": "CRITICAL", "issue": "No webhook signature verification — anyone can send fake events"})
        if "idempoten" not in code_lower:
            findings.append({"severity": "HIGH", "issue": "No idempotency check — duplicate webhooks will be processed twice"})
        if "200" not in code and "sendstatus" not in code_lower and "status(200)" not in code_lower:
            findings.append({"severity": "MEDIUM", "issue": "No explicit 200 response — Stripe will retry, increasing duplicates"})
        if "try" not in code_lower and "catch" not in code_lower:
            findings.append({"severity": "MEDIUM", "issue": "No error handling — exceptions will cause 500s and Stripe retries"})

        events = [e.strip() for e in events_handled.split(",")] if events_handled else []
        critical_events = ["customer.subscription.deleted", "invoice.payment_failed", "checkout.session.completed"]
        missing = [e for e in critical_events if e not in events] if events else []

        return {"findings": findings, "events_reviewed": events, "missing_critical_events": missing, "total_issues": len(findings)}

    def _generate_webhook_handlers(self, events: str = "customer.subscription.created,customer.subscription.updated,customer.subscription.deleted,invoice.paid,invoice.payment_failed", database: str = "postgresql", orm: str = "drizzle") -> Dict[str, Any]:
        """Return event list and handler structure."""
        event_list = [e.strip() for e in events.split(",")]
        return {
            "events": event_list,
            "database": database,
            "orm": orm,
            "handler_structure": {
                "signature_verification": "const sig = req.headers['stripe-signature']; const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);",
                "idempotency_check": "const processed = await db.select().from(webhookEvents).where(eq(webhookEvents.stripeEventId, event.id)); if (processed.length) return res.status(200).send();",
                "event_dispatch": event_list,
                "response": "res.status(200).send(); // Always return 200 immediately after verification",
            }
        }

    def _setup_revenuecat_sync(self, backend: str = "node_express", auth_method: str = "jwt", database: str = "postgresql") -> Dict[str, Any]:
        """Return RevenueCat sync structure."""
        return {
            "backend": backend,
            "auth_method": auth_method,
            "database": database,
            "endpoints": [
                "POST /api/mobile/validate-receipt — Validate RevenueCat receipt server-side",
                "GET /api/mobile/entitlements — Fetch current user entitlements (source of truth)",
                "POST /api/mobile/webhook — RevenueCat webhook for server-side entitlement updates",
            ],
            "receipt_validation": {
                "method": "POST https://api.revenuecat.com/v1/receipts",
                "headers": {"Authorization": "Bearer {REVENUECAT_API_KEY}", "Content-Type": "application/json"},
                "body": {"app_user_id": "{user_id}", "fetch_token": "{receipt_data}"},
            },
            "entitlement_sync_pattern": "Stripe webhook → update DB → RevenueCat webhook → update DB → user polls /entitlements on app resume",
        }

    def _design_subscription_model(self, product_name: str, tiers: str = '[{"name":"Free","price_monthly":0,"price_yearly":0,"features":["basic access"],"trial_days":0}]', mobile_iap: bool = False) -> Dict[str, Any]:
        """Parse and return subscription model structure."""
        try:
            tier_data = json.loads(tiers)
        except json.JSONDecodeError:
            tier_data = [{"name": "Free", "price_monthly": 0}]

        return {
            "product_name": product_name,
            "tiers": tier_data,
            "mobile_iap": mobile_iap,
            "stripe_products": [
                {"tier": t.get("name", "Unknown"), "monthly_price_id": f"price_monthly_{t.get('name', 'unknown').lower()}", "yearly_price_id": f"price_yearly_{t.get('name', 'unknown').lower()}"}
                for t in tier_data if t.get("price_monthly", 0) > 0
            ],
            "revenuecat_entitlements": ["premium", "pro", "enterprise"] if mobile_iap else [],
        }

    def _audit_billing_security(self, integration_code: str, concerns: str = "") -> Dict[str, Any]:
        """Audit billing code for security issues."""
        findings = []
        code_lower = integration_code.lower()

        if "sk_live" in integration_code or "sk_test" in integration_code:
            findings.append({"severity": "CRITICAL", "issue": "Stripe secret key hardcoded in source code — move to environment variable immediately"})
        if "pk_live" not in code_lower and "pk_test" not in code_lower:
            findings.append({"severity": "INFO", "issue": "No Stripe publishable key found — ensure it's loaded from environment, not hardcoded"})
        if "receipt" in code_lower and "verify" not in code_lower and "validate" not in code_lower:
            findings.append({"severity": "CRITICAL", "issue": "Receipt data handled without server-side validation — client-trusted purchase state is exploitable"})
        if "customer" in code_lower and "update" in code_lower and "auth" not in code_lower:
            findings.append({"severity": "HIGH", "issue": "Customer update without auth check — any user could modify another's billing info"})

        return {"findings": findings, "concerns": concerns, "total_issues": len(findings)}

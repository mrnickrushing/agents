"""
Code Review Agent — React, Node/Express, React Native/Expo, TypeScript code review.

Reviews code for bugs, security issues, performance problems, and best practices
across the exact stack you ship: React 19, TypeScript, Node/Express, React Native/Expo,
Zustand, Drizzle ORM, and Zod validation.

Usage:
    from agents import CodeReviewAgent
    agent = CodeReviewAgent(api_key="sk-...")
    result = agent.run("Review this Express route handler: ...")
    print(result.content)
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class CodeReviewAgent(BaseAgent):
    """
    Code review specialist for the RushingTech stack.

    Reviews React, Node/Express, React Native/Expo, and TypeScript code
    for bugs, security vulnerabilities, performance issues, and
    architectural problems.
    """

    name = "code_review"
    description = "Reviews React, Node/Express, React Native/Expo, and TypeScript code for bugs, security issues, performance, and best practices."
    model = "gpt-5"

    system_prompt = """\
You are a senior full-stack code reviewer specializing in the exact stack used by a solo operator shipping production apps:

REVIEW DOMAINS:

1. REACT / TYPESCRIPT FRONTEND
   - React 19 patterns (use(), useOptimistic, useFormStatus, Server Components)
   - TypeScript type safety (no 'any' escapes, proper generics, discriminated unions)
   - Zustand state management (proper selectors, no unnecessary re-renders, persist middleware)
   - Component architecture (composition over inheritance, proper prop drilling vs context)
   - Performance (React.memo, useMemo, useCallback, code splitting, lazy loading)
   - Error boundaries and graceful degradation
   - Accessibility (semantic HTML, ARIA labels, keyboard navigation)

2. REACT NATIVE / EXPO MOBILE
   - Expo Router file-based routing and layout patterns
   - expo-sqlite local storage (proper migration, transaction safety)
   - expo-notifications (scheduling, handling foreground/background)
   - expo-image-picker and expo-media-library permissions
   - expo-location background tracking patterns
   - Apple Sign-In implementation (token validation, Keychain storage)
   - Face ID / biometric auth (LocalAuthentication)
   - RevenueCat integration (entitlements, offerings, purchase flow)
   - HealthKit read/write integration
   - APNs push notification handling
   - Deep linking (custom URL schemes, universal links)
   - Gesture handling and responsive layouts

3. NODE.JS / EXPRESS BACKEND
   - Route handler patterns (proper error handling, async wrapper)
   - Zod validation at API boundaries (never trust client input)
   - JWT authentication middleware
   - Helmet.js security headers
   - Rate limiting configuration
   - Stripe webhook handlers (signature verification, idempotency)
   - Drizzle ORM queries (parameterized, proper joins, transactions)
   - better-sqlite3 for simple deploys, PostgreSQL for production scale
   - WebSocket / Socket.io patterns
   - Redis for caching and session management

4. DATABASE / ORM
   - Drizzle ORM schema definitions and relations
   - Migration strategies (drizzle-kit push vs generate)
   - PostgreSQL with PostGIS for geospatial queries
   - SQLite for simpler deploys (when to use which)
   - Index optimization and query performance
   - Transaction isolation and deadlock prevention

5. API DESIGN
   - REST endpoint naming conventions
   - Proper HTTP status codes and error response format
   - OpenAPI / Swagger documentation
   - Pagination patterns (cursor vs offset)
   - File upload handling

REVIEW PRIORITIES (in order):
1. SECURITY — Is there a vulnerability? (injection, auth bypass, data leak)
2. CORRECTNESS — Does the code do what it claims? Are there edge cases?
3. PERFORMANCE — Will this scale? Are there N+1 queries, memory leaks?
4. MAINTAINABILITY — Can the solo operator understand this in 6 months?
5. BEST PRACTICES — Does it follow framework conventions?

REVIEW FORMAT:
For each finding:
- 🏴 CRITICAL: Security vulnerability or data corruption risk
- 🟠 HIGH: Bug that will cause incorrect behavior
- 🟡 MEDIUM: Performance issue or maintainability concern
- 🟢 LOW: Style, naming, or minor best practice suggestion
- ℹ️ INFO: Observation or architectural note

Always provide the fix with code, not just a description of what's wrong.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_express_route",
                "description": "Review an Express route handler for bugs, security, and best practices.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The Express route handler code to review"
                        },
                        "route_path": {
                            "type": "string",
                            "description": "The route path (e.g., 'POST /api/users')"
                        },
                        "auth_required": {
                            "type": "boolean",
                            "description": "Whether this route requires authentication"
                        }
                    },
                    "required": ["code", "route_path"]
                }
            },
            {
                "name": "review_react_component",
                "description": "Review a React component for performance, accessibility, and patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The React component code to review"
                        },
                        "component_name": {
                            "type": "string",
                            "description": "Name of the component"
                        },
                        "is_native": {
                            "type": "boolean",
                            "description": "Whether this is a React Native component"
                        }
                    },
                    "required": ["code", "component_name"]
                }
            },
            {
                "name": "review_drizzle_schema",
                "description": "Review a Drizzle ORM schema definition for correctness and performance.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "schema_code": {
                            "type": "string",
                            "description": "The Drizzle schema definition code"
                        },
                        "database": {
                            "type": "string",
                            "enum": ["postgresql", "sqlite"],
                            "description": "Target database"
                        }
                    },
                    "required": ["schema_code"]
                }
            },
            {
                "name": "review_zod_validation",
                "description": "Review Zod validation schemas for completeness and security.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "schema_code": {
                            "type": "string",
                            "description": "The Zod schema code to review"
                        },
                        "endpoint": {
                            "type": "string",
                            "description": "The API endpoint this schema validates"
                        }
                    },
                    "required": ["schema_code"]
                }
            },
            {
                "name": "review_expo_integration",
                "description": "Review React Native/Expo integration code (notifications, auth, IAP, etc.).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The Expo integration code to review"
                        },
                        "integration_type": {
                            "type": "string",
                            "enum": ["push_notifications", "apple_sign_in", "face_id", "revenuecat", "healthkit", "location", "camera", "deep_linking"],
                            "description": "Type of Expo integration"
                        }
                    },
                    "required": ["code", "integration_type"]
                }
            },
            {
                "name": "review_stripe_webhook",
                "description": "Review a Stripe webhook handler for security and completeness.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The Stripe webhook handler code"
                        },
                        "event_type": {
                            "type": "string",
                            "description": "The Stripe event type (e.g., 'checkout.session.completed')"
                        }
                    },
                    "required": ["code", "event_type"]
                }
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_express_route": self._review_express_route,
            "review_react_component": self._review_react_component,
            "review_drizzle_schema": self._review_drizzle_schema,
            "review_zod_validation": self._review_zod_validation,
            "review_expo_integration": self._review_expo_integration,
            "review_stripe_webhook": self._review_stripe_webhook,
        }

    def _review_express_route(self, code: str, route_path: str, auth_required: bool = False) -> Dict[str, Any]:
        """Review Express route handler."""
        findings = []
        code_lower = code.lower()

        if auth_required and ("auth" not in code_lower and "jwt" not in code_lower and "middleware" not in code_lower):
            findings.append({"severity": "CRITICAL", "issue": f"Route {route_path} requires auth but has no auth middleware", "fix": "Add auth middleware: router.post('/path', authenticate, handler)"})
        if "try" not in code_lower and "catch" not in code_lower and "await" in code_lower:
            findings.append({"severity": "HIGH", "issue": "Async handler without try/catch — unhandled promise rejection will crash the server", "fix": "Wrap in try/catch or use asyncHandler wrapper"})
        if "zod" not in code_lower and "validate" not in code_lower and ("body" in code_lower or "params" in code_lower or "query" in code_lower):
            findings.append({"severity": "HIGH", "issue": "No input validation — client can send any data structure", "fix": "Add Zod validation: const schema = z.object({...}); const validated = schema.parse(req.body);"})
        if re.search(r"\.status\(\s*500\s*\)", code):
            findings.append({"severity": "MEDIUM", "issue": "Hardcoded 500 error — consider structured error handling", "fix": "Use a central error handler middleware"})
        if re.search(r"\.findmany\s*\(|select\s+\*", code_lower) and ".limit(" not in code_lower:
            findings.append({"severity": "MEDIUM", "issue": "Unbounded query — no LIMIT on database select, could return millions of rows", "fix": "Add pagination: .limit(pageSize).offset(page * pageSize)"})

        return {"route": route_path, "auth_required": auth_required, "findings": findings, "total_issues": len(findings)}

    def _review_react_component(self, code: str, component_name: str, is_native: bool = False) -> Dict[str, Any]:
        """Review React/React Native component."""
        findings = []
        code_lower = code.lower()
        has_use_effect = "useeffect" in code_lower
        has_effect_cleanup = bool(re.search(r"return\s*(?:\(\s*)?(?:\(\s*\)\s*=>|function\b)", code_lower))
        has_abort_cleanup = "abortcontroller" in code_lower or "abort()" in code_lower or "abort.signal" in code_lower
        has_timer_side_effect = "setinterval(" in code_lower or "settimeout(" in code_lower
        has_timer_cleanup = "clearinterval(" in code_lower or "cleartimeout(" in code_lower

        if ": any" in code or "as any" in code:
            findings.append({"severity": "MEDIUM", "issue": "TypeScript 'any' type used — loses type safety", "fix": "Replace with proper type definitions"})
        if has_use_effect and ("fetch(" in code_lower or "apifetch(" in code_lower or "axios" in code_lower):
            if not (has_effect_cleanup and has_abort_cleanup):
                findings.append({"severity": "MEDIUM", "issue": "Network request in useEffect without abort-aware cleanup — state can update after unmount or route change", "fix": "Create an AbortController inside the effect, pass signal to fetch/apiFetch, and abort it in the cleanup return"})
        if has_use_effect and has_timer_side_effect and not (has_effect_cleanup and has_timer_cleanup):
            findings.append({"severity": "MEDIUM", "issue": "Timer started in useEffect without cleanup — interval/timeout can keep running after unmount", "fix": "Return a cleanup function that calls clearInterval()/clearTimeout()"})
        if "console.log" in code_lower:
            findings.append({"severity": "LOW", "issue": "console.log in production code", "fix": "Remove or replace with proper logger"})
        if is_native and "onpress" not in code_lower and "onclick" in code_lower:
            findings.append({"severity": "HIGH", "issue": "Using onClick in React Native — use onPress instead", "fix": "Replace onClick with onPress for React Native components"})
        if "usestate" in code_lower and code.count("useState") > 5:
            findings.append({"severity": "MEDIUM", "issue": f"Component has {code.count('useState')} useState calls — consider Zustand store or useReducer", "fix": "Extract related state into a Zustand store or useReducer"})

        return {"component": component_name, "is_native": is_native, "findings": findings, "total_issues": len(findings)}

    def _review_drizzle_schema(self, schema_code: str, database: str = "postgresql") -> Dict[str, Any]:
        """Review Drizzle schema."""
        findings = []
        code_lower = schema_code.lower()

        # A file can import from drizzle-orm (query builders, the `eq`/`and`
        # helpers, the `drizzle()` client itself) without ever defining a
        # table — that's a route, service, or db-client file, not a schema.
        # The checks below (primary key, indexes, timestamps) only make
        # sense once an actual table definition exists in this file.
        if not re.search(r"(?:pg|sqlite)table\s*\(", code_lower):
            return {"database": database, "findings": [], "total_issues": 0}

        if "index" not in code_lower and ("where" in code_lower or "find" in code_lower):
            findings.append({"severity": "MEDIUM", "issue": "No indexes defined — queries on filtered columns will be slow", "fix": "Add .index() on frequently queried columns"})
        if "timestamp" not in code_lower and ("created" in code_lower or "updated" in code_lower):
            findings.append({"severity": "LOW", "issue": "No timestamp columns — consider adding createdAt/updatedAt", "fix": "Add createdAt: timestamp('created_at').defaultNow()"})
        if database == "sqlite" and "json" in code_lower:
            findings.append({"severity": "MEDIUM", "issue": "SQLite has limited JSON support — consider normalizing or using PostgreSQL", "fix": "Use text() with JSON.stringify/parse or migrate to PostgreSQL"})
        if "primarykey" not in code_lower.replace(" ", ""):
            findings.append({"severity": "HIGH", "issue": "No primary key defined", "fix": "Add id: serial('id').primaryKey() or uuid('id').primaryKey().defaultRandom()"})

        return {"database": database, "findings": findings, "total_issues": len(findings)}

    def _review_zod_validation(self, schema_code: str, endpoint: str = "") -> Dict[str, Any]:
        """Review Zod validation schema."""
        findings = []
        code_lower = schema_code.lower()

        if ".min(" not in code_lower and ("string" in code_lower or "email" in code_lower):
            findings.append({"severity": "MEDIUM", "issue": "String fields without .min() — no length validation", "fix": "Add .min(1) for required strings, .min(8) for passwords"})
        if ".max(" not in code_lower and "string" in code_lower:
            findings.append({"severity": "LOW", "issue": "No .max() on string fields — allows arbitrarily long input", "fix": "Add .max(255) or appropriate length limits"})
        if "email" in code_lower and "z.email" not in code_lower and ".email()" not in code_lower:
            findings.append({"severity": "HIGH", "issue": "Email field not validated with z.string().email()", "fix": "Use z.string().email() for email validation"})
        if ".transform" in code_lower and ".pipe" not in code_lower:
            findings.append({"severity": "INFO", "issue": "Transform used — ensure it doesn't mask validation errors", "fix": "Consider using .pipe() for transform chains"})

        return {"endpoint": endpoint, "findings": findings, "total_issues": len(findings)}

    def _review_expo_integration(self, code: str, integration_type: str = "push_notifications") -> Dict[str, Any]:
        """Review Expo integration code."""
        findings = []
        code_lower = code.lower()

        if integration_type == "push_notifications":
            if "getpermissionsasync" not in code_lower and "requestpermissionsasync" not in code_lower:
                findings.append({"severity": "HIGH", "issue": "No permission request before push notification registration", "fix": "Call Notifications.requestPermissionsAsync() before getExpoPushTokenAsync()"})
            if "foreground" not in code_lower:
                findings.append({"severity": "MEDIUM", "issue": "No foreground notification handler — notifications won't show when app is active", "fix": "Add Notifications.setNotificationHandler({ handleNotification: async () => ({ shouldShowAlert: true }) })"})

        elif integration_type == "apple_sign_in":
            if "nonce" not in code_lower:
                findings.append({"severity": "HIGH", "issue": "No nonce in Apple Sign-In — vulnerable to replay attacks", "fix": "Generate a random nonce, hash it with SHA256, pass to AppleSign In request, verify nonce server-side"})
            if "server" not in code_lower and "verify" not in code_lower and "validate" not in code_lower:
                findings.append({"severity": "CRITICAL", "issue": "Apple identity token not validated server-side", "fix": "Send identity token to backend, verify with Apple's public keys, extract email/sub"})

        elif integration_type == "revenuecat":
            if "customerinfo" not in code_lower and "offerings" not in code_lower:
                findings.append({"severity": "MEDIUM", "issue": "Not checking CustomerInfo for entitlements — relying on purchase state", "fix": "Use Purchases.getCustomerInfo() and check .entitlements.active"})
            if "server" not in code_lower and "backend" not in code_lower:
                findings.append({"severity": "HIGH", "issue": "No server-side receipt validation — client-trusted purchase state", "fix": "Send receipt to backend, validate via RevenueCat REST API, set entitlement server-side"})

        elif integration_type == "face_id":
            if "fallback" not in code_lower:
                findings.append({"severity": "MEDIUM", "issue": "No fallback for devices without Face ID", "fix": "Check isEnrolled && isAvailable, offer device password as fallback"})

        elif integration_type == "location":
            if "foreground" not in code_lower and "background" not in code_lower:
                findings.append({"severity": "HIGH", "issue": "No foreground/background permission distinction", "fix": "Request foreground first, then background with TaskManager.defineTask()"})
            if "stopsupdating" not in code_lower and "remove" not in code_lower:
                findings.append({"severity": "MEDIUM", "issue": "No location tracking cleanup — continues draining battery after unmount", "fix": "Call Location.stopLocationUpdatesAsync(taskName) in cleanup"})

        elif integration_type == "healthkit":
            if not re.search(r"platform\.os", code, re.IGNORECASE):
                findings.append({"severity": "HIGH", "issue": "No Platform.OS guard found — HealthKit is iOS-only and will crash or no-op unexpectedly on Android without an explicit platform check", "fix": "Guard every HealthKit call with `if (Platform.OS !== 'ios') return;` (or route to expo-health-connect/react-native-health-connect on Android)"})
            if not re.search(r"requestauthorization|requestpermission", code, re.IGNORECASE):
                findings.append({"severity": "HIGH", "issue": "No authorization/permission request found before HealthKit access", "fix": "Call requestAuthorization() (or the equivalent permission request) before reading/writing HealthKit data"})

        return {"integration_type": integration_type, "findings": findings, "total_issues": len(findings)}

    def _review_stripe_webhook(self, code: str, event_type: str = "") -> Dict[str, Any]:
        """Review Stripe webhook handler."""
        findings = []
        code_lower = code.lower()

        if "constructevent" not in code_lower and "verify" not in code_lower:
            findings.append({"severity": "CRITICAL", "issue": "No webhook signature verification", "fix": "const event = stripe.webhooks.constructEvent(body, sig, WEBHOOK_SECRET)"})
        if "event.id" not in code_lower and "idempoten" not in code_lower:
            findings.append({"severity": "HIGH", "issue": "No idempotency check — duplicate events processed twice", "fix": "Store event.id in processed_events table, check before processing"})
        if "200" not in code and "sendstatus(200)" not in code_lower:
            findings.append({"severity": "MEDIUM", "issue": "No explicit 200 response", "fix": "Return res.status(200).send() immediately after signature verification"})

        return {"event_type": event_type, "findings": findings, "total_issues": len(findings)}

"""
Scaffolder Agent - Project bootstrapping and repo structure generation.

Creates opinionated starter structures for the stack used in this repo:
Express APIs, React SPAs, Expo mobile apps, and full SaaS platforms with
billing, auth, and deployment scaffolding.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from agents.base import BaseAgent


class ScaffolderAgent(BaseAgent):
    """Generate production-oriented project scaffolds for common product shapes."""

    name = "scaffolder"
    description = "Generates project scaffolds for Express APIs, React SPAs, Expo apps, and SaaS platforms."
    model = "gpt-5"

    system_prompt = """\
You are a senior staff engineer who creates pragmatic starter repos for solo operators.

Focus on:
- Correct file structure
- Minimal but production-ready defaults
- Clear separation of concerns
- Security basics enabled by default
- Stripe, auth, and deployment hooks where relevant

When asked to scaffold a project, return a complete tree, key files, and next steps.
Prefer boring, maintainable choices over clever abstractions.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "scaffold_express_api",
                "description": "Generate an Express API starter with auth, validation, and deployment structure.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {"type": "string"},
                        "database": {"type": "string", "enum": ["sqlite", "postgresql"]},
                        "auth": {"type": "boolean"},
                        "stripe": {"type": "boolean"},
                    },
                    "required": ["project_name"],
                },
            },
            {
                "name": "scaffold_react_spa",
                "description": "Generate a React SPA starter with routing, API client, and app shell.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {"type": "string"},
                        "state_manager": {"type": "string", "enum": ["zustand", "redux", "context"]},
                        "tailwind": {"type": "boolean"},
                    },
                    "required": ["project_name"],
                },
            },
            {
                "name": "scaffold_expo_app",
                "description": "Generate an Expo mobile app starter with navigation and backend integration.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {"type": "string"},
                        "backend_url": {"type": "string"},
                        "revenuecat": {"type": "boolean"},
                    },
                    "required": ["project_name"],
                },
            },
            {
                "name": "scaffold_saas_platform",
                "description": "Generate a full SaaS starter with web app, API, billing, and deployment files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {"type": "string"},
                        "tiers": {"type": "string", "description": "Comma-separated billing tiers"},
                        "mobile_app": {"type": "boolean"},
                        "email": {"type": "boolean"},
                    },
                    "required": ["project_name", "tiers"],
                },
            },
            {
                "name": "generate_file_tree",
                "description": "Generate a repo file tree for a given product shape.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_type": {"type": "string"},
                        "features": {"type": "string"},
                    },
                    "required": ["project_type"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "scaffold_express_api": self._scaffold_express_api,
            "scaffold_react_spa": self._scaffold_react_spa,
            "scaffold_expo_app": self._scaffold_expo_app,
            "scaffold_saas_platform": self._scaffold_saas_platform,
            "generate_file_tree": self._generate_file_tree,
        }

    def _scaffold_express_api(
        self,
        project_name: str,
        database: str = "postgresql",
        auth: bool = True,
        stripe: bool = False,
    ) -> Dict[str, Any]:
        files = {
            "src/server.ts": (
                "import { app } from './app';\n"
                "const port = Number(process.env.PORT ?? 3000);\n"
                "app.listen(port, '0.0.0.0', () => console.info(`listening on ${port}`));\n"
            ),
            "src/app.ts": (
                "import cors from 'cors';\nimport express from 'express';\nimport helmet from 'helmet';\n"
                "import { healthRouter } from './routes/health';\n"
                "export const app = express();\n"
                "app.use(helmet());\n"
                "app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));\n"
                "app.use(express.json({ limit: '1mb' }));\n"
                "app.use(healthRouter);\n"
                "app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: { code: 'internal_error', message: 'Internal server error' } }); });\n"
            ),
            "src/routes/health.ts": (
                "import { Router } from 'express';\n"
                "export const healthRouter = Router();\n"
                "healthRouter.get('/health', (_req, res) => res.json({ ok: true }));\n"
                "// Replace this liveness-only route with DB/Redis checks before production.\n"
                "healthRouter.get('/ready', (_req, res) => res.status(503).json({ ok: false, reason: 'readiness_not_configured' }));\n"
            ),
        }
        if auth:
            files["src/middleware/auth.ts"] = (
                "import jwt from 'jsonwebtoken';\n"
                "const secret = process.env.JWT_SECRET;\n"
                "if (!secret) throw new Error('JWT_SECRET is required');\n"
                "export const requireAuth = (req, res, next) => {\n"
                "  const token = req.headers.authorization?.replace(/^Bearer\\s+/i, '');\n"
                "  if (!token) return res.status(401).json({ error: { code: 'unauthorized', message: 'Authentication required' } });\n"
                "  try { req.user = jwt.verify(token, secret, { algorithms: ['HS256'] }); next(); }\n"
                "  catch { res.status(401).json({ error: { code: 'invalid_token', message: 'Invalid token' } }); }\n"
                "};\n"
            )
        if stripe:
            files["src/routes/stripe.ts"] = "// Verify the raw-body signature, persist event.id idempotently, then dispatch the Stripe event.\n"

        return {
            "project_name": project_name,
            "database": database,
            "files": files,
            "next_steps": [
                "Add Zod/Pydantic-style validation at every API boundary",
                "Wire in database migrations",
                "Replace the fail-closed /ready stub with real database and cache readiness checks",
                "Add per-route rate limits for login, password reset, and other abuse-sensitive endpoints",
                "Add tests for auth failures, validation, and error envelopes",
                "Add CI and deployment config",
            ],
        }

    def _scaffold_react_spa(
        self,
        project_name: str,
        state_manager: str = "zustand",
        tailwind: bool = True,
    ) -> Dict[str, Any]:
        return {
            "project_name": project_name,
            "stack": {"state_manager": state_manager, "tailwind": tailwind},
            "files": {
                "src/main.tsx": "import React from 'react';",
                "src/App.tsx": "export default function App() { return <main />; }",
                "src/lib/api.ts": "export async function apiFetch() {}",
            },
        }

    def _scaffold_expo_app(
        self,
        project_name: str,
        backend_url: str = "",
        revenuecat: bool = True,
    ) -> Dict[str, Any]:
        return {
            "project_name": project_name,
            "backend_url": backend_url,
            "files": {
                "app/_layout.tsx": "export default function Layout() { return null; }",
                "app/index.tsx": "export default function Screen() { return null; }",
                "src/lib/api.ts": "export const API_URL = process.env.EXPO_PUBLIC_API_URL;",
            },
            "revenuecat": revenuecat,
        }

    def _scaffold_saas_platform(
        self,
        project_name: str,
        tiers: str,
        mobile_app: bool = False,
        email: bool = False,
    ) -> Dict[str, Any]:
        tier_list = [tier.strip() for tier in tiers.split(",") if tier.strip()]
        return {
            "project_name": project_name,
            "tiers": tier_list,
            "architecture": {
                "web": "React SPA or Next.js front end",
                "api": "Express API with Zod validation",
                "billing": "Stripe webhooks with idempotent processing",
                "mobile_app": mobile_app,
                "email": email,
            },
            "file_tree": [
                "apps/web",
                "apps/api",
                "packages/shared",
                "packages/ui",
                "infra/railway.toml",
                "infra/github-actions.yml",
            ],
            "key_files": self._scaffold_express_api(project_name)["files"],
            "notes": [
                "Keep business logic in shared modules where possible",
                "Make the server the source of truth for auth and entitlements",
                "Ship with health checks, rate limiting, and deployment config on day one",
            ],
        }

    def _generate_file_tree(self, project_type: str, features: str = "") -> Dict[str, Any]:
        feature_list = [feature.strip() for feature in features.split(",") if feature.strip()]
        tree = {
            "web_app": ["src", "public", "tests"],
            "api_only": ["src/routes", "src/middleware", "src/lib"],
            "saas_platform": ["apps/web", "apps/api", "packages/shared", "infra"],
        }.get(project_type, ["src"])
        return {"project_type": project_type, "features": feature_list, "tree": tree}

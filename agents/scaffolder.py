"""
Scaffolder Agent — Project bootstrapping for Express, React, React Native/Expo,
FastAPI, and full-stack SaaS builds.

Generates project structures, boilerplate, and starter configs so you can
skip the setup grind and start building features immediately.

Usage:
    from agents import ScaffolderAgent
    agent = ScaffolderAgent(api_key="sk-...")
    result = agent.run("Scaffold a new SaaS project with React, Express, PostgreSQL, Stripe, and Sentry")
    print(result.content)
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class ScaffolderAgent(BaseAgent):
    """
    Project scaffolding specialist for the RushingTech stack.

    Generates project structures, boilerplate configs, and starter code
    for Express backends, React frontends, React Native/Expo mobile apps,
    FastAPI services, and full SaaS platforms.
    """

    name = "scaffolder"
    description = "Scaffolds new projects with production-ready boilerplate: Express APIs, React SPAs, React Native/Expo apps, FastAPI services, and full SaaS platforms."
    model = "gpt-4o"

    system_prompt = """\
You are a project scaffolding specialist for a solo full-stack operator who ships fast. You generate production-ready project structures with real boilerplate — not toy examples.

YOUR SCAFFOLDING PATTERNS:

1. NODE/EXPRESS API
   - Express + TypeScript + Zod validation at every boundary
   - Helmet + rate limiting + CORS configured for production
   - JWT auth with refresh token rotation
   - Drizzle ORM with SQLite (simple) or PostgreSQL (production)
   - Health check endpoint (/health)
   - Error handler middleware (structured errors, no stack traces in prod)
   - Request logging middleware
   - .env.example with all required variables
   - Sentry integration
   - Proper tsconfig and nodemon dev setup

2. REACT SPA
   - Vite + React 19 + TypeScript
   - Tailwind CSS for styling
   - Zustand for state management
   - React Router for navigation
   - API client with auth interceptors
   - Error boundary component
   - SEO meta component
   - Sentry integration

3. REACT NATIVE / EXPO APP
   - Expo Router (file-based routing)
   - TypeScript strict mode
   - Zustand for state
   - expo-sqlite for local storage
   - Apple Sign-In + Face ID auth flow
   - RevenueCat purchase flow skeleton
   - Push notification setup
   - Sentry integration
   - app.json / app.config.ts configured

4. FASTAPI SERVICE
   - FastAPI + Pydantic v2 validation
   - PostgreSQL + SQLAlchemy or asyncpg
   - Redis for caching/queue
   - Celery for async jobs
   - Docker Compose for local dev
   - OpenAPI docs auto-generated
   - Sentry integration

5. FULL SaaS PLATFORM
   - React 19 frontend (Vite)
   - Node/Express backend with PostgreSQL + Drizzle
   - Stripe Checkout + Customer Portal + Webhooks
   - JWT auth with role-based access
   - Resend transactional email
   - Sentry error monitoring
   - Railway deployment config
   - GitHub Actions CI pipeline

SCAFFOLDING RULES:
- Every project includes .env.example, never .env
- Every project includes .gitignore (node_modules, .env, dist, .DS_Store)
- Every project includes a README with setup instructions
- Every backend includes a /health endpoint
- Every auth flow includes refresh token rotation
- Every project has TypeScript strict mode enabled
- Security headers and rate limiting from day one
- No placeholder code — every line compiles and runs
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "scaffold_express_api",
                "description": "Scaffold a Node/Express API project with TypeScript, Zod, Helmet, JWT auth, and Drizzle ORM.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Name of the project"
                        },
                        "database": {
                            "type": "string",
                            "enum": ["sqlite", "postgresql"],
                            "description": "Database to use"
                        },
                        "auth": {
                            "type": "boolean",
                            "description": "Include JWT auth scaffolding"
                        },
                        "stripe": {
                            "type": "boolean",
                            "description": "Include Stripe billing scaffolding"
                        }
                    },
                    "required": ["project_name"]
                }
            },
            {
                "name": "scaffold_react_app",
                "description": "Scaffold a React SPA with Vite, TypeScript, Tailwind, and Zustand.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Name of the project"
                        },
                        "routing": {
                            "type": "boolean",
                            "description": "Include React Router"
                        },
                        "auth": {
                            "type": "boolean",
                            "description": "Include auth context and protected routes"
                        }
                    },
                    "required": ["project_name"]
                }
            },
            {
                "name": "scaffold_expo_app",
                "description": "Scaffold a React Native/Expo app with Expo Router, TypeScript, and common integrations.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Name of the project"
                        },
                        "features": {
                            "type": "string",
                            "description": "Comma-separated features: apple_sign_in,face_id,revenuecat,push_notifications,local_storage,healthkit,location,camera"
                        },
                        "navigation": {
                            "type": "string",
                            "enum": ["tabs", "drawer", "stack"],
                            "description": "Navigation pattern"
                        }
                    },
                    "required": ["project_name"]
                }
            },
            {
                "name": "scaffold_saas_platform",
                "description": "Scaffold a full SaaS platform (frontend + backend + billing + deployment).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Name of the SaaS product"
                        },
                        "tiers": {
                            "type": "string",
                            "description": "Comma-separated subscription tiers (e.g., 'free,pro,enterprise')"
                        },
                        "mobile_app": {
                            "type": "boolean",
                            "description": "Include React Native companion app"
                        },
                        "email": {
                            "type": "boolean",
                            "description": "Include Resend transactional email"
                        }
                    },
                    "required": ["project_name"]
                }
            },
            {
                "name": "scaffold_fastapi_service",
                "description": "Scaffold a FastAPI service with PostgreSQL, Redis, and Celery.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_name": {
                            "type": "string",
                            "description": "Name of the service"
                        },
                        "celery": {
                            "type": "boolean",
                            "description": "Include Celery worker queue"
                        },
                        "docker": {
                            "type": "boolean",
                            "description": "Include Docker Compose for local dev"
                        }
                    },
                    "required": ["project_name"]
                }
            },
            {
                "name": "generate_env_template",
                "description": "Generate a .env.example template for a project type.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_type": {
                            "type": "string",
                            "enum": ["express_api", "react_spa", "expo_app", "saas_full_stack", "fastapi_service"],
                            "description": "Type of project"
                        },
                        "integrations": {
                            "type": "string",
                            "description": "Comma-separated integrations (stripe,revenuecat,sentry,resend,redis,cloudflare,apns)"
                        }
                    },
                    "required": ["project_type"]
                }
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "scaffold_express_api": self._scaffold_express_api,
            "scaffold_react_app": self._scaffold_react_app,
            "scaffold_expo_app": self._scaffold_expo_app,
            "scaffold_saas_platform": self._scaffold_saas_platform,
            "scaffold_fastapi_service": self._scaffold_fastapi_service,
            "generate_env_template": self._generate_env_template,
        }

    def _scaffold_express_api(self, project_name: str, database: str = "sqlite", auth: bool = True, stripe: bool = False) -> Dict[str, Any]:
        """Generate Express API project structure."""
        files = [
            f"{project_name}/package.json",
            f"{project_name}/tsconfig.json",
            f"{project_name}/.env.example",
            f"{project_name}/.gitignore",
            f"{project_name}/src/index.ts",
            f"{project_name}/src/middleware/auth.ts" if auth else None,
            f"{project_name}/src/middleware/errorHandler.ts",
            f"{project_name}/src/middleware/validate.ts",
            f"{project_name}/src/middleware/rateLimiter.ts",
            f"{project_name}/src/routes/health.ts",
            f"{project_name}/src/routes/auth.ts" if auth else None,
            f"{project_name}/src/routes/stripe.ts" if stripe else None,
            f"{project_name}/src/db/schema.ts",
            f"{project_name}/src/db/index.ts",
            f"{project_name}/src/utils/errors.ts",
            f"{project_name}/railway.toml",
            f"{project_name}/README.md",
        ]

        structure = [f for f in files if f is not None]

        return {
            "project_name": project_name,
            "database": database,
            "auth": auth,
            "stripe": stripe,
            "file_structure": structure,
            "dependencies": {
                "production": ["express", "helmet", "cors", "jsonwebtoken", "zod", "drizzle-orm", "better-sqlite3" if database == "sqlite" else "postgres", "stripe" if stripe else None, "sentry"],
                "dev": ["typescript", "@types/express", "@types/node", "tsx", "nodemon", "drizzle-kit"],
            },
            "key_features": [
                "Helmet.js with production CSP",
                "Rate limiting on auth endpoints",
                "Zod validation at every API boundary",
                "JWT auth with refresh token rotation" if auth else None,
                "Stripe webhook handler with signature verification" if stripe else None,
                "Health check endpoint",
                "Structured error responses",
                "Sentry error monitoring",
                "Railway deployment config",
            ],
        }

    def _scaffold_react_app(self, project_name: str, routing: bool = True, auth: bool = True) -> Dict[str, Any]:
        """Generate React SPA project structure."""
        files = [
            f"{project_name}/package.json",
            f"{project_name}/tsconfig.json",
            f"{project_name}/vite.config.ts",
            f"{project_name}/tailwind.config.ts",
            f"{project_name}/.env.example",
            f"{project_name}/.gitignore",
            f"{project_name}/index.html",
            f"{project_name}/src/main.tsx",
            f"{project_name}/src/App.tsx",
            f"{project_name}/src/store/authStore.ts" if auth else None,
            f"{project_name}/src/hooks/useAuth.ts" if auth else None,
            f"{project_name}/src/components/ErrorBoundary.tsx",
            f"{project_name}/src/lib/api.ts",
            f"{project_name}/src/lib/sentry.ts",
            f"{project_name}/src/pages/Home.tsx",
            f"{project_name}/src/pages/Login.tsx" if auth else None,
            f"{project_name}/src/pages/Dashboard.tsx" if auth else None,
        ]

        return {
            "project_name": project_name,
            "routing": routing,
            "auth": auth,
            "file_structure": [f for f in files if f is not None],
            "dependencies": {
                "production": ["react", "react-dom", "react-router-dom", "zustand", "axios", "@sentry/react"],
                "dev": ["typescript", "@types/react", "@types/react-dom", "vite", "@vitejs/plugin-react", "tailwindcss", "autoprefixer", "postcss"],
            },
        }

    def _scaffold_expo_app(self, project_name: str, features: str = "", navigation: str = "tabs") -> Dict[str, Any]:
        """Generate Expo app project structure."""
        feature_list = [f.strip() for f in features.split(",")] if features else []
        files = [
            f"{project_name}/package.json",
            f"{project_name}/app.json",
            f"{project_name}/tsconfig.json",
            f"{project_name}/.env.example",
            f"{project_name}/.gitignore",
            f"{project_name}/app/_layout.tsx",
            f"{project_name}/app/(tabs)/_layout.tsx" if navigation == "tabs" else None,
            f"{project_name}/app/(tabs)/index.tsx" if navigation == "tabs" else None,
            f"{project_name}/app/(tabs)/settings.tsx" if navigation == "tabs" else None,
            f"{project_name}/src/store/appStore.ts",
            f"{project_name}/src/services/auth.ts" if "apple_sign_in" in feature_list else None,
            f"{project_name}/src/services/purchases.ts" if "revenuecat" in feature_list else None,
            f"{project_name}/src/services/notifications.ts" if "push_notifications" in feature_list else None,
            f"{project_name}/src/services/storage.ts" if "local_storage" in feature_list else None,
            f"{project_name}/src/services/health.ts" if "healthkit" in feature_list else None,
            f"{project_name}/src/services/location.ts" if "location" in feature_list else None,
            f"{project_name}/src/lib/api.ts",
            f"{project_name}/src/lib/sentry.ts",
            f"{project_name}/README.md",
        ]

        return {
            "project_name": project_name,
            "navigation": navigation,
            "features": feature_list,
            "file_structure": [f for f in files if f is not None],
            "dependencies": {
                "production": ["expo", "expo-router", "expo-status-bar", "zustand", "axios", "@sentry/react-native"],
                "expo_packages": [f for f in [
                    "expo-secure-store" if "apple_sign_in" in feature_list else None,
                    "expo-local-authentication" if "face_id" in feature_list else None,
                    "react-native-purchases" if "revenuecat" in feature_list else None,
                    "expo-notifications" if "push_notifications" in feature_list else None,
                    "expo-sqlite" if "local_storage" in feature_list else None,
                    "expo-health" if "healthkit" in feature_list else None,
                    "expo-location" if "location" in feature_list else None,
                    "expo-image-picker" if "camera" in feature_list else None,
                ] if f is not None],
            },
        }

    def _scaffold_saas_platform(self, project_name: str, tiers: str = "free,pro,enterprise", mobile_app: bool = False, email: bool = True) -> Dict[str, Any]:
        """Generate full SaaS platform structure."""
        tier_list = [t.strip() for t in tiers.split(",")]
        files = [
            f"{project_name}/README.md",
            f"{project_name}/.gitignore",
            f"{project_name}/.env.example",
            f"{project_name}/frontend/package.json",
            f"{project_name}/frontend/src/main.tsx",
            f"{project_name}/frontend/src/App.tsx",
            f"{project_name}/frontend/src/store/authStore.ts",
            f"{project_name}/frontend/src/store/subscriptionStore.ts",
            f"{project_name}/frontend/src/pages/Pricing.tsx",
            f"{project_name}/frontend/src/pages/Dashboard.tsx",
            f"{project_name}/backend/package.json",
            f"{project_name}/backend/src/index.ts",
            f"{project_name}/backend/src/middleware/auth.ts",
            f"{project_name}/backend/src/middleware/errorHandler.ts",
            f"{project_name}/backend/src/middleware/validate.ts",
            f"{project_name}/backend/src/routes/health.ts",
            f"{project_name}/backend/src/routes/auth.ts",
            f"{project_name}/backend/src/routes/stripe.ts",
            f"{project_name}/backend/src/routes/user.ts",
            f"{project_name}/backend/src/db/schema.ts",
            f"{project_name}/backend/railway.toml",
            f"{project_name}/.github/workflows/ci.yml",
        ]

        if mobile_app:
            files.extend([
                f"{project_name}/mobile/package.json",
                f"{project_name}/mobile/app/_layout.tsx",
                f"{project_name}/mobile/app/(tabs)/_layout.tsx",
                f"{project_name}/mobile/src/services/auth.ts",
                f"{project_name}/mobile/src/services/purchases.ts",
            ])

        return {
            "project_name": project_name,
            "tiers": tier_list,
            "mobile_app": mobile_app,
            "email": email,
            "file_structure": files,
            "architecture": {
                "frontend": "React 19 + Vite + TypeScript + Tailwind + Zustand",
                "backend": "Node/Express + TypeScript + PostgreSQL + Drizzle ORM + Zod",
                "billing": "Stripe Checkout + Customer Portal + Webhooks",
                "auth": "JWT with refresh token rotation + role-based access",
                "monitoring": "Sentry + health checks",
                "deployment": "Railway (backend) + Vercel (frontend)",
                "email": "Resend transactional email" if email else None,
                "mobile": "React Native + Expo + RevenueCat" if mobile_app else None,
            },
        }

    def _scaffold_fastapi_service(self, project_name: str, celery: bool = False, docker: bool = True) -> Dict[str, Any]:
        """Generate FastAPI project structure."""
        files = [
            f"{project_name}/requirements.txt",
            f"{project_name}/.env.example",
            f"{project_name}/.gitignore",
            f"{project_name}/app/main.py",
            f"{project_name}/app/api/routes.py",
            f"{project_name}/app/models/schemas.py",
            f"{project_name}/app/db/database.py",
            f"{project_name}/app/core/config.py",
            f"{project_name}/app/core/security.py",
            f"{project_name}/app/tasks.py" if celery else None,
            f"{project_name}/docker-compose.yml" if docker else None,
            f"{project_name}/Dockerfile" if docker else None,
            f"{project_name}/README.md",
        ]

        return {
            "project_name": project_name,
            "celery": celery,
            "docker": docker,
            "file_structure": [f for f in files if f is not None],
            "dependencies": {
                "core": ["fastapi", "uvicorn", "pydantic", "sqlalchemy", "asyncpg"],
                "auth": ["python-jose", "passlib", "bcrypt"],
                "celery": ["celery", "redis"] if celery else [],
                "monitoring": ["sentry-sdk"],
                "docker": docker,
            },
        }

    def _generate_env_template(self, project_type: str = "express_api", integrations: str = "") -> Dict[str, Any]:
        """Generate .env.example template."""
        base_vars = {
            "express_api": ["PORT=3000", "NODE_ENV=development", "JWT_SECRET=your-secret-here", "JWT_EXPIRES_IN=15m", "JWT_REFRESH_EXPIRES_IN=7d", "DATABASE_URL=", "CORS_ORIGIN=http://localhost:3000"],
            "react_spa": ["VITE_API_URL=http://localhost:3000", "VITE_SENTRY_DSN=", "VITE_STRIPE_PUBLISHABLE_KEY="],
            "expo_app": ["EXPO_PUBLIC_API_URL=http://localhost:3000", "EXPO_PUBLIC_SENTRY_DSN=", "EXPO_PUBLIC_REVENUECAT_API_KEY="],
            "saas_full_stack": ["# Backend", "PORT=3000", "NODE_ENV=development", "JWT_SECRET=", "DATABASE_URL=", "CORS_ORIGIN=http://localhost:5173", "# Frontend", "VITE_API_URL=http://localhost:3000", "VITE_STRIPE_PUBLISHABLE_KEY="],
            "fastapi_service": ["PORT=8000", "DATABASE_URL=postgresql+asyncpg://user:pass@localhost/db", "SECRET_KEY=", "REDIS_URL=redis://localhost:6379/0"],
        }

        integration_vars = {
            "stripe": ["STRIPE_SECRET_KEY=", "STRIPE_PUBLISHABLE_KEY=", "STRIPE_WEBHOOK_SECRET=", "STRIPE_PRICE_ID_PRO=", "STRIPE_PRICE_ID_ENTERPRISE="],
            "revenuecat": ["REVENUECAT_API_KEY=", "REVENUECAT_WEBHOOK_AUTH="],
            "sentry": ["SENTRY_DSN=", "SENTRY_AUTH_TOKEN="],
            "resend": ["RESEND_API_KEY=", "RESEND_FROM_EMAIL=noreply@yourdomain.com"],
            "redis": ["REDIS_URL=redis://localhost:6379/0"],
            "cloudflare": ["CLOUDFLARE_API_TOKEN=", "CLOUDFLARE_ZONE_ID="],
            "apns": ["APNS_KEY_ID=", "APNS_TEAM_ID=", "APNS_KEY_PATH="],
        }

        template = base_vars.get(project_type, base_vars["express_api"])
        if integrations:
            for integration in integrations.split(","):
                integration = integration.strip()
                if integration in integration_vars:
                    template.append(f"\n# {integration.upper()}")
                    template.extend(integration_vars[integration])

        return {"project_type": project_type, "integrations": integrations.split(",") if integrations else [], "env_template": template}

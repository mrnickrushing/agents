"""
Railway Deploy Agent — Deployment, logs, env vars, health checks, and infra management.

Tailored for your Railway + Vercel + Cloudflare Workers deployment pattern.
Handles Nixpacks builds, PostgreSQL/Redis services, persistent volumes,
custom domains, SSL, and monitoring.

Usage:
    from agents import RailwayDeployAgent
    agent = RailwayDeployAgent(api_key="sk-...")
    result = agent.run("My Railway deploy is failing — here's the build log: ...")
    print(result.content)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class RailwayDeployAgent(BaseAgent):
    """
    Railway and deployment infrastructure specialist.

    Knows Railway Nixpacks builds, Vercel edge deployments, Cloudflare Workers,
    PostgreSQL/Redis service provisioning, persistent volumes, custom domains,
    CI/CD with GitHub, and the deployment patterns that keep a solo operator shipping.
    """

    name = "railway_deploy"
    description = "Manages Railway deployments, Vercel edge deploys, Cloudflare Workers, env vars, build logs, health checks, and infrastructure for solo full-stack operators."
    model = "gpt-5"

    system_prompt = """\
You are a deployment and infrastructure specialist for solo full-stack operators shipping production apps on Railway, Vercel, and Cloudflare. You understand:

RAILWAY:
- Nixpacks auto-detection for Node.js, Python, and static sites
- Railway.toml configuration for custom build/start commands
- PostgreSQL and Redis as Railway services (private networking)
- Persistent volumes for SQLite and file storage
- Custom domains with SSL (GoDaddy DNS → Railway)
- Environment variables (encrypted at rest, per-service scoping)
- Monorepo deployment (multiple services from one repo)
- Health check endpoints and deployment failure recovery
- Railway CLI commands (railway up, railway logs, railway variables)
- Railway linked to GitHub for auto-deploy on push
- Blue/green and rolling deployment strategies
- Resource limits and scaling (RAM, vCPU, disk)

VERCEL:
- Next.js and React SPA deployments
- Edge functions and serverless functions
- Vercel CLI (vercel deploy, vercel env)
- Preview deployments per branch
- Custom domains with automatic SSL
- ISR and static optimization

CLOUDFLARE WORKERS:
- Edge-deployed marketing sites and admin panels
- Workers Sites for static assets
- Custom domains and DNS management
- KV storage for edge state
- Rate limiting at the edge

CI/CD PATTERNS:
- GitHub → Railway auto-deploy on push to main
- Codemagic for React Native / Expo iOS builds (code signing, provisioning, submission)
- EAS Build for Expo OTA updates
- GitHub Actions for lint, test, deploy pipelines
- Sentry release tracking and source maps

DEPLOYMENT CHECKLIST:
1. Environment variables set (not defaults)
2. Database migrations run (Drizzle push or custom)
3. Health check endpoint responds 200
4. SSL and custom domain verified
5. Sentry DSN configured and reporting
6. CORS origins set to production domain (not localhost)
7. Stripe webhook endpoint URL updated
8. Rate limiting configured for production traffic
9. Error monitoring confirmed working (trigger test error)
10. Backup/restore strategy documented

When helping with deployment issues:
- Always identify the root cause from build logs or error output
- Provide exact CLI commands to fix the issue
- Note any environment variable or service dependency
- Flag when a local dev pattern won't work in production
- Include rollback steps for risky changes
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_deployment_config",
                "description": "Review an existing Railway/Docker/Procfile deployment config for production reliability and security gaps.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "config_text": {"type": "string"},
                        "filename": {"type": "string"},
                    },
                    "required": ["config_text", "filename"],
                },
            },
            {
                "name": "diagnose_build_failure",
                "description": "Diagnose a Railway or Vercel build failure from the build log.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "build_log": {
                            "type": "string",
                            "description": "The build log output showing the failure"
                        },
                        "platform": {
                            "type": "string",
                            "enum": ["railway", "vercel", "cloudflare_workers", "eas_build"],
                            "description": "Deployment platform"
                        },
                        "runtime": {
                            "type": "string",
                            "description": "Runtime/language (e.g., 'node', 'python', 'static')"
                        }
                    },
                    "required": ["build_log", "platform"]
                }
            },
            {
                "name": "generate_railway_toml",
                "description": "Generate a railway.toml configuration for a project.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_type": {
                            "type": "string",
                            "enum": ["node_express", "node_nextjs", "python_fastapi", "static_site"],
                            "description": "Type of project to deploy"
                        },
                        "start_command": {
                            "type": "string",
                            "description": "Custom start command (e.g., 'node server.js')"
                        },
                        "healthcheck_path": {
                            "type": "string",
                            "description": "Health check endpoint path (e.g., '/health')"
                        },
                        "needs_postgres": {
                            "type": "boolean",
                            "description": "Whether the project needs a PostgreSQL service"
                        },
                        "needs_redis": {
                            "type": "boolean",
                            "description": "Whether the project needs a Redis service"
                        }
                    },
                    "required": ["project_type"]
                }
            },
            {
                "name": "generate_docker_compose",
                "description": "Generate a Docker Compose file for local development matching Railway services.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "services": {
                            "type": "string",
                            "description": "Comma-separated list of services (e.g., 'postgres,redis,app,celery')"
                        },
                        "app_port": {
                            "type": "integer",
                            "description": "Port the app runs on"
                        },
                        "database": {
                            "type": "string",
                            "enum": ["postgresql", "sqlite", "both"],
                            "description": "Database type"
                        }
                    },
                    "required": ["services"]
                }
            },
            {
                "name": "deployment_checklist",
                "description": "Generate a pre-deployment checklist for a given project type and platform.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_type": {
                            "type": "string",
                            "enum": ["web_app", "mobile_app_backend", "saas_platform", "marketing_site", "api_only"],
                            "description": "Type of project being deployed"
                        },
                        "platform": {
                            "type": "string",
                            "enum": ["railway", "vercel", "cloudflare_workers"],
                            "description": "Deployment platform"
                        },
                        "has_stripe": {
                            "type": "boolean",
                            "description": "Whether the project uses Stripe"
                        },
                        "has_sentry": {
                            "type": "boolean",
                            "description": "Whether the project uses Sentry"
                        }
                    },
                    "required": ["project_type", "platform"]
                }
            },
            {
                "name": "setup_env_vars",
                "description": "List all required environment variables for a given project type.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_type": {
                            "type": "string",
                            "enum": ["node_express_sqlite", "node_express_postgres", "python_fastapi", "expo_mobile_backend", "saas_full_stack"],
                            "description": "Project stack type"
                        },
                        "integrations": {
                            "type": "string",
                            "description": "Comma-separated integrations (e.g., 'stripe,revenuecat,sentry,resend,redis')"
                        }
                    },
                    "required": ["project_type"]
                }
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_deployment_config": self._review_deployment_config,
            "diagnose_build_failure": self._diagnose_build_failure,
            "generate_railway_toml": self._generate_railway_toml,
            "generate_docker_compose": self._generate_docker_compose,
            "deployment_checklist": self._deployment_checklist,
            "setup_env_vars": self._setup_env_vars,
        }

    def _review_deployment_config(self, config_text: str, filename: str) -> Dict[str, Any]:
        """Review an existing deployment config rather than generating one.

        Findings are limited to properties visible in the file. Cross-service
        concerns (for example, whether Railway has a dashboard health check)
        are phrased as verification gaps instead of asserted failures.
        """
        findings = []
        name = os.path.basename(filename).lower()

        literal_secret = re.search(
            r"(?im)^\s*(?:ENV|ARG)?\s*([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*)\s*(?:=|\s)\s*([^$\s][^\s#]{5,})",
            config_text,
        )
        if literal_secret and not re.search(r"example|changeme|replace_me|dummy", literal_secret.group(2), re.IGNORECASE):
            findings.append({
                "severity": "CRITICAL",
                "issue": f"Deployment config assigns a literal value to {literal_secret.group(1)}",
                "fix": "Inject secrets through the deployment platform's secret store; never bake them into an image or committed config",
            })

        if name == "dockerfile" or name.endswith(".dockerfile"):
            if re.search(r"(?im)^\s*FROM\s+\S+:latest(?:\s|$)", config_text):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Docker base image uses the mutable :latest tag — identical source can produce different deployments",
                    "fix": "Pin a major/minor image tag, or ideally an immutable digest",
                })
            if re.search(r"(?im)^\s*RUN\s+npm\s+install(?:\s|$)", config_text) and not re.search(r"(?im)^\s*RUN\s+npm\s+ci(?:\s|$)", config_text):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Docker build uses npm install instead of the lockfile-strict npm ci",
                    "fix": "Copy package.json plus the lockfile first, then run npm ci for reproducible installs",
                })
            if not re.search(r"(?im)^\s*USER\s+\S+", config_text) and re.search(r"(?im)^\s*FROM\s+(node|python)(?::|@|\s)", config_text):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Container never switches away from the default root user",
                    "fix": "Create/select an unprivileged runtime user with USER in the final image stage",
                })

        if name in {"railway.toml", "railway.json"}:
            if not re.search(r"healthcheck(path|Path)|healthcheck_path", config_text, re.IGNORECASE):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "No health-check path is declared in the Railway config",
                    "fix": "Declare a readiness endpoint that checks required dependencies, or verify the equivalent setting exists in the Railway dashboard",
                })
            if re.search(r'(?:--port|PORT\s*=)\s*["\']?\d{2,5}\b', config_text):
                findings.append({
                    "severity": "HIGH",
                    "issue": "Deployment command hardcodes a port instead of using Railway's assigned PORT",
                    "fix": "Bind to $PORT / process.env.PORT while listening on 0.0.0.0",
                })
            if not re.search(r"restartPolicy|restart_policy", config_text, re.IGNORECASE):
                findings.append({
                    "severity": "LOW",
                    "issue": "No restart policy is declared in the Railway config",
                    "fix": "Declare an on-failure restart policy with a bounded retry count, or verify it is configured in the dashboard",
                })

        if name == "procfile" and re.search(r"(?:--port|PORT=)\s*\d{2,5}\b", config_text):
            findings.append({
                "severity": "HIGH",
                "issue": "Procfile hardcodes the listening port",
                "fix": "Use the platform-provided $PORT value",
            })

        return {"filename": filename, "findings": findings, "total_issues": len(findings)}

    def _diagnose_build_failure(self, build_log: str, platform: str = "railway", runtime: str = "node") -> Dict[str, Any]:
        """Diagnose common build failures."""
        findings = []
        log_lower = build_log.lower()

        if "out of memory" in log_lower or "oom" in log_lower or "cannot allocate" in log_lower:
            findings.append({"severity": "CRITICAL", "issue": "Out of memory during build", "fix": "Increase Railway plan RAM or optimize build (reduce node_modules, use build cache)"})
        if "module not found" in log_lower or "cannot find module" in log_lower:
            findings.append({"severity": "CRITICAL", "issue": "Missing dependency — module not found", "fix": "Ensure npm install runs in build step and package.json is complete"})
        if "eprotocol" in log_lower or "econnrefused" in log_lower or "database" in log_lower and "connect" in log_lower:
            findings.append({"severity": "HIGH", "issue": "Database connection failure", "fix": "Check DATABASE_URL env var and that Postgres service is running and linked"})
        if "enoent" in log_lower:
            findings.append({"severity": "HIGH", "issue": "File not found (ENOENT)", "fix": "Check file paths — Railway builds in /app, not project root. Ensure start command references correct paths."})
        if "permission denied" in log_lower:
            findings.append({"severity": "HIGH", "issue": "Permission denied", "fix": "Check file permissions. Railway runs as non-root user by default."})
        if "port" in log_lower and ("in use" in log_lower or "eaddrinuse" in log_lower):
            findings.append({"severity": "MEDIUM", "issue": "Port already in use", "fix": "Railway auto-assigns PORT. Use process.env.PORT, not a hardcoded port number."})
        if "timeout" in log_lower:
            findings.append({"severity": "HIGH", "issue": "Build timeout", "fix": "Railway builds have time limits. Optimize build steps, use caching, or split into smaller builds."})

        if not findings:
            findings.append({"severity": "INFO", "issue": "No common failure pattern detected in log", "fix": "Review the full build log for the specific error message"})

        return {"platform": platform, "runtime": runtime, "diagnoses": findings}

    def _generate_railway_toml(self, project_type: str = "node_express", start_command: str = "", healthcheck_path: str = "/health", needs_postgres: bool = False, needs_redis: bool = False) -> Dict[str, Any]:
        """Generate railway.toml configuration."""
        defaults = {
            "node_express": {"builder": "nixpacks", "buildCommand": "npm run build", "startCommand": start_command or "node server.js"},
            "node_nextjs": {"builder": "nixpacks", "buildCommand": "npm run build", "startCommand": start_command or "npm start"},
            "python_fastapi": {"builder": "nixpacks", "buildCommand": "pip install -r requirements.txt", "startCommand": start_command or "uvicorn main:app --host 0.0.0.0 --port $PORT"},
            "static_site": {"builder": "nixpacks", "buildCommand": "npm run build", "startCommand": start_command or "npx serve -s dist -l $PORT"},
        }

        config = defaults.get(project_type, defaults["node_express"])
        config["healthcheckPath"] = healthcheck_path
        config["healthcheckTimeout"] = 300

        toml_content = f"""[build]
builder = "{config['builder']}"
buildCommand = "{config['buildCommand']}"

[deploy]
startCommand = "{config['startCommand']}"
healthcheckPath = "{healthcheck_path}"
healthcheckTimeout = 300
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
"""

        services = []
        if needs_postgres:
            services.append({"name": "postgres", "type": "postgresql", "version": "15"})
        if needs_redis:
            services.append({"name": "redis", "type": "redis", "version": "7"})

        return {"railway_toml": toml_content, "additional_services": services}

    def _generate_docker_compose(self, services: str = "app,postgres", app_port: int = 3000, database: str = "postgresql") -> Dict[str, Any]:
        """Generate Docker Compose structure."""
        service_list = [s.strip() for s in services.split(",")]
        compose = {
            "version": "3.8",
            "services": {},
        }

        if "postgres" in service_list:
            compose["services"]["postgres"] = {
                "image": "postgres:15",
                "environment": ["POSTGRES_USER=dev", "POSTGRES_PASSWORD=dev", "POSTGRES_DB=app"],
                "ports": ["5432:5432"],
                "volumes": ["pgdata:/var/lib/postgresql/data"],
            }
        if "redis" in service_list:
            compose["services"]["redis"] = {
                "image": "redis:7-alpine",
                "ports": ["6379:6379"],
            }
        if "celery" in service_list:
            compose["services"]["celery"] = {
                "build": ".",
                "command": "celery -A tasks worker --loglevel=info",
                "depends_on": ["redis"],
                "environment": ["CELERY_BROKER_URL=redis://redis:6379/0"],
            }
        if "app" in service_list:
            compose["services"]["app"] = {
                "build": ".",
                "ports": [f"{app_port}:{app_port}"],
                "depends_on": [s for s in ["postgres", "redis"] if s in service_list],
                "environment": [f"PORT={app_port}", "NODE_ENV=development"],
            }

        return {"docker_compose": compose}

    def _deployment_checklist(self, project_type: str = "web_app", platform: str = "railway", has_stripe: bool = False, has_sentry: bool = False) -> Dict[str, Any]:
        """Generate deployment checklist."""
        base_checklist = [
            {"step": 1, "item": "All environment variables set in platform dashboard", "critical": True},
            {"step": 2, "item": "Database migrations run against production DB", "critical": True},
            {"step": 3, "item": "Health check endpoint responds 200", "critical": True},
            {"step": 4, "item": "Custom domain configured with SSL", "critical": True},
            {"step": 5, "item": "CORS origins set to production domain (not localhost)", "critical": True},
            {"step": 6, "item": "Helmet security headers configured", "critical": False},
            {"step": 7, "item": "Rate limiting enabled for auth endpoints", "critical": False},
            {"step": 8, "item": "Error monitoring confirmed working", "critical": False},
        ]

        if has_stripe:
            base_checklist.extend([
                {"step": 9, "item": "Stripe webhook endpoint URL updated to production domain", "critical": True},
                {"step": 10, "item": "STRIPE_WEBHOOK_SECRET set in env vars", "critical": True},
                {"step": 11, "item": "Test Stripe checkout flow end-to-end", "critical": True},
            ])
        if has_sentry:
            base_checklist.extend([
                {"step": 12, "item": "Sentry DSN configured and reporting", "critical": False},
                {"step": 13, "item": "Source maps uploaded for error tracing", "critical": False},
                {"step": 14, "item": "Release tracking configured", "critical": False},
            ])

        return {"project_type": project_type, "platform": platform, "checklist": base_checklist, "total_steps": len(base_checklist)}

    def _setup_env_vars(self, project_type: str = "node_express_postgres", integrations: str = "") -> Dict[str, Any]:
        """List required environment variables."""
        base_vars = {
            "node_express_sqlite": ["PORT", "NODE_ENV", "JWT_SECRET", "JWT_EXPIRES_IN"],
            "node_express_postgres": ["PORT", "NODE_ENV", "DATABASE_URL", "JWT_SECRET", "JWT_EXPIRES_IN"],
            "python_fastapi": ["PORT", "DATABASE_URL", "SECRET_KEY", "REDIS_URL"],
            "expo_mobile_backend": ["PORT", "NODE_ENV", "DATABASE_URL", "JWT_SECRET", "APNS_KEY_ID", "APNS_TEAM_ID"],
            "saas_full_stack": ["PORT", "NODE_ENV", "DATABASE_URL", "JWT_SECRET", "FRONTEND_URL"],
        }

        required = base_vars.get(project_type, base_vars["node_express_postgres"])
        integration_vars = {
            "stripe": ["STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PRICE_ID"],
            "revenuecat": ["REVENUECAT_API_KEY", "REVENUECAT_WEBHOOK_AUTH"],
            "sentry": ["SENTRY_DSN", "SENTRY_AUTH_TOKEN"],
            "resend": ["RESEND_API_KEY", "RESEND_FROM_EMAIL"],
            "redis": ["REDIS_URL"],
            "cloudflare": ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID"],
        }

        if integrations:
            for integration in integrations.split(","):
                integration = integration.strip()
                if integration in integration_vars:
                    required.extend(integration_vars[integration])

        return {"project_type": project_type, "integrations": integrations.split(",") if integrations else [], "required_env_vars": required}

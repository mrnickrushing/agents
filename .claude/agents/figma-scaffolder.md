---
name: figma-scaffolder
description: Use for turning a Figma design (exported API JSON) into a production Expo app plus Railway Node backend — design tokens, EAS config, Sentry with PII off, RevenueCat, Apple Sign-In with the JWKS nonce flow, Helmet/CORS/rate-limiting, and a Stripe webhook handler. Use when the user asks to scaffold an app from a Figma file or design tokens.
tools: Read, Write, Edit, Glob, Bash
---

Use `python -m agents.cli scaffold-app-from-figma --app-name <Name> --output <dir> [--figma-json <export.json>] [--payment-model subscription|one_time|freemium]`. Without `--figma-json` it scaffolds from default tokens. Never write into a non-empty directory without `--force` and the user's say-so. After generation, list the files created and the secrets the app expects at runtime (Sentry DSN, RevenueCat keys, Stripe secret/webhook secret) — none of them are in the generated code.

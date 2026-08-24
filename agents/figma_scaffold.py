"""
Figma-to-App Scaffold Agent — Figma design → full Expo app scaffold.

FigmaScaffoldAgent orchestrates:
1. Parsing Figma design data (colors, typography, spacing)
2. Generating a design-token file
3. Scaffolding an Expo app with EAS, RevenueCat, Apple Sign-In, Sentry
4. Scaffolding a Railway Node backend with Stripe webhook handling

Usage:
    from agents.figma_scaffold import FigmaScaffoldAgent
    agent = FigmaScaffoldAgent()
    result = agent._scaffold_from_tokens(tokens, app_name="MyApp")

CLI:
    python -m agents.cli scaffold-app-from-figma \
        --app-name MyApp --output ~/MyApp
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent

# Default design tokens when no Figma data is available
_DEFAULT_TOKENS: Dict[str, Any] = {
    "colors": {
        "primary": "#007AFF",
        "secondary": "#5856D6",
        "background": "#FFFFFF",
        "surface": "#F2F2F7",
        "text": "#000000",
        "textSecondary": "#6C6C70",
        "error": "#FF3B30",
        "success": "#34C759",
    },
    "typography": {
        "fontFamily": "System",
        "sizes": {"xs": 12, "sm": 14, "md": 16, "lg": 20, "xl": 28, "xxl": 34},
        "weights": {"regular": "400", "medium": "500", "semibold": "600", "bold": "700"},
    },
    "spacing": {2: 2, 4: 4, 8: 8, 12: 12, 16: 16, 24: 24, 32: 32, 48: 48, 64: 64},
    "borderRadius": {"sm": 4, "md": 8, "lg": 12, "xl": 16, "full": 9999},
}


class FigmaScaffoldAgent(BaseAgent):
    """
    Generates a production-ready Expo app and Railway backend scaffold
    from Figma design tokens or defaults.
    """

    name = "figma_scaffold"
    description = "Scaffolds a production Expo mobile app + Railway backend from Figma design tokens."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "extract_design_tokens",
                "description": "Parse Figma API response JSON into normalized design tokens.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "figma_json": {"type": "string", "description": "Raw Figma API file response"},
                    },
                    "required": ["figma_json"],
                },
            },
            {
                "name": "scaffold_from_tokens",
                "description": "Generate Expo app file structure from design tokens.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tokens": {"type": "object", "description": "Design tokens dict"},
                        "app_name": {"type": "string", "description": "App name"},
                        "payment_model": {
                            "type": "string",
                            "enum": ["subscription", "one_time", "freemium"],
                            "description": "Payment model",
                        },
                    },
                    "required": ["tokens", "app_name"],
                },
            },
            {
                "name": "scaffold_default_app",
                "description": "Scaffold a production Expo app using default design tokens.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "app_name": {"type": "string"},
                        "payment_model": {"type": "string", "enum": ["subscription", "one_time", "freemium"]},
                    },
                    "required": ["app_name"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "extract_design_tokens": self._extract_design_tokens,
            "scaffold_from_tokens": self._scaffold_from_tokens,
            "scaffold_default_app": self._scaffold_default_app,
        }

    # ── Tool handlers ─────────────────────────────────────────────────

    def _extract_design_tokens(self, figma_json: str) -> Dict[str, Any]:
        """Parse a Figma file JSON and extract design tokens."""
        try:
            data = json.loads(figma_json)
        except json.JSONDecodeError as exc:
            return {"error": f"Invalid JSON: {exc}", "tokens": _DEFAULT_TOKENS}

        tokens: Dict[str, Any] = {"colors": {}, "typography": {}, "spacing": {}}

        # Walk Figma document styles
        styles = data.get("styles", {})
        for _key, style in styles.items():
            name = style.get("name", "")
            stype = style.get("styleType", "")
            if stype == "FILL" and name:
                token_name = re.sub(r"[^a-zA-Z0-9]", "_", name).strip("_").lower()
                tokens["colors"][token_name] = "#000000"  # placeholder; real impl reads fill color
            elif stype == "TEXT" and name:
                token_name = re.sub(r"[^a-zA-Z0-9]", "_", name).strip("_").lower()
                tokens["typography"][token_name] = {"size": 16, "weight": "400"}

        if not tokens["colors"]:
            tokens["colors"] = _DEFAULT_TOKENS["colors"]
        if not tokens["typography"]:
            tokens["typography"] = _DEFAULT_TOKENS["typography"]
        tokens["spacing"] = _DEFAULT_TOKENS["spacing"]
        tokens["borderRadius"] = _DEFAULT_TOKENS["borderRadius"]

        return {"tokens": tokens, "source": "figma"}

    def _scaffold_from_tokens(
        self,
        tokens: Dict[str, Any],
        app_name: str = "MyApp",
        payment_model: str = "subscription",
    ) -> Dict[str, Any]:
        """Generate the full file scaffold for the Expo app."""
        files: Dict[str, str] = {}

        # Design tokens file
        files["src/theme/tokens.ts"] = _render_tokens_file(tokens, app_name)

        # App entry point
        files["app/_layout.tsx"] = _render_layout(app_name)

        # EAS config
        files["eas.json"] = _render_eas_config(app_name)

        # Sentry init
        files["src/lib/sentry.ts"] = _render_sentry_init(app_name)

        # RevenueCat setup (for subscription/freemium)
        if payment_model in ("subscription", "freemium"):
            files["src/lib/revenuecat.ts"] = _render_revenuecat_init()

        # Apple Sign-In handler
        files["src/lib/auth.ts"] = _render_apple_signin()

        # Railway backend starter
        files["backend/src/index.ts"] = _render_backend(app_name, payment_model)
        files["backend/package.json"] = _render_backend_package(app_name)

        return {
            "app_name": app_name,
            "payment_model": payment_model,
            "files": files,
            "files_count": len(files),
            "summary": (
                f"Scaffolded {len(files)} files for '{app_name}' "
                f"({payment_model} model)."
            ),
        }

    def _scaffold_default_app(
        self,
        app_name: str = "MyApp",
        payment_model: str = "subscription",
    ) -> Dict[str, Any]:
        """Scaffold using default design tokens."""
        return self._scaffold_from_tokens(_DEFAULT_TOKENS, app_name, payment_model)


# ── Render helpers ─────────────────────────────────────────────────────────

def _render_tokens_file(tokens: Dict[str, Any], app_name: str) -> str:
    colors = tokens.get("colors", _DEFAULT_TOKENS["colors"])
    spacing = tokens.get("spacing", _DEFAULT_TOKENS["spacing"])
    typography = tokens.get("typography", _DEFAULT_TOKENS["typography"])
    color_lines = "\n".join(f"  {k}: '{v}'," for k, v in colors.items())
    spacing_lines = "\n".join(f"  s{k}: {v}," for k, v in spacing.items() if isinstance(k, int))
    return f"""\
// Auto-generated design tokens for {app_name}
// Generated by agents FigmaScaffoldAgent

export const colors = {{
{color_lines}
}};

export const spacing = {{
{spacing_lines}
}};

export const borderRadius = {{
  sm: 4, md: 8, lg: 12, xl: 16, full: 9999,
}};
"""


def _render_layout(app_name: str) -> str:
    return f"""\
import {{ Stack }} from 'expo-router';
import * as Sentry from '@sentry/react-native';
import {{ initSentry }} from '../src/lib/sentry';

initSentry();

export default function RootLayout() {{
  return (
    <Stack>
      <Stack.Screen name="(tabs)" options={{{{ headerShown: false }}}} />
    </Stack>
  );
}}
"""


def _render_eas_config(app_name: str) -> str:
    slug = re.sub(r"[^a-z0-9-]", "-", app_name.lower()).strip("-")
    return json.dumps({
        "cli": {"version": ">= 5.0.0"},
        "build": {
            "development": {
                "developmentClient": True,
                "distribution": "internal",
                "env": {"APP_ENV": "development"},
            },
            "preview": {
                "distribution": "internal",
                "env": {"APP_ENV": "preview"},
            },
            "production": {
                "autoIncrement": True,
                "env": {"APP_ENV": "production"},
            },
        },
        "submit": {
            "production": {
                "ios": {"appleId": "your-apple-id@example.com", "ascAppId": "your-app-store-id"},
                "android": {"serviceAccountKeyPath": "./google-service-account.json"},
            }
        },
    }, indent=2)


def _render_sentry_init(app_name: str) -> str:
    return f"""\
import * as Sentry from '@sentry/react-native';

export function initSentry() {{
  Sentry.init({{
    dsn: process.env.EXPO_PUBLIC_SENTRY_DSN,
    environment: process.env.APP_ENV ?? 'development',
    // Never send PII to Sentry
    sendDefaultPii: false,
    beforeSend(event) {{
      // Redact user emails and IDs
      if (event.user) {{
        delete event.user.email;
        delete event.user.username;
      }}
      return event;
    }},
    tracesSampleRate: process.env.APP_ENV === 'production' ? 0.2 : 1.0,
  }});
}}
"""


def _render_revenuecat_init() -> str:
    return """\
import Purchases, { LOG_LEVEL } from 'react-native-purchases';

export function initRevenueCat() {
  if (__DEV__) Purchases.setLogLevel(LOG_LEVEL.DEBUG);
  Purchases.configure({
    apiKey: process.env.EXPO_PUBLIC_REVENUECAT_KEY!,
  });
}
"""


def _render_apple_signin() -> str:
    return """\
import * as AppleAuthentication from 'expo-apple-authentication';
import { randomUUID } from 'expo-crypto';
import { sha256 } from 'js-sha256';

export async function signInWithApple(): Promise<{ idToken: string; nonce: string }> {
  const rawNonce = randomUUID();
  const hashedNonce = sha256(rawNonce);

  const credential = await AppleAuthentication.signInAsync({
    requestedScopes: [
      AppleAuthentication.AppleAuthenticationScope.EMAIL,
      AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
    ],
    nonce: hashedNonce,
  });

  // Send credential.identityToken + rawNonce to the backend for server-side JWKS verification
  return { idToken: credential.identityToken!, nonce: rawNonce };
}
"""


def _render_backend(app_name: str, payment_model: str) -> str:
    webhook_block = ""
    if payment_model in ("subscription", "one_time"):
        webhook_block = """
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err}`);
  }
  // TODO: handle event types
  res.json({ received: true });
});
"""
    return f"""\
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

app.use(helmet());
app.use(cors({{ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? [] }}));
app.use(rateLimit({{ windowMs: 15 * 60 * 1000, max: 100 }}));
app.use(express.json());

app.get('/health', (_req, res) => res.json({{ status: 'ok', app: '{app_name}' }}));
{webhook_block}
const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => console.log(`{app_name} backend listening on port ${{PORT}}`));
"""


def _render_backend_package(app_name: str) -> str:
    slug = re.sub(r"[^a-z0-9-]", "-", app_name.lower()).strip("-")
    return json.dumps({
        "name": f"{slug}-backend",
        "version": "1.0.0",
        "scripts": {
            "start": "node dist/index.js",
            "dev": "ts-node-dev src/index.ts",
            "build": "tsc",
        },
        "dependencies": {
            "express": "^4.21.0",
            "helmet": "^8.0.0",
            "cors": "^2.8.5",
            "express-rate-limit": "^7.4.0",
            "stripe": "^17.0.0",
        },
        "devDependencies": {
            "@types/express": "^4.17.21",
            "@types/cors": "^2.8.17",
            "typescript": "^5.6.0",
            "ts-node-dev": "^2.0.0",
        },
    }, indent=2)

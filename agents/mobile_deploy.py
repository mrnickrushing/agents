"""
Mobile Deploy Agent — EAS Build/Submit, Codemagic, and App Store readiness.

Complements RailwayDeployAgent (which is backend/web-focused) with the
mobile-specific half of shipping: EAS build profiles, Codemagic CI/CD,
App Store/Play Store submission requirements, and RevenueCat IAP setup
that has to be right before a build is worth submitting at all.

Usage:
    from agents import MobileDeployAgent
    agent = MobileDeployAgent(api_key="sk-...")
    result = agent.run("Review my eas.json for the production profile")
    print(result.content)
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class MobileDeployAgent(BaseAgent):
    """
    EAS/Codemagic/App Store submission specialist for Expo apps.

    Knows EAS build profiles and secret handling, Codemagic workflow YAML,
    App Store Connect / Play Console submission requirements, and RevenueCat
    product/offering setup.
    """

    name = "mobile_deploy"
    description = "Reviews EAS build config, Codemagic workflows, App Store/Play submission readiness, and RevenueCat IAP setup for Expo apps."
    model = "gpt-5"

    system_prompt = """\
You are a mobile release engineering specialist for Expo/React Native apps built by a solo operator. You understand:

EAS BUILD/SUBMIT:
- eas.json build profiles (development, preview, production) and what should differ between them
- env vars in eas.json are committed to git — secrets belong in EAS Secrets (`eas secret:create`) or account/project-level env vars, referenced by name, never as literal values in the committed file
- EXPO_PUBLIC_* vars are bundled into the client and are not confidential — but that doesn't mean they should be duplicated as git-committed literals; they still need centralized rotation
- credentialsSource (local vs remote), autoIncrement for production builds, and per-profile distribution (internal vs store)
- eas submit config for App Store Connect / Play Console

CODEMAGIC:
- Workflow triggers (push/tag/PR) and branch/changeset filtering
- Code signing: certificates and provisioning profiles should come from encrypted Codemagic env vars or integrations, never checked into the repo
- TestFlight vs App Store vs internal-track submission steps
- OTA updates (eas update) vs full native builds — know which changes require which

APP STORE / PLAY STORE SUBMISSION:
- App Store Connect metadata (privacy nutrition labels, age rating, export compliance / ITSAppUsesNonExemptEncryption)
- App Tracking Transparency (ATT) prompt required before any IDFA-adjacent tracking
- Screenshots per required device size, App Review guidelines relevant to the app category (health apps: HealthKit data-use disclosures; finance/security apps: extra scrutiny)
- IAP products/subscriptions must be in "Ready to Submit" state in App Store Connect before a build referencing them can be submitted
- TestFlight beta review vs full App Review timing

REVENUECAT:
- Purchases SDK configured once, early (before any paywall can render)
- Offerings fetched with a loading/error state — never assume they're always available
- restorePurchases() exposed to the user (App Review requirement)
- Entitlement checks read `customerInfo.entitlements.active`, not raw product/purchase state

When reviewing configs, always call out the exact key/line that's wrong and the fix — not generic "review your secrets management" advice.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_eas_config",
                "description": "Review an eas.json file for hardcoded secrets, missing production hardening, and submit config gaps.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "eas_json": {"type": "string", "description": "The contents of eas.json"},
                    },
                    "required": ["eas_json"],
                },
            },
            {
                "name": "review_codemagic_config",
                "description": "Review a codemagic.yaml for code-signing hygiene, trigger scoping, and submission steps.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "codemagic_yaml": {"type": "string", "description": "The contents of codemagic.yaml"},
                    },
                    "required": ["codemagic_yaml"],
                },
            },
            {
                "name": "app_store_submission_checklist",
                "description": "Generate an App Store / Play Store submission checklist for a given app category.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "platform": {"type": "string", "enum": ["ios", "android", "both"]},
                        "app_category": {"type": "string", "enum": ["health", "finance_security", "social", "utility", "other"]},
                        "has_iap": {"type": "boolean", "description": "Whether the app has in-app purchases/subscriptions"},
                        "uses_healthkit": {"type": "boolean"},
                        "uses_tracking": {"type": "boolean", "description": "Whether the app does any IDFA-adjacent tracking (requires ATT prompt)"},
                    },
                    "required": ["platform"],
                },
            },
            {
                "name": "review_revenuecat_setup",
                "description": "Review RevenueCat SDK integration code for configuration, offerings, restore, and entitlement-check patterns.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The RevenueCat integration code to review"},
                    },
                    "required": ["code"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_eas_config": self._review_eas_config,
            "review_codemagic_config": self._review_codemagic_config,
            "app_store_submission_checklist": self._app_store_submission_checklist,
            "review_revenuecat_setup": self._review_revenuecat_setup,
        }

    # ── Tool handlers ──────────────────────────────────────────────────

    def _review_eas_config(self, eas_json: str) -> Dict[str, Any]:
        """Review eas.json for hardcoded secrets and production hardening."""
        findings = []
        try:
            config = json.loads(eas_json)
        except json.JSONDecodeError:
            return {"error": "Invalid eas.json"}

        profiles = config.get("build", {})
        secret_key_pattern = re.compile(r"(secret|token|api[_-]?key|password|credential)", re.IGNORECASE)
        # A value that isn't a reference (env-file interpolation, empty, or an
        # obvious placeholder) is a literal committed straight into the file.
        reference_pattern = re.compile(r"^\$\{?\w|^\s*$")

        literal_secrets: Dict[str, List[str]] = {}
        for profile_name, profile in profiles.items():
            env = profile.get("env", {}) if isinstance(profile, dict) else {}
            for key, value in env.items():
                if secret_key_pattern.search(key) and isinstance(value, str) and value and not reference_pattern.match(value):
                    literal_secrets.setdefault(key, []).append(profile_name)

        for key, profile_names in literal_secrets.items():
            findings.append({
                "severity": "MEDIUM",
                "setting": key,
                "issue": f"'{key}' is a literal value committed in eas.json across profile(s) {profile_names} — it's in git history and duplicated per-profile, making rotation a multi-place, easy-to-miss edit",
                "fix": "Move to an EAS project/account env var (`eas env:create`) referenced by name, or at minimum keep one source of truth and reference it — don't hand-duplicate the same literal into every profile",
            })

        if "production" not in profiles:
            findings.append({"severity": "HIGH", "setting": "build.production", "issue": "No 'production' build profile found", "fix": "Add a production profile with credentialsSource and autoIncrement set"})
        else:
            prod = profiles["production"]
            if not prod.get("autoIncrement"):
                findings.append({"severity": "LOW", "setting": "build.production.autoIncrement", "issue": "autoIncrement not set on the production profile — build numbers must be bumped manually", "fix": 'Set "autoIncrement": true on the production profile'})

        if "submit" not in config:
            findings.append({"severity": "INFO", "setting": "submit", "issue": "No 'submit' section — eas submit will require inline flags every time", "fix": "Add a submit.production block (App Store Connect / Play Console identifiers)"})

        return {"profiles": list(profiles.keys()), "findings": findings, "total_issues": len(findings)}

    def _review_codemagic_config(self, codemagic_yaml: str) -> Dict[str, Any]:
        """Review codemagic.yaml (regex-scanned, no YAML parser dependency)."""
        findings = []

        # Look for what appear to be inline certificate/key material rather than
        # references to Codemagic's encrypted env vars or integrations block.
        if re.search(r"-----BEGIN (RSA )?PRIVATE KEY-----", codemagic_yaml):
            findings.append({"severity": "CRITICAL", "issue": "A private key appears to be inlined directly in codemagic.yaml", "fix": "Store signing keys as encrypted Codemagic environment variables or use the code_signing_identities integration — never commit key material"})

        has_ios_workflow = bool(re.search(r"\bios\b", codemagic_yaml, re.IGNORECASE))
        has_signing_config = bool(re.search(
            r"code_signing_identities|ios_signing|CM_CERTIFICATE|automatic_code_signing"
            r"|app_store_connect|keychain|fetch-signing-files|certificate_private_key",
            codemagic_yaml, re.IGNORECASE,
        ))
        if has_ios_workflow and not has_signing_config:
            findings.append({"severity": "INFO", "issue": "No explicit code-signing configuration found for what looks like an iOS workflow — confirm signing is handled via App Store Connect API integration or an explicit certificate/profile setup", "fix": "Add an ios_signing or code_signing_identities block, or confirm automatic signing via an App Store Connect integration"})

        if not re.search(r"triggering:|events:", codemagic_yaml):
            findings.append({"severity": "LOW", "issue": "No explicit triggering config found — confirm this workflow isn't relying on manual-only runs when you expect it to be automatic (or vice versa)", "fix": "Add a triggering.events block (push/tag/pull_request) if this should run automatically"})

        if re.search(r"testflight|app_store_connect", codemagic_yaml, re.IGNORECASE) and not re.search(r"submit_to_testflight|submit_to_app_store|beta_groups", codemagic_yaml, re.IGNORECASE):
            findings.append({"severity": "INFO", "issue": "App Store Connect integration referenced but no explicit submit_to_testflight/submit_to_app_store step found", "fix": "Add publishing.app_store_connect.submit_to_testflight (or submit_to_app_store) so the build is actually delivered, not just archived"})

        workflow_count = len(re.findall(r"^\s{2}[\w-]+:\s*$", codemagic_yaml, re.MULTILINE))

        return {"workflow_blocks_detected": workflow_count, "findings": findings, "total_issues": len(findings)}

    def _app_store_submission_checklist(
        self,
        platform: str = "ios",
        app_category: str = "other",
        has_iap: bool = False,
        uses_healthkit: bool = False,
        uses_tracking: bool = False,
    ) -> Dict[str, Any]:
        """Generate a submission checklist."""
        checklist = [
            {"item": "App Store Connect / Play Console metadata complete (description, keywords, support URL)", "critical": True},
            {"item": "Screenshots provided for every required device size", "critical": True},
            {"item": "Privacy policy URL set and reachable", "critical": True},
            {"item": "Privacy nutrition label / Data Safety form filled out accurately (matches what the app actually collects)", "critical": True},
            {"item": "Age rating questionnaire completed", "critical": True},
        ]

        if platform in ("ios", "both"):
            checklist.append({"item": "Export compliance (ITSAppUsesNonExemptEncryption) set correctly in Info.plist/eas.json", "critical": True})
            checklist.append({"item": "TestFlight internal build validated before submitting for full App Review", "critical": False})

        if platform in ("android", "both"):
            checklist.append({"item": "Play Console Data Safety section matches SDKs actually bundled (RevenueCat, Sentry, analytics)", "critical": True})
            checklist.append({"item": "Target API level meets Play Store's current minimum requirement", "critical": True})

        if has_iap:
            checklist.append({"item": "All IAP products/subscriptions are in 'Ready to Submit' state in App Store Connect / Play Console before referencing them in a submitted build", "critical": True})
            checklist.append({"item": "Restore Purchases is reachable from the UI (App Review requirement)", "critical": True})
            checklist.append({"item": "Subscription terms (price, duration, auto-renewal) disclosed in-app before purchase", "critical": True})

        if uses_healthkit:
            checklist.append({"item": "HealthKit usage strings (NSHealthShareUsageDescription / NSHealthUpdateUsageDescription) are specific about what's read/written", "critical": True})
            checklist.append({"item": "Health data is not used for advertising — confirm this explicitly, App Review checks it", "critical": True})

        if uses_tracking:
            checklist.append({"item": "App Tracking Transparency (ATT) prompt shown before any IDFA-adjacent tracking begins", "critical": True})
            checklist.append({"item": "NSUserTrackingUsageDescription set in Info.plist", "critical": True})

        if app_category == "finance_security":
            checklist.append({"item": "Extra App Review scrutiny expected for finance/security categories — budget review time accordingly, and have documentation ready for reviewer questions", "critical": False})

        return {"platform": platform, "app_category": app_category, "checklist": checklist, "total_items": len(checklist)}

    def _review_revenuecat_setup(self, code: str) -> Dict[str, Any]:
        """Review RevenueCat SDK integration."""
        findings = []
        code_lower = code.lower()

        if "purchases.configure" not in code_lower and "purchases.configure(" not in code_lower.replace(" ", ""):
            findings.append({"severity": "HIGH", "issue": "No Purchases.configure() call found — RevenueCat must be configured once, early, before any paywall can render", "fix": "Call Purchases.configure({ apiKey }) at app startup, before rendering any screen that checks entitlements"})

        if "getofferings" in code_lower or "offerings" in code_lower:
            if not re.search(r"catch|error|loading|isloading|try\s*{", code, re.IGNORECASE):
                findings.append({"severity": "MEDIUM", "issue": "Offerings fetched without a visible loading/error state — offerings can be empty or fail to load (network, misconfigured products)", "fix": "Handle the empty/error offerings case explicitly rather than assuming a paywall always has products to show"})

        if not re.search(r"restorepurchases", code_lower):
            findings.append({"severity": "MEDIUM", "issue": "No restorePurchases() call found — Apple requires a visible restore option for any app with IAP", "fix": "Expose a 'Restore Purchases' action that calls Purchases.restorePurchases()"})

        if re.search(r"purchasepackage|purchaseproduct", code_lower) and not re.search(r"entitlements", code_lower):
            findings.append({"severity": "HIGH", "issue": "Purchase flow found but no entitlements check — gate premium features on customerInfo.entitlements.active, not on the raw purchase call succeeding", "fix": "After purchase, check customerInfo.entitlements.active['<entitlement_id>'] rather than assuming success == entitled"})

        return {"findings": findings, "total_issues": len(findings)}

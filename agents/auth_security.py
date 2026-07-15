"""
Auth Security Agent — JWT session flow, Apple/Google Sign-In, shared-secret
app gates, and biometric auth review.

SecurityAuditAgent covers surface-level JWT hygiene (algorithm, storage,
expiry). This agent goes one layer deeper into the *flow*: refresh token
rotation and revocation, Apple/Google identity token verification, the
x-api-key-style shared-secret app gate pattern used alongside per-user JWTs,
and biometric (Face ID / LocalAuthentication) auth that should unlock a
credential rather than replace one.

Usage:
    from agents import AuthSecurityAgent
    agent = AuthSecurityAgent(api_key="sk-...")
    result = agent.run("Review this Apple Sign-In handler for server-side validation")
    print(result.content)
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class AuthSecurityAgent(BaseAgent):
    """
    Auth flow specialist for the RushingTech mobile + backend stack.

    Knows JWT access/refresh rotation, Apple Sign-In (JWKS, nonce, audience),
    Google OAuth, the shared x-api-key app-gate pattern layered under
    per-user auth, and Face ID / biometric auth on Expo.
    """

    name = "auth_security"
    description = "Reviews auth flows: JWT refresh rotation, Apple/Google Sign-In server-side verification, shared-secret app gates, and biometric auth."
    model = "gpt-5"

    system_prompt = """\
You are an authentication and session-security specialist for solo full-stack operators shipping Expo mobile apps backed by Node/Express or FastAPI. You review the *flow*, not just individual token settings:

YOUR DOMAIN:

1. JWT ACCESS/REFRESH FLOW
   - Access tokens short-lived (<=15min), refresh tokens longer-lived but rotated on use
   - Refresh token reuse detection: reusing an already-rotated refresh token should revoke the whole session family (token theft signal)
   - Refresh tokens stored hashed at rest (sha256/bcrypt), never in plaintext
   - Explicit `algorithms=[...]` allowlist on every decode/verify call — omitting it enables algorithm-confusion attacks (an RS256-signed token re-submitted and accepted as HS256 with the public key as the HMAC secret)
   - Session/device tracking (AuthSession, Device-style models) so a user can see and revoke individual logins

2. APPLE SIGN-IN
   - Nonce generated client-side, SHA256-hashed, sent to Apple, then the raw nonce is verified server-side against the identity token's nonce claim (replay protection)
   - Identity token verified against Apple's JWKS (https://appleid.apple.com/auth/keys), not decoded unverified
   - `iss` claim == https://appleid.apple.com, `aud` claim == your app's bundle ID
   - JWKS client cached/reused across requests, not re-fetched per sign-in

3. GOOGLE / SOCIAL OAUTH
   - `state` parameter used and validated (CSRF protection on the OAuth callback)
   - Authorization code exchanged for tokens server-side only (client_secret never shipped to the app)
   - id_token audience validated against your OAuth client ID
   - Redirect URI allowlisted, not accepted from client input

4. SHARED-SECRET APP GATES (x-api-key pattern)
   - A single shared secret that gates "is this our app" is not a substitute for per-user auth — it should sit alongside JWTs, not replace them for user-scoped routes
   - Compared with a timing-safe function (crypto.timingSafeEqual / hmac.compare_digest), not `===`/`==`
   - No hardcoded fallback default if the env var is unset

5. BIOMETRIC AUTH (Face ID / LocalAuthentication)
   - Biometric success should unlock a stored credential/token (Keychain), not itself be the source of truth for access
   - A non-biometric fallback (device passcode) must exist for unenrolled devices
   - isEnrolled/isAvailable checked before offering the biometric path

When reviewing code, always cite the specific flow step that's missing (not just "add security"), and give the exact fix.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "review_refresh_token_rotation",
                "description": "Review a JWT access/refresh token issuance and rotation flow for reuse detection, hashed storage, and algorithm confusion.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The token issuance/refresh/verify code to review"},
                        "language": {"type": "string", "enum": ["node", "python"], "description": "Implementation language"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_apple_sign_in",
                "description": "Review an Apple Sign-In server-side verification handler for nonce, JWKS, issuer, and audience checks.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The Apple Sign-In handling code (client or server side)"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_oauth_flow",
                "description": "Review a Google/social OAuth authorization-code flow for CSRF state, server-side token exchange, and audience validation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The OAuth flow code to review"},
                        "provider": {"type": "string", "enum": ["google", "generic"], "description": "OAuth provider"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "audit_shared_secret_auth",
                "description": "Audit a shared-secret app-gate pattern (e.g. x-api-key header) for timing-safe comparison and hardcoded fallbacks.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The middleware/handler code that checks the shared secret"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "review_biometric_auth",
                "description": "Review Face ID / biometric auth integration (e.g. Expo LocalAuthentication) for fallback and credential binding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The biometric auth integration code"},
                    },
                    "required": ["code"],
                },
            },
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "review_refresh_token_rotation": self._review_refresh_token_rotation,
            "review_apple_sign_in": self._review_apple_sign_in,
            "review_oauth_flow": self._review_oauth_flow,
            "audit_shared_secret_auth": self._audit_shared_secret_auth,
            "review_biometric_auth": self._review_biometric_auth,
        }

    # ── Tool handlers ──────────────────────────────────────────────────

    def _review_refresh_token_rotation(self, code: str, language: str = "node") -> Dict[str, Any]:
        """Review JWT refresh-token issuance/rotation flow."""
        findings = []
        has_refresh = bool(re.search(r"refresh[_-]?token", code, re.IGNORECASE))

        # Rotation is the *issuer's* job. A file that only stores tokens it
        # received (SecureStore/Keychain/AsyncStorage-backed helpers) and
        # never itself signs/creates one isn't where rotation logic would
        # live — that's a mobile client file calling a backend /refresh
        # endpoint implemented in a different service entirely, not
        # reachable via this file's imports.
        is_pure_client_consumer = (
            not re.search(r"jwt\.sign\(|create.*refresh.*token|jose\.sign", code, re.IGNORECASE)
            and re.search(r"securestore|keychain|asyncstorage|savetoken|accepttokens", code, re.IGNORECASE)
        )
        if has_refresh and is_pure_client_consumer:
            return {"language": language, "findings": findings, "total_issues": len(findings)}

        if has_refresh and not re.search(r"rotat|revoke|blacklist|reuse|invalidat|session_?id|family", code, re.IGNORECASE):
            findings.append({
                "severity": "HIGH",
                "issue": "No refresh token rotation/revocation logic detected — a leaked refresh token stays valid for its entire lifetime with no way to detect reuse",
                "fix": "Rotate the refresh token on every use, and if an already-rotated (old) token is presented again, treat it as a theft signal and revoke the entire session family",
            })

        # Client-side secure storage (SecureStore/Keychain/AsyncStorage) is a
        # different concern than server-side persistence: the client needs the
        # raw token back to use it, so "hash before storing" doesn't apply —
        # only flag what looks like server-side persistence (DB/ORM calls).
        is_client_storage = bool(re.search(r"securestore|keychain|asyncstorage", code, re.IGNORECASE))
        # "create_refresh_token(...)" is a token-*generation* call (issuing a
        # new token), not a persistence call — exclude it explicitly, since
        # "create" is otherwise indistinguishable from a real ORM .create()
        # persistence call and matched every token-issuing function by name.
        token_factory_re = re.compile(r"(create|generate|issue|make)\w*refresh\w*token", re.IGNORECASE)
        persist_lines = [
            ln for ln in code.splitlines()
            if re.search(r"(insert|save|store|create)\w*\(", ln, re.IGNORECASE)
            and re.search(r"refresh", ln, re.IGNORECASE)
            and not token_factory_re.search(ln)
        ]
        if has_refresh and not is_client_storage and persist_lines and not re.search(r"hash|sha256|bcrypt|digest", "\n".join(persist_lines), re.IGNORECASE):
            findings.append({
                "severity": "MEDIUM",
                "issue": "Refresh token appears to be persisted server-side without hashing — a DB read (or dump/backup leak) exposes usable tokens directly",
                "fix": "Store sha256(token) or a bcrypt hash of the refresh token, and compare hashes on lookup instead of the raw token",
            })

        if re.search(r"jwt\.verify\s*\(", code) and not re.search(r"algorithms\s*:", code):
            findings.append({
                "severity": "CRITICAL",
                "issue": "jwt.verify() called without an explicit algorithms allowlist — vulnerable to algorithm confusion (an RS256 token's public key can be replayed as an HS256 secret)",
                "fix": "jwt.verify(token, key, { algorithms: ['RS256'] }) — always pass an explicit algorithms array",
            })
        if re.search(r"jwt\.decode\s*\(", code) and not re.search(r"algorithms\s*=", code):
            findings.append({
                "severity": "HIGH",
                "issue": "jwt.decode() called without an explicit algorithms allowlist",
                "fix": "jwt.decode(token, key, algorithms=[settings.ALGORITHM]) — always pass algorithms explicitly",
            })

        if not re.search(r"session|device", code, re.IGNORECASE):
            findings.append({
                "severity": "INFO",
                "issue": "No session/device tracking visible in this snippet — consider whether users can see and revoke individual logins elsewhere in the app",
                "fix": "Track sessions with a session_id claim tied to a revocable DB row (device, IP, last-seen) so logout-everywhere is possible",
            })

        return {"language": language, "findings": findings, "total_issues": len(findings)}

    def _review_apple_sign_in(self, code: str) -> Dict[str, Any]:
        """Review Apple Sign-In server-side verification."""
        findings = []
        code_lower = code.lower()

        if "nonce" not in code_lower:
            findings.append({"severity": "HIGH", "issue": "No nonce handling found — vulnerable to identity token replay", "fix": "Generate a random nonce client-side, SHA256-hash it for the Apple request, and verify the raw nonce server-side against the token's nonce claim"})

        # Expo's client SDK (AppleAuthentication.signInAsync) only *obtains*
        # the identity token — verifying its signature/issuer/audience is a
        # backend responsibility. A file that gets the token this way and
        # never itself attempts a JWT decode/verify isn't the place that
        # logic belongs; it's forwarding the token to an API that (should)
        # verify it elsewhere, in a different file this one has no import
        # relationship to (mobile app vs. backend service).
        is_client_token_acquisition = (
            re.search(r"signinasync\s*\(", code_lower.replace(" ", "")) is not None
            and not re.search(r"jwt\.(decode|verify)\(|jwtverify\(|createremotejwkset", code, re.IGNORECASE)
        )
        if is_client_token_acquisition:
            return {"findings": findings, "total_issues": len(findings)}

        uses_jwks = bool(re.search(r"jwks|pyjwkclient|get_signing_key", code, re.IGNORECASE))
        unverified_decode = bool(re.search(r"verify_signature[\"']?\s*:\s*false|jwt\.decode\([^)]*verify\s*=\s*false", code, re.IGNORECASE))
        if unverified_decode:
            findings.append({"severity": "CRITICAL", "issue": "Identity token decoded with signature verification explicitly disabled — anyone can forge a token claiming to be any user", "fix": "Fetch Apple's public key via JWKS and verify the signature; never decode with verify_signature=False in a code path that trusts the result"})
        elif not uses_jwks:
            findings.append({"severity": "HIGH", "issue": "No JWKS-based signature verification found — the identity token's signature may not actually be checked against Apple's keys", "fix": "Use a JWKS client (e.g. PyJWKClient(APPLE_JWKS_URL) in Python, jwks-rsa in Node) to fetch the signing key and verify the token"})

        if not re.search(r"appleid\.apple\.com", code, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "No issuer check against https://appleid.apple.com found", "fix": "Verify the decoded token's iss claim equals https://appleid.apple.com"})

        if not re.search(r"\baud\b|audience\s*[:=]", code, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "No audience (aud) claim check found", "fix": "Verify the decoded token's aud claim equals your app's bundle identifier"})

        return {"findings": findings, "total_issues": len(findings)}

    def _review_oauth_flow(self, code: str, provider: str = "google") -> Dict[str, Any]:
        """Review a social OAuth authorization-code flow."""
        findings = []
        code_lower = code.lower()

        # The state/CSRF concern only applies to a redirect + authorization-code
        # exchange. A lot of mobile sign-in is identity-token-based instead (the
        # native SDK hands the backend an already-signed token to verify via
        # JWKS — no redirect, no state, by design) — and a plain settings file
        # that just declares GOOGLE_OAUTH_CLIENT_ID/SECRET isn't flow logic at
        # all. Only fire this when there's actual redirect-flow evidence.
        is_redirect_flow = bool(re.search(r"redirect_uri|authorization_code|/authorize\b|code_verifier|pkce", code, re.IGNORECASE))
        if is_redirect_flow and "state" not in code_lower:
            findings.append({"severity": "HIGH", "issue": "No 'state' parameter found in the OAuth redirect flow — vulnerable to CSRF on the callback (an attacker can bind their own account to a victim's session)", "fix": "Generate a random state value, store it (session/cookie), send it in the auth request, and verify it matches on callback"})

        # A whole-file co-occurrence check is too loose: a single backend
        # settings file legitimately handles many concerns (OAuth secrets,
        # push tokens, etc.), and an unrelated "Expo push notifications"
        # comment elsewhere in the file would falsely implicate an unrelated
        # client_secret field. Scope to lines that actually mention both —
        # and use lookaround, not \b, since \b treats underscore as a word
        # char and wouldn't stop "mobile" matching inside MOBILE_RETURN_URI.
        client_side_re = re.compile(r"(?<![A-Za-z0-9_])(expo|react-native|mobile|frontend|client-side)(?![A-Za-z0-9_])", re.IGNORECASE)
        secret_lines = [ln for ln in code.splitlines() if "client_secret" in ln.lower()]
        if any(client_side_re.search(ln) for ln in secret_lines):
            findings.append({"severity": "CRITICAL", "issue": "client_secret referenced on a line that also looks client-side/mobile — OAuth client secrets must never ship in an app bundle", "fix": "Exchange the authorization code for tokens on your backend only; the mobile app should never see client_secret"})

        if not re.search(r"\baud\b|audience|client_id", code, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "No audience/client_id validation found on the returned id_token", "fix": "Verify the id_token's aud claim matches your OAuth client ID before trusting it"})

        if "redirect_uri" in code_lower and not re.search(r"allowlist|allowed_redirect|redirect_uris\s*=", code, re.IGNORECASE):
            findings.append({"severity": "INFO", "issue": "redirect_uri usage found — confirm it's validated against a server-side allowlist, not accepted from client input", "fix": "Validate redirect_uri against a fixed allowlist rather than trusting whatever the client sends"})

        return {"provider": provider, "findings": findings, "total_issues": len(findings)}

    def _audit_shared_secret_auth(self, code: str) -> Dict[str, Any]:
        """Audit a shared-secret app-gate (x-api-key style) middleware."""
        findings = []
        secret_re = re.compile(r"(x-api-key|internal_api_key|app[_-]?secret)", re.IGNORECASE)

        if secret_re.search(code):
            # Scope the ===/== check to lines actually mentioning the secret —
            # otherwise an unrelated `hostname === 'localhost'` comparison
            # 40 lines away from a CORS allowedHeaders entry that merely
            # *names* x-api-key falsely reads as an insecure secret compare.
            secret_lines = [ln for ln in code.splitlines() if secret_re.search(ln)]
            secret_context = "\n".join(secret_lines)
            if re.search(r"===|==", secret_context) and not re.search(r"timingsafeequal|compare_digest|constant.?time", code, re.IGNORECASE):
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Shared secret compared with ===/== — vulnerable in principle to a timing attack that leaks the secret byte-by-byte",
                    "fix": "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) (Node) or hmac.compare_digest(a, b) (Python) instead of === / ==",
                })
            if re.search(r"(x-api-key|internal_api_key|app[_-]?secret)\s*(\|\||\?\?)\s*[\"'][\w-]{2,}[\"']", code, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": "Shared secret has a hardcoded fallback value (e.g. `|| \"default\"`) — if the env var is ever unset in production, auth silently falls back to a known secret",
                    "fix": "Fail closed: throw/exit at startup if the secret env var is missing, rather than defaulting to a literal",
                })

        if re.search(r"(x-api-key|internal_api_key)", code, re.IGNORECASE) and not re.search(r"jwt|bearer|session|req\.user|current_user", code, re.IGNORECASE):
            findings.append({
                "severity": "INFO",
                "issue": "This snippet only checks the shared app-gate secret with no per-user auth visible — confirm routes that touch user-specific data also require a user-scoped JWT, since the shared secret only proves \"this is our app,\" not \"this is user X\"",
                "fix": "Layer per-user JWT/session auth on top of the shared secret for any route that reads or writes user data",
            })

        return {"findings": findings, "total_issues": len(findings)}

    def _review_biometric_auth(self, code: str) -> Dict[str, Any]:
        """Review Face ID / biometric auth integration."""
        findings = []
        code_lower = code.lower()

        if not re.search(r"isenrolled|isavailable|hardware", code, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "No isEnrolled/isAvailable/hasHardware check before offering biometric auth", "fix": "Check LocalAuthentication.hasHardwareAsync() and isEnrolledAsync() before showing the Face ID option"})

        if not re.search(r"fallback|passcode|password", code_lower):
            findings.append({"severity": "MEDIUM", "issue": "No fallback path for devices without biometrics enrolled", "fix": "Offer device passcode or password as a fallback when biometrics aren't available/enrolled"})

        if re.search(r"authenticateasync|biometric", code_lower) and not re.search(r"keychain|securestore|token|credential", code_lower):
            findings.append({
                "severity": "HIGH",
                "issue": "Biometric success doesn't appear to unlock a stored credential/token — if the biometric prompt itself is treated as the auth result, it can be a weaker, purely-local gate rather than proof of identity to your backend",
                "fix": "Use biometric success to unlock a token from SecureStore/Keychain (set up at login), not as a standalone substitute for a server-verified credential",
            })

        return {"findings": findings, "total_issues": len(findings)}

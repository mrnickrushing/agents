"""
CLI for RushingTech Agents — invoke the deterministic tool handlers directly,
with no OPENAI_API_KEY / ANTHROPIC_API_KEY required.

Every agent's `.run()` needs an LLM to plan which tool to call. But the tool
*handlers* themselves are plain Python — regex/heuristic checks that take a
string and return findings. This CLI calls those handlers directly, so any
script (or another agent, e.g. Claude Code itself) can use the checks as a
static-analysis toolkit without a network round trip.

Usage:
    python -m agents.cli list
    python -m agents.cli run security_audit check_jwt_implementation --file code=backend/src/routes/auth.ts
    python -m agents.cli run security_audit scan_dependencies --file package_json=backend/package.json
    python -m agents.cli scan --path ~/Vitality
    python -m agents.cli scan --path ~/shield-ai --agents security_audit,auth_security --out report.json

`scan` findings are heuristic and can false-positive on context outside the one
file being checked. If ANTHROPIC_API_KEY or OPENAI_API_KEY is set, scan
automatically runs a second-pass LLM triage over the findings (override with
--triage/--no-triage) — see agents/triage.py.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import tokenize
from typing import Any, Callable, Dict, List, Optional, Tuple

from agents.api_architect import APIArchitectAgent
from agents.auth_security import AuthSecurityAgent
from agents.code_review import CodeReviewAgent
from agents.database_architect import DatabaseArchitectAgent
from agents.infra_monitor import InfraMonitorAgent
from agents.mobile_deploy import MobileDeployAgent
from agents.railway_deploy import RailwayDeployAgent
from agents.scaffolder import ScaffolderAgent
from agents.security_audit import SecurityAuditAgent
from agents.stripe_billing import StripeBillingAgent
from agents.ui_generation import UIGenerationAgent
from agents import __version__
from agents.evolution import EvolutionStore, attach_finding_ids, default_database_path

AGENTS: Dict[str, type] = {
    "security_audit": SecurityAuditAgent,
    "code_review": CodeReviewAgent,
    "stripe_billing": StripeBillingAgent,
    "railway_deploy": RailwayDeployAgent,
    "scaffolder": ScaffolderAgent,
    "ui_generation": UIGenerationAgent,
    "auth_security": AuthSecurityAgent,
    "mobile_deploy": MobileDeployAgent,
    "api_architect": APIArchitectAgent,
    "database_architect": DatabaseArchitectAgent,
    "infra_monitor": InfraMonitorAgent,
}

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

EXCLUDED_DIRS = {
    "node_modules", ".git", "dist", "build", ".expo", ".next", "__pycache__",
    ".venv", "venv", ".pytest_cache", "Pods", ".gradle", ".railway", ".eas",
    "coverage", ".turbo", "vendor", "artifacts",
}
MAX_FILE_BYTES = 1_000_000

# Content-pattern rules (glob is None) are meant to scan actual source code —
# without this, "jsonwebtoken"/"svix" appearing as a *dependency name* in
# package.json, or "client_secret"/"Face ID" appearing in prose in CLAUDE.md,
# matched the same regexes as real jwt.verify()/webhook-handler code and
# produced nonsense findings against files that have no logic to review.
CODE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".vue", ".svelte"}
NON_CODE_BASENAMES = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
TEXT_EXTENSIONS = CODE_EXTENSIONS | {
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".sql", ".md", ".txt",
    ".env", ".cfg", ".ini", ".sh", ".bash", ".zsh", ".fish", ".dockerfile",
}
TEXT_BASENAMES = {
    "Dockerfile", "Procfile", "Gemfile", "Makefile", "requirements.txt",
    "package.json", "eas.json", "codemagic.yaml", "codemagic.yml",
}

RAW_DISCOVERY_TOOLS = {
    "scan_dependencies",
    "audit_hardcoded_secrets",
    "review_eas_config",
    "review_codemagic_config",
    "review_deployment_config",
    "diagnose_build_failure",
}


def _get_agent(name: str):
    cls = AGENTS.get(name)
    if not cls:
        raise SystemExit(f"Unknown agent '{name}'. Available: {', '.join(sorted(AGENTS))}")
    return cls()


def _coerce(value: str) -> Any:
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    try:
        return int(value)
    except ValueError:
        pass
    return value


# ── `run`: direct single tool-call invocation ───────────────────────────

def cmd_list(_args: argparse.Namespace) -> None:
    for agent_name, cls in sorted(AGENTS.items()):
        instance = cls()
        print(f"\n{agent_name} — {instance.description}")
        for tool_name in sorted(instance._tool_handlers):
            print(f"  - {tool_name}")


def cmd_run(args: argparse.Namespace) -> None:
    agent = _get_agent(args.agent)
    handler = agent._tool_handlers.get(args.tool)
    if not handler:
        raise SystemExit(f"Unknown tool '{args.tool}' for agent '{args.agent}'. Available: {', '.join(sorted(agent._tool_handlers))}")

    kwargs: Dict[str, Any] = {}
    for item in args.arg or []:
        key, _, value = item.partition("=")
        kwargs[key] = _coerce(value)
    for item in args.file or []:
        key, _, path = item.partition("=")
        with open(os.path.expanduser(path), "r", errors="ignore") as fh:
            kwargs[key] = fh.read()
    if args.stdin:
        kwargs[args.stdin] = sys.stdin.read()

    result = handler(**kwargs)
    print(json.dumps(result, indent=2, default=str))


# ── `scan`: auto-discover relevant files and run the right handlers ────

def _iter_files(root: str, diagnostics: Optional[List[Dict[str, Any]]] = None):
    """Yield project files while recording anything that could not be scanned.

    A clean report must not quietly mean "we skipped the interesting file".
    Large and unreadable files are therefore surfaced as coverage diagnostics
    instead of disappearing from the result.
    """
    diagnostics = diagnostics if diagnostics is not None else []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDED_DIRS
            and not d.startswith(("dist-", "build-"))
            and (not d.startswith(".") or d in {".github"})
        ]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(path)
                # Binary assets are never opened by the text analyzers, so a
                # large PNG/video is not a scan gap. Only report an oversized
                # file when it otherwise would have been analyzed as text.
                if size > MAX_FILE_BYTES and _is_text_candidate(path):
                    diagnostics.append({
                        "file": os.path.relpath(path, root),
                        "reason": "file_too_large",
                        "size_bytes": size,
                    })
                    continue
            except OSError as exc:
                diagnostics.append({
                    "file": os.path.relpath(path, root),
                    "reason": "stat_failed",
                    "error": str(exc),
                })
                continue
            yield path


def _read(path: str) -> str:
    with open(path, "r", errors="ignore") as fh:
        return fh.read()


def _discovery_text(path: str, content: str, tool_name: str) -> str:
    """Remove comments/string literals for rule *discovery* only.

    Detector implementations, tests, docs, and examples often mention a
    dangerous API as text. Searching raw source made a regex that documents
    ``eval(`` look exactly like production code that calls eval. Handlers
    still receive the original file; this sanitized view is only used to
    decide whether a handler is relevant. Secret/config/log rules explicitly
    opt into raw discovery because their evidence lives in literal values.
    """
    if tool_name in RAW_DISCOVERY_TOOLS:
        return content
    ext = os.path.splitext(path)[1].lower()
    if ext == ".py":
        try:
            tokens = []
            for token_info in tokenize.generate_tokens(io.StringIO(content).readline):
                token_type, token_text, start, end, line = token_info
                if token_type in {tokenize.STRING, tokenize.COMMENT}:
                    token_text = "\n" * token_text.count("\n")
                tokens.append((token_type, token_text))
            return tokenize.untokenize(tokens)
        except (tokenize.TokenError, IndentationError):
            return content

    # Conservative JS/TS removal. Preserve newlines so any line-oriented
    # patterns still behave predictably. Template-expression contents are
    # intentionally removed here; a real dangerous call also appears outside
    # the template in executable code and will still trigger its rule.
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), content, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"`(?:\\.|[^`])*`", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    text = re.sub(r"([\"'])(?:\\.|(?!\1).)*\1", "", text)
    return text


# Some checks review a call site whose actual logic lives one hop away in an
# imported helper (a paywall screen that calls `Purchases.configure()`
# through a shared `lib/revenuecat.ts` wrapper, rather than inline). Judged
# alone, the call site looks like it's missing the setup it's actually
# delegating to that helper. For these tools, follow local imports one level
# deep and let the check see the imported file's content too.
CROSS_FILE_TOOLS = {
    "review_revenuecat_setup",
    "review_pagination",
    "review_apple_sign_in",
    "audit_health_check_endpoint",
    "review_error_boundary_coverage",
}

_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_JS_LOCAL_IMPORT_RE = re.compile(r"""from\s+["'](\.{1,2}/[^"']+|@/[^"']+)["']""")
_PY_LOCAL_IMPORT_RE = re.compile(r"^\s*from\s+([.\w]+)\s+import", re.MULTILINE)


def _find_alias_root(start_dir: str) -> str:
    """A `@/...` import conventionally resolves against the nearest ancestor
    directory that has a package.json — walk up to find it."""
    current = os.path.realpath(start_dir)
    while True:
        if os.path.isfile(os.path.join(current, "package.json")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return start_dir


def _alias_base_dir(alias_root: str) -> str:
    """Read tsconfig.json's `@/*` path mapping (e.g. "./app/*") if present —
    it doesn't always point at the project root itself (Expo Router
    projects commonly map it to ./app/*) — falling back to the root."""
    try:
        with open(os.path.join(alias_root, "tsconfig.json")) as fh:
            tsconfig = json.load(fh)
        pattern = tsconfig.get("compilerOptions", {}).get("paths", {}).get("@/*", ["./*"])[0]
        return os.path.normpath(os.path.join(alias_root, pattern.rstrip("*")))
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        # Malformed/missing tsconfig.json, unexpected `paths` shape, or an
        # empty paths list ([0] on []) — any of these just means "couldn't
        # read a real alias mapping," fall back to the root guess.
        return alias_root


def _resolve_js_import(spec: str, from_dir: str) -> Optional[str]:
    if spec.startswith("@/"):
        base = os.path.join(_alias_base_dir(_find_alias_root(from_dir)), spec[2:])
    else:
        base = os.path.normpath(os.path.join(from_dir, spec))
    candidates = [base] + [base + ext for ext in _JS_EXTS] + [os.path.join(base, "index" + ext) for ext in _JS_EXTS]
    # TypeScript ESM source commonly imports the emitted `.js` filename.
    # Resolve that specifier back to its authored `.ts`/`.tsx` counterpart.
    base_ext = os.path.splitext(base)[1].lower()
    if base_ext in {".js", ".mjs", ".cjs"}:
        source_base = base[: -len(base_ext)]
        candidates.extend(source_base + ext for ext in _JS_EXTS)
    return next((c for c in candidates if os.path.isfile(c)), None)


def _resolve_py_import(module: str, from_dir: str, root: str) -> Optional[str]:
    relative_level = len(module) - len(module.lstrip("."))
    parts = [p for p in module.lstrip(".").split(".") if p]
    if not parts:
        return None
    if relative_level:
        relative_base = from_dir
        for _ in range(relative_level - 1):
            relative_base = os.path.dirname(relative_base)
        search_bases = (relative_base,)
    else:
        search_bases = (root, from_dir)
    for base in search_bases:
        candidate = os.path.join(base, *parts) + ".py"
        if os.path.isfile(candidate):
            return candidate
        # A package import (e.g. `from app.models import User`) resolves to
        # the package directory's __init__.py, not a same-named .py file.
        candidate_init = os.path.join(base, *parts, "__init__.py")
        if os.path.isfile(candidate_init):
            return candidate_init
    return None


def _inline_local_imports(path: str, content: str, root: str, max_files: int = 8) -> str:
    """Append up to `max_files` locally-imported helper modules' content to
    `content`, so a single-file regex check can see logic that actually
    lives one import away instead of judging the call site in isolation."""
    from_dir = os.path.dirname(path)
    ext = os.path.splitext(path)[1]
    resolved: List[str] = []

    if ext in _JS_EXTS:
        for spec in _JS_LOCAL_IMPORT_RE.findall(content):
            found = _resolve_js_import(spec, from_dir)
            if found and found != path:
                resolved.append(found)
    elif ext == ".py":
        for module in _PY_LOCAL_IMPORT_RE.findall(content):
            found = _resolve_py_import(module, from_dir, root)
            if found and found != path:
                resolved.append(found)

    comment_prefix = "#" if ext == ".py" else "//"
    combined = content
    for found in resolved[:max_files]:
        try:
            combined += f"\n\n{comment_prefix} --- imported from {os.path.relpath(found, root)} ---\n" + _read(found)
        except OSError:
            continue
    return combined


_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__)/|"
    r"(^|/)(test_\w+|\w+_test|\w+\.(test|spec))\.\w+$|"
    r"(^|/)(vitest|jest|playwright|cypress)\.config\.[^/]+$"
)


def _is_test_file(path: str) -> bool:
    # Test files mock/reference real function and constant names (e.g.
    # patching "_verify_apple_identity_token") without implementing the
    # logic themselves — content-based implementation-review rules would
    # otherwise "review" the mock as if it were the real handler.
    return bool(_TEST_PATH_RE.search(path.replace(os.sep, "/")))


# Per-tool basename exclusions: a file can match a rule's content trigger
# without being the right *kind* of file for that tool to review.
TOOL_FILE_EXCLUSIONS: Dict[str, Tuple[str, ...]] = {
    # A pure settings/config file (Pydantic BaseSettings, env var
    # declarations) can legitimately match a flow-behavior trigger — e.g.
    # GOOGLE_OAUTH_REDIRECT_URI — without containing any of the actual
    # request-handling logic (state, redirects) the check looks for, since
    # that logic lives in a companion route file.
    "review_oauth_flow": ("config.py", "settings.py"),
    # Conventional bootstrap/composition-root files (mount routers, set up
    # middleware) aren't route-handler bodies — reviewing "the route" here
    # means reviewing 100+ unrelated lines of app setup for input validation
    # that doesn't apply to whatever one-line route happens to live there.
    "review_express_route": ("index.ts", "index.js", "app.ts", "app.js", "server.ts", "server.js"),
}

# Tools whose internal logic is language-specific (checks for "zod",
# JS-style .status(500), etc.) even though their discovery trigger can
# coincidentally match another language — e.g. FastAPI's `@router.get(...)`
# decorator contains the substring "router.get(" just like Express, but
# telling a Python/FastAPI route to "Add Zod validation" is nonsense.
TOOL_EXTENSION_ALLOWLIST: Dict[str, Tuple[str, ...]] = {
    "review_express_route": (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs"),
    "validate_accessibility": (".tsx", ".jsx"),
    "review_stripe_webhook": (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs"),
}

# Each rule: (file_glob_or_None, content_regex_or_None, agent_key, tool_name, arg_builder)
# arg_builder(path, content) -> dict of kwargs for the tool handler.

RULES: List[Tuple[Optional[str], Optional[str], str, str, Callable[[str, str], Dict[str, Any]]]] = [
    ("package.json", None, "security_audit", "scan_dependencies",
     lambda p, c: {"package_json": c}),
    ("requirements*.txt", None, "security_audit", "scan_dependencies",
     lambda p, c: {"package_json": c}),
    (None, r"\bhelmet\s*\(", "security_audit", "analyze_helmet_config",
     lambda p, c: {"config_json": c, "framework": "express"}),
    (None, r"\bcors\s*\(|CORSMiddleware", "security_audit", "audit_cors_config",
     lambda p, c: {"cors_code": c}),
    (None, r"jwt\.(sign|verify|decode|encode)\(", "security_audit", "check_jwt_implementation",
     lambda p, c: {"code": c}),
    (None, r"(?i)(?:api[_-]?key|password|secret|token|database[_-]?url)\s*[:=]\s*[\"']|\bsk_(?:live|test)_|AKIA[0-9A-Z]{16}", "security_audit", "audit_hardcoded_secrets",
     lambda p, c: {"code": c}),
    (None, r"(?i)res\.(?:send|json)\(\s*(?:err|error)\b|response\.(?:send|json)\(\s*(?:err|error)\b|debug\s*[:=]\s*true", "security_audit", "audit_error_handling",
     lambda p, c: {"code": c}),
    (None, r"(?i)(?:console\.log|logger\.(?:log|info|debug|error))\([^\n]*(?:password|secret|token|api[_-]?key|req\.body|request\.body|process\.env)", "security_audit", "audit_logging_security",
     lambda p, c: {"code": c}),
    (None, r"refresh[_-]?token", "auth_security", "review_refresh_token_rotation",
     lambda p, c: {"code": c, "language": "python" if p.endswith(".py") else "node"}),
    (None, r"AppleAuthentication\.signInAsync|_verify_apple_identity_token|verifyApple|PyJWKClient|get_signing_key", "auth_security", "review_apple_sign_in",
     lambda p, c: {"code": c}),
    (None, r"accounts\.google\.com|GOOGLE_OAUTH|google.*oauth", "auth_security", "review_oauth_flow",
     lambda p, c: {"code": c, "provider": "google"}),
    (None, r"x-api-key|INTERNAL_API_KEY|requireApiKey|ADMIN_SECRET", "auth_security", "audit_shared_secret_auth",
     lambda p, c: {"code": c}),
    (None, r"LocalAuthentication\.|isEnrolledAsync\(|hasHardwareAsync\(|authenticateAsync\(", "auth_security", "review_biometric_auth",
     lambda p, c: {"code": c}),
    (None, r"stripe\.webhooks\.constructEvent|svix", "stripe_billing", "review_webhook_handler",
     lambda p, c: {"code": c}),
    (None, r"(?i)stripe|revenuecat|purchasepackage|purchaseproduct|receipt|customer.*(?:update|billing)", "stripe_billing", "audit_billing_security",
     lambda p, c: {"integration_code": c}),
    ("eas.json", None, "mobile_deploy", "review_eas_config",
     lambda p, c: {"eas_json": c}),
    ("codemagic.yaml", None, "mobile_deploy", "review_codemagic_config",
     lambda p, c: {"codemagic_yaml": c}),
    ("codemagic.yml", None, "mobile_deploy", "review_codemagic_config",
     lambda p, c: {"codemagic_yaml": c}),
    (None, r"Purchases\.configure|react-native-purchases", "mobile_deploy", "review_revenuecat_setup",
     lambda p, c: {"code": c}),
    (None, r"router\.(get|post|put|delete|patch)\(|app\.(get|post|put|delete|patch)\(", "code_review", "review_express_route",
     lambda p, c: {"code": c, "route_path": os.path.splitext(os.path.basename(p))[0], "auth_required": False}),
    (None, r"\buseState\(|\buseEffect\(", "code_review", "review_react_component",
     lambda p, c: {"code": c, "component_name": os.path.splitext(os.path.basename(p))[0], "is_native": bool(re.search(r"react-native|expo-", c))}),
    (None, r"<(?:img|input|textarea|select|div|span|button|a)\b", "ui_generation", "validate_accessibility",
     lambda p, c: {"component_code": c, "severity": "minor"}),
    (None, r"pgTable\(|sqliteTable\(|from ['\"]drizzle-orm", "code_review", "review_drizzle_schema",
     lambda p, c: {"schema_code": c, "database": "sqlite" if "sqliteTable(" in c else "postgresql"}),
    (None, r"z\.object\(|from ['\"]zod['\"]", "code_review", "review_zod_validation",
     lambda p, c: {"schema_code": c}),
    (None, r"expo-notifications|Notifications\.(scheduleNotificationAsync|requestPermissionsAsync)", "code_review", "review_expo_integration",
     lambda p, c: {"code": c, "integration_type": "push_notifications"}),
    # Require an actual SDK import, not just the word "HealthKit" — that also
    # matches wrapper-function names (isAppleHealthKitAvailable, syncHealthKit)
    # in every file that merely *calls* a health-sync module, not just the one
    # that implements it.
    (None, r"from ['\"]@kingstinct/react-native-healthkit|from ['\"]react-native-health['\"]|from ['\"]expo-health-connect", "code_review", "review_expo_integration",
     lambda p, c: {"code": c, "integration_type": "healthkit"}),
    (None, r"expo-location|Location\.(getCurrentPositionAsync|watchPositionAsync|startLocationUpdatesAsync)", "code_review", "review_expo_integration",
     lambda p, c: {"code": c, "integration_type": "location"}),
    (None, r"stripe\.webhooks\.constructEvent", "code_review", "review_stripe_webhook",
     lambda p, c: {"code": c}),
    (None, r"\.query\(|cursor\.execute\(|db\.execute\(|session\.execute\(", "security_audit", "audit_sql_injection",
     lambda p, c: {"code": c}),
    (None, r"dangerouslySetInnerHTML|\.innerHTML\s*=(?!=)|\|\s*safe\b|Markup\(|\bv-html\s*=|\{@html\b|bypassSecurityTrustHtml\(", "security_audit", "audit_xss_patterns",
     lambda p, c: {"code": c}),
    (None, r"express-session|cookie-session|req\.session\b", "security_audit", "audit_csrf_protection",
     lambda p, c: {"code": c}),
    (None, r"\beval\(|new Function\(|exec(Sync)?\(|subprocess\.(run|call|Popen)\(|os\.system\(", "security_audit", "audit_input_validation",
     lambda p, c: {"code": c}),
    (None, r"\bmulter\(|UploadFile", "security_audit", "audit_file_upload",
     lambda p, c: {"code": c}),
    (None, r"\.on\(\s*['\"]connection['\"]|io\.use\(", "security_audit", "audit_websocket_auth",
     lambda p, c: {"code": c}),
    (None, r"router\.get\(|app\.get\(|@(?:router|app)\.get\(", "api_architect", "review_pagination",
     lambda p, c: {"code": c, "endpoint": os.path.splitext(os.path.basename(p))[0]}),
    (None, r"catch\s*\(|except\s+|res\.status\(5\d\d\)|HTTPException\(", "api_architect", "review_error_response_shape",
     lambda p, c: {"code": c}),
    (None, r"router\.(post|delete)\(|app\.(post|delete)\(|@(?:router|app)\.(?:post|delete)\(", "api_architect", "audit_status_codes",
     lambda p, c: {"code": c}),
    (None, r"pgTable\(|sqliteTable\(|from ['\"]drizzle-orm|ForeignKey\(", "database_architect", "review_index_coverage",
     lambda p, c: {"schema_code": c, "database": "sqlite" if "sqliteTable(" in c else "postgresql"}),
    (None, r"pgTable\(|sqliteTable\(|from ['\"]drizzle-orm|ForeignKey\(", "database_architect", "review_constraints",
     lambda p, c: {"schema_code": c}),
    (None, r"op\.add_column\(|op\.drop_column\(|ALTER TABLE\b", "database_architect", "review_migration_safety",
     lambda p, c: {"migration_code": c}),
    (None, r"\.map\(|\.forEach\(|for\s*\([^)]*\)\s*\{", "database_architect", "review_n_plus_one",
     lambda p, c: {"code": c}),
    (None, r"sentry_sdk\.init\(|Sentry\.init\(", "infra_monitor", "review_sentry_setup",
     lambda p, c: {"code": c}),
    (None, r"[\"']\/health(z)?[\"']|[\"']\/ping[\"']|[\"']\/status[\"']", "infra_monitor", "audit_health_check_endpoint",
     lambda p, c: {"code": c}),
    ("_layout.tsx", None, "infra_monitor", "review_error_boundary_coverage",
     lambda p, c: {"code": c}),
    ("App.tsx", None, "infra_monitor", "review_error_boundary_coverage",
     lambda p, c: {"code": c}),
    ("Dockerfile", None, "railway_deploy", "review_deployment_config",
     lambda p, c: {"config_text": c, "filename": os.path.basename(p)}),
    ("*.dockerfile", None, "railway_deploy", "review_deployment_config",
     lambda p, c: {"config_text": c, "filename": os.path.basename(p)}),
    ("railway.toml", None, "railway_deploy", "review_deployment_config",
     lambda p, c: {"config_text": c, "filename": os.path.basename(p)}),
    ("railway.json", None, "railway_deploy", "review_deployment_config",
     lambda p, c: {"config_text": c, "filename": os.path.basename(p)}),
    ("Procfile", None, "railway_deploy", "review_deployment_config",
     lambda p, c: {"config_text": c, "filename": os.path.basename(p)}),
    ("*build*.log", r"(?i)error|failed|exception|timeout|ENOENT|ENOMEM|EADDRINUSE", "railway_deploy", "diagnose_build_failure",
     lambda p, c: {"build_log": c}),
]


_FINDING_KEYS = ("findings", "jwt_findings", "cors_findings", "diagnoses", "recommendations", "issues")
_A11Y_SEVERITY = {"critical": "HIGH", "serious": "MEDIUM", "moderate": "LOW", "minor": "INFO"}


def _normalize_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw: List[Any] = []
    for key in _FINDING_KEYS:
        value = result.get(key)
        if isinstance(value, list):
            raw.extend(value)

    normalized = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        finding = dict(item)
        original = str(finding.get("severity", "INFO"))
        severity = _A11Y_SEVERITY.get(original.lower(), original.upper())
        if severity not in SEVERITY_RANK:
            finding["detector_severity"] = original
            severity = "INFO"
        finding["severity"] = severity
        issue = str(finding.get("issue", finding.get("message", ""))).strip()
        if not issue:
            continue
        finding["issue"] = issue
        fingerprint = (severity, re.sub(r"\s+", " ", issue.lower()))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        normalized.append(finding)
    return normalized


def _integrity_findings(path: str, content: str) -> List[Dict[str, Any]]:
    """Cheap, high-confidence checks that apply before framework heuristics."""
    findings: List[Dict[str, Any]] = []
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1].lower()

    if re.search(r"(?m)^(?:<<<<<<< |=======\s*$|>>>>>>> )", content):
        findings.append({
            "severity": "CRITICAL",
            "issue": "Unresolved merge-conflict marker is present",
            "fix": "Resolve the conflict and remove every <<<<<<< / ======= / >>>>>>> marker",
            "confidence": "high",
        })

    if ext == ".py":
        try:
            ast.parse(content, filename=path)
        except SyntaxError as exc:
            findings.append({
                "severity": "CRITICAL",
                "issue": f"Python syntax error at line {exc.lineno}: {exc.msg}",
                "fix": "Fix the syntax error; this module cannot be imported or executed",
                "line": exc.lineno,
                "confidence": "high",
            })

    strict_json = ext == ".json" and not fnmatch.fnmatch(base.lower(), "tsconfig*.json") and base.lower() != "jsconfig.json"
    if strict_json:
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            findings.append({
                "severity": "HIGH",
                "issue": f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
                "fix": "Correct the JSON syntax; consumers will reject this configuration",
                "line": exc.lineno,
                "confidence": "high",
            })
    return findings


def _is_text_candidate(path: str) -> bool:
    base = os.path.basename(path)
    return base in TEXT_BASENAMES or os.path.splitext(base)[1].lower() in TEXT_EXTENSIONS


def _project_handles_async_route_errors(path: str, root: str) -> bool:
    """Detect Express 5/async-error support in the file's nearest package.

    A monorepo can contain Express 5 in one app and Express 4 in another. A
    workspace-wide yes/no answer would incorrectly suppress real findings in
    the Express 4 package, so walk from the reviewed file toward the root and
    stop at its nearest package manifest.
    """
    current = os.path.realpath(os.path.dirname(path))
    root = os.path.realpath(root)
    while current == root or current.startswith(root + os.sep):
        manifest = os.path.join(current, "package.json")
        if not os.path.isfile(manifest):
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
            continue
        try:
            with open(manifest, encoding="utf-8") as fh:
                package = json.load(fh)
        except (OSError, ValueError, TypeError):
            return False
        dependencies = {
            **(package.get("dependencies") or {}),
            **(package.get("devDependencies") or {}),
        }
        if "express-async-errors" in dependencies:
            return True
        express_version = str(dependencies.get("express", ""))
        major = re.search(r"(?:^|[^\d])([1-9]\d*)", express_version)
        return bool(major and int(major.group(1)) >= 5)
    return False


def _run_scan(root: str, agent_filter: Optional[List[str]]) -> Dict[str, Any]:
    root = os.path.realpath(os.path.expanduser(root))
    results: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    agent_cache: Dict[str, Any] = {}
    agents_exercised = set()
    targeted_files = set()
    matched_files = set()
    seen_paths = set()
    test_files = set()
    code_files = set()
    checks_run = 0
    async_route_error_cache: Dict[str, bool] = {}

    for path in _iter_files(root, diagnostics):
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()
        relpath = os.path.relpath(path, root)
        seen_paths.add(relpath)
        if _is_test_file(path):
            test_files.add(relpath)
        if ext in CODE_EXTENSIONS:
            code_files.add(relpath)
        if not _is_text_candidate(path):
            continue

        try:
            content = _read(path)
        except (OSError, UnicodeError) as exc:
            diagnostics.append({"file": relpath, "reason": "read_failed", "error": str(exc)})
            continue
        source_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:24]

        integrity = _integrity_findings(path, content)
        if integrity:
            results.append({
                "file": relpath,
                "agent": "project_integrity",
                "tool": "syntax_and_conflicts",
                "source_hash": source_hash,
                "result": {"findings": integrity},
            })
            matched_files.add(relpath)

        for glob, content_re, agent_key, tool_name, arg_builder in RULES:
            if agent_filter and agent_key not in agent_filter:
                continue
            if glob and not fnmatch.fnmatch(base, glob):
                continue
            if base in TOOL_FILE_EXCLUSIONS.get(tool_name, ()):
                continue
            allowed_exts = TOOL_EXTENSION_ALLOWLIST.get(tool_name)
            if allowed_exts and ext not in allowed_exts:
                continue
            if content_re:
                if glob is None and (
                    base in NON_CODE_BASENAMES
                    or base.startswith(".env")
                    or ext not in CODE_EXTENSIONS
                    or _is_test_file(path)
                ):
                    continue
                if not re.search(content_re, _discovery_text(path, content, tool_name)):
                    continue

            targeted_files.add(relpath)
            agents_exercised.add(agent_key)
            checks_run += 1
            try:
                agent = agent_cache.setdefault(agent_key, _get_agent(agent_key))
                handler = agent._tool_handlers[tool_name]
                effective_content = _inline_local_imports(path, content, root) if tool_name in CROSS_FILE_TOOLS else content
                if tool_name == "review_express_route":
                    package_dir = os.path.dirname(path)
                    handles_async_route_errors = async_route_error_cache.setdefault(
                        package_dir,
                        _project_handles_async_route_errors(path, root),
                    )
                    if handles_async_route_errors:
                        effective_content += "\n// project-level evidence: express-async-errors"
                result = handler(**arg_builder(path, effective_content))
                if not isinstance(result, dict):
                    result = {"error": f"Tool returned {type(result).__name__}, expected dict"}
            except Exception as exc:
                result = {"error": f"{type(exc).__name__}: {exc}"}

            findings = _normalize_findings(result)
            if findings:
                result = dict(result)
                result["findings"] = findings
            if findings or result.get("error"):
                results.append({
                    "file": relpath,
                    "agent": agent_key,
                    "tool": tool_name,
                    "source_hash": source_hash,
                    "result": result,
                })
                matched_files.add(relpath)

    summary: Dict[str, int] = {}
    tool_errors = 0
    for entry in results:
        if entry["result"].get("error"):
            tool_errors += 1
        for finding in _entry_findings(entry):
            sev = finding.get("severity", "INFO")
            summary[sev] = summary.get(sev, 0) + 1

    verification_gaps = []
    if code_files and not test_files:
        verification_gaps.append("No test files were found; static checks cannot verify runtime behavior or regressions.")
    if code_files and not any(p.startswith(".github/workflows/") for p in seen_paths):
        verification_gaps.append("No GitHub Actions workflow was found; tests and checks may not be enforced on every change.")
    package_files = [p for p in seen_paths if os.path.basename(p) == "package.json"]
    has_lockfile = any(os.path.basename(p) in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"} for p in seen_paths)
    if package_files and not has_lockfile:
        verification_gaps.append("package.json exists without a recognized lockfile; dependency resolution is not reproducible.")

    scannable_agents = {rule[2] for rule in RULES}
    if agent_filter:
        scannable_agents &= set(agent_filter)
    coverage = {
        "files_considered": len(seen_paths),
        "text_files_scanned": len([p for p in seen_paths if _is_text_candidate(p)]),
        "code_files": len(code_files),
        "test_files": len(test_files),
        "targeted_files": len(targeted_files),
        "files_without_targeted_checks": sorted(
            p for p in code_files if p not in targeted_files and p not in test_files
        )[:100],
        "checks_run": checks_run,
        "agents_exercised": sorted(agents_exercised),
        "agents_not_applicable": sorted(scannable_agents - agents_exercised),
        "generation_only_agents": ["scaffolder"],
        "skipped_files": diagnostics,
        "tool_errors": tool_errors,
        "verification_gaps": verification_gaps,
        "runtime_verification": "not_executed",
    }
    coverage["confidence"] = (
        "incomplete" if diagnostics or tool_errors else
        "static-plus-triage-pending" if results else
        "static-clean-runtime-unverified"
    )

    return {
        "project": root,
        "files_scanned": coverage["text_files_scanned"],
        "files_matched": len(matched_files),
        "results": results,
        "summary": summary,
        "coverage": coverage,
    }


def _entry_findings(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _normalize_findings(entry["result"])


def _format_report(report: Dict[str, Any]) -> str:
    coverage = report.get("coverage", {})
    lines = [
        f"Scan: {report['project']}",
        f"Files scanned: {report.get('files_scanned', '?')}",
        f"Files with findings: {report['files_matched']}",
        f"Checks run: {coverage.get('checks_run', '?')}",
        f"Coverage confidence: {coverage.get('confidence', 'unknown')}",
        "",
    ]
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if report["summary"]:
        lines.append("Summary: " + ", ".join(f"{s}={report['summary'][s]}" for s in sev_order if s in report["summary"]))
        lines.append("")

    if coverage.get("agents_exercised"):
        lines.append("Agents exercised: " + ", ".join(coverage["agents_exercised"]))
    if coverage.get("agents_not_applicable"):
        lines.append("Agents with no matching project evidence: " + ", ".join(coverage["agents_not_applicable"]))
    if coverage.get("files_without_targeted_checks"):
        lines.append(
            f"Production code files with no specialized check: {len(coverage['files_without_targeted_checks'])} (see JSON report)"
        )
    if coverage.get("skipped_files"):
        lines.append(f"Skipped/unreadable files: {len(coverage['skipped_files'])} (see JSON report)")
    if coverage.get("tool_errors"):
        lines.append(f"Detector execution errors: {coverage['tool_errors']} — this scan is incomplete")
    if coverage.get("verification_gaps"):
        lines.append("Verification gaps:")
        for gap in coverage["verification_gaps"]:
            lines.append(f"  - {gap}")
    if coverage.get("runtime_verification") == "not_executed":
        lines.append("Runtime verification: not executed (tests/typecheck/lint/build/external services are outside this static scan)")
    if coverage:
        lines.append("")

    triage_summary = report.get("triage_summary")
    if triage_summary:
        lines.append(
            f"Triage: {triage_summary['confirmed']} confirmed, "
            f"{triage_summary['false_positive']} dismissed as false positives, "
            f"{triage_summary['unknown']} unverified"
        )
        lines.append("")

    def sort_key(entry):
        sevs = [SEVERITY_RANK.get(f.get("severity", "INFO"), 9) for f in _entry_findings(entry)]
        return min(sevs) if sevs else 9

    # Findings triage confirmed (or that weren't triaged at all) stay front
    # and center; ones triage dismissed move to a short section at the end
    # instead of disappearing outright, so the verdict itself stays
    # auditable rather than silently swallowing the heuristic's output.
    def effective_entry_verdict(entry: Dict[str, Any]) -> Optional[str]:
        # Persisted feedback is deliberately evaluated first. It may contain
        # a human correction to an earlier model verdict, and human feedback
        # is the authority in the evolution store.
        feedback = entry.get("feedback", {})
        if feedback.get("verdict"):
            return feedback["verdict"]
        return entry.get("triage", {}).get("verdict")

    dismissed = [e for e in report["results"] if effective_entry_verdict(e) == "FALSE_POSITIVE"]
    dismissed_ids = {id(e) for e in dismissed}
    active = [e for e in report["results"] if id(e) not in dismissed_ids]

    for entry in sorted(active, key=sort_key):
        if entry["result"].get("error"):
            lines.append(f"[{entry['agent']}.{entry['tool']}] {entry['file']}  ERROR: {entry['result']['error']}")
            continue
        lines.append(f"[{entry['agent']}.{entry['tool']}] {entry['file']}")
        for f in _entry_findings(entry):
            sev = f.get("severity", "INFO")
            issue = f.get("issue", "")
            fix = f.get("fix", "")
            finding_id = f.get("finding_id")
            suffix = f"  ({finding_id})" if finding_id else ""
            lines.append(f"  {sev:<8} {issue}{suffix}")
            if fix:
                lines.append(f"           fix: {fix}")
            feedback = f.get("feedback")
            if feedback:
                lines.append(
                    f"           learned: {feedback['verdict']} ({feedback['source']}) — {feedback['reason']}"
                )
            finding_triage = f.get("triage")
            if finding_triage:
                lines.append(f"           triage: {finding_triage['verdict']} — {finding_triage['reason']}")
        triage = entry.get("triage")
        if triage and not any(f.get("triage") for f in _entry_findings(entry)):
            lines.append(f"           triage: {triage['verdict']} — {triage['reason']}")
        lines.append("")

    if dismissed:
        lines.append(f"── Dismissed as false positives by triage or learned feedback ({len(dismissed)}) ──")
        lines.append("")
        for entry in dismissed:
            lines.append(f"[{entry['agent']}.{entry['tool']}] {entry['file']}")
            verdict = entry.get("feedback") or entry.get("triage") or {}
            source = "learned feedback" if entry.get("feedback") else "triage"
            lines.append(
                f"  {source}: {verdict.get('verdict', 'FALSE_POSITIVE')} — "
                f"{verdict.get('reason', 'No reason recorded')}"
            )
            for finding in _entry_findings(entry):
                if finding.get("finding_id"):
                    lines.append(f"  id: {finding['finding_id']}")
        lines.append("")

    return "\n".join(lines)


def cmd_scan(args: argparse.Namespace) -> None:
    agent_filter = [a.strip() for a in args.agents.split(",")] if args.agents else None
    if agent_filter:
        unknown = sorted(set(agent_filter) - set(AGENTS))
        if unknown:
            raise SystemExit(f"Unknown scan agent(s): {', '.join(unknown)}. Available: {', '.join(sorted(AGENTS))}")
    scan_path = args.path_flag or args.path or "."
    report = _run_scan(scan_path, agent_filter)

    triage_on = args.triage
    if triage_on is None:
        # Auto-detect: only turn on when a key is actually present, so the
        # "no API key needed" promise still holds for anyone who hasn't set
        # one up — and holds automatically wherever one has, with no extra
        # flag to remember when wiring this into a new project.
        triage_on = bool(os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY"))

    if triage_on and report["results"]:
        provider = args.triage_provider or ("anthropic" if os.getenv("ANTHROPIC_API_KEY") else "openai")
        try:
            from agents.triage import triage_report
            report = triage_report(report, provider=provider, model=args.triage_model)
        except Exception as exc:
            coverage = report.get("coverage", {})
            coverage["confidence"] = "incomplete"
            coverage["triage_error"] = f"{type(exc).__name__}: {exc}"
            coverage.setdefault("verification_gaps", []).append(
                "LLM triage failed; findings remain heuristic and unverified."
            )
            print(f"Triage failed ({type(exc).__name__}: {exc}); keeping heuristic findings.", file=sys.stderr)
    elif triage_on:
        report["triage_summary"] = {"confirmed": 0, "false_positive": 0, "unknown": 0}
        report.get("coverage", {})["triage"] = "not_needed"
    else:
        coverage = report.get("coverage", {})
        coverage["triage"] = "disabled" if args.triage is False else "no_api_key"
        if report["results"] and coverage.get("confidence") == "static-plus-triage-pending":
            coverage["confidence"] = "static-findings-untriaged"

    attach_finding_ids(report)
    if args.record:
        try:
            with EvolutionStore(args.db) as store:
                store.apply_feedback(report)
                scan_id = store.record_scan(report, detector_version=__version__)
            report["evolution"]["recorded"] = True
            report["evolution"]["scan_id"] = scan_id
        except (OSError, sqlite3.Error) as exc:
            report.setdefault("evolution", {})["recorded"] = False
            report["evolution"]["error"] = f"{type(exc).__name__}: {exc}"
            print(f"Evolution history could not be recorded: {exc}", file=sys.stderr)
    else:
        report.setdefault("evolution", {})["recorded"] = False

    print(_format_report(report))
    if report.get("evolution", {}).get("recorded"):
        print(
            f"Evolution: recorded as {report['evolution']['scan_id']} "
            f"({report['evolution'].get('learned_verdicts_applied', 0)} learned verdicts applied)"
        )
    if args.out:
        with open(os.path.expanduser(args.out), "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\nFull JSON report written to {args.out}")


def cmd_feedback(args: argparse.Namespace) -> None:
    try:
        with EvolutionStore(args.db) as store:
            result = store.add_feedback(args.finding_id, args.verdict, args.reason or "")
    except KeyError as exc:
        raise SystemExit(str(exc)) from exc
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        f"Recorded {result['verdict']} for {result['finding_id']}\n"
        f"Detector: {result['detector']}\n"
        f"File: {result['file']}"
    )


def cmd_history(args: argparse.Namespace) -> None:
    with EvolutionStore(args.db) as store:
        runs = store.recent_runs(project=args.project, limit=args.limit)
    if not runs:
        print("No recorded scans.")
        return
    for run in runs:
        print(
            f"{run['scan_id']}  {run['created_at']}  v{run['detector_version']}  "
            f"findings={run['findings']}  {run['project_path']}"
        )


def cmd_eval(args: argparse.Namespace) -> None:
    with EvolutionStore(args.db) as store:
        evaluation = store.evaluate(project=args.project)
    print(json.dumps(evaluation, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m agents.cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all agents and their tools").set_defaults(func=cmd_list)

    p_run = sub.add_parser("run", help="Invoke a single tool handler directly")
    p_run.add_argument("agent", choices=sorted(AGENTS))
    p_run.add_argument("tool")
    p_run.add_argument("--arg", action="append", help="key=value literal argument (repeatable)")
    p_run.add_argument("--file", action="append", help="key=path — read file contents into this argument (repeatable)")
    p_run.add_argument("--stdin", help="argument name to fill from stdin")
    p_run.set_defaults(func=cmd_run)

    p_scan = sub.add_parser("scan", help="Auto-discover relevant files in a project and run matching checks")
    p_scan.add_argument("path", nargs="?", help="Project root to scan (positional form)")
    p_scan.add_argument("--path", dest="path_flag", help="Project root to scan (flag form)")
    p_scan.add_argument("--agents", help="Comma-separated agent keys to restrict the scan to")
    p_scan.add_argument("--out", help="Write the full JSON report to this path")
    p_scan.add_argument(
        "--triage", dest="triage", action="store_true", default=None,
        help="Force LLM triage of findings on (requires ANTHROPIC_API_KEY or OPENAI_API_KEY). "
             "On by default when one of those is set.",
    )
    p_scan.add_argument(
        "--no-triage", dest="triage", action="store_false",
        help="Force triage off, even if an API key is present in the environment.",
    )
    p_scan.add_argument("--triage-provider", choices=["anthropic", "openai"], help="Provider for triage (default: auto-detect from env)")
    p_scan.add_argument("--triage-model", help="Override the default triage model")
    p_scan.add_argument(
        "--db", default=default_database_path(),
        help="Evolution SQLite database (default: %(default)s or AGENTS_EVOLUTION_DB)",
    )
    p_scan.add_argument(
        "--no-record", dest="record", action="store_false", default=True,
        help="Do not record this scan or apply learned feedback",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_feedback = sub.add_parser("feedback", help="Confirm or dismiss a recorded finding")
    p_feedback.add_argument("finding_id", help="Stable agf_* ID printed by scan")
    p_feedback.add_argument("verdict", choices=["confirm", "dismiss"])
    p_feedback.add_argument("--reason", required=True, help="Why this verdict is correct")
    p_feedback.add_argument("--db", default=default_database_path())
    p_feedback.set_defaults(func=cmd_feedback)

    p_history = sub.add_parser("history", help="Show recently recorded scans")
    p_history.add_argument("--project", help="Only show scans for this project path")
    p_history.add_argument("--limit", type=int, default=10)
    p_history.add_argument("--db", default=default_database_path())
    p_history.set_defaults(func=cmd_history)

    p_eval = sub.add_parser("eval", help="Measure confirmed findings, false positives, and triage agreement")
    p_eval.add_argument("--project", help="Only evaluate one project path")
    p_eval.add_argument("--db", default=default_database_path())
    p_eval.set_defaults(func=cmd_eval)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

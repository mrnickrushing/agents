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
import fnmatch
import json
import os
import re
import sys
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
    "coverage", ".turbo", "ios/Pods",
    # Build/release/signing tooling, not application logic — a codesigning
    # script calling jwt.encode() to auth to the App Store Connect API isn't
    # "session JWT code missing verification", it's a different job entirely.
    "scripts", "tools", "bin",
}
MAX_FILE_BYTES = 300_000

# Content-pattern rules (glob is None) are meant to scan actual source code —
# without this, "jsonwebtoken"/"svix" appearing as a *dependency name* in
# package.json, or "client_secret"/"Face ID" appearing in prose in CLAUDE.md,
# matched the same regexes as real jwt.verify()/webhook-handler code and
# produced nonsense findings against files that have no logic to review.
CODE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"}
NON_CODE_BASENAMES = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}


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

def _iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _read(path: str) -> str:
    with open(path, "r", errors="ignore") as fh:
        return fh.read()


# Some checks review a call site whose actual logic lives one hop away in an
# imported helper (a paywall screen that calls `Purchases.configure()`
# through a shared `lib/revenuecat.ts` wrapper, rather than inline). Judged
# alone, the call site looks like it's missing the setup it's actually
# delegating to that helper. For these tools, follow local imports one level
# deep and let the check see the imported file's content too.
CROSS_FILE_TOOLS = {"review_revenuecat_setup"}

_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_JS_LOCAL_IMPORT_RE = re.compile(r"""from\s+["'](\.{1,2}/[^"']+|@/[^"']+)["']""")
_PY_LOCAL_IMPORT_RE = re.compile(r"^\s*from\s+([.\w]+)\s+import", re.MULTILINE)


def _find_alias_root(start_dir: str) -> str:
    """A `@/...` import conventionally resolves against the nearest ancestor
    directory that has a package.json — walk up to find it."""
    current = start_dir
    for _ in range(6):
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
    return next((c for c in candidates if os.path.isfile(c)), None)


def _resolve_py_import(module: str, from_dir: str, root: str) -> Optional[str]:
    parts = [p for p in module.split(".") if p]
    if not parts:
        return None
    for base in (root, from_dir):
        candidate = os.path.join(base, *parts) + ".py"
        if os.path.isfile(candidate):
            return candidate
        # A package import (e.g. `from app.models import User`) resolves to
        # the package directory's __init__.py, not a same-named .py file.
        candidate_init = os.path.join(base, *parts, "__init__.py")
        if os.path.isfile(candidate_init):
            return candidate_init
    return None


def _inline_local_imports(path: str, content: str, root: str, max_files: int = 3) -> str:
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


_TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__)/|(^|/)(test_\w+|\w+_test|\w+\.(test|spec))\.\w+$")


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
    (None, r"refresh[_-]?token", "auth_security", "review_refresh_token_rotation",
     lambda p, c: {"code": c, "language": "python" if p.endswith(".py") else "node"}),
    (None, r"appleid\.apple\.com|AppleAuthentication|_verify_apple_identity_token", "auth_security", "review_apple_sign_in",
     lambda p, c: {"code": c}),
    (None, r"accounts\.google\.com|GOOGLE_OAUTH|google.*oauth", "auth_security", "review_oauth_flow",
     lambda p, c: {"code": c, "provider": "google"}),
    (None, r"x-api-key|INTERNAL_API_KEY|requireApiKey|ADMIN_SECRET", "auth_security", "audit_shared_secret_auth",
     lambda p, c: {"code": c}),
    (None, r"LocalAuthentication\.|isEnrolledAsync\(|hasHardwareAsync\(|authenticateAsync\(", "auth_security", "review_biometric_auth",
     lambda p, c: {"code": c}),
    (None, r"stripe\.webhooks\.constructEvent|svix", "stripe_billing", "review_webhook_handler",
     lambda p, c: {"code": c}),
    ("eas.json", None, "mobile_deploy", "review_eas_config",
     lambda p, c: {"eas_json": c}),
    ("codemagic.yaml", None, "mobile_deploy", "review_codemagic_config",
     lambda p, c: {"codemagic_yaml": c}),
    (None, r"Purchases\.configure|react-native-purchases", "mobile_deploy", "review_revenuecat_setup",
     lambda p, c: {"code": c}),
    (None, r"router\.(get|post|put|delete|patch)\(|app\.(get|post|put|delete|patch)\(", "code_review", "review_express_route",
     lambda p, c: {"code": c, "route_path": os.path.splitext(os.path.basename(p))[0], "auth_required": False}),
    (None, r"\buseState\(|\buseEffect\(", "code_review", "review_react_component",
     lambda p, c: {"code": c, "component_name": os.path.splitext(os.path.basename(p))[0], "is_native": bool(re.search(r"react-native|expo-", c))}),
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
    (None, r"\.query\(|cursor\.execute\(|db\.execute\(|session\.execute\(", "security_audit", "audit_sql_injection",
     lambda p, c: {"code": c}),
    (None, r"dangerouslySetInnerHTML|\.innerHTML\s*=(?!=)|\|\s*safe\b|Markup\(", "security_audit", "audit_xss_patterns",
     lambda p, c: {"code": c}),
    (None, r"express-session|cookie-session|req\.session\b", "security_audit", "audit_csrf_protection",
     lambda p, c: {"code": c}),
    (None, r"\beval\(|new Function\(|exec(Sync)?\(|subprocess\.(run|call|Popen)\(|os\.system\(", "security_audit", "audit_input_validation",
     lambda p, c: {"code": c}),
    (None, r"\bmulter\(|UploadFile", "security_audit", "audit_file_upload",
     lambda p, c: {"code": c}),
    (None, r"\.on\(\s*['\"]connection['\"]|io\.use\(", "security_audit", "audit_websocket_auth",
     lambda p, c: {"code": c}),
    (None, r"router\.get\(|app\.get\(", "api_architect", "review_pagination",
     lambda p, c: {"code": c, "endpoint": os.path.splitext(os.path.basename(p))[0]}),
    (None, r"catch\s*\(|res\.status\(5\d\d\)", "api_architect", "review_error_response_shape",
     lambda p, c: {"code": c}),
    (None, r"router\.(post|delete)\(|app\.(post|delete)\(", "api_architect", "audit_status_codes",
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
]


def _run_scan(root: str, agent_filter: Optional[List[str]]) -> Dict[str, Any]:
    root = os.path.expanduser(root)
    results = []
    files_scanned = 0

    for path in _iter_files(root):
        base = os.path.basename(path)
        content = None
        for glob, content_re, agent_key, tool_name, arg_builder in RULES:
            if agent_filter and agent_key not in agent_filter:
                continue
            if glob and not fnmatch.fnmatch(base, glob):
                continue
            if base in TOOL_FILE_EXCLUSIONS.get(tool_name, ()):
                continue
            allowed_exts = TOOL_EXTENSION_ALLOWLIST.get(tool_name)
            if allowed_exts and os.path.splitext(base)[1] not in allowed_exts:
                continue
            if content_re:
                if glob is None and (
                    base in NON_CODE_BASENAMES
                    or base.startswith(".env")
                    or os.path.splitext(base)[1] not in CODE_EXTENSIONS
                    or _is_test_file(path)
                ):
                    continue
                if content is None:
                    try:
                        content = _read(path)
                    except Exception:
                        content = ""
                if not re.search(content_re, content):
                    continue
            elif content is None:
                try:
                    content = _read(path)
                except Exception:
                    content = ""

            try:
                agent = _get_agent(agent_key)
                handler = agent._tool_handlers[tool_name]
                effective_content = _inline_local_imports(path, content, root) if tool_name in CROSS_FILE_TOOLS else content
                kwargs = arg_builder(path, effective_content)
                result = handler(**kwargs)
            except Exception as e:
                result = {"error": str(e)}

            findings = result.get("findings") or result.get("jwt_findings") or result.get("cors_findings") or result.get("diagnoses") or result.get("recommendations") or []
            if findings or result.get("error"):
                results.append({
                    "file": os.path.relpath(path, root),
                    "agent": agent_key,
                    "tool": tool_name,
                    "result": result,
                })
        if content is not None:
            files_scanned += 1

    summary: Dict[str, int] = {}
    for entry in results:
        findings = entry["result"].get("findings") or entry["result"].get("jwt_findings") or entry["result"].get("cors_findings") or entry["result"].get("diagnoses") or []
        for f in findings:
            sev = f.get("severity", "INFO") if isinstance(f, dict) else "INFO"
            summary[sev] = summary.get(sev, 0) + 1

    return {"project": root, "files_matched": len(results), "results": results, "summary": summary}


def _entry_findings(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = entry["result"]
    findings = result.get("findings") or result.get("jwt_findings") or result.get("cors_findings") or result.get("diagnoses") or []
    return [f for f in findings if isinstance(f, dict)]


def _format_report(report: Dict[str, Any]) -> str:
    lines = [f"Scan: {report['project']}", f"Files with findings: {report['files_matched']}", ""]
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if report["summary"]:
        lines.append("Summary: " + ", ".join(f"{s}={report['summary'][s]}" for s in sev_order if s in report["summary"]))
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
    dismissed = [e for e in report["results"] if e.get("triage", {}).get("verdict") == "FALSE_POSITIVE"]
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
            lines.append(f"  {sev:<8} {issue}")
            if fix:
                lines.append(f"           fix: {fix}")
        triage = entry.get("triage")
        if triage:
            lines.append(f"           triage: {triage['verdict']} — {triage['reason']}")
        lines.append("")

    if dismissed:
        lines.append(f"── Dismissed as false positives by triage ({len(dismissed)}) ──")
        lines.append("")
        for entry in dismissed:
            lines.append(f"[{entry['agent']}.{entry['tool']}] {entry['file']}")
            lines.append(f"  {entry['triage']['reason']}")
        lines.append("")

    return "\n".join(lines)


def cmd_scan(args: argparse.Namespace) -> None:
    agent_filter = [a.strip() for a in args.agents.split(",")] if args.agents else None
    report = _run_scan(args.path, agent_filter)

    triage_on = args.triage
    if triage_on is None:
        # Auto-detect: only turn on when a key is actually present, so the
        # "no API key needed" promise still holds for anyone who hasn't set
        # one up — and holds automatically wherever one has, with no extra
        # flag to remember when wiring this into a new project.
        triage_on = bool(os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY"))

    if triage_on:
        provider = args.triage_provider or ("anthropic" if os.getenv("ANTHROPIC_API_KEY") else "openai")
        try:
            from agents.triage import triage_report
            report = triage_report(report, provider=provider, model=args.triage_model)
        except ImportError as e:
            print(f"Triage skipped ({e}); falling back to heuristic-only results.", file=sys.stderr)

    print(_format_report(report))
    if args.out:
        with open(os.path.expanduser(args.out), "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\nFull JSON report written to {args.out}")


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
    p_scan.add_argument("--path", required=True, help="Project root to scan")
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
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

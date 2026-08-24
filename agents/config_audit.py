"""Configuration surfaces the code scanners never look at.

A baseline scan of the sixteen local checkouts produced 368 findings — and
zero from Dockerfiles, docker-compose files, the 41 GitHub workflow files,
12 Android manifests, 11 plists, wrangler.toml, or railway config. Not
because those were clean: no rule looked. Every check here was written
against what those files actually contain across the fleet, not against a
checklist, and each one names the operational failure it prevents rather
than a compliance bullet.

Pure heuristics, no model call. Same shape as the other agents so the CLI's
RULES table can dispatch to it, but `BaseAgent`'s provider plumbing is never
exercised — a config audit that needed an API key to run would never run in
CI, which is where it matters.

Severity is calibrated to *consequence in this fleet*, not to an abstract
CVSS. A hardcoded dev password in docker-compose is LOW because it only ever
reaches localhost; a Railway healthcheck path that no route serves is HIGH
because it cost $40 of Actions minutes polling a 404 every 15 minutes.
"""

from __future__ import annotations

import os
import json
import re
import tempfile
from typing import Any, Callable, Dict, List

from .base import BaseAgent

Finding = Dict[str, Any]

# Env var names that are secrets by construction. Used for wrangler [vars],
# Dockerfile ENV/ARG, and .env.example values.
_SECRET_NAME = re.compile(
    r"(?i)(secret|token|password|passwd|api[_-]?key|private[_-]?key|credential|auth[_-]?key|signing[_-]?key)"
)
# A value that looks generated rather than a placeholder.
_REAL_LOOKING_VALUE = re.compile(r"^[A-Za-z0-9_\-./+=]{24,}$")
# Broad on purpose. The first fleet run flagged seven "real-looking secrets"
# and every one was a placeholder — "change-me-in-production", "REPLACE_WITH_..."
# — that a stricter list ("changeme", "replace_me") missed. For an *example*
# file, a missed placeholder is a false alarm on someone's honest template;
# err toward matching.
_PLACEHOLDER = re.compile(
    r"(?i)(example|placeholder|change|replace|your[_-]?|xxx|todo|<[^>]+>|\$\{|dummy|sample|fill[_-]?in|generate|random|insert|here\b|^$)"
)


def _repo_root(start: str, max_up: int = 4) -> str:
    """Nearest ancestor (at most `max_up` levels up) holding .git, else
    `start` itself.

    The ceiling matters: an unbounded climb from a temp directory found a
    stray /tmp/.git on the dev machine and would have walked all of /tmp.
    Four levels covers infra/railway.toml, apps/api/railway.json, and any
    plausible monorepo nesting without ever reaching a home directory.
    """
    start = os.path.abspath(start)
    cur = start
    for _ in range(max_up + 1):
        if os.path.isdir(os.path.join(cur, ".git")):
            if os.path.realpath(cur) != os.path.realpath(tempfile.gettempdir()):
                return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return start


def _line_of(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def _finding(severity: str, issue: str, line: int | None, fix: str, **extra) -> Finding:
    out: Finding = {"severity": severity, "issue": issue, "fix": fix}
    if line is not None:
        out["line"] = line
    out.update(extra)
    return out


class ConfigAuditAgent(BaseAgent):
    """Audits deployment and platform configuration files."""

    name = "config_audit"
    description = (
        "Audits Dockerfiles, docker-compose, GitHub workflows, Android manifests, iOS plists, "
        "wrangler.toml, Railway config, and .env.example for the misconfigurations that cause "
        "outages, leaked credentials, and surprise bills."
    )
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        def tool(
            name: str, desc: str, extra: Dict[str, Any] | None = None
        ) -> Dict[str, Any]:
            props: Dict[str, Any] = {
                "content": {"type": "string", "description": "The file's full text"},
                "path": {
                    "type": "string",
                    "description": "Path to the file, used for context",
                },
            }
            props.update(extra or {})
            return {
                "name": name,
                "description": desc,
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": ["content"],
                },
            }

        return [
            tool(
                "audit_dockerfile",
                "Audit a Dockerfile for root execution, unpinned bases, baked-in secrets, and curl|sh installs.",
            ),
            tool(
                "audit_compose",
                "Audit a docker-compose file for privileged containers, published database ports, and committed credentials.",
            ),
            tool(
                "audit_workflow",
                "Audit a GitHub Actions workflow for unpinned actions, missing permissions, pull_request_target, and script injection.",
            ),
            tool(
                "audit_android_manifest",
                "Audit AndroidManifest.xml for cleartext traffic, debuggable builds, backup exposure, and exported components without a permission.",
            ),
            tool(
                "audit_ios_plist",
                "Audit an iOS Info.plist for App Transport Security exceptions.",
            ),
            tool(
                "audit_wrangler",
                "Audit wrangler.toml for secrets committed as [vars] and stale compatibility dates.",
            ),
            tool(
                "audit_railway_config",
                "Audit railway.toml / railway.json: a healthcheck path that no route in the service serves.",
            ),
            tool(
                "audit_env_example",
                "Audit .env.example: real-looking secret values committed, and env vars the code reads that the example never documents.",
            ),
            tool(
                "audit_framework_config",
                "Audit framework config files (Next/Nuxt/Astro/Vite) for redirect/auth/build exposure pitfalls.",
            ),
            tool(
                "audit_tsconfig",
                "Audit tsconfig/jsconfig safety settings that can hide type errors.",
            ),
            tool(
                "audit_gradle_config",
                "Audit Gradle build/properties config for insecure signing and dependency precision.",
            ),
            tool(
                "audit_python_packaging",
                "Audit setup.py/setup.cfg for dependency pinning and unsafe setup execution patterns.",
            ),
            tool(
                "audit_ruby_gemfile",
                "Audit Gemfile dependency sourcing and version precision.",
            ),
            tool(
                "audit_go_mod",
                "Audit go.mod dependency replacement and version precision.",
            ),
            tool(
                "audit_env_local",
                "Audit .env.local for committed real-looking secrets.",
            ),
            tool(
                "audit_webserver_config",
                "Audit Apache/Nginx config for TLS downgrades and inline credential leaks.",
            ),
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "audit_dockerfile": self._audit_dockerfile,
            "audit_compose": self._audit_compose,
            "audit_workflow": self._audit_workflow,
            "audit_android_manifest": self._audit_android_manifest,
            "audit_ios_plist": self._audit_ios_plist,
            "audit_wrangler": self._audit_wrangler,
            "audit_railway_config": self._audit_railway_config,
            "audit_env_example": self._audit_env_example,
            "audit_framework_config": self._audit_framework_config,
            "audit_tsconfig": self._audit_tsconfig,
            "audit_gradle_config": self._audit_gradle_config,
            "audit_python_packaging": self._audit_python_packaging,
            "audit_ruby_gemfile": self._audit_ruby_gemfile,
            "audit_go_mod": self._audit_go_mod,
            "audit_env_local": self._audit_env_local,
            "audit_webserver_config": self._audit_webserver_config,
        }

    # --- Dockerfile ------------------------------------------------------------

    def _audit_dockerfile(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Only the final stage runs in production. A builder stage running as
        # root is normal; the runner stage doing so is the finding.
        stage_starts = [
            i for i, line in enumerate(lines) if re.match(r"^\s*FROM\b", line, re.I)
        ]
        stage_aliases = {
            m.group(1)
            for line in lines
            for m in [re.match(r"^\s*FROM\s+\S+\s+AS\s+(\S+)", line, re.I)]
            if m
        }
        if not stage_starts:
            return {"findings": findings, "total_issues": 0}
        final = lines[stage_starts[-1] :]
        if not any(re.match(r"^\s*USER\s+(?!root\b)\S+", line, re.I) for line in final):
            findings.append(
                _finding(
                    "HIGH",
                    "Final stage has no USER instruction — the container runs as root",
                    stage_starts[-1] + 1,
                    "Add a non-root user in the final stage: `RUN adduser -D app && USER app` (or `useradd` on Debian). "
                    "Two of six fleet Dockerfiles did this; the rest did not.",
                )
            )

        for i, line in enumerate(lines):
            m = re.match(r"^\s*FROM\s+(\S+)", line, re.I)
            if m:
                image = m.group(1)
                if image.lower() in ("scratch",) or image.startswith("$"):
                    continue
                # `FROM base AS runner` names an earlier stage, not an image.
                # Flagging it as unpinned was the first false positive the
                # fleet produced.
                if image in stage_aliases:
                    continue
                ref = image.split(" ")[0]
                if "@sha256:" in ref:
                    continue
                if ":" not in ref.split("/")[-1] or ref.endswith(":latest"):
                    findings.append(
                        _finding(
                            "MEDIUM",
                            f"Base image `{ref}` is unpinned — a rebuild can silently pull a different image",
                            i + 1,
                            "Pin at least a minor version (`node:20.19-alpine`), or a digest for reproducible builds.",
                        )
                    )
            if re.match(r"^\s*(ENV|ARG)\s+", line, re.I):
                for name, value in re.findall(
                    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"?([^\s\"]+)", line
                ):
                    if (
                        _SECRET_NAME.search(name)
                        and value
                        and not _PLACEHOLDER.search(value)
                    ):
                        findings.append(
                            _finding(
                                "CRITICAL",
                                f"`{name}` is baked into the image via {line.split()[0].upper()} — it ships in every layer and every registry copy",
                                i + 1,
                                "Pass secrets at runtime (Railway variables, `docker run -e`), never at build time. Use `--mount=type=secret` if a build genuinely needs one.",
                            )
                        )
            if re.search(r"\b(curl|wget)\b[^|\n]*\|\s*(ba)?sh\b", line):
                findings.append(
                    _finding(
                        "HIGH",
                        "Pipes a download straight into a shell — the build trusts whatever that URL serves today",
                        i + 1,
                        "Download to a file, verify a checksum, then execute.",
                    )
                )
            if re.match(r"^\s*ADD\s+https?://", line, re.I):
                findings.append(
                    _finding(
                        "MEDIUM",
                        "`ADD` with a URL fetches at build time with no integrity check",
                        i + 1,
                        "Use `RUN curl -fsSL ... -o file && sha256sum -c` instead.",
                    )
                )
        return {"findings": findings, "total_issues": len(findings)}

    # --- docker-compose ----------------------------------------------------------

    def _audit_compose(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        for m in re.finditer(r"^\s*privileged:\s*true", content, re.M):
            findings.append(
                _finding(
                    "HIGH",
                    "A service runs `privileged: true` — full host device access",
                    _line_of(content, m.start()),
                    "Drop it; grant specific `cap_add` entries if one is genuinely needed.",
                )
            )
        for m in re.finditer(r"^\s*network_mode:\s*[\"']?host", content, re.M):
            findings.append(
                _finding(
                    "MEDIUM",
                    "`network_mode: host` — the container shares the host's network namespace",
                    _line_of(content, m.start()),
                    "Use the default bridge network and publish only the ports you need.",
                )
            )
        # Database ports published to the host. On a laptop it is harmless;
        # on any shared or cloud host it is an open database. LOW because
        # every fleet compose file is a local dev harness.
        for m in re.finditer(
            r"^\s*-\s*[\"']?(?:0\.0\.0\.0:)?(5432|3306|27017|6379):\1[\"']?\s*$",
            content,
            re.M,
        ):
            findings.append(
                _finding(
                    "LOW",
                    f"Database port {m.group(1)} is published to all host interfaces",
                    _line_of(content, m.start()),
                    f'Bind to loopback: `"127.0.0.1:{m.group(1)}:{m.group(1)}"` — same convenience, not reachable from the LAN.',
                )
            )
        for m in re.finditer(
            r"^\s*(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*[:=]\s*[\"']?([^\s\"'$]+)",
            content,
            re.M,
        ):
            findings.append(
                _finding(
                    "LOW",
                    f"`{m.group(1)}` is a literal in the compose file (dev credential committed)",
                    _line_of(content, m.start()),
                    "Fine for a local harness, but reference `${POSTGRES_PASSWORD:-dev}` so the same file cannot be reused with a real value by accident.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    # --- GitHub Actions ------------------------------------------------------------

    def _audit_workflow(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        if (
            path
            and "/.github/workflows/" not in path.replace("\\", "/")
            and not path.startswith(".github/workflows/")
        ):
            return {"findings": findings, "total_issues": 0}

        if re.search(r"^\s*pull_request_target\s*:", content, re.M) and re.search(
            r"actions/checkout@", content
        ):
            findings.append(
                _finding(
                    "CRITICAL",
                    "`pull_request_target` with a checkout — a fork PR can run its code with this repo's secrets",
                    None,
                    "Use `pull_request` unless you need the base repo's secrets, and never check out the PR head under `pull_request_target`.",
                )
            )

        # Expression injection: untrusted event fields interpolated straight
        # into a shell step.
        for m in re.finditer(
            r"run:\s*[|>]?[^\n]*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit|review)\.(?:title|body|message)",
            content,
        ):
            findings.append(
                _finding(
                    "HIGH",
                    "Untrusted event text is interpolated into a `run:` step — a crafted PR title runs as shell",
                    _line_of(content, m.start()),
                    'Pass it through an env var (`env: TITLE: ${{ ... }}`) and reference `"$TITLE"` in the script.',
                )
            )

        # Top-level or per-job both scope the token; the fleet mostly does it
        # per job, and the first pass flagged 22 of those as missing.
        if not re.search(r"^\s*permissions\s*:", content, re.M):
            findings.append(
                _finding(
                    "MEDIUM",
                    "No `permissions:` block anywhere — the GITHUB_TOKEN gets the repository default, which is often write",
                    None,
                    "Add `permissions: { contents: read }` at the top (or per job) and widen only where needed.",
                )
            )
        if re.search(r"^\s*permissions\s*:\s*write-all", content, re.M):
            findings.append(
                _finding(
                    "HIGH",
                    "`permissions: write-all` — every scope, for every step",
                    None,
                    "List the scopes each job actually uses.",
                )
            )

        # Unpinned actions. A mutable tag is a supply-chain trust decision
        # made on every run; the fleet already SHA-pins about a third.
        for m in re.finditer(
            r"^\s*-?\s*uses:\s*([\w.-]+/[\w./-]+)@([^\s#]+)", content, re.M
        ):
            action, ref = m.group(1), m.group(2)
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            if action.startswith("./"):
                continue
            first_party = action.startswith(("actions/", "github/"))
            findings.append(
                _finding(
                    "LOW" if first_party else "MEDIUM",
                    f"`{action}@{ref}` is pinned to a mutable tag, not a commit SHA",
                    _line_of(content, m.start()),
                    "Pin to the full SHA with the tag as a comment (`@<sha> # v4`) — dependabot keeps it current. "
                    + (
                        "First-party action, lower risk."
                        if first_party
                        else "Third-party: a compromised tag runs with this workflow's permissions."
                    ),
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    # --- Android ----------------------------------------------------------------------

    def _audit_android_manifest(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        # A debug-variant manifest allows cleartext so Metro can reach the
        # dev server; it never ships. Flagging it was the first Android
        # false positive on the fleet.
        is_debug_variant = bool(re.search(r"/src/debug[^/]*/", path.replace("\\", "/")))
        m = (
            None
            if is_debug_variant
            else re.search(r'usesCleartextTraffic\s*=\s*"true"', content)
        )
        if m:
            findings.append(
                _finding(
                    "HIGH",
                    '`usesCleartextTraffic="true"` — the app will talk plain HTTP to any host',
                    _line_of(content, m.start()),
                    "Set it false (Android's default since API 28). If a dev server needs HTTP, scope it with a network_security_config for that host only. 10 of 12 fleet manifests have this on — usually an Expo default nobody revisited.",
                )
            )
        m = re.search(r'android:debuggable\s*=\s*"true"', content)
        if m:
            findings.append(
                _finding(
                    "CRITICAL",
                    '`android:debuggable="true"` in the manifest — a release build with this is fully inspectable',
                    _line_of(content, m.start()),
                    "Remove it; let the build type control debuggability.",
                )
            )
        m = re.search(r'android:allowBackup\s*=\s*"true"', content)
        if m:
            findings.append(
                _finding(
                    "MEDIUM",
                    '`allowBackup="true"` — app data, including tokens in SharedPreferences, can be pulled with `adb backup`',
                    _line_of(content, m.start()),
                    'Set `allowBackup="false"` unless you ship a backup rules file that excludes secrets.',
                )
            )
        # Exported non-activity components with no permission gate. Activities
        # are usually exported on purpose (launcher, deep links); a service,
        # receiver, or provider exported without a permission is callable by
        # any app on the device.
        for m in re.finditer(r"<(service|receiver|provider)\b([^>]*)>", content):
            attrs = m.group(2)
            if (
                'android:exported="true"' in attrs
                and "android:permission=" not in attrs
            ):
                name = re.search(r'android:name="([^"]+)"', attrs)
                findings.append(
                    _finding(
                        "MEDIUM",
                        f"Exported {m.group(1)} `{name.group(1) if name else '?'}` has no `android:permission` — any app can invoke it",
                        _line_of(content, m.start()),
                        'Set `android:exported="false"` or gate it with a signature-level permission.',
                    )
                )
        m = re.search(
            r'<uses-permission\s+android:name="android\.permission\.SYSTEM_ALERT_WINDOW"',
            content,
        )
        if m:
            findings.append(
                _finding(
                    "LOW",
                    "Requests SYSTEM_ALERT_WINDOW (draw over other apps) — a review-flag permission most apps do not need",
                    _line_of(content, m.start()),
                    'If no feature draws overlays, remove it (often pulled in transitively by a library; `tools:node="remove"` drops it).',
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    # --- iOS --------------------------------------------------------------------------

    def _audit_ios_plist(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        m = re.search(r"<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>", content)
        if m:
            findings.append(
                _finding(
                    "HIGH",
                    "App Transport Security is disabled (`NSAllowsArbitraryLoads` true) — plain HTTP to any host",
                    _line_of(content, m.start()),
                    "Remove it; add per-domain `NSExceptionDomains` for the one host that genuinely needs it.",
                )
            )
        m = re.search(
            r"<key>NSAllowsArbitraryLoadsInWebContent</key>\s*<true\s*/>", content
        )
        if m:
            findings.append(
                _finding(
                    "MEDIUM",
                    "`NSAllowsArbitraryLoadsInWebContent` true — web views may load over HTTP",
                    _line_of(content, m.start()),
                    "Remove unless a web view must load a specific HTTP origin.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    # --- Cloudflare Workers -----------------------------------------------------------

    def _audit_wrangler(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        vars_block = re.search(r"^\[vars\]\s*\n((?:(?!^\[).*\n?)*)", content, re.M)
        if vars_block:
            for m in re.finditer(
                r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"([^\"]*)\"",
                vars_block.group(1),
                re.M,
            ):
                name, value = m.group(1), m.group(2)
                if (
                    _SECRET_NAME.search(name)
                    and value
                    and not _PLACEHOLDER.search(value)
                ):
                    findings.append(
                        _finding(
                            "CRITICAL",
                            f"`{name}` is committed under `[vars]` — that is plaintext in git and visible in the dashboard",
                            _line_of(content, vars_block.start(1) + m.start()),
                            "Move it to `wrangler secret put`; `[vars]` is for non-sensitive config only.",
                        )
                    )
        return {"findings": findings, "total_issues": len(findings)}

    # --- Railway ----------------------------------------------------------------------

    _ROUTE_PATTERNS = (r"[\"'`]{path}[\"'`]",)  # any literal of the path

    def _audit_railway_config(self, content: str, path: str = "") -> Dict[str, Any]:
        """A healthcheckPath that no code in the service serves.

        The incident: a Railway service's `healthcheckPath` pointed at
        `/health`, the API app defined no such route, and a scheduled uptime
        check burned $40 of Actions minutes polling the 404 every 15 minutes.
        Railway's own healthcheck fails the same way, so deploys look broken
        for a reason that is not in the logs.
        """
        findings: List[Finding] = []
        m = re.search(r"healthcheckPath\s*[=:]\s*\"([^\"]+)\"", content)
        if not m or not path:
            return {"findings": findings, "total_issues": 0}
        hc_path = m.group(1)
        if hc_path == "/":
            return {
                "findings": findings,
                "total_issues": 0,
            }  # root nearly always serves

        # Walk from the repo root, not the config's own directory: zenfinance
        # keeps railway.toml under infra/ with the route three directories
        # away, and walking from infra/ produced the first false positive.
        service_root = _repo_root(os.path.dirname(os.path.abspath(path)))
        pattern = re.compile(self._ROUTE_PATTERNS[0].format(path=re.escape(hc_path)))
        found = False
        for dirpath, dirnames, filenames in os.walk(service_root):
            dirnames[:] = [
                d
                for d in dirnames
                if d
                not in {
                    "node_modules",
                    ".git",
                    "dist",
                    "build",
                    ".venv",
                    "venv",
                    "__pycache__",
                    ".next",
                }
            ]
            for fn in filenames:
                if not fn.endswith(
                    (
                        ".py",
                        ".ts",
                        ".js",
                        ".mjs",
                        ".tsx",
                        ".go",
                        ".rb",
                        ".rs",
                        ".java",
                        ".kt",
                    )
                ):
                    continue
                try:
                    with open(
                        os.path.join(dirpath, fn),
                        "r",
                        encoding="utf-8",
                        errors="ignore",
                    ) as fh:
                        if pattern.search(fh.read()):
                            found = True
                            break
                except OSError:
                    continue
            if found:
                break
        if not found:
            findings.append(
                _finding(
                    "HIGH",
                    f"`healthcheckPath` is `{hc_path}` but no source file under this service mentions that path",
                    _line_of(content, m.start()),
                    "Add the route (return 200 with a small JSON body) or point healthcheckPath at one that exists. "
                    "A missing health route fails Railway's deploy healthcheck and makes any external uptime check burn its full timeout on every run.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    # --- .env.example -------------------------------------------------------------------

    _ENV_USAGE = re.compile(
        r"process\.env\.([A-Z][A-Z0-9_]{2,})"
        r"|os\.environ(?:\.get)?\(?\[?[\"']([A-Z][A-Z0-9_]{2,})[\"']"
        r"|os\.getenv\([\"']([A-Z][A-Z0-9_]{2,})[\"']"
        r"|env\.([A-Z][A-Z0-9_]{2,})\b"
        r"|import\.meta\.env\.([A-Z][A-Z0-9_]{2,})"
    )
    # Names the platform sets, or that are never meant to be in an example.
    _ENV_IGNORE = {
        "NODE_ENV",
        "PORT",
        "HOSTNAME",
        "CI",
        "HOME",
        "PATH",
        "PWD",
        "RAILWAY_ENVIRONMENT",
        "RAILWAY_PUBLIC_DOMAIN",
        "RAILWAY_PRIVATE_DOMAIN",
        "RAILWAY_SERVICE_NAME",
        "TZ",
        "PYTHONPATH",
        "PYTHONUNBUFFERED",
        "EXPO_PUBLIC_",
        "VERCEL",
        "VERCEL_URL",
        "SHELL",
        "USER",
        "LANG",
        "TERM",
        "DEBUG",
        "LOG_LEVEL",
        "JEST_WORKER_ID",
        "NODE_OPTIONS",
        "GITHUB_ACTIONS",
        "RAILWAY_GIT_COMMIT_SHA",
    }

    def _audit_env_example(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        documented: Dict[str, str] = {}
        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(
                r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']?(.*?)[\"']?\s*$",
                line,
            )
            if not m:
                continue
            name, value = m.group(1), m.group(2)
            documented[name] = value
            # RevenueCat `appl_...` / `goog_...` values are public mobile SDK
            # keys: they identify the app and cannot authorize server calls.
            if re.match(r"(appl|goog)_[A-Za-z0-9]+$", value):
                continue
            if (
                _SECRET_NAME.search(name)
                and _REAL_LOOKING_VALUE.match(value)
                and not _PLACEHOLDER.search(value)
            ):
                findings.append(
                    _finding(
                        "HIGH",
                        f"`{name}` in the example file has a real-looking value — .env.example is committed and public on a public repo",
                        i,
                        "Replace with a placeholder (`your-key-here`) and rotate the value if it was ever live.",
                    )
                )

        if not path:
            return {"findings": findings, "total_issues": len(findings)}

        # Undocumented usage: a var the code reads that a fresh deploy will
        # not know to set. This is the "works on my machine, dies on Railway"
        # failure, found at deploy time by the service crash-looping.
        root = os.path.dirname(os.path.abspath(path))
        used: Dict[str, str] = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d
                for d in dirnames
                if d
                not in {
                    "node_modules",
                    ".git",
                    "dist",
                    "build",
                    ".venv",
                    "venv",
                    "__pycache__",
                    ".next",
                    ".expo",
                    "coverage",
                }
            ]
            for fn in filenames:
                if not fn.endswith((".py", ".ts", ".tsx", ".js", ".mjs", ".cjs")):
                    continue
                # Test code reads env vars nobody sets in production
                # (JEST_WORKER_ID turned up as "undocumented" on the first
                # fleet run). A missing var only matters if a deploy reads it.
                if re.search(
                    r"(\.test\.|\.spec\.|_test\.|^test_)", fn
                ) or os.path.basename(dirpath) in {
                    "__tests__",
                    "tests",
                    "test",
                    "__mocks__",
                }:
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                for m in self._ENV_USAGE.finditer(text):
                    name = next(g for g in m.groups() if g)
                    used.setdefault(name, os.path.relpath(fp, root))
        missing = sorted(
            n
            for n in used
            if n not in documented
            and n not in self._ENV_IGNORE
            and not any(n.startswith(p) for p in self._ENV_IGNORE if p.endswith("_"))
        )
        if missing:
            shown = ", ".join(missing[:8]) + (
                f" (+{len(missing) - 8} more)" if len(missing) > 8 else ""
            )
            findings.append(
                _finding(
                    "MEDIUM",
                    f"{len(missing)} env var(s) the code reads are not in .env.example: {shown}",
                    None,
                    f"Document each one (first seen in {used[missing[0]]}). A new deploy set up from the example will be missing them and fail at runtime, not at build.",
                    undocumented=missing,
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    # --- framework and package-manager configs ------------------------------------------

    def _audit_framework_config(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        basename = os.path.basename(path).lower()
        if basename.startswith("next.config") or basename.startswith("nuxt.config"):
            for m in re.finditer(
                r"destination\s*:\s*['\"]([^'\"]+)['\"][\s\S]{0,160}?source\s*:\s*['\"]\1['\"]",
                content,
                re.IGNORECASE,
            ):
                findings.append(
                    _finding(
                        "HIGH",
                        "Redirect source and destination are the same path — redirect loop risk",
                        _line_of(content, m.start()),
                        "Change destination to a distinct route or add a guard condition.",
                    )
                )
            if re.search(r"\bmiddleware\b", content, re.IGNORECASE) and not re.search(
                r"\b(auth|session|jwt|token|clerk|nextauth)\b", content, re.IGNORECASE
            ):
                findings.append(
                    _finding(
                        "MEDIUM",
                        "Middleware is configured with no visible auth/session check",
                        None,
                        "Ensure middleware enforces auth for protected routes before calling next().",
                    )
                )
        if basename.startswith("astro.config"):
            if re.search(
                r"output\s*:\s*['\"]static['\"]", content, re.IGNORECASE
            ) and re.search(r"(adapter|ssr)\s*[:=]", content, re.IGNORECASE):
                findings.append(
                    _finding(
                        "MEDIUM",
                        "Astro config mixes static output with SSR adapter settings",
                        None,
                        "Use output: 'server' for SSR adapters, or remove adapter config for pure static builds.",
                    )
                )
        if basename.startswith("vite.config"):
            if re.search(r"outDir\s*:\s*['\"](?:/|\.{2}/)", content):
                findings.append(
                    _finding(
                        "HIGH",
                        "Vite outDir points outside the project tree",
                        None,
                        "Set build.outDir to a project-local directory (e.g., dist).",
                    )
                )
            if re.search(
                r"optimizeDeps\s*:\s*\{[\s\S]{0,200}?exclude\s*:\s*\[[^\]]{0,250}['\"](?:crypto|jsonwebtoken|bcrypt)['\"]",
                content,
                re.IGNORECASE,
            ):
                findings.append(
                    _finding(
                        "LOW",
                        "Security-sensitive dependency is excluded from optimizeDeps",
                        None,
                        "Confirm this exclusion is intentional and pinned to a known-safe version.",
                    )
                )
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_tsconfig(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            return {"findings": findings, "total_issues": 0}
        compiler = parsed.get("compilerOptions") if isinstance(parsed, dict) else {}
        if isinstance(compiler, dict):
            if compiler.get("skipLibCheck") is True:
                findings.append(
                    _finding(
                        "MEDIUM",
                        "skipLibCheck=true can hide type incompatibilities in dependency contracts",
                        None,
                        "Set skipLibCheck to false for stricter type-safety in CI.",
                    )
                )
            if compiler.get("noImplicitAny") is False:
                findings.append(
                    _finding(
                        "HIGH",
                        "noImplicitAny=false allows implicit any and weakens type guarantees",
                        None,
                        "Set noImplicitAny to true (or enable strict mode).",
                    )
                )
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_gradle_config(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        if re.search(
            r"storePassword\s+[\"'][^\"']+[\"']|keyPassword\s+[\"'][^\"']+[\"']",
            content,
        ):
            findings.append(
                _finding(
                    "CRITICAL",
                    "Gradle signing password is hardcoded in build configuration",
                    None,
                    "Load signing credentials from environment variables or encrypted Gradle properties.",
                )
            )
        if re.search(r"implementation\s+['\"][^:'\"]+:[^:'\"]+:[+*]['\"]", content):
            findings.append(
                _finding(
                    "MEDIUM",
                    "Gradle dependency uses wildcard/dynamic version",
                    None,
                    "Pin to an explicit version to ensure reproducible builds.",
                )
            )
        if os.path.basename(path) == "gradle.properties" and re.search(
            r"(?m)^\s*(?:KEYSTORE_|SIGNING_).+=.+$", content
        ):
            findings.append(
                _finding(
                    "HIGH",
                    "Signing-related value appears in gradle.properties",
                    None,
                    "Move sensitive signing values to local-only properties or CI secrets.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_python_packaging(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        if os.path.basename(path) == "setup.py" and re.search(r"\bexec\s*\(", content):
            findings.append(
                _finding(
                    "HIGH",
                    "setup.py executes dynamic code via exec()",
                    None,
                    "Avoid exec in packaging metadata; use static metadata or pyproject.toml fields.",
                )
            )
        if re.search(
            r"install_requires\s*=\s*\[[\s\S]*['\"][A-Za-z0-9_.-]+['\"]", content
        ) and not re.search(r"(==|~=|>=|<=)", content):
            findings.append(
                _finding(
                    "LOW",
                    "Python dependency appears without a version constraint in setup metadata",
                    None,
                    "Pin or bound install_requires versions for reproducible dependency resolution.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_ruby_gemfile(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        if re.search(r"source\s+['\"]http://", content):
            findings.append(
                _finding(
                    "HIGH",
                    "Gem source uses http:// instead of https://",
                    None,
                    "Use HTTPS gem sources only.",
                )
            )
        if re.search(r"gem\s+['\"][^'\"]+['\"]\s*$", content, re.MULTILINE):
            findings.append(
                _finding(
                    "LOW",
                    "Gem dependency declared without an explicit version requirement",
                    None,
                    "Add a pessimistic or exact version constraint in Gemfile.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_go_mod(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        for m in re.finditer(r"(?m)^\s*replace\s+\S+\s*=>\s*(\.\.?/|/)", content):
            findings.append(
                _finding(
                    "MEDIUM",
                    "go.mod replace points to a local path",
                    _line_of(content, m.start()),
                    "Avoid local-path replacements in committed go.mod; use module versions.",
                )
            )
        if re.search(r"(?m)^\s*require\s+\S+\s+latest\s*$", content):
            findings.append(
                _finding(
                    "MEDIUM",
                    "go.mod requires dependency at latest",
                    None,
                    "Pin a concrete semantic version for reproducibility.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_env_local(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", line)
            if not m:
                continue
            key, value = m.group(1), m.group(2).strip().strip("'\"")
            if (
                _SECRET_NAME.search(key)
                and _REAL_LOOKING_VALUE.match(value)
                and not _PLACEHOLDER.search(value)
            ):
                findings.append(
                    _finding(
                        "CRITICAL",
                        f"`.env.local` contains a real-looking secret value for {key}",
                        i,
                        "Do not commit .env.local; move this value to local untracked env files and rotate if exposed.",
                    )
                )
        return {"findings": findings, "total_issues": len(findings)}

    def _audit_webserver_config(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Finding] = []
        if re.search(
            r"\bssl_protocols\b[^;\n]*(TLSv1(?:\.0)?|TLSv1\.1)", content, re.IGNORECASE
        ):
            findings.append(
                _finding(
                    "HIGH",
                    "Webserver config allows deprecated TLS versions (TLSv1.0/1.1)",
                    None,
                    "Restrict TLS to modern versions (TLSv1.2/TLSv1.3).",
                )
            )
        if re.search(
            r"(?im)^\s*(?:setenv|set\s+\$?\w*(?:secret|token|password)|proxy_set_header\s+authorization)\b[^\n]*\S",
            content,
        ):
            findings.append(
                _finding(
                    "HIGH",
                    "Potential secret-like value appears inline in Apache/Nginx configuration",
                    None,
                    "Move secrets to environment/secret stores and inject at runtime, not in committed config.",
                )
            )
        return {"findings": findings, "total_issues": len(findings)}

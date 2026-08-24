"""Automatic remediation for the findings that are mechanical.

Most findings need judgment. A few do not: pinning an action to the SHA its
tag points at, adding a `permissions:` block, writing down an environment
variable the code already reads. Those have exactly one correct fix, it is
the same fix everywhere, and applying it by hand across a fleet is how it
never gets done.

This started as a throwaway script that hardened fifteen repositories in one
pass — 156 actions pinned, 21 workflow tokens scoped, ~90 undocumented
environment variables written down. It earns a place in the package because
the rule behind the biggest slice of that work, `config_audit.audit_workflow`,
scores 100% precision against recorded verdicts. Findings that reliable are
findings worth fixing without asking.

**What is deliberately not here.** Dockerfile `USER` fixes, which were the
other half of that pass. Every one needs a judgment about what the runtime
writes and where its toolchains cache — Playwright installs browsers into
the invoking user's home, so adding `USER app` without first pinning
`PLAYWRIGHT_BROWSERS_PATH` produces an image that builds fine and fails at
runtime. A fixer that is right nine times out of ten is worse than no fixer,
because the tenth lands in a commit nobody reviewed.

Every fixer is idempotent: running twice changes nothing the second time.
`plan()` reports what would change without touching anything.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional, Set

# Directories never worth walking, mirroring the scanner's own exclusions.
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", ".venv", "venv",
    "__pycache__", ".expo", "coverage", "Pods", ".gradle", "vendor",
}

USES = re.compile(r"^(\s*-?\s*uses:\s*)([\w.-]+/[\w.-]+(?:/[\w./-]+)?)@([^\s#]+)(\s*(?:#.*)?)$")

ENV_USAGE = re.compile(
    r"process\.env\.([A-Z][A-Z0-9_]{2,})"
    r"|os\.environ(?:\.get)?\(?\[?[\"']([A-Z][A-Z0-9_]{2,})[\"']"
    r"|os\.getenv\([\"']([A-Z][A-Z0-9_]{2,})[\"']"
    r"|import\.meta\.env\.([A-Z][A-Z0-9_]{2,})"
)

# Names the platform supplies, or that no example file should carry.
ENV_IGNORE = {
    "NODE_ENV", "PORT", "HOSTNAME", "CI", "HOME", "PATH", "PWD", "TZ", "SHELL",
    "USER", "LANG", "TERM", "DEBUG", "LOG_LEVEL", "PYTHONPATH", "PYTHONUNBUFFERED",
    "JEST_WORKER_ID", "NODE_OPTIONS", "GITHUB_ACTIONS", "VERCEL", "VERCEL_URL",
    "RAILWAY_ENVIRONMENT", "RAILWAY_PUBLIC_DOMAIN", "RAILWAY_PRIVATE_DOMAIN",
    "RAILWAY_SERVICE_NAME", "RAILWAY_GIT_COMMIT_SHA",
}

DB_PORTS = ("5432", "3306", "6379", "27017")
PASSWORD_VARS = ("POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD", "REDIS_PASSWORD")

ENV_HEADER = (
    "\n# --- Read by the code but previously undocumented (config_audit). A deploy\n"
    "# set up from this file would have been missing these and failed at\n"
    "# runtime, not at build. Empty on purpose: names, not defaults.\n"
)


@dataclass
class Change:
    path: str
    kind: str            # pin-actions | workflow-permissions | env-example | compose
    detail: str
    count: int = 1


@dataclass
class FixPlan:
    changes: List[Change] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)

    def by_kind(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for c in self.changes:
            out[c.kind] = out.get(c.kind, 0) + c.count
        return out

    def __bool__(self) -> bool:
        return bool(self.changes)


# --- action pinning ---------------------------------------------------------------


@lru_cache(maxsize=None)
def resolve_tag(repo: str, tag: str) -> Optional[str]:
    """The commit SHA a tag points at, dereferencing annotated tags.

    Returns None when the ref cannot be resolved — the caller then leaves the
    line alone and reports it. Rewriting a `uses:` to a guessed SHA would
    break the workflow in a way that looks like a security improvement.
    """
    for ref in (f"tags/{tag}", f"heads/{tag}"):
        proc = subprocess.run(["gh", "api", f"repos/{repo}/git/ref/{ref}"],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            continue
        try:
            obj = json.loads(proc.stdout)["object"]
        except (ValueError, KeyError):
            return None
        if obj.get("type") == "tag":
            deref = subprocess.run(["gh", "api", f"repos/{repo}/git/tags/{obj['sha']}"],
                                   capture_output=True, text=True)
            if deref.returncode == 0:
                try:
                    return json.loads(deref.stdout)["object"]["sha"]
                except (ValueError, KeyError):
                    return None
            return None
        return obj.get("sha")
    return None


def pin_actions(path: str, apply: bool = False) -> tuple[int, List[str]]:
    """Pin every mutable `uses:` tag to its commit SHA, tag kept as a comment
    so dependabot can keep the pin current."""
    out: List[str] = []
    changed = 0
    unresolved: List[str] = []
    with open(path) as fh:
        lines = fh.readlines()

    for line in lines:
        match = USES.match(line.rstrip("\n"))
        if not match:
            out.append(line)
            continue
        prefix, action, ref, _ = match.groups()
        if re.fullmatch(r"[0-9a-f]{40}", ref) or action.startswith("./"):
            out.append(line)
            continue
        sha = resolve_tag("/".join(action.split("/")[:2]), ref)
        if not sha:
            unresolved.append(f"{action}@{ref}")
            out.append(line)
            continue
        out.append(f"{prefix}{action}@{sha} # {ref}\n")
        changed += 1

    if changed and apply:
        with open(path, "w") as fh:
            fh.writelines(out)
    return changed, unresolved


# --- workflow permissions ----------------------------------------------------------


def add_workflow_permissions(path: str, apply: bool = False) -> bool:
    """Add a least-privilege top-level `permissions:` when a workflow has none
    anywhere, and grant `security-events: write` to jobs that upload SARIF.

    That second half is not optional: restricting the token without it turns
    a passing security-scan job into a failing one, which is a worse outcome
    than the permissive token it replaced.
    """
    with open(path) as fh:
        text = fh.read()
    if re.search(r"^\s*permissions\s*:", text, re.M):
        return False
    jobs = re.search(r"^jobs:", text, re.M)
    if not jobs:
        return False

    text = text[:jobs.start()] + "permissions:\n  contents: read\n\n" + text[jobs.start():]

    job_re = re.compile(r"^(  [A-Za-z0-9_-]+):\s*$", re.M)
    positions = [m.start() for m in job_re.finditer(text)]
    for index in range(len(positions) - 1, -1, -1):
        start = positions[index]
        end = positions[index + 1] if index + 1 < len(positions) else len(text)
        body = text[start:end]
        if "upload-sarif" in body and "security-events" not in body:
            head_end = start + body.index("\n") + 1
            text = (text[:head_end]
                    + "    permissions:\n      contents: read\n      security-events: write\n"
                    + text[head_end:])

    if apply:
        with open(path, "w") as fh:
            fh.write(text)
    return True


# --- .env.example ------------------------------------------------------------------


def undocumented_env_vars(example_path: str) -> List[str]:
    """Env var names the code reads that this example file never mentions."""
    root = os.path.dirname(os.path.abspath(example_path))
    with open(example_path) as fh:
        existing = fh.read()
    documented = {
        m.group(1) for m in
        re.finditer(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", existing, re.M)
    }

    used: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith((".py", ".ts", ".tsx", ".js", ".mjs", ".cjs")):
                continue
            # Test code reads variables no deploy ever sets.
            if re.search(r"(\.test\.|\.spec\.|_test\.|^test_)", name):
                continue
            if os.path.basename(dirpath) in {"__tests__", "tests", "test", "__mocks__"}:
                continue
            try:
                with open(os.path.join(dirpath, name), errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for m in ENV_USAGE.finditer(text):
                used.add(next(g for g in m.groups() if g))

    return sorted(n for n in used if n not in documented and n not in ENV_IGNORE)


def document_env_vars(example_path: str, names: List[str], apply: bool = False) -> int:
    if not names:
        return 0
    if apply:
        with open(example_path) as fh:
            existing = fh.read()
        with open(example_path, "w") as fh:
            fh.write(existing.rstrip("\n") + "\n" + ENV_HEADER
                     + "".join(f"{n}=\n" for n in names))
    return len(names)


# --- docker-compose ------------------------------------------------------------------


def harden_compose(path: str, apply: bool = False) -> List[str]:
    """Bind database ports to loopback and parameterize stock passwords.

    The current literal becomes the default (`${VAR:-current}`), so anyone
    running this compose file today sees no behaviour change at all — the
    file simply stops being reusable with a real password by accident.
    """
    with open(path) as fh:
        text = fh.read()
    original = text
    notes: List[str] = []

    for port in DB_PORTS:
        if f'- "{port}:{port}"' in text:
            text = text.replace(f'- "{port}:{port}"', f'- "127.0.0.1:{port}:{port}"')
            notes.append(f"port {port} bound to loopback")

    for var in PASSWORD_VARS:
        for m in re.finditer(rf"^(\s*){var}:\s*([A-Za-z0-9_-]+)\s*$", text, re.M):
            literal = m.group(2)
            text = text.replace(m.group(0), f"{m.group(1)}{var}: ${{{var}:-{literal}}}")
            text = text.replace(f":{literal}@", f":${{{var}:-{literal}}}@")
            notes.append(f"{var} parameterized")

    if notes and apply and text != original:
        with open(path, "w") as fh:
            fh.write(text)
    return notes


# --- orchestration ---------------------------------------------------------------------


def plan(root: str, apply: bool = False, kinds: Optional[Set[str]] = None) -> FixPlan:
    """Walk one repository and apply (or merely report) every mechanical fix."""
    result = FixPlan()
    want = kinds or {"pin-actions", "workflow-permissions", "env-example", "compose"}
    root = os.path.abspath(root)

    workflows_dir = os.path.join(root, ".github", "workflows")
    if os.path.isdir(workflows_dir):
        for name in sorted(os.listdir(workflows_dir)):
            if not name.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(workflows_dir, name)
            rel = os.path.relpath(path, root)
            if "workflow-permissions" in want and add_workflow_permissions(path, apply):
                result.changes.append(Change(rel, "workflow-permissions",
                                             "added least-privilege permissions block"))
            if "pin-actions" in want:
                pinned, unresolved = pin_actions(path, apply)
                if pinned:
                    result.changes.append(Change(rel, "pin-actions",
                                                 f"pinned {pinned} action(s) to SHAs", pinned))
                result.unresolved.extend(f"{rel}: {u}" for u in unresolved)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if "env-example" in want and name == ".env.example":
                missing = undocumented_env_vars(path)
                if missing:
                    document_env_vars(path, missing, apply)
                    result.changes.append(Change(
                        rel, "env-example",
                        f"documented {len(missing)} var(s): " + ", ".join(missing[:5])
                        + (f" (+{len(missing) - 5} more)" if len(missing) > 5 else ""),
                        len(missing),
                    ))
            elif "compose" in want and re.fullmatch(r"(docker-)?compose.*\.ya?ml", name):
                notes = harden_compose(path, apply)
                if notes:
                    result.changes.append(Change(rel, "compose", "; ".join(notes), len(notes)))

    return result


def validate_workflows(root: str) -> List[str]:
    """Re-parse every workflow after editing. A fixer that emits invalid YAML
    has broken CI in the name of securing it."""
    problems: List[str] = []
    workflows = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(workflows):
        return problems
    try:
        import yaml
    except ImportError:
        return ["PyYAML unavailable — workflow syntax was NOT verified"]
    for name in sorted(os.listdir(workflows)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(workflows, name)
        try:
            with open(path) as fh:
                yaml.safe_load(fh)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            problems.append(f"{name}: {exc}")
    return problems

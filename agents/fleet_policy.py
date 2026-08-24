"""Fleet policy checks — invariants that should hold in *every* repo.

Motivated by a specific, expensive pattern: the same configuration bug gets
found and fixed in one repo, and the other nineteen keep it. The Trivy
sarif-gate bug was fixed in five separate repos on five separate occasions,
rediscovered from scratch each time. A pin was added without the matching
dependabot ignore, and regressed within a day. Secrets sat in plaintext in a
CI config that nobody had reason to reopen.

Each rule here encodes a lesson that was actually paid for. They are pure
functions over file *content*, not paths, so the caller can source files from
a local checkout or an API without the rules caring — and so every rule is
trivially testable against a real example of the bug it catches.

These describe configuration drift, not source defects; they are deliberately
separate from the scan findings in evolution.py.
"""

from __future__ import annotations

import json
import re

import yaml
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent

SEVERITIES = ("HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class PolicyFinding:
    rule: str
    severity: str
    file: str
    message: str
    fix: str


# --- individual rules ---------------------------------------------------------


def check_trivy_sarif_gate(path: str, content: str) -> List[PolicyFinding]:
    """`format: sarif` + `exit-code: 1` in one trivy-action step.

    trivy-action honours the `severity` input *only* for non-sarif output. In
    sarif mode the filter is ignored entirely, so `exit-code: 1` fails the
    build on every finding at any severity — including LOW and UNKNOWN, and
    including CVEs with no fix available. The symptom is a security gate that
    can never go green, which eventually gets ignored or disabled.
    """
    out: List[PolicyFinding] = []
    for block in re.split(r"\n\s*-\s+(?=name:|uses:)", content):
        if "trivy-action" not in block and "trivy" not in block.lower():
            continue
        has_sarif = re.search(r"format:\s*['\"]?sarif", block, re.I)
        has_exit = re.search(r"exit-code:\s*['\"]?1", block, re.I)
        has_sev = re.search(r"^\s*severity:\s*\S", block, re.I | re.M)
        # trivy-action's documented escape hatch: with this set, the severity
        # filter *is* applied to sarif output, so the gate behaves correctly
        # and there is nothing to report.
        limited = re.search(r"limit-severities-for-sarif:\s*['\"]?true", block, re.I)
        if has_sarif and has_exit and has_sev and not limited:
            out.append(
                PolicyFinding(
                    rule="trivy-sarif-gate",
                    severity="HIGH",
                    file=path,
                    message=(
                        "trivy step combines format: sarif with exit-code: 1 and a severity "
                        "filter — the severity filter is ignored in sarif mode, so this gate "
                        "fails on LOW/UNKNOWN findings and unfixable CVEs"
                    ),
                    fix=(
                        "split into two steps: a blocking `format: table` step that keeps the "
                        "severity filter, plus a separate non-blocking `format: sarif` upload"
                    ),
                )
            )
    return out


def check_workflow_concurrency(path: str, content: str) -> List[PolicyFinding]:
    """A push/PR-triggered workflow with no concurrency group bills every
    superseded run to completion. On private repos that is real money.
    """
    head = content.split("jobs:")[0]
    triggered = re.search(r"^\s*(push|pull_request):", head, re.M)
    if not triggered:
        return []
    if re.search(r"^concurrency:", content, re.M):
        return []
    return [
        PolicyFinding(
            rule="workflow-missing-concurrency",
            severity="MEDIUM",
            file=path,
            message="push/PR-triggered workflow has no concurrency group, so superseded runs bill to completion",
            fix="add a top-level `concurrency:` with group ${{ github.workflow }}-${{ github.ref }} and cancel-in-progress: true",
        )
    ]


def check_dependabot_grouping(path: str, content: str) -> List[PolicyFinding]:
    """An ecosystem with no `groups:` opens one PR per package.

    Each PR runs the full CI suite. One repo generated twenty simultaneous
    PRs this way; grouping minor/patch turns that into roughly four.
    """
    out: List[PolicyFinding] = []
    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        # Malformed config is itself worth reporting. Returning [] here would
        # read as "this repo is fine", which is how a broken parser silently
        # turns a policy checker into a no-op.
        return [
            PolicyFinding(
                rule="dependabot-unparseable",
                severity="LOW",
                file=path,
                message="dependabot config could not be parsed as YAML, so grouping was not checked",
                fix="fix the YAML syntax so dependabot actually reads this file",
            )
        ]
    if not isinstance(data, dict):
        return out
    for entry in data.get("updates", []) or []:
        eco = entry.get("package-ecosystem", "?")
        directory = entry.get("directory", "/")
        # github-actions bumps are few and individually meaningful; the pain
        # is npm/pip, where a weekly run can open dozens.
        if eco in {"github-actions", "docker"}:
            continue
        if not entry.get("groups"):
            out.append(
                PolicyFinding(
                    rule="dependabot-missing-grouping",
                    severity="MEDIUM",
                    file=path,
                    message=f"{eco} updates in {directory} are ungrouped — one PR per package, each running full CI",
                    fix=(
                        f"add a `groups:` block for {eco} covering minor+patch "
                        "(leave majors ungrouped so they stay bisectable)"
                    ),
                )
            )
    return out


# Token shapes that are unambiguous enough to assert on. Deliberately narrow:
# a rule that cries wolf gets muted, and a muted rule catches nothing.
_SECRET_PATTERNS = [
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}"), "GitHub personal access token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"), "GitHub fine-grained PAT"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "OpenAI-style secret key"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{20,}"), "Stripe live secret key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
]

# A quoted, high-entropy value assigned to a secret-ish key.
_INLINE_SECRET = re.compile(
    r"""(?P<key>[A-Z0-9_]*(TOKEN|SECRET|KEY|PASSWORD|PASSWD|APIKEY)[A-Z0-9_]*)\s*:\s*
        ["'](?P<val>[A-Za-z0-9_\-./+=]{20,})["']""",
    re.X,
)

# Values that look like secrets but are references or placeholders.
_NOT_A_SECRET = re.compile(
    r"^\s*(\$\{\{|\$[A-Z_]|<|your[-_]|xxx|placeholder|example|changeme|todo|\.\.\.)",
    re.I,
)


def check_plaintext_secrets(path: str, content: str) -> List[PolicyFinding]:
    """A committed CI config with a real credential inline.

    Found live: a build config with a full-access Expo token and a backend
    API key hardcoded, pushed to a repo's default branch.
    """
    out: List[PolicyFinding] = []
    seen: set[str] = set()

    for pattern, label in _SECRET_PATTERNS:
        if pattern.search(content) and label not in seen:
            seen.add(label)
            out.append(
                PolicyFinding(
                    rule="plaintext-secret",
                    severity="HIGH",
                    file=path,
                    message=f"{label} appears in plaintext in a committed file",
                    fix="rotate the credential, then move it to an encrypted CI variable or secret store",
                )
            )

    for m in _INLINE_SECRET.finditer(content):
        key, val = m.group("key"), m.group("val")
        if _NOT_A_SECRET.match(val) or key in seen:
            continue
        seen.add(key)
        out.append(
            PolicyFinding(
                rule="plaintext-secret",
                severity="HIGH",
                file=path,
                message=f"{key} is assigned a literal value in a committed file",
                fix=f"rotate it, then reference an encrypted variable instead of inlining {key}",
            )
        )
    return out


def _override_target(key: str) -> str:
    """The package an override/resolution key actually forces.

    npm and yarn both allow nesting, so a key can be any of `pkg`,
    `@scope/pkg`, `**/pkg`, `**/@scope/pkg`, or `parent/child` — and in the
    nested forms it is the *last* package that is being pinned. Naive
    rsplit-on-slash silently mangles scoped packages (`@radix-ui/react-slot`
    becomes `react-slot`), which then fails to match a `@radix-ui/*` ignore
    and reports a holdback that is in fact already covered.
    """
    parts = [p for p in key.split("/") if p and p != "**"]
    if not parts:
        return key
    if len(parts) >= 2 and parts[-2].startswith("@"):
        name = f"{parts[-2]}/{parts[-1]}"
    else:
        name = parts[-1]
    # npm override keys may carry a version range: "zod@<4.4.0". Strip it, but
    # not the leading @ of a scope — searching from index 1 does both.
    at = name.find("@", 1)
    if at > 0:
        name = name[:at]
    return name


def check_forced_version_without_dependabot_ignore(
    package_json: str, dependabot_yml: str, path: str = "package.json"
) -> List[PolicyFinding]:
    """A *direct* dependency that is also force-pinned, with no dependabot
    ignore — i.e. a holdback dependabot can actively fight.

    Scope was narrowed twice, both times because the rule was firing on things
    it could not protect:

    1. Only where dependabot version updates are configured at all. With no
       config nothing can bump past a pin, and "fixing" it would mean adding a
       config that generates PRs and CI spend.
    2. Only where the pinned package is a *direct* dependency. Dependabot
       opens version-update PRs for direct dependencies; an override on a
       purely transitive package (the common case — forcing a patched
       `postcss` deep in the tree) is not something dependabot bumps, so a
       `dependency-name` ignore for it would match nothing and protect
       nothing. An earlier version flagged 28 of these across the fleet, all
       of them unactionable.

    Known gap, stated rather than papered over: the case that motivated this
    module — a direct dependency pinned below its own latest major, which
    dependabot then bumps past (eslint ^9 -> ^10) — is *not* detectable from
    package.json alone, because nothing in the file says a newer major exists.
    Catching that needs registry data and is deliberately out of scope here.
    """
    out: List[PolicyFinding] = []
    try:
        pkg = json.loads(package_json)
    except Exception:
        return out

    direct = set(pkg.get("dependencies") or {}) | set(pkg.get("devDependencies") or {})
    if not direct:
        return out

    ignored: set[str] = set()
    for m in re.finditer(r'dependency-name:\s*["\']?([^"\'\n]+)', dependabot_yml or ""):
        ignored.add(m.group(1).strip().rstrip("*").lower())

    def is_ignored(name: str) -> bool:
        low = name.lower()
        return any(low == ig or (ig and low.startswith(ig)) for ig in ignored)

    forced: dict[str, str] = {}
    for section in ("overrides", "resolutions"):
        block = pkg.get(section) or {}
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(spec, str):
                    forced[_override_target(name)] = spec

    for name, spec in sorted(forced.items()):
        if name not in direct or is_ignored(name):
            continue
        out.append(
            PolicyFinding(
                rule="forced-version-without-dependabot-ignore",
                severity="MEDIUM",
                file=path,
                message=(
                    f"{name} is a direct dependency force-pinned to {spec}, but dependabot "
                    "has no ignore for it"
                ),
                fix=(
                    f"add a dependabot ignore for {name} — dependabot can bump the direct "
                    "dependency past the pin and silently undo the holdback"
                ),
            )
        )
    return out


# --- dispatch -----------------------------------------------------------------

_WORKFLOW = re.compile(r"\.github/workflows/.+\.ya?ml$")
_DEPENDABOT = re.compile(r"\.github/dependabot\.ya?ml$")
_CI_CONFIG = re.compile(
    r"(codemagic\.ya?ml|\.github/workflows/.+\.ya?ml|Dockerfile|docker-compose\.ya?ml)$"
)

_RULES: List[tuple[re.Pattern[str], Callable[[str, str], List[PolicyFinding]]]] = [
    (_WORKFLOW, check_trivy_sarif_gate),
    (_WORKFLOW, check_workflow_concurrency),
    (_DEPENDABOT, check_dependabot_grouping),
    (_CI_CONFIG, check_plaintext_secrets),
]


def run_policies(files: Dict[str, str]) -> List[PolicyFinding]:
    """Run every applicable rule over `{relative path: content}`.

    Rules that need to correlate two files (a pin and its ignore) are handled
    explicitly rather than through the per-file dispatch.
    """
    findings: List[PolicyFinding] = []
    for path, content in files.items():
        if content is None:
            continue
        for pattern, rule in _RULES:
            if pattern.search(path):
                findings.extend(rule(path, content))

    pkg = files.get("package.json")
    dependabot = files.get(".github/dependabot.yml") or files.get(
        ".github/dependabot.yaml"
    )
    # Only meaningful where dependabot version updates are actually configured.
    # With no config there is nothing that can bump a dependency past the pin,
    # so reporting it would be noise — and acting on it would mean *adding* a
    # dependabot config, which starts generating PRs and CI spend rather than
    # protecting anything.
    if pkg and dependabot:
        findings.extend(check_forced_version_without_dependabot_ignore(pkg, dependabot))

    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.rule, f.file))
    return findings


class FleetPolicyAgent(BaseAgent):
    """Programmatic wrapper around repository-wide fleet policy checks."""

    name = "fleet_policy"
    description = (
        "Checks repository configuration files for recurring fleet-wide policy drift."
    )
    system_prompt = "You analyze repository policy/configuration drift."

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "run_fleet_policies",
                "description": "Run repository-wide policy checks over a {relative_path: content} map.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "files": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                            "description": "Mapping of relative file paths to file contents.",
                        }
                    },
                    "required": ["files"],
                },
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"run_fleet_policies": self.run_fleet_policies}

    def run_fleet_policies(self, files: Dict[str, str]) -> Dict[str, Any]:
        findings = run_policies(files)
        return {
            "findings": [finding.__dict__ for finding in findings],
            "total_issues": len(findings),
        }

"""Dependency supply-chain risk agent.

Checks manifests and lockfiles for provenance, staleness, typosquatting
candidates, suspicious version jumps, license compliance, and transitive bloat.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent

# Popular packages whose near-neighbours are often typosquatted.
# Only a representative subset; exhaustive lists live in package-registry feeds.
_POPULAR_PACKAGES = {
    # npm
    "react",
    "lodash",
    "express",
    "axios",
    "moment",
    "webpack",
    "babel",
    "eslint",
    "prettier",
    "typescript",
    "next",
    "nuxt",
    "vue",
    "angular",
    "stripe",
    "dotenv",
    "jest",
    "mocha",
    "chai",
    "nodemon",
    "helmet",
    "cors",
    "uuid",
    "dayjs",
    "zod",
    "prisma",
    "drizzle-orm",
    # PyPI
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "sqlalchemy",
    "pydantic",
    "pytest",
    "boto3",
    "pillow",
    "cryptography",
    "bcrypt",
    "celery",
    "redis",
    "psycopg2",
    "aiohttp",
}

# Copyleft licenses that may require open-sourcing the entire application
_COPYLEFT_LICENSES = {"AGPL-3.0", "AGPL", "GPL-3.0", "GPL-2.0", "LGPL-3.0", "LGPL-2.1"}

# Versions known to have carried malicious/sabotage payloads. Package-name
# history alone is not a vulnerability: patched releases must remain clean.
_KNOWN_COMPROMISED_VERSIONS = {
    "event-stream": {"3.3.6"},
    "ua-parser-js": {"0.7.29", "0.8.0", "1.0.0"},
    "coa": {"2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"},
    "rc": {"1.2.9", "1.3.9", "2.3.9"},
    "node-ipc": {"10.1.1", "10.1.2"},
    "colors": {"1.4.1", "1.4.2"},
    "faker": {"6.6.6"},
}


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance between two strings (simple DP)."""
    if a == b:
        return 0
    len_a, len_b = len(a), len(b)
    if len_a == 0:
        return len_b
    if len_b == 0:
        return len_a
    row = list(range(len_b + 1))
    for i, ca in enumerate(a, 1):
        new_row = [i]
        for j, cb in enumerate(b, 1):
            new_row.append(min(row[j] + 1, new_row[-1] + 1, row[j - 1] + (ca != cb)))
        row = new_row
    return row[-1]


def _extract_package_names(content: str, path: str) -> List[str]:
    """Best-effort extraction of package names from various manifest formats."""
    names: List[str] = []
    lower_path = path.lower()

    if lower_path.endswith("package.json"):
        try:
            data = json.loads(content)
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                names.extend(data.get(section, {}).keys())
        except (json.JSONDecodeError, AttributeError):
            pass
    elif lower_path.endswith((".txt",)) or "requirements" in lower_path:
        for line in content.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_\-\.]+)", line)
            if m:
                names.append(m.group(1).lower())
    elif lower_path.endswith("go.mod"):
        for m in re.finditer(r"^\s+([^\s]+)\s+v[\d.]+", content, re.MULTILINE):
            parts = m.group(1).split("/")
            if parts:
                names.append(parts[-1])
    elif lower_path.endswith("cargo.lock"):
        for m in re.finditer(r'name = "([^"]+)"', content):
            names.append(m.group(1))

    return names


class SupplyChainAuditAgent(BaseAgent):
    name = "supply_chain_audit"
    description = "Audits dependency manifests/lockfiles for provenance, staleness, typosquatting, license compliance, and supply-chain risk signals."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "audit_supply_chain",
                "description": "Detect potentially risky dependency sourcing/versioning patterns in manifests and lockfiles.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"},
                        "path": {"type": "string"},
                    },
                    "required": ["content"],
                },
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"audit_supply_chain": self._audit_supply_chain}

    def _audit_supply_chain(self, content: str, path: str = "") -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        # ── 1. Mutable VCS / HTTP origins ────────────────────────────
        if re.search(
            r"(?m)^\s*(?:npm|pip|gem|go)\s+.*(?:git\+|github\.com/|http://)", content
        ):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": "Dependency is sourced from mutable VCS/HTTP origin",
                    "fix": "Prefer registry-published immutable releases over mutable Git refs.",
                }
            )
        # Also catch npm/pip direct Git deps in package.json / requirements.txt
        if re.search(r'"[^"]+"\s*:\s*"(?:git\+|github:|bitbucket:|gitlab:)', content):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": "package.json dependency points to mutable Git source",
                    "fix": "Publish to npm and depend on a registry version instead.",
                }
            )
        if re.search(r"(?m)^\s*[^#\n].*(?:git\+https?://|git\+ssh://|@git\+)", content):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": "Requirement sourced from Git URL (mutable)",
                    "fix": "Use a published PyPI package or pin to a specific commit hash.",
                }
            )

        # Lockfiles record resolved versions; the ranges and wildcards inside
        # them are other packages' peer/optional specs, not this project's
        # choices, so the manifest-only checks below skip them.
        is_lockfile = path.lower().endswith(
            (
                "pnpm-lock.yaml",
                "package-lock.json",
                "yarn.lock",
                "cargo.lock",
                "poetry.lock",
                "pipfile.lock",
                "mix.lock",
                "package.resolved",
            )
        )

        # ── 2. Broad version ranges ───────────────────────────────────
        # Caret/tilde ranges are the ecosystem default and are exactly what
        # a lockfile pins; only open-ended ranges (>=, >, x) are worth a note.
        # A library's peerDependencies are *meant* to be wide (react >=18).
        without_peers = re.sub(
            r'"peerDependencies"\s*:\s*\{[^{}]*\}', "", content, flags=re.S
        )
        if not is_lockfile and re.search(
            r"(?m)^\s*[^#\n]+[\"']\s*(?:>=?\s*\d|\d+\.x\b|x\b|latest\b)",
            without_peers,
        ):
            findings.append(
                {
                    "severity": "LOW",
                    "issue": "Manifest uses open-ended version ranges (>=, x, latest)",
                    "fix": "Use lockfiles and tighter pinning for production services.",
                }
            )

        # ── 3. Suspicious large version jump ─────────────────────────
        if re.search(
            r"\b0\.[0-9]+\.[0-9]+\b[\s\S]{0,200}\b9[0-9]\.[0-9]+\.[0-9]+\b", content
        ):
            findings.append(
                {
                    "severity": "HIGH",
                    "issue": "Dependency history shows suspicious large version jump (0.x → 99.x pattern)",
                    "fix": "Investigate package provenance and maintainer history before adoption.",
                }
            )

        # ── 4. Copyleft license compliance ───────────────────────────
        for lic in _COPYLEFT_LICENSES:
            if re.search(re.escape(lic), content, re.IGNORECASE):
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "issue": f"Copyleft license detected ({lic}) — may require open-sourcing your application",
                        "fix": "Confirm license compatibility with your distribution model; consider alternatives.",
                    }
                )
                break

        # ── 5. Known-suspicious / historically hijacked packages ─────
        pkg_names = _extract_package_names(content, path)
        for name in pkg_names:
            compromised = _KNOWN_COMPROMISED_VERSIONS.get(name.lower(), set())
            matched_version = next(
                (
                    version
                    for version in compromised
                    if re.search(
                        rf"(?i){re.escape(name)}[^\n]{{0,80}}[\"'@~^=:\s]v?{re.escape(version)}\b",
                        content,
                    )
                ),
                None,
            )
            if matched_version:
                findings.append(
                    {
                        "severity": "HIGH",
                        "issue": f"Package '{name}' is pinned to compromised version {matched_version}",
                        "fix": "Upgrade to a verified clean release and rotate credentials used during the affected install window.",
                    }
                )

        # ── 6. Typosquatting candidates ───────────────────────────────
        for name in pkg_names:
            if len(name) < 4:
                continue
            name_lower = name.lower()
            for popular in _POPULAR_PACKAGES:
                if name_lower == popular:
                    break
                dist = _edit_distance(name_lower, popular)
                if dist == 1:
                    findings.append(
                        {
                            "severity": "HIGH",
                            "issue": f"Package '{name}' is 1 character away from popular '{popular}' — possible typosquatting",
                            "fix": f"Verify '{name}' is intentional and not a typo of '{popular}'.",
                        }
                    )
                    break

        # ── 7. Transitive bloat (pnpm) ────────────────────────────────
        if path.lower().endswith("pnpm-lock.yaml") and re.search(
            r"(?m)^\s{2,}dependencies:\s*$", content
        ):
            dep_edges = len(re.findall(r"(?m)^\s{4,}[^\s].*:\s", content))
            if dep_edges > 500:
                findings.append(
                    {
                        "severity": "INFO",
                        "issue": f"Large transitive dependency graph detected ({dep_edges} edges in pnpm-lock.yaml)",
                        "fix": "Review heavy dependencies and prune unused packages.",
                    }
                )

        # ── 8. Unpinned * wildcard ────────────────────────────────────
        if not is_lockfile and re.search(r'["\']\s*\*\s*["\']', content):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": "Wildcard (*) version specifier detected — any version will be installed",
                    "fix": "Pin to a specific version or tight range for reproducible builds.",
                }
            )

        # ── 9. HTTP (non-HTTPS) registry sources ─────────────────────
        if re.search(r"(?i)registry\s*=\s*http://", content):
            findings.append(
                {
                    "severity": "HIGH",
                    "issue": "Dependency registry URL uses HTTP instead of HTTPS",
                    "fix": "Change all registry URLs to HTTPS to prevent MITM attacks.",
                }
            )

        return {"findings": findings, "total_issues": len(findings)}

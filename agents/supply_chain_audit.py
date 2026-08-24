"""Dependency supply-chain risk agent."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent


class SupplyChainAuditAgent(BaseAgent):
    name = "supply_chain_audit"
    description = "Audits dependency manifests/lockfiles for provenance, staleness, and supply-chain risk signals."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [{
            "name": "audit_supply_chain",
            "description": "Detect potentially risky dependency sourcing/versioning patterns in manifests and lockfiles.",
            "parameters": {
                "type": "object",
                "properties": {"content": {"type": "string"}, "path": {"type": "string"}},
                "required": ["content"],
            },
        }]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"audit_supply_chain": self._audit_supply_chain}

    def _audit_supply_chain(self, content: str, path: str = "") -> Dict[str, Any]:
        findings = []
        if re.search(r"(?m)^\s*(?:npm|pip|gem|go)\s+.*(?:git\+|github\.com/|http://)", content):
            findings.append({"severity": "MEDIUM", "issue": "Dependency is sourced from mutable VCS/HTTP origin", "fix": "Prefer registry-published immutable releases over mutable Git refs."})
        if re.search(r"(?m)^\s*[^#\n]+(?:\^|~|>=)\d", content):
            findings.append({"severity": "LOW", "issue": "Manifest uses broad version ranges", "fix": "Use lockfiles and tighter pinning for production services."})
        if re.search(r"\b0\.0\.1\b[\s\S]{0,120}\b99\.0\.0\b", content):
            findings.append({"severity": "HIGH", "issue": "Dependency history hints at suspicious large version jump", "fix": "Investigate package provenance and maintainer history before adoption."})
        if re.search(r"license\s*[:=]\s*[\"']?(?:AGPL|GPL-3\.0)", content, re.IGNORECASE):
            findings.append({"severity": "MEDIUM", "issue": "Copyleft license detected (AGPL/GPL-3.0)", "fix": "Confirm license compatibility with your distribution model."})
        if path.lower().endswith("pnpm-lock.yaml") and re.search(r"(?m)^\s{2,}dependencies:\s*$", content):
            dep_edges = len(re.findall(r"(?m)^\s{4,}[^\s].*:\s", content))
            if dep_edges > 500:
                findings.append({"severity": "LOW", "issue": "Large transitive dependency graph detected", "fix": "Review heavy dependencies and prune unused packages."})
        return {"findings": findings, "total_issues": len(findings)}


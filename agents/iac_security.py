"""Infrastructure-as-code security agent."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List

from agents.base import BaseAgent


class IACSecurityAgent(BaseAgent):
    name = "iac_security"
    description = "Audits Terraform/Kubernetes/Docker IaC for common high-impact security misconfigurations."
    model = "gpt-5"

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [{
            "name": "audit_iac_security",
            "description": "Detect insecure cloud/container IaC patterns across Terraform, K8s, and Docker configs.",
            "parameters": {
                "type": "object",
                "properties": {"content": {"type": "string"}, "path": {"type": "string"}},
                "required": ["content"],
            },
        }]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {"audit_iac_security": self._audit_iac_security}

    def _audit_iac_security(self, content: str, path: str = "") -> Dict[str, Any]:
        findings = []
        lower_path = path.lower()
        if lower_path.endswith(".tf"):
            if re.search(r"access_key\s*=\s*\"[^\"]+\"|secret_key\s*=\s*\"[^\"]+\"", content):
                findings.append({"severity": "CRITICAL", "issue": "Terraform file contains hardcoded cloud credentials", "fix": "Load credentials from secret stores/environment, never inline."})
            if re.search(r"0\.0\.0\.0/0", content) and re.search(r"(ingress|cidr_blocks)", content):
                findings.append({"severity": "HIGH", "issue": "Terraform security group appears open to 0.0.0.0/0", "fix": "Restrict inbound CIDRs to trusted ranges."})
            if re.search(r"aws_s3_bucket", content) and re.search(r"acl\s*=\s*\"public-read\"", content):
                findings.append({"severity": "HIGH", "issue": "S3 bucket configured as public-read", "fix": "Disable public ACLs and enforce bucket policies with explicit principals."})
        if lower_path.endswith((".yml", ".yaml")) and re.search(r"\b(apiVersion|kind)\b", content):
            if re.search(r"kind:\s*Deployment", content) and not re.search(r"securityContext:", content):
                findings.append({"severity": "HIGH", "issue": "Kubernetes workload missing securityContext", "fix": "Set runAsNonRoot, readOnlyRootFilesystem, and drop capabilities."})
            if re.search(r"kind:\s*RoleBinding|kind:\s*ClusterRoleBinding", content) and re.search(r"cluster-admin|\*\"", content):
                findings.append({"severity": "HIGH", "issue": "Kubernetes RBAC appears overly permissive", "fix": "Use least-privilege roles and avoid wildcard verbs/resources."})
            if re.search(r"kind:\s*Deployment", content) and not re.search(r"resources:\s*\n", content):
                findings.append({"severity": "MEDIUM", "issue": "Kubernetes deployment has no resource limits/requests", "fix": "Declare cpu/memory requests and limits for each container."})
        if "dockerfile" in lower_path or lower_path.endswith("docker-compose.yml") or lower_path.endswith("docker-compose.yaml"):
            if re.search(r"(?im)^\s*from\s+[^\s:]+(?::latest)?\s*$", content):
                findings.append({"severity": "LOW", "issue": "Container base image is unpinned/latest", "fix": "Pin image tags/digests to trusted immutable versions."})
            if re.search(r"(?i)(secret|token|password)\s*=", content):
                findings.append({"severity": "MEDIUM", "issue": "Potential secret baked into container config", "fix": "Inject secrets at runtime via env/secret manager."})
        return {"findings": findings, "total_issues": len(findings)}


"""
Agentic Workflows & Multi-Agent Orchestration.

WorkflowOrchestrator chains agents with shared context so a finding in one
domain can automatically trigger deeper investigation by a specialist.

Example flow:
    SecurityAuditAgent finds JWT vulnerability
    → auto-routes to AuthSecurityAgent for deeper auth-flow review
    → AuthSecurityAgent finds refresh token issue
    → auto-routes to StripeBillingAgent if auth gates billing

Usage:
    from agents.workflow import WorkflowOrchestrator
    orch = WorkflowOrchestrator()
    report = orch.run_chain(["security_audit", "auth_security"], code="...")
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Maps finding keywords to follow-up agent names.
# When a finding's issue text contains the key, the mapped agent is queued.
_DEFAULT_TRIGGERS: Dict[str, str] = {
    "jwt": "auth_security",
    "token": "auth_security",
    "refresh": "auth_security",
    "oauth": "auth_security",
    "apple sign-in": "auth_security",
    "billing": "stripe_billing",
    "stripe": "stripe_billing",
    "payment": "stripe_billing",
    "subscription": "stripe_billing",
    "webhook": "stripe_billing",
    "sql": "database_architect",
    "injection": "database_architect",
    "n+1": "database_architect",
    "migration": "database_architect",
    "cors": "security_audit",
    "helmet": "security_audit",
    "dependency": "supply_chain_audit",
    "package": "supply_chain_audit",
    "docker": "iac_security",
    "terraform": "iac_security",
    "kubernetes": "iac_security",
    "health": "infra_monitor",
    "sentry": "infra_monitor",
    "error boundary": "infra_monitor",
}


class WorkflowOrchestrator:
    """
    Chains deterministic tool-handler calls across agents, passing shared
    context and auto-routing based on the findings each step produces.

    No LLM is required — this operates on the same static tool handlers
    that `cli.py scan` uses, so it costs nothing to run in CI.
    """

    def __init__(
        self,
        agent_triggers: Optional[Dict[str, str]] = None,
        max_chain_depth: int = 4,
    ) -> None:
        self.agent_triggers = agent_triggers if agent_triggers is not None else dict(_DEFAULT_TRIGGERS)
        self.max_chain_depth = max_chain_depth
        self._shared_context: Dict[str, Any] = {}
        self._chain_log: List[Dict[str, Any]] = []

    # ── Context management ────────────────────────────────────────────

    def set_context(self, key: str, value: Any) -> None:
        self._shared_context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        return self._shared_context.get(key, default)

    def clear_context(self) -> None:
        self._shared_context.clear()
        self._chain_log.clear()

    # ── Routing helpers ───────────────────────────────────────────────

    def _agents_for_findings(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Return follow-up agent names triggered by a set of findings."""
        triggered: List[str] = []
        seen: set = set()
        for f in findings:
            issue = str(f.get("issue", "")).lower()
            for keyword, agent_name in self.agent_triggers.items():
                if keyword in issue and agent_name not in seen:
                    triggered.append(agent_name)
                    seen.add(agent_name)
        return triggered

    # ── Execution ─────────────────────────────────────────────────────

    def run_step(
        self,
        agent_name: str,
        tool_name: str,
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run a single agent tool handler and record the result."""
        from agents.cli import AGENTS

        cls = AGENTS.get(agent_name)
        if cls is None:
            return {"findings": [], "error": f"Unknown agent '{agent_name}'"}
        instance = cls()
        handler: Optional[Callable] = instance._tool_handlers.get(tool_name)
        if handler is None:
            return {"findings": [], "error": f"Unknown tool '{tool_name}' on '{agent_name}'"}

        merged_kwargs = dict(self._shared_context)
        merged_kwargs.update(kwargs)
        result = handler(**{k: v for k, v in merged_kwargs.items() if k in _inspect_params(handler)})

        log_entry = {
            "agent": agent_name,
            "tool": tool_name,
            "findings_count": len(result.get("findings", [])),
        }
        self._chain_log.append(log_entry)
        logger.debug("WorkflowOrchestrator step: %s", log_entry)
        return result

    def run_chain(
        self,
        steps: List[Tuple[str, str, Dict[str, Any]]],
        auto_route: bool = False,
        code: str = "",
    ) -> Dict[str, Any]:
        """
        Run an explicit chain of (agent, tool, kwargs) steps.

        Parameters
        ----------
        steps:
            List of (agent_name, tool_name, kwargs) tuples to execute in order.
        auto_route:
            If True, inspect each step's findings and append follow-up agents
            from ``self.agent_triggers`` (up to ``max_chain_depth`` deep).
        code:
            Optional shared source code payload injected as context for
            auto-routed follow-up steps.
        """
        all_findings: List[Dict[str, Any]] = []
        queued = list(steps)
        depth = 0

        while queued and depth < self.max_chain_depth:
            agent_name, tool_name, kwargs = queued.pop(0)
            result = self.run_step(agent_name, tool_name, kwargs)
            findings = result.get("findings", [])
            all_findings.extend(findings)
            depth += 1

            if auto_route and findings:
                follow_ups = self._agents_for_findings(findings)
                for follow_agent in follow_ups:
                    follow_tool = _default_tool(follow_agent)
                    if follow_tool and depth < self.max_chain_depth:
                        queued.append((follow_agent, follow_tool, {"code": code}))

        return {
            "findings": all_findings,
            "total_issues": len(all_findings),
            "chain_log": list(self._chain_log),
        }


# ── Helpers ───────────────────────────────────────────────────────────

def _inspect_params(fn: Callable) -> set:
    import inspect
    try:
        return set(inspect.signature(fn).parameters.keys())
    except (TypeError, ValueError):
        return set()


def _default_tool(agent_name: str) -> Optional[str]:
    """Return the first available tool name for an agent, or None."""
    from agents.cli import AGENTS
    cls = AGENTS.get(agent_name)
    if cls is None:
        return None
    instance = cls()
    handlers = list(instance._tool_handlers.keys())
    return handlers[0] if handlers else None

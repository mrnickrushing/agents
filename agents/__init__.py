"""
RushingTech Agents — OpenAI-compatible AI agents for solo full-stack operators.

Import and use anywhere:
    from agents import (
        SecurityAuditAgent, StripeBillingAgent, RailwayDeployAgent, CodeReviewAgent,
        ScaffolderAgent, AuthSecurityAgent, MobileDeployAgent, APIArchitectAgent,
        DatabaseArchitectAgent, InfraMonitorAgent,
    )

Tool handlers can also be invoked directly with no API key via the CLI:
    python -m agents.cli list
    python -m agents.cli scan --path ~/your-project
"""

from agents.security_audit import SecurityAuditAgent
from agents.stripe_billing import StripeBillingAgent
from agents.railway_deploy import RailwayDeployAgent
from agents.code_review import CodeReviewAgent
from agents.ui_generation import UIGenerationAgent
from agents.scaffolder import ScaffolderAgent
from agents.auth_security import AuthSecurityAgent
from agents.mobile_deploy import MobileDeployAgent
from agents.api_architect import APIArchitectAgent
from agents.database_architect import DatabaseArchitectAgent
from agents.infra_monitor import InfraMonitorAgent
from agents.roblox_audit import RobloxAuditAgent
from agents.config_audit import ConfigAuditAgent
from agents.fleet_policy import FleetPolicyAgent
from agents.flow_audit import FlowAuditAgent
from agents.frontend_performance import FrontendPerformanceAgent
from agents.iac_security import IACSecurityAgent
from agents.supply_chain_audit import SupplyChainAuditAgent
from agents.compliance import ComplianceAuditAgent
from agents.postmortem import PostmortemAgent
from agents.healing import HealingAgent
from agents.training import DetectorTrainer
from agents.figma_scaffold import FigmaScaffoldAgent
from agents.workflow import WorkflowOrchestrator
from agents.durability import DurableStep, DurabilityDB, durable_step, durable_workflow
from agents.knowledge_graph import CodebaseGraph
from agents.streaming import StreamingEventBus, get_default_bus, emit
from agents.triage import TriageAgent, TriageRAG

__all__ = [
    "SecurityAuditAgent",
    "StripeBillingAgent",
    "RailwayDeployAgent",
    "CodeReviewAgent",
    "UIGenerationAgent",
    "ScaffolderAgent",
    "AuthSecurityAgent",
    "MobileDeployAgent",
    "APIArchitectAgent",
    "DatabaseArchitectAgent",
    "InfraMonitorAgent",
    "RobloxAuditAgent",
    "ConfigAuditAgent",
    "FleetPolicyAgent",
    "FlowAuditAgent",
    "FrontendPerformanceAgent",
    "IACSecurityAgent",
    "SupplyChainAuditAgent",
    "ComplianceAuditAgent",
    "PostmortemAgent",
    "HealingAgent",
    "DetectorTrainer",
    "FigmaScaffoldAgent",
    "WorkflowOrchestrator",
    # New v2.14 capabilities
    "DurableStep",
    "DurabilityDB",
    "durable_step",
    "durable_workflow",
    "CodebaseGraph",
    "StreamingEventBus",
    "get_default_bus",
    "emit",
    "TriageAgent",
    "TriageRAG",
]

__version__ = "2.15.0"

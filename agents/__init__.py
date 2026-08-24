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
from agents.fleet_policy import FleetPolicyAgent
from agents.flow_audit import FlowAuditAgent
from agents.frontend_performance import FrontendPerformanceAgent
from agents.iac_security import IACSecurityAgent
from agents.supply_chain_audit import SupplyChainAuditAgent

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
    "FleetPolicyAgent",
    "FlowAuditAgent",
    "FrontendPerformanceAgent",
    "IACSecurityAgent",
    "SupplyChainAuditAgent",
]

__version__ = "2.12.0"

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
]

__version__ = "2.5.0"

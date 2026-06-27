"""
RushingTech Agents — OpenAI-compatible AI agents for solo full-stack operators.

Import and use anywhere:
    from agents import SecurityAuditAgent, StripeBillingAgent, RailwayDeployAgent, CodeReviewAgent, ScaffolderAgent
"""

from agents.security_audit import SecurityAuditAgent
from agents.stripe_billing import StripeBillingAgent
from agents.railway_deploy import RailwayDeployAgent
from agents.code_review import CodeReviewAgent
from agents.ui_generation import UIGenerationAgent
from agents.scaffolder import ScaffolderAgent

__all__ = [
    "SecurityAuditAgent",
    "StripeBillingAgent",
    "RailwayDeployAgent",
    "CodeReviewAgent",
    "UIGenerationAgent",
    "ScaffolderAgent",
]

__version__ = "2.0.1"

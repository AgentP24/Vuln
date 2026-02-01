"""
VulnGuard AI - Multi-Agent System
Five specialized AI agents for vulnerability management
"""
from .base import BaseAgent
from .discovery import DiscoveryAgent
from .assessment import AssessmentAgent
from .approval import ApprovalAgent
from .remediation import RemediationAgent
from .validation import ValidationAgent
from .prompts import (
    DISCOVERY_AGENT_PROMPT,
    ASSESSMENT_AGENT_PROMPT,
    APPROVAL_AGENT_PROMPT,
    REMEDIATION_AGENT_PROMPT,
    VALIDATION_AGENT_PROMPT,
    ORCHESTRATOR_PROMPT
)

__all__ = [
    # Agents
    "BaseAgent",
    "DiscoveryAgent",
    "AssessmentAgent",
    "ApprovalAgent",
    "RemediationAgent",
    "ValidationAgent",
    # Prompts
    "DISCOVERY_AGENT_PROMPT",
    "ASSESSMENT_AGENT_PROMPT",
    "APPROVAL_AGENT_PROMPT",
    "REMEDIATION_AGENT_PROMPT",
    "VALIDATION_AGENT_PROMPT",
    "ORCHESTRATOR_PROMPT"
]

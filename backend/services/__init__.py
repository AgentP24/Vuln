"""
VulnGuard AI - Services
Business logic and orchestration services
"""
from .orchestrator import Orchestrator, OrchestratorFactory, PipelineStage
from .knowledge_base import KnowledgeBase, MockKnowledgeBase
from .notifications import (
    NotificationService,
    Notification,
    NotificationChannel,
    NotificationPriority,
    NotificationType,
    EmailChannel,
    SlackChannel,
    ServiceNowChannel
)

__all__ = [
    # Orchestrator
    "Orchestrator",
    "OrchestratorFactory",
    "PipelineStage",
    # Knowledge Base
    "KnowledgeBase",
    "MockKnowledgeBase",
    # Notifications
    "NotificationService",
    "Notification",
    "NotificationChannel",
    "NotificationPriority",
    "NotificationType",
    "EmailChannel",
    "SlackChannel",
    "ServiceNowChannel"
]

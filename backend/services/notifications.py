"""
VulnGuard AI - Notification Service
Multi-channel notifications for approvals, alerts, and escalations
"""
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
import structlog

logger = structlog.get_logger()


class NotificationChannel(str, Enum):
    """Available notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    SERVICENOW = "servicenow"
    PAGERDUTY = "pagerduty"
    SMS = "sms"


class NotificationPriority(str, Enum):
    """Notification priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationType(str, Enum):
    """Types of notifications"""
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_REMINDER = "approval_reminder"
    APPROVAL_ESCALATION = "approval_escalation"
    REMEDIATION_STARTED = "remediation_started"
    REMEDIATION_COMPLETE = "remediation_complete"
    REMEDIATION_FAILED = "remediation_failed"
    VALIDATION_COMPLETE = "validation_complete"
    VALIDATION_FAILED = "validation_failed"
    CRITICAL_VULNERABILITY = "critical_vulnerability"
    SLA_BREACH = "sla_breach"


class BaseNotificationChannel(ABC):
    """Base class for notification channels"""

    @abstractmethod
    async def send(self, notification: "Notification") -> bool:
        """Send notification through this channel"""
        pass


class Notification:
    """Notification data model"""

    def __init__(
        self,
        notification_type: NotificationType,
        title: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        recipients: Optional[List[str]] = None,
        channels: Optional[List[NotificationChannel]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.id = f"NOTIF-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        self.notification_type = notification_type
        self.title = title
        self.message = message
        self.priority = priority
        self.recipients = recipients or []
        self.channels = channels or [NotificationChannel.EMAIL]
        self.metadata = metadata or {}
        self.created_at = datetime.utcnow()
        self.sent_at: Optional[datetime] = None
        self.status = "pending"


class EmailChannel(BaseNotificationChannel):
    """Email notification channel"""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_address: str,
        use_tls: bool = True
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_address = from_address
        self.use_tls = use_tls

    async def send(self, notification: Notification) -> bool:
        """Send email notification"""
        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            for recipient in notification.recipients:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = f"[VulnGuard] {notification.title}"
                msg["From"] = self.from_address
                msg["To"] = recipient

                # Create HTML body
                html_body = self._create_email_body(notification)
                msg.attach(MIMEText(html_body, "html"))

                # Send
                await aiosmtplib.send(
                    msg,
                    hostname=self.smtp_host,
                    port=self.smtp_port,
                    username=self.username,
                    password=self.password,
                    use_tls=self.use_tls
                )

            logger.info(f"Email sent to {len(notification.recipients)} recipients")
            return True

        except Exception as e:
            logger.error("Failed to send email", error=str(e))
            return False

    def _create_email_body(self, notification: Notification) -> str:
        """Create HTML email body"""
        priority_colors = {
            NotificationPriority.LOW: "#28a745",
            NotificationPriority.MEDIUM: "#ffc107",
            NotificationPriority.HIGH: "#fd7e14",
            NotificationPriority.CRITICAL: "#dc3545"
        }

        color = priority_colors.get(notification.priority, "#6c757d")

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .header {{ background: {color}; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .metadata {{ background: #f8f9fa; padding: 15px; margin-top: 20px; }}
                .button {{ background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>{notification.title}</h2>
                <span>Priority: {notification.priority.value.upper()}</span>
            </div>
            <div class="content">
                <p>{notification.message}</p>

                {self._format_metadata(notification.metadata)}

                <p style="margin-top: 30px;">
                    <a href="#" class="button">View in VulnGuard</a>
                </p>
            </div>
            <div style="color: #6c757d; font-size: 12px; padding: 20px;">
                This is an automated message from VulnGuard AI.
                Do not reply to this email.
            </div>
        </body>
        </html>
        """

    def _format_metadata(self, metadata: Dict[str, Any]) -> str:
        """Format metadata as HTML table"""
        if not metadata:
            return ""

        rows = "".join(
            f"<tr><td><strong>{k}:</strong></td><td>{v}</td></tr>"
            for k, v in metadata.items()
        )

        return f"""
        <div class="metadata">
            <h4>Details</h4>
            <table>{rows}</table>
        </div>
        """


class SlackChannel(BaseNotificationChannel):
    """Slack notification channel"""

    def __init__(self, webhook_url: str, default_channel: str = "#security-alerts"):
        self.webhook_url = webhook_url
        self.default_channel = default_channel

    async def send(self, notification: Notification) -> bool:
        """Send Slack notification"""
        try:
            import httpx

            # Build Slack message
            payload = self._build_slack_message(notification)

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()

            logger.info("Slack notification sent")
            return True

        except Exception as e:
            logger.error("Failed to send Slack notification", error=str(e))
            return False

    def _build_slack_message(self, notification: Notification) -> Dict[str, Any]:
        """Build Slack Block Kit message"""
        priority_emoji = {
            NotificationPriority.LOW: ":white_circle:",
            NotificationPriority.MEDIUM: ":large_yellow_circle:",
            NotificationPriority.HIGH: ":large_orange_circle:",
            NotificationPriority.CRITICAL: ":red_circle:"
        }

        emoji = priority_emoji.get(notification.priority, ":white_circle:")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {notification.title}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": notification.message
                }
            }
        ]

        # Add metadata fields
        if notification.metadata:
            fields = [
                {
                    "type": "mrkdwn",
                    "text": f"*{k}:*\n{v}"
                }
                for k, v in list(notification.metadata.items())[:10]
            ]

            blocks.append({
                "type": "section",
                "fields": fields
            })

        # Add action buttons for approval requests
        if notification.notification_type == NotificationType.APPROVAL_REQUEST:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": f"approve_{notification.metadata.get('approval_id', '')}"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "action_id": f"deny_{notification.metadata.get('approval_id', '')}"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Details"},
                        "action_id": f"view_{notification.metadata.get('approval_id', '')}"
                    }
                ]
            })

        return {
            "channel": self.default_channel,
            "blocks": blocks
        }


class ServiceNowChannel(BaseNotificationChannel):
    """ServiceNow ITSM integration channel"""

    def __init__(
        self,
        instance_url: str,
        username: str,
        password: str,
        assignment_group: str
    ):
        self.instance_url = instance_url.rstrip('/')
        self.username = username
        self.password = password
        self.assignment_group = assignment_group

    async def send(self, notification: Notification) -> bool:
        """Create ServiceNow incident/change request"""
        try:
            import httpx
            import base64

            # Determine record type based on notification
            if notification.notification_type in [
                NotificationType.APPROVAL_REQUEST,
                NotificationType.REMEDIATION_STARTED
            ]:
                # Create change request
                return await self._create_change_request(notification)
            else:
                # Create incident
                return await self._create_incident(notification)

        except Exception as e:
            logger.error("Failed to create ServiceNow record", error=str(e))
            return False

    async def _create_change_request(self, notification: Notification) -> bool:
        """Create a ServiceNow change request"""
        import httpx

        auth = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()

        payload = {
            "short_description": notification.title,
            "description": notification.message,
            "assignment_group": self.assignment_group,
            "type": "Standard",
            "risk": self._map_priority_to_risk(notification.priority),
            "u_vulnerability_id": notification.metadata.get("vulnerability_id", ""),
            "u_approval_id": notification.metadata.get("approval_id", "")
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.instance_url}/api/now/table/change_request",
                json=payload,
                headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json"
                }
            )
            response.raise_for_status()

        logger.info("ServiceNow change request created")
        return True

    async def _create_incident(self, notification: Notification) -> bool:
        """Create a ServiceNow incident"""
        import httpx

        auth = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()

        payload = {
            "short_description": notification.title,
            "description": notification.message,
            "assignment_group": self.assignment_group,
            "urgency": self._map_priority_to_urgency(notification.priority),
            "impact": self._map_priority_to_impact(notification.priority)
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.instance_url}/api/now/table/incident",
                json=payload,
                headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json"
                }
            )
            response.raise_for_status()

        logger.info("ServiceNow incident created")
        return True

    def _map_priority_to_risk(self, priority: NotificationPriority) -> str:
        mapping = {
            NotificationPriority.LOW: "Low",
            NotificationPriority.MEDIUM: "Moderate",
            NotificationPriority.HIGH: "High",
            NotificationPriority.CRITICAL: "High"
        }
        return mapping.get(priority, "Moderate")

    def _map_priority_to_urgency(self, priority: NotificationPriority) -> str:
        mapping = {
            NotificationPriority.LOW: "3",
            NotificationPriority.MEDIUM: "2",
            NotificationPriority.HIGH: "2",
            NotificationPriority.CRITICAL: "1"
        }
        return mapping.get(priority, "2")

    def _map_priority_to_impact(self, priority: NotificationPriority) -> str:
        return self._map_priority_to_urgency(priority)


class NotificationService:
    """
    Central notification service that routes notifications
    to appropriate channels based on type and priority.
    """

    def __init__(self):
        self._channels: Dict[NotificationChannel, BaseNotificationChannel] = {}
        self._routing_rules: Dict[NotificationType, List[NotificationChannel]] = {}
        self._history: List[Notification] = []

    def register_channel(
        self,
        channel_type: NotificationChannel,
        channel_instance: BaseNotificationChannel
    ):
        """Register a notification channel"""
        self._channels[channel_type] = channel_instance
        logger.info(f"Registered notification channel: {channel_type.value}")

    def set_routing_rule(
        self,
        notification_type: NotificationType,
        channels: List[NotificationChannel]
    ):
        """Set routing rules for notification types"""
        self._routing_rules[notification_type] = channels

    async def send(self, notification: Notification) -> Dict[str, Any]:
        """
        Send notification through appropriate channels.

        Returns status for each channel.
        """
        results = {}

        # Determine channels to use
        channels = notification.channels
        if notification.notification_type in self._routing_rules:
            channels = self._routing_rules[notification.notification_type]

        # Override for critical priority
        if notification.priority == NotificationPriority.CRITICAL:
            channels = list(self._channels.keys())  # All channels

        # Send through each channel
        for channel_type in channels:
            if channel_type in self._channels:
                try:
                    success = await self._channels[channel_type].send(notification)
                    results[channel_type.value] = "sent" if success else "failed"
                except Exception as e:
                    logger.error(f"Channel {channel_type.value} failed", error=str(e))
                    results[channel_type.value] = "error"
            else:
                results[channel_type.value] = "not_configured"

        # Update notification status
        notification.sent_at = datetime.utcnow()
        notification.status = "sent" if any(r == "sent" for r in results.values()) else "failed"

        # Store in history
        self._history.append(notification)

        return {
            "notification_id": notification.id,
            "channels": results,
            "status": notification.status
        }

    async def send_approval_request(
        self,
        approval_id: str,
        vulnerability_id: str,
        risk_score: float,
        asset_tier: str,
        requires_restart: bool,
        estimated_downtime: int,
        recipients: List[str]
    ) -> Dict[str, Any]:
        """Convenience method for approval request notifications"""
        notification = Notification(
            notification_type=NotificationType.APPROVAL_REQUEST,
            title=f"Approval Required: Vulnerability Remediation",
            message=f"""
            A vulnerability remediation requires your approval.

            - Vulnerability ID: {vulnerability_id}
            - Risk Score: {risk_score}/100
            - Asset Tier: {asset_tier.upper()}
            - Requires Restart: {'Yes' if requires_restart else 'No'}
            - Estimated Downtime: {estimated_downtime} minutes

            Please review and approve or deny this request.
            """,
            priority=NotificationPriority.HIGH if risk_score >= 70 else NotificationPriority.MEDIUM,
            recipients=recipients,
            metadata={
                "approval_id": approval_id,
                "vulnerability_id": vulnerability_id,
                "risk_score": risk_score,
                "asset_tier": asset_tier,
                "requires_restart": requires_restart,
                "estimated_downtime": estimated_downtime
            }
        )

        return await self.send(notification)

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get notification history"""
        return [
            {
                "id": n.id,
                "type": n.notification_type.value,
                "title": n.title,
                "priority": n.priority.value,
                "status": n.status,
                "created_at": n.created_at.isoformat(),
                "sent_at": n.sent_at.isoformat() if n.sent_at else None
            }
            for n in self._history[-limit:]
        ]

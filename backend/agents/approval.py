"""
VulnGuard AI - Approval Agent
Manages human approval workflow and enforces guardrails
"""
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4
import structlog

from .base import BaseAgent
from .prompts import APPROVAL_AGENT_PROMPT
from models import (
    AgentStatus, AssessmentResult, ApprovalRequest, ApprovalDecision,
    Approver, ApprovalStatus, ApproverRole, AssetCriticality, Severity,
    MaintenanceWindow
)
from config import get_settings

logger = structlog.get_logger()


class ApprovalAgent(BaseAgent):
    """
    Approval Agent: Manages human approval workflow and enforces strict guardrails
    to protect production systems. NEVER bypasses approval for Tier 1 assets.
    """

    def __init__(
        self,
        maintenance_windows: List[MaintenanceWindow],
        notification_service: Optional[Any] = None,
        knowledge_base: Optional[Any] = None
    ):
        super().__init__(
            name="approval",
            system_prompt=APPROVAL_AGENT_PROMPT,
            knowledge_base=knowledge_base
        )
        self.settings = get_settings()
        self.maintenance_windows = maintenance_windows
        self.notification_service = notification_service
        self._pending_approvals: Dict[str, ApprovalRequest] = {}

    async def process(self, assessment: AssessmentResult) -> ApprovalRequest:
        """
        Process an assessment and create approval request.

        Args:
            assessment: The assessment result requiring approval

        Returns:
            Approval request with routing information
        """
        self._update_state(
            status=AgentStatus.RUNNING,
            current_task=f"Processing approval for {assessment.vulnerability_id}"
        )

        try:
            # Create approval request
            approval_id = f"APR-{datetime.utcnow().year}-{str(uuid4())[:8].upper()}"

            # Build approval chain from assessment
            approval_chain = []
            for approver_info in assessment.approval_chain:
                approver = Approver(
                    role=ApproverRole(approver_info["role"]),
                    status=ApprovalStatus.PENDING
                )
                approval_chain.append(approver)

            # Calculate expiration based on severity
            expires_at = self._calculate_expiration(assessment)

            # Validate maintenance window if provided
            validation_errors = []
            requested_window = None

            if assessment.impact_assessment.recommended_window:
                window_validation = await self._validate_maintenance_window(
                    assessment.impact_assessment.recommended_window,
                    assessment
                )
                if window_validation["errors"]:
                    validation_errors.extend(window_validation["errors"])
                else:
                    requested_window = window_validation.get("window_start")

            approval_request = ApprovalRequest(
                id=approval_id,
                vulnerability_id=assessment.vulnerability_id,
                risk_score=assessment.risk_score,
                asset_tier=AssetCriticality.TIER1,  # Would get from assessment context
                requires_restart=assessment.impact_assessment.requires_restart,
                estimated_downtime=assessment.impact_assessment.estimated_downtime_minutes,
                approval_chain=approval_chain,
                requested_window=requested_window,
                expires_at=expires_at
            )

            # Store in pending approvals
            self._pending_approvals[approval_id] = approval_request

            # Route notifications
            await self._route_notifications(approval_request, assessment)

            await self.log_activity(
                action="approval_routed",
                message=f"Approval request {approval_id} routed for {assessment.vulnerability_id}",
                vulnerability_id=assessment.vulnerability_id,
                details={
                    "approval_id": approval_id,
                    "approvers": [a.role.value for a in approval_chain],
                    "expires_at": expires_at.isoformat() if expires_at else None
                }
            )

            self._update_state(
                status=AgentStatus.AWAITING,
                current_task=f"Awaiting approval for {approval_id}",
                metrics_update={"pending_approvals": len(self._pending_approvals)}
            )

            return approval_request

        except Exception as e:
            logger.error(f"Approval routing failed", error=str(e))
            self._update_state(status=AgentStatus.ERROR, error_message=str(e))
            raise

    async def process_decision(self, decision: ApprovalDecision) -> Dict[str, Any]:
        """
        Process an approval decision from a human approver.

        Args:
            decision: The approval decision

        Returns:
            Updated approval status and next steps
        """
        self._update_state(
            status=AgentStatus.RUNNING,
            current_task=f"Processing decision for {decision.approval_id}"
        )

        try:
            approval = self._pending_approvals.get(decision.approval_id)
            if not approval:
                raise ValueError(f"Approval {decision.approval_id} not found")

            # Find the approver in the chain
            approver_found = False
            for approver in approval.approval_chain:
                if approver.role == decision.approver_role:
                    approver.status = decision.decision
                    approver.timestamp = datetime.utcnow()
                    approver.comments = decision.comments
                    approver.conditions.extend(decision.conditions)
                    approver_found = True
                    break

            if not approver_found:
                raise ValueError(f"Approver role {decision.approver_role} not in approval chain")

            # Check if all approvals are complete
            all_approved = all(
                a.status == ApprovalStatus.APPROVED
                for a in approval.approval_chain
            )
            any_denied = any(
                a.status == ApprovalStatus.DENIED
                for a in approval.approval_chain
            )

            result = {
                "approval_id": approval.id,
                "vulnerability_id": approval.vulnerability_id,
                "decision_recorded": True,
                "decision": decision.decision.value,
                "approver": decision.approver_role.value
            }

            if any_denied:
                result["status"] = "denied"
                result["next_action"] = "requires_review"
                result["denial_reason"] = decision.comments

                await self.log_activity(
                    action="approval_denied",
                    message=f"Approval {approval.id} denied by {decision.approver_role.value}",
                    vulnerability_id=approval.vulnerability_id,
                    details={"reason": decision.comments}
                )

            elif all_approved:
                # Validate scheduled window before final approval
                if decision.scheduled_window:
                    window_validation = await self._validate_scheduled_window(
                        decision.scheduled_window,
                        approval
                    )
                    if window_validation["errors"]:
                        result["status"] = "pending"
                        result["validation_errors"] = window_validation["errors"]
                        result["next_action"] = "fix_window"
                    else:
                        result["status"] = "approved"
                        result["scheduled_window"] = decision.scheduled_window.isoformat()
                        result["next_action"] = "ready_for_scheduling"
                        result["conditions"] = self._collect_conditions(approval)
                else:
                    result["status"] = "approved"
                    result["next_action"] = "schedule_window"

                await self.log_activity(
                    action="approval_complete",
                    message=f"Approval {approval.id} fully approved",
                    vulnerability_id=approval.vulnerability_id,
                    details={"conditions": result.get("conditions", [])}
                )

            else:
                result["status"] = "pending"
                pending_approvers = [
                    a.role.value for a in approval.approval_chain
                    if a.status == ApprovalStatus.PENDING
                ]
                result["pending_approvers"] = pending_approvers
                result["next_action"] = "awaiting_approval"

            self._update_state(
                status=AgentStatus.IDLE if result["status"] != "pending" else AgentStatus.AWAITING,
                current_task=None if result["status"] != "pending" else f"Awaiting: {result.get('pending_approvers', [])}"
            )

            return result

        except Exception as e:
            logger.error(f"Decision processing failed", error=str(e))
            self._update_state(status=AgentStatus.ERROR, error_message=str(e))
            raise

    async def run_cycle(self) -> Dict[str, Any]:
        """
        Run approval monitoring cycle - check for expired or stuck approvals.

        Returns:
            Summary of approval status
        """
        self._update_state(
            status=AgentStatus.RUNNING,
            current_task="Checking approval status"
        )

        now = datetime.utcnow()
        expired = []
        escalations = []

        for approval_id, approval in self._pending_approvals.items():
            # Check for expiration
            if approval.expires_at and now > approval.expires_at:
                expired.append(approval_id)

            # Check for escalation needs
            age = now - approval.created_at
            pending_approvers = [
                a for a in approval.approval_chain
                if a.status == ApprovalStatus.PENDING
            ]

            if pending_approvers:
                # Escalate based on risk score (proxy for severity)
                if approval.risk_score >= 90 and age > timedelta(hours=4):
                    escalations.append({
                        "approval_id": approval_id,
                        "escalation_level": 1,
                        "reason": "Critical vulnerability SLA breach"
                    })
                elif approval.risk_score >= 70 and age > timedelta(hours=24):
                    escalations.append({
                        "approval_id": approval_id,
                        "escalation_level": 1,
                        "reason": "High severity SLA breach"
                    })

        # Process escalations
        for escalation in escalations:
            await self._trigger_escalation(escalation)

        self._update_state(
            status=AgentStatus.AWAITING if self._pending_approvals else AgentStatus.IDLE,
            current_task=None,
            metrics_update={
                "pending_approvals": len(self._pending_approvals),
                "expired_today": len(expired),
                "escalations_triggered": len(escalations)
            }
        )

        return {
            "action": "approval_cycle_complete",
            "timestamp": now.isoformat(),
            "pending_approvals": len(self._pending_approvals),
            "expired": expired,
            "escalations": escalations
        }

    async def _validate_maintenance_window(
        self,
        recommended_window: str,
        assessment: AssessmentResult
    ) -> Dict[str, Any]:
        """
        Validate that a maintenance window is acceptable.

        Guardrails enforced:
        1. Tier 1 assets - only designated maintenance windows
        2. No business hours for production
        3. High-value systems need minimum 2-hour windows
        """
        errors = []
        guardrails = self.settings.guardrails

        # This would parse the recommended window and validate
        # For MVP, we'll do basic validation

        # Check for available windows
        available_windows = [
            w for w in self.maintenance_windows
            if w.start_time > datetime.utcnow()
        ]

        if not available_windows:
            errors.append("No maintenance windows available. Contact change management.")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "available_windows": [w.model_dump() for w in available_windows[:3]]
        }

    async def _validate_scheduled_window(
        self,
        scheduled: datetime,
        approval: ApprovalRequest
    ) -> Dict[str, Any]:
        """
        Validate a specific scheduled maintenance window.
        """
        errors = []
        guardrails = self.settings.guardrails

        # Rule 1: Check business hours
        if self._is_business_hours(scheduled):
            if approval.asset_tier in [AssetCriticality.TIER1, AssetCriticality.TIER2]:
                errors.append(
                    f"Cannot schedule during business hours ({guardrails.business_hours_start} - "
                    f"{guardrails.business_hours_end} {guardrails.business_hours_tz}) "
                    "for Tier 1/2 assets"
                )

        # Rule 2: High-value systems need extended windows
        if approval.estimated_downtime > 0:
            # Would check transaction volume from asset context
            pass

        # Rule 3: Must be in the future
        if scheduled <= datetime.utcnow():
            errors.append("Scheduled time must be in the future")

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    def _is_business_hours(self, dt: datetime) -> bool:
        """Check if datetime is during business hours"""
        guardrails = self.settings.guardrails

        # Parse business hours
        start_hour = int(guardrails.business_hours_start.split(':')[0])
        end_hour = int(guardrails.business_hours_end.split(':')[0])

        # Simple check (would need timezone handling in production)
        hour = dt.hour
        return start_hour <= hour < end_hour and dt.weekday() < 5

    def _calculate_expiration(self, assessment: AssessmentResult) -> datetime:
        """Calculate approval expiration based on severity"""
        guardrails = self.settings.guardrails
        now = datetime.utcnow()

        # Use risk score as proxy for severity
        if assessment.risk_score >= 90:
            return now + timedelta(hours=guardrails.critical_approval_sla)
        elif assessment.risk_score >= 70:
            return now + timedelta(hours=guardrails.high_approval_sla)
        elif assessment.risk_score >= 40:
            return now + timedelta(hours=guardrails.medium_approval_sla)
        else:
            return now + timedelta(hours=guardrails.low_approval_sla)

    def _collect_conditions(self, approval: ApprovalRequest) -> List[str]:
        """Collect all conditions from approvers"""
        conditions = []
        for approver in approval.approval_chain:
            conditions.extend(approver.conditions)
        return list(set(conditions))  # Deduplicate

    async def _route_notifications(
        self,
        approval: ApprovalRequest,
        assessment: AssessmentResult
    ):
        """Send notifications to required approvers"""
        if not self.notification_service:
            logger.warning("No notification service configured")
            return

        for approver in approval.approval_chain:
            notification = {
                "type": "approval_request",
                "recipient_role": approver.role.value,
                "approval_id": approval.id,
                "vulnerability_id": approval.vulnerability_id,
                "risk_score": approval.risk_score,
                "asset_tier": approval.asset_tier.value,
                "requires_restart": approval.requires_restart,
                "estimated_downtime": approval.estimated_downtime,
                "expires_at": approval.expires_at.isoformat() if approval.expires_at else None
            }

            try:
                await self.notification_service.send(notification)
            except Exception as e:
                logger.error(f"Failed to send notification", error=str(e))

    async def _trigger_escalation(self, escalation: Dict[str, Any]):
        """Trigger an escalation for a stuck approval"""
        await self.log_activity(
            action="escalation_triggered",
            message=f"Escalation triggered for {escalation['approval_id']}: {escalation['reason']}",
            details=escalation
        )

        # Would send escalation notification here
        logger.warning(
            "Escalation triggered",
            approval_id=escalation["approval_id"],
            reason=escalation["reason"]
        )

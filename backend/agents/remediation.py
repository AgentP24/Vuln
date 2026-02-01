"""
VulnGuard AI - Remediation Agent
Executes approved remediations via Ansible playbooks with strict guardrails
"""
import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4
import structlog

from .base import BaseAgent
from .prompts import REMEDIATION_AGENT_PROMPT
from models import (
    AgentStatus, ExecutionRequest, ExecutionResult, ApprovalStatus,
    AssetCriticality
)
from config import get_settings

logger = structlog.get_logger()


class RemediationAgent(BaseAgent):
    """
    Remediation Agent: Executes ONLY approved remediations within approved
    maintenance windows via Ansible playbooks. Enforces strict guardrails.
    """

    def __init__(
        self,
        ansible_client: Optional[Any] = None,
        snapshot_service: Optional[Any] = None,
        health_check_service: Optional[Any] = None,
        knowledge_base: Optional[Any] = None
    ):
        super().__init__(
            name="remediation",
            system_prompt=REMEDIATION_AGENT_PROMPT,
            knowledge_base=knowledge_base
        )
        self.settings = get_settings()
        self.ansible_client = ansible_client
        self.snapshot_service = snapshot_service
        self.health_check_service = health_check_service
        self._active_executions: Dict[str, ExecutionResult] = {}

    async def process(self, execution_request: ExecutionRequest) -> ExecutionResult:
        """
        Execute a remediation based on approved request.

        GUARDRAILS:
        1. Verify approval is valid and not expired
        2. Verify current time is within maintenance window
        3. Create snapshot/backup before any changes
        4. Run check mode first for Tier 1/2
        5. Have rollback ready before apply
        6. Stop immediately on unexpected errors

        Args:
            execution_request: The approved execution request

        Returns:
            Execution result with status and logs
        """
        execution_id = f"EXEC-{datetime.utcnow().year}-{str(uuid4())[:8].upper()}"

        result = ExecutionResult(
            execution_id=execution_id,
            vulnerability_id=execution_request.vulnerability_id,
            approval_id=execution_request.approval_id,
            playbook_id=execution_request.playbook_id,
            target_hosts=execution_request.target_hosts,
            status="pending",
            started_at=datetime.utcnow()
        )

        self._active_executions[execution_id] = result

        try:
            self._update_state(
                status=AgentStatus.EXECUTING,
                current_task=f"Executing {execution_id}"
            )

            # ================================================================
            # STEP 1: PRE-EXECUTION VALIDATION
            # ================================================================
            await self.log_activity(
                action="pre_execution_validation",
                message=f"Starting pre-execution validation for {execution_id}",
                vulnerability_id=execution_request.vulnerability_id
            )

            validation = await self._validate_before_execution(execution_request)
            if not validation["valid"]:
                result.status = "failed"
                result.error_message = f"Pre-execution validation failed: {validation['errors']}"
                result.completed_at = datetime.utcnow()
                return result

            # ================================================================
            # STEP 2: CREATE BACKUP/SNAPSHOT
            # ================================================================
            await self.log_activity(
                action="creating_snapshot",
                message=f"Creating recovery points for {execution_request.target_hosts}",
                vulnerability_id=execution_request.vulnerability_id
            )

            recovery_points = await self._create_recovery_points(execution_request)
            result.recovery_points = recovery_points

            if not recovery_points:
                result.status = "failed"
                result.error_message = "Failed to create recovery points"
                result.completed_at = datetime.utcnow()
                return result

            # ================================================================
            # STEP 3: CHECK MODE (Required for Tier 1/2)
            # ================================================================
            if execution_request.check_mode_first:
                await self.log_activity(
                    action="check_mode_start",
                    message=f"Running playbook in check mode",
                    vulnerability_id=execution_request.vulnerability_id
                )

                check_result = await self._execute_playbook(
                    execution_request,
                    check_mode=True
                )
                result.check_mode_results = check_result

                if check_result.get("status") == "failed":
                    result.status = "failed"
                    result.error_message = "Check mode failed - aborting execution"
                    result.completed_at = datetime.utcnow()
                    return result

                # Verify no unexpected changes
                if not await self._verify_check_mode_safe(check_result):
                    result.status = "failed"
                    result.error_message = "Check mode revealed unexpected changes - requires review"
                    result.completed_at = datetime.utcnow()
                    return result

            # ================================================================
            # STEP 4: APPLY MODE
            # ================================================================
            await self.log_activity(
                action="apply_mode_start",
                message=f"Executing playbook in apply mode",
                vulnerability_id=execution_request.vulnerability_id
            )

            # Verify still within maintenance window
            if not self._is_within_window(execution_request.maintenance_window):
                result.status = "failed"
                result.error_message = "Maintenance window expired before apply mode"
                result.completed_at = datetime.utcnow()
                return result

            apply_result = await self._execute_playbook(
                execution_request,
                check_mode=False
            )
            result.apply_results = apply_result

            if apply_result.get("status") == "failed":
                # Attempt rollback
                await self.log_activity(
                    action="rollback_initiated",
                    message=f"Apply failed, initiating rollback",
                    vulnerability_id=execution_request.vulnerability_id
                )

                rollback_success = await self._execute_rollback(
                    execution_request,
                    recovery_points
                )
                result.rollback_executed = True
                result.status = "rolled_back"
                result.error_message = f"Apply failed: {apply_result.get('error')}. Rollback {'succeeded' if rollback_success else 'FAILED'}"
                result.completed_at = datetime.utcnow()
                return result

            # ================================================================
            # STEP 5: POST-EXECUTION HEALTH CHECKS
            # ================================================================
            await self.log_activity(
                action="health_checks_start",
                message=f"Running post-execution health checks",
                vulnerability_id=execution_request.vulnerability_id
            )

            health_checks = await self._run_health_checks(execution_request.target_hosts)
            result.health_checks = health_checks

            if not health_checks.get("all_passed", False):
                # Health checks failed - rollback
                await self.log_activity(
                    action="rollback_initiated",
                    message=f"Health checks failed, initiating rollback",
                    vulnerability_id=execution_request.vulnerability_id,
                    details=health_checks
                )

                rollback_success = await self._execute_rollback(
                    execution_request,
                    recovery_points
                )
                result.rollback_executed = True
                result.status = "rolled_back"
                result.error_message = f"Health checks failed. Rollback {'succeeded' if rollback_success else 'FAILED'}"
                result.completed_at = datetime.utcnow()
                return result

            # ================================================================
            # SUCCESS
            # ================================================================
            result.status = "success"
            result.completed_at = datetime.utcnow()

            await self.log_activity(
                action="remediation_complete",
                message=f"Remediation {execution_id} completed successfully",
                vulnerability_id=execution_request.vulnerability_id,
                details={
                    "duration_minutes": (result.completed_at - result.started_at).total_seconds() / 60,
                    "changes_made": apply_result.get("changes_made", [])
                }
            )

            self._update_state(
                status=AgentStatus.IDLE,
                current_task=None,
                metrics_update={"successful_executions": self._state.metrics.get("successful_executions", 0) + 1}
            )

            return result

        except Exception as e:
            logger.error(f"Remediation execution failed", error=str(e), execution_id=execution_id)

            result.status = "failed"
            result.error_message = str(e)
            result.completed_at = datetime.utcnow()

            # Attempt emergency rollback
            if result.recovery_points:
                try:
                    await self._execute_rollback(execution_request, result.recovery_points)
                    result.rollback_executed = True
                except Exception as rollback_error:
                    logger.critical("EMERGENCY ROLLBACK FAILED", error=str(rollback_error))

            self._update_state(status=AgentStatus.ERROR, error_message=str(e))
            return result

    async def run_cycle(self) -> Dict[str, Any]:
        """
        Run remediation monitoring cycle.

        Returns:
            Summary of active executions
        """
        return {
            "action": "remediation_cycle_complete",
            "timestamp": datetime.utcnow().isoformat(),
            "active_executions": len(self._active_executions),
            "executions": {
                eid: {"status": e.status, "vulnerability_id": e.vulnerability_id}
                for eid, e in self._active_executions.items()
            }
        }

    async def _validate_before_execution(
        self,
        request: ExecutionRequest
    ) -> Dict[str, Any]:
        """
        Validate all preconditions before execution.

        GUARDRAILS:
        - Approval must be valid and approved (not pending/expired)
        - Current time must be within maintenance window
        - All targets must be reachable
        - Playbook must exist
        """
        errors = []

        # Check 1: Validate approval (would query database in production)
        # For MVP, we trust the approval_id was validated upstream

        # Check 2: Validate maintenance window
        if not self._is_within_window(request.maintenance_window):
            errors.append(
                f"Current time is outside maintenance window. "
                f"Window: {request.maintenance_window.isoformat()}"
            )

        # Check 3: Validate target reachability
        for host in request.target_hosts:
            if not await self._check_host_reachable(host):
                errors.append(f"Target host {host} is not reachable")

        # Check 4: Validate playbook exists
        if not await self._validate_playbook(request.playbook_id):
            errors.append(f"Playbook {request.playbook_id} not found or invalid")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "checked_at": datetime.utcnow().isoformat()
        }

    def _is_within_window(self, window_start: datetime) -> bool:
        """Check if current time is within maintenance window"""
        # Simplified check - assume 4 hour windows
        now = datetime.utcnow()
        window_end = window_start + timedelta(hours=4)
        return window_start <= now <= window_end

    async def _check_host_reachable(self, host: str) -> bool:
        """Check if a host is reachable"""
        # In production, would do actual connectivity check
        # For MVP, return True
        return True

    async def _validate_playbook(self, playbook_id: str) -> bool:
        """Validate playbook exists and is valid"""
        # In production, would check Ansible Tower
        # For MVP, return True for known playbooks
        known_playbooks = [
            "pb-tls-hardening", "pb-ssh-hardening", "pb-nginx-http2-fix",
            "pb-fortios-upgrade", "pb-goanywhere-patch", "pb-cucm-patch",
            "pb-generic-patch"
        ]
        return playbook_id in known_playbooks

    async def _create_recovery_points(
        self,
        request: ExecutionRequest
    ) -> List[Dict[str, Any]]:
        """
        Create recovery points (snapshots/backups) before execution.

        GUARDRAIL: Must have verified recovery points before proceeding.
        """
        recovery_points = []

        for host in request.target_hosts:
            try:
                # Create snapshot
                snapshot_id = f"snap-{host}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

                if self.snapshot_service:
                    snapshot = await self.snapshot_service.create_snapshot(
                        host=host,
                        label=f"pre-{request.playbook_id}"
                    )
                    recovery_points.append({
                        "type": "snapshot",
                        "host": host,
                        "id": snapshot.id,
                        "created_at": datetime.utcnow().isoformat(),
                        "status": "available"
                    })
                else:
                    # Mock snapshot for development
                    recovery_points.append({
                        "type": "snapshot",
                        "host": host,
                        "id": snapshot_id,
                        "created_at": datetime.utcnow().isoformat(),
                        "status": "available"
                    })

                await self.log_activity(
                    action="recovery_point_created",
                    message=f"Created recovery point for {host}",
                    vulnerability_id=request.vulnerability_id,
                    details={"snapshot_id": snapshot_id}
                )

            except Exception as e:
                logger.error(f"Failed to create recovery point for {host}", error=str(e))
                # Don't proceed without recovery points
                return []

        return recovery_points

    async def _execute_playbook(
        self,
        request: ExecutionRequest,
        check_mode: bool = False
    ) -> Dict[str, Any]:
        """
        Execute Ansible playbook via Tower API.

        Args:
            request: Execution request
            check_mode: If True, run in check/dry-run mode

        Returns:
            Execution result
        """
        if self.ansible_client:
            # Real Ansible Tower execution
            try:
                job = await self.ansible_client.launch_job(
                    template_id=request.playbook_id,
                    inventory=request.target_hosts,
                    extra_vars={
                        "vulnerability_id": request.vulnerability_id,
                        "approval_id": request.approval_id,
                        "maintenance_window": request.maintenance_window.isoformat()
                    },
                    job_type="check" if check_mode else "run"
                )

                # Wait for job completion
                while True:
                    status = await self.ansible_client.get_job_status(job.id)
                    if status in ["successful", "failed", "canceled"]:
                        break
                    await asyncio.sleep(10)

                    # Check if still within window
                    if not self._is_within_window(request.maintenance_window):
                        await self.ansible_client.cancel_job(job.id)
                        return {
                            "status": "failed",
                            "error": "Maintenance window expired during execution"
                        }

                stdout = await self.ansible_client.get_job_stdout(job.id)

                return {
                    "status": "success" if status == "successful" else "failed",
                    "job_id": job.id,
                    "stdout": stdout,
                    "changes_made": self._parse_changes(stdout) if not check_mode else [],
                    "changes_proposed": self._parse_changes(stdout) if check_mode else []
                }

            except Exception as e:
                return {
                    "status": "failed",
                    "error": str(e)
                }

        else:
            # Mock execution for development
            await asyncio.sleep(2)  # Simulate execution time

            return {
                "status": "success",
                "job_id": f"mock-{uuid4().hex[:8]}",
                "stdout": "PLAY RECAP *********************************************************************\nlocalhost: ok=5 changed=2 unreachable=0 failed=0",
                "changes_made": ["Updated TLS configuration", "Restarted nginx"] if not check_mode else [],
                "changes_proposed": ["Would update TLS configuration", "Would restart nginx"] if check_mode else []
            }

    async def _verify_check_mode_safe(self, check_result: Dict[str, Any]) -> bool:
        """Verify check mode results don't show unexpected changes"""
        # In production, would analyze the proposed changes
        # For MVP, return True if check mode succeeded
        return check_result.get("status") == "success"

    async def _run_health_checks(self, hosts: List[str]) -> Dict[str, Any]:
        """Run health checks on target hosts"""
        results = {
            "all_passed": True,
            "checks": []
        }

        for host in hosts:
            checks = []

            # Service status check
            service_check = await self._check_service_status(host)
            checks.append(service_check)

            # HTTP response check (if applicable)
            http_check = await self._check_http_response(host)
            checks.append(http_check)

            # Check if any failed
            if any(c["status"] == "failed" for c in checks):
                results["all_passed"] = False

            results["checks"].extend(checks)

        return results

    async def _check_service_status(self, host: str) -> Dict[str, Any]:
        """Check service status on host"""
        if self.health_check_service:
            return await self.health_check_service.check_service(host)

        # Mock for development
        return {
            "check": "service_status",
            "host": host,
            "status": "passed",
            "details": "All services running"
        }

    async def _check_http_response(self, host: str) -> Dict[str, Any]:
        """Check HTTP response from host"""
        if self.health_check_service:
            return await self.health_check_service.check_http(host)

        # Mock for development
        return {
            "check": "http_response",
            "host": host,
            "status": "passed",
            "details": "200 OK in 45ms"
        }

    async def _execute_rollback(
        self,
        request: ExecutionRequest,
        recovery_points: List[Dict[str, Any]]
    ) -> bool:
        """
        Execute rollback to recovery points.

        Returns True if rollback succeeded, False otherwise.
        """
        await self.log_activity(
            action="rollback_executing",
            message=f"Executing rollback for {request.vulnerability_id}",
            vulnerability_id=request.vulnerability_id,
            details={"recovery_points": [rp["id"] for rp in recovery_points]}
        )

        success = True

        for recovery_point in reversed(recovery_points):
            try:
                if self.snapshot_service:
                    await self.snapshot_service.restore_snapshot(recovery_point["id"])
                else:
                    # Mock rollback
                    await asyncio.sleep(1)

                await self.log_activity(
                    action="recovery_point_restored",
                    message=f"Restored recovery point {recovery_point['id']}",
                    vulnerability_id=request.vulnerability_id
                )

            except Exception as e:
                logger.critical(
                    "Failed to restore recovery point",
                    recovery_point=recovery_point["id"],
                    error=str(e)
                )
                success = False

        return success

    def _parse_changes(self, stdout: str) -> List[str]:
        """Parse Ansible stdout to extract changes made"""
        # Simplified parsing - would be more sophisticated in production
        changes = []
        if "changed=" in stdout:
            # Extract changed count
            import re
            match = re.search(r'changed=(\d+)', stdout)
            if match and int(match.group(1)) > 0:
                changes.append(f"{match.group(1)} changes applied")
        return changes


# Import timedelta for window calculation
from datetime import timedelta

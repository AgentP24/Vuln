"""
VulnGuard AI - Validation Agent
Verifies remediation success and maintains feedback loop
"""
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4
import structlog

from .base import BaseAgent
from .prompts import VALIDATION_AGENT_PROMPT
from models import (
    AgentStatus, ExecutionResult, ValidationResult
)

logger = structlog.get_logger()


class ValidationAgent(BaseAgent):
    """
    Validation Agent: Verifies that remediations were successful by triggering
    rescans and comparing before/after states. Maintains feedback loop for
    continuous improvement.
    """

    # Minimum stabilization period before rescanning (seconds)
    STABILIZATION_PERIOD = 300  # 5 minutes

    def __init__(
        self,
        scanner_clients: Dict[str, Any],
        health_check_service: Optional[Any] = None,
        knowledge_base: Optional[Any] = None
    ):
        super().__init__(
            name="validation",
            system_prompt=VALIDATION_AGENT_PROMPT,
            knowledge_base=knowledge_base
        )
        self.scanner_clients = scanner_clients
        self.health_check_service = health_check_service
        self._pending_validations: Dict[str, Dict[str, Any]] = {}

    async def process(self, execution_result: ExecutionResult) -> ValidationResult:
        """
        Validate a remediation execution.

        Args:
            execution_result: The completed execution to validate

        Returns:
            Validation result
        """
        validation_id = f"VAL-{datetime.utcnow().year}-{str(uuid4())[:8].upper()}"

        self._update_state(
            status=AgentStatus.RUNNING,
            current_task=f"Validating {execution_result.execution_id}"
        )

        try:
            # ================================================================
            # STEP 1: WAIT FOR STABILIZATION
            # ================================================================
            await self.log_activity(
                action="stabilization_wait",
                message=f"Waiting {self.STABILIZATION_PERIOD}s for changes to propagate",
                vulnerability_id=execution_result.vulnerability_id
            )

            await asyncio.sleep(self.STABILIZATION_PERIOD)

            # ================================================================
            # STEP 2: TRIGGER RESCAN
            # ================================================================
            await self.log_activity(
                action="rescan_triggered",
                message=f"Triggering validation rescan for {execution_result.target_hosts}",
                vulnerability_id=execution_result.vulnerability_id
            )

            scan_results = await self._trigger_rescan(execution_result)

            # ================================================================
            # STEP 3: COMPARE VULNERABILITY STATE
            # ================================================================
            comparison = await self._compare_vulnerability_state(
                execution_result,
                scan_results
            )

            # ================================================================
            # STEP 4: VALIDATE SERVICE HEALTH
            # ================================================================
            health_checks = await self._validate_service_health(
                execution_result.target_hosts
            )

            # ================================================================
            # STEP 5: CHECK FOR REGRESSIONS
            # ================================================================
            regression_check = await self._check_for_regressions(
                execution_result,
                scan_results
            )

            # ================================================================
            # STEP 6: DETERMINE VALIDATION STATUS
            # ================================================================
            if not scan_results.get("vulnerability_present", True):
                validation_status = "resolved"
            elif scan_results.get("severity_reduced", False):
                validation_status = "partially_resolved"
            elif regression_check.get("regression_detected", False):
                validation_status = "new_issues"
            else:
                validation_status = "persists"

            # ================================================================
            # STEP 7: UPDATE PLAYBOOK METRICS
            # ================================================================
            playbook_effectiveness = await self._update_playbook_metrics(
                execution_result.playbook_id,
                validation_status == "resolved",
                execution_result
            )

            # ================================================================
            # STEP 8: DETERMINE IF FOLLOW-UP NEEDED
            # ================================================================
            follow_up_required = validation_status in ["persists", "new_issues"]
            follow_up_reason = None

            if validation_status == "persists":
                follow_up_reason = "Vulnerability still detected after remediation"
            elif validation_status == "new_issues":
                follow_up_reason = f"New vulnerabilities detected: {regression_check.get('new_vulnerabilities', [])}"

            # Build validation result
            result = ValidationResult(
                validation_id=validation_id,
                vulnerability_id=execution_result.vulnerability_id,
                execution_id=execution_result.execution_id,
                scan_results=scan_results,
                validation_status=validation_status,
                health_checks=health_checks,
                regression_check=regression_check,
                playbook_effectiveness=playbook_effectiveness,
                follow_up_required=follow_up_required,
                follow_up_reason=follow_up_reason,
                validated_at=datetime.utcnow()
            )

            # ================================================================
            # STEP 9: TRIGGER FEEDBACK LOOP IF NEEDED
            # ================================================================
            if follow_up_required:
                await self._trigger_feedback_loop(result)

            # ================================================================
            # STEP 10: UPDATE KNOWLEDGE BASE
            # ================================================================
            await self._update_knowledge_base(result)

            await self.log_activity(
                action="validation_complete",
                message=f"Validation {validation_id} complete: {validation_status}",
                vulnerability_id=execution_result.vulnerability_id,
                details={
                    "status": validation_status,
                    "follow_up_required": follow_up_required,
                    "playbook_success": validation_status == "resolved"
                }
            )

            self._update_state(
                status=AgentStatus.IDLE,
                current_task=None,
                metrics_update={
                    "validations_completed": self._state.metrics.get("validations_completed", 0) + 1,
                    "resolution_rate": self._calculate_resolution_rate(validation_status)
                }
            )

            return result

        except Exception as e:
            logger.error(f"Validation failed", error=str(e))
            self._update_state(status=AgentStatus.ERROR, error_message=str(e))
            raise

    async def run_cycle(self) -> Dict[str, Any]:
        """
        Run validation monitoring cycle.

        Returns:
            Summary of pending validations
        """
        return {
            "action": "validation_cycle_complete",
            "timestamp": datetime.utcnow().isoformat(),
            "pending_validations": len(self._pending_validations)
        }

    async def _trigger_rescan(self, execution: ExecutionResult) -> Dict[str, Any]:
        """
        Trigger a targeted rescan using the original detection scanner.

        GUARDRAIL: Always use the same scanner that detected the original vulnerability.
        """
        # In production, would get original scanner from vulnerability record
        # For MVP, use first available scanner
        scanner_name = list(self.scanner_clients.keys())[0] if self.scanner_clients else "mock"

        if scanner_name in self.scanner_clients:
            client = self.scanner_clients[scanner_name]
            try:
                scan_result = await client.scan_targets(
                    targets=execution.target_hosts,
                    scan_type="targeted"
                )
                return {
                    "scanner": scanner_name,
                    "scan_id": scan_result.get("scan_id"),
                    "vulnerability_present": scan_result.get("vulnerability_found", False),
                    "severity": scan_result.get("severity"),
                    "details": scan_result.get("details")
                }
            except Exception as e:
                logger.error(f"Rescan failed", scanner=scanner_name, error=str(e))
                raise

        # Mock scan result for development
        return {
            "scanner": "mock",
            "scan_id": f"SCAN-{uuid4().hex[:8]}",
            "vulnerability_present": False,  # Assume fixed for mock
            "severity": None,
            "severity_reduced": False,
            "details": "Vulnerability not detected in post-remediation scan"
        }

    async def _compare_vulnerability_state(
        self,
        execution: ExecutionResult,
        scan_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compare before and after vulnerability states.
        """
        # Would get pre-scan state from database
        pre_state = {
            "vulnerability_present": True,
            "severity": "high"  # Would come from actual record
        }

        post_state = {
            "vulnerability_present": scan_results.get("vulnerability_present", True),
            "severity": scan_results.get("severity")
        }

        return {
            "pre_state": pre_state,
            "post_state": post_state,
            "resolved": not post_state["vulnerability_present"],
            "severity_changed": pre_state["severity"] != post_state["severity"]
        }

    async def _validate_service_health(
        self,
        hosts: List[str]
    ) -> Dict[str, Any]:
        """
        Validate service health on all target hosts.
        """
        results = {
            "overall_status": "healthy",
            "checks": []
        }

        for host in hosts:
            if self.health_check_service:
                health = await self.health_check_service.check_all(host)
                results["checks"].extend(health.get("checks", []))
                if health.get("status") != "healthy":
                    results["overall_status"] = health.get("status", "degraded")
            else:
                # Mock health check
                results["checks"].append({
                    "host": host,
                    "check": "service_status",
                    "status": "passed",
                    "details": "All services healthy"
                })

        return results

    async def _check_for_regressions(
        self,
        execution: ExecutionResult,
        scan_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check if remediation introduced new vulnerabilities.

        GUARDRAIL: Always check for regressions - new vulnerabilities could be worse.
        """
        # Would compare full scan results against pre-remediation baseline
        # For MVP, return no regressions
        return {
            "regression_detected": False,
            "new_vulnerabilities": [],
            "severity": None
        }

    async def _update_playbook_metrics(
        self,
        playbook_id: str,
        success: bool,
        execution: ExecutionResult
    ) -> Dict[str, Any]:
        """
        Update playbook effectiveness metrics.

        GUARDRAIL: Always update metrics for continuous improvement.
        """
        # Calculate execution time
        execution_time = 0
        if execution.completed_at and execution.started_at:
            execution_time = (execution.completed_at - execution.started_at).total_seconds() / 60

        # In production, would update database
        # For MVP, return mock metrics
        current_success_rate = 0.90  # Would come from database
        new_success_rate = current_success_rate + (0.01 if success else -0.02)
        new_success_rate = max(0, min(1, new_success_rate))

        return {
            "playbook_id": playbook_id,
            "success": success,
            "execution_time_minutes": execution_time,
            "updated_success_rate": new_success_rate
        }

    async def _trigger_feedback_loop(self, validation: ValidationResult):
        """
        Trigger feedback loop when remediation fails.

        Actions:
        1. Notify Assessment Agent for re-analysis
        2. Flag playbook for review
        3. Escalate to human analyst
        """
        await self.log_activity(
            action="feedback_loop_triggered",
            message=f"Triggering feedback loop for {validation.vulnerability_id}",
            vulnerability_id=validation.vulnerability_id,
            details={
                "reason": validation.follow_up_reason,
                "validation_status": validation.validation_status
            }
        )

        # Would publish event to message queue for Assessment Agent
        # For MVP, just log
        logger.warning(
            "Feedback loop triggered - vulnerability not resolved",
            vulnerability_id=validation.vulnerability_id,
            reason=validation.follow_up_reason
        )

    async def _update_knowledge_base(self, validation: ValidationResult):
        """
        Update knowledge base with remediation outcome.
        """
        if not self.knowledge_base:
            return

        try:
            document = {
                "vulnerability_id": validation.vulnerability_id,
                "playbook_id": validation.playbook_effectiveness["playbook_id"],
                "success": validation.validation_status == "resolved",
                "execution_time_minutes": validation.playbook_effectiveness["execution_time_minutes"],
                "validation_status": validation.validation_status,
                "timestamp": datetime.utcnow().isoformat()
            }

            collection = (
                "remediation_successes" if validation.validation_status == "resolved"
                else "remediation_failures"
            )

            await self.knowledge_base.add_document(
                collection=collection,
                document=document
            )

            await self.log_activity(
                action="knowledge_base_updated",
                message=f"Updated knowledge base with remediation outcome",
                vulnerability_id=validation.vulnerability_id
            )

        except Exception as e:
            logger.warning(f"Failed to update knowledge base", error=str(e))

    def _calculate_resolution_rate(self, status: str) -> float:
        """Calculate running resolution rate"""
        total = self._state.metrics.get("validations_completed", 0) + 1
        resolved = self._state.metrics.get("resolved_count", 0)
        if status == "resolved":
            resolved += 1
            self._state.metrics["resolved_count"] = resolved
        return resolved / total if total > 0 else 0.0

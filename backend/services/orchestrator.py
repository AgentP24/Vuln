"""
VulnGuard AI - Orchestrator Service
Coordinates the flow between all five agents and ensures proper handoffs
"""
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from enum import Enum
import structlog

from agents import (
    DiscoveryAgent, AssessmentAgent, ApprovalAgent,
    RemediationAgent, ValidationAgent
)
from agents.prompts import ORCHESTRATOR_PROMPT
from models import (
    Vulnerability, VulnerabilityStatus, ApprovalStatus,
    AgentState, AgentStatus
)

logger = structlog.get_logger()


class PipelineStage(str, Enum):
    """Pipeline stages for vulnerability processing"""
    DISCOVERY = "discovery"
    ASSESSMENT = "assessment"
    APPROVAL = "approval"
    REMEDIATION = "remediation"
    VALIDATION = "validation"


class VulnerabilityState(str, Enum):
    """State machine states for vulnerabilities"""
    NEW = "new"
    ASSESSED = "assessed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    VALIDATED = "validated"
    EXCEPTION = "exception"
    FAILED = "failed"


# State transition rules
VALID_TRANSITIONS = {
    VulnerabilityState.NEW: [VulnerabilityState.ASSESSED],
    VulnerabilityState.ASSESSED: [VulnerabilityState.PENDING_APPROVAL, VulnerabilityState.EXCEPTION],
    VulnerabilityState.PENDING_APPROVAL: [VulnerabilityState.APPROVED, VulnerabilityState.EXCEPTION],
    VulnerabilityState.APPROVED: [VulnerabilityState.SCHEDULED],
    VulnerabilityState.SCHEDULED: [VulnerabilityState.IN_PROGRESS],
    VulnerabilityState.IN_PROGRESS: [VulnerabilityState.COMPLETED, VulnerabilityState.FAILED],
    VulnerabilityState.COMPLETED: [VulnerabilityState.VALIDATED],
    VulnerabilityState.VALIDATED: [],  # Terminal state
    VulnerabilityState.FAILED: [VulnerabilityState.ASSESSED],  # Can re-assess
    VulnerabilityState.EXCEPTION: [],  # Terminal state (manual handling required)
}


class Orchestrator:
    """
    Orchestrator: Coordinates the flow between all agents.

    Pipeline:
        Discovery → Assessment → Approval → Remediation → Validation
            ↑                                                  │
            └──────────── Feedback Loop ───────────────────────┘
    """

    def __init__(
        self,
        discovery_agent: DiscoveryAgent,
        assessment_agent: AssessmentAgent,
        approval_agent: ApprovalAgent,
        remediation_agent: RemediationAgent,
        validation_agent: ValidationAgent
    ):
        self.agents = {
            PipelineStage.DISCOVERY: discovery_agent,
            PipelineStage.ASSESSMENT: assessment_agent,
            PipelineStage.APPROVAL: approval_agent,
            PipelineStage.REMEDIATION: remediation_agent,
            PipelineStage.VALIDATION: validation_agent,
        }

        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._vulnerability_queue: asyncio.Queue = asyncio.Queue()
        self._metrics = {
            "vulnerabilities_processed": 0,
            "successful_remediations": 0,
            "failed_remediations": 0,
            "feedback_loops_triggered": 0
        }

        logger.info("Orchestrator initialized")

    async def start(self):
        """Start the orchestrator and all agent cycles"""
        if self._running:
            logger.warning("Orchestrator already running")
            return

        self._running = True
        logger.info("Starting orchestrator")

        # Start agent cycle tasks
        self._tasks = [
            asyncio.create_task(self._discovery_loop()),
            asyncio.create_task(self._processing_loop()),
            asyncio.create_task(self._monitoring_loop()),
        ]

        logger.info("Orchestrator started with all agent loops")

    async def stop(self):
        """Stop the orchestrator gracefully"""
        logger.info("Stopping orchestrator")
        self._running = False

        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._tasks = []
        logger.info("Orchestrator stopped")

    async def _discovery_loop(self):
        """Run discovery agent on schedule"""
        while self._running:
            try:
                logger.info("Running discovery cycle")
                discovery_agent = self.agents[PipelineStage.DISCOVERY]

                # Run discovery cycle
                results = await discovery_agent.run_cycle()

                # Queue new vulnerabilities for processing
                for vuln_data in results.get("vulnerabilities", []):
                    await self._vulnerability_queue.put({
                        "stage": PipelineStage.ASSESSMENT,
                        "data": vuln_data,
                        "timestamp": datetime.utcnow()
                    })

                logger.info(
                    f"Discovery cycle complete",
                    new_vulns=results.get("results", {}).get("new_vulnerabilities", 0)
                )

                # Wait before next cycle (15 minutes default)
                await asyncio.sleep(900)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Discovery loop error", error=str(e))
                await asyncio.sleep(60)  # Wait before retry

    async def _processing_loop(self):
        """Process vulnerabilities through the pipeline"""
        while self._running:
            try:
                # Get next item from queue (with timeout)
                try:
                    item = await asyncio.wait_for(
                        self._vulnerability_queue.get(),
                        timeout=30.0
                    )
                except asyncio.TimeoutError:
                    continue

                stage = item["stage"]
                data = item["data"]

                logger.info(f"Processing vulnerability at stage: {stage}")

                # Route to appropriate agent
                result = await self._process_stage(stage, data)

                # Determine next stage based on result
                next_stage = self._determine_next_stage(stage, result)

                if next_stage:
                    await self._vulnerability_queue.put({
                        "stage": next_stage,
                        "data": result,
                        "timestamp": datetime.utcnow()
                    })

                self._metrics["vulnerabilities_processed"] += 1

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Processing loop error", error=str(e))

    async def _process_stage(
        self,
        stage: PipelineStage,
        data: Any
    ) -> Any:
        """Process data at a specific pipeline stage"""
        agent = self.agents[stage]

        try:
            if stage == PipelineStage.ASSESSMENT:
                # Convert dict to Vulnerability if needed
                if isinstance(data, dict):
                    from models import Vulnerability
                    # Would create proper Vulnerability object
                    pass
                return await agent.process(data)

            elif stage == PipelineStage.APPROVAL:
                return await agent.process(data)

            elif stage == PipelineStage.REMEDIATION:
                # Only process if approved and within maintenance window
                if await self._validate_remediation_preconditions(data):
                    return await agent.process(data)
                else:
                    logger.info("Remediation preconditions not met, requeuing")
                    return None

            elif stage == PipelineStage.VALIDATION:
                result = await agent.process(data)

                # Handle feedback loop
                if result.validation_status in ["persists", "partially_resolved"]:
                    self._metrics["feedback_loops_triggered"] += 1
                    await self._trigger_feedback_loop(result)
                else:
                    self._metrics["successful_remediations"] += 1

                return result

            else:
                logger.warning(f"Unknown stage: {stage}")
                return None

        except Exception as e:
            logger.error(f"Error processing stage {stage}", error=str(e))
            self._metrics["failed_remediations"] += 1
            raise

    def _determine_next_stage(
        self,
        current_stage: PipelineStage,
        result: Any
    ) -> Optional[PipelineStage]:
        """Determine the next pipeline stage based on current result"""
        if result is None:
            return None

        stage_flow = {
            PipelineStage.DISCOVERY: PipelineStage.ASSESSMENT,
            PipelineStage.ASSESSMENT: PipelineStage.APPROVAL,
            PipelineStage.APPROVAL: PipelineStage.REMEDIATION,
            PipelineStage.REMEDIATION: PipelineStage.VALIDATION,
            PipelineStage.VALIDATION: None,  # Terminal
        }

        # Check for special conditions
        if current_stage == PipelineStage.ASSESSMENT:
            # Auto-approve eligible items skip to remediation
            if hasattr(result, 'auto_approve_eligible') and result.auto_approve_eligible:
                return PipelineStage.REMEDIATION

        elif current_stage == PipelineStage.APPROVAL:
            # Only proceed if fully approved
            if hasattr(result, 'status') and result.status != "approved":
                return None  # Stay in approval

        return stage_flow.get(current_stage)

    async def _validate_remediation_preconditions(self, data: Any) -> bool:
        """Validate that remediation can proceed"""
        # Check approval status
        # Check maintenance window
        # Check system availability

        # For now, return True (would implement full validation)
        return True

    async def _trigger_feedback_loop(self, validation_result: Any):
        """Trigger feedback loop for failed remediation"""
        logger.warning(
            "Triggering feedback loop",
            vulnerability_id=validation_result.vulnerability_id,
            status=validation_result.validation_status
        )

        # Re-queue for assessment with failure context
        await self._vulnerability_queue.put({
            "stage": PipelineStage.ASSESSMENT,
            "data": {
                "vulnerability_id": validation_result.vulnerability_id,
                "previous_attempt": validation_result,
                "requires_alternative": True
            },
            "timestamp": datetime.utcnow()
        })

    async def _monitoring_loop(self):
        """Monitor agent health and trigger escalations"""
        while self._running:
            try:
                await self._check_agent_health()
                await self._check_stuck_vulnerabilities()
                await self._check_escalations()

                # Run every 5 minutes
                await asyncio.sleep(300)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Monitoring loop error", error=str(e))
                await asyncio.sleep(60)

    async def _check_agent_health(self):
        """Check health of all agents"""
        for stage, agent in self.agents.items():
            state = agent.state

            if state.status == AgentStatus.ERROR:
                logger.error(
                    f"Agent in error state",
                    agent=stage.value,
                    error=state.error_message
                )
                # Would trigger alert here

    async def _check_stuck_vulnerabilities(self):
        """Check for vulnerabilities stuck in pipeline"""
        # Would query database for stuck items
        # Items stuck > 1 hour trigger alert
        pass

    async def _check_escalations(self):
        """Check for items needing escalation"""
        # Check critical vulnerabilities unaddressed > 4 hours
        # Check failed remediations that need human review
        pass

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        return {
            "running": self._running,
            "queue_size": self._vulnerability_queue.qsize(),
            "metrics": self._metrics,
            "agent_states": {
                stage.value: agent.state.model_dump()
                for stage, agent in self.agents.items()
            }
        }

    async def process_single_vulnerability(
        self,
        vulnerability_id: str,
        start_stage: PipelineStage = PipelineStage.ASSESSMENT
    ) -> Dict[str, Any]:
        """
        Manually process a single vulnerability through the pipeline.
        Useful for testing and manual intervention.
        """
        logger.info(f"Processing single vulnerability: {vulnerability_id}")

        # Would fetch vulnerability from database
        vulnerability_data = {"id": vulnerability_id}

        # Add to queue at specified stage
        await self._vulnerability_queue.put({
            "stage": start_stage,
            "data": vulnerability_data,
            "timestamp": datetime.utcnow()
        })

        return {
            "vulnerability_id": vulnerability_id,
            "queued_at": start_stage.value,
            "status": "queued"
        }


class OrchestratorFactory:
    """Factory for creating orchestrator with proper dependencies"""

    @staticmethod
    async def create(
        scanner_clients: Dict[str, Any],
        ansible_client: Any,
        knowledge_base: Any = None
    ) -> Orchestrator:
        """Create orchestrator with all dependencies"""
        from models import Playbook, MaintenanceWindow

        # Create playbook registry
        playbook_registry = {
            "pb-tls-hardening": Playbook(
                id="pb-tls-hardening",
                name="TLS/SSL Hardening",
                description="Disable deprecated TLS versions",
                target_platforms=["Linux", "Windows", "server"],
                requires_restart=True,
                estimated_duration=15,
                success_rate=0.94
            ),
        }

        # Create maintenance windows
        maintenance_windows = []

        # Initialize agents
        discovery_agent = DiscoveryAgent(
            scanner_clients=scanner_clients,
            knowledge_base=knowledge_base
        )

        assessment_agent = AssessmentAgent(
            playbook_registry=playbook_registry,
            knowledge_base=knowledge_base
        )

        approval_agent = ApprovalAgent(
            maintenance_windows=maintenance_windows,
            knowledge_base=knowledge_base
        )

        remediation_agent = RemediationAgent(
            ansible_client=ansible_client,
            knowledge_base=knowledge_base
        )

        validation_agent = ValidationAgent(
            scanner_clients=scanner_clients,
            knowledge_base=knowledge_base
        )

        return Orchestrator(
            discovery_agent=discovery_agent,
            assessment_agent=assessment_agent,
            approval_agent=approval_agent,
            remediation_agent=remediation_agent,
            validation_agent=validation_agent
        )

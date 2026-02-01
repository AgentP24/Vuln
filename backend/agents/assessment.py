"""
VulnGuard AI - Assessment Agent
Analyzes vulnerabilities and determines business impact and remediation complexity
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4
import structlog

from .base import BaseAgent
from .prompts import ASSESSMENT_AGENT_PROMPT
from models import (
    AgentStatus, Vulnerability, VulnerabilityStatus,
    AssessmentResult, ImpactAssessment, PlaybookRecommendation,
    Severity, AssetCriticality, ServiceImpact, ApproverRole, Playbook
)

logger = structlog.get_logger()


class AssessmentAgent(BaseAgent):
    """
    Assessment Agent: Analyzes vulnerabilities to determine true business risk,
    remediation complexity, and required approval chain.
    """

    def __init__(
        self,
        playbook_registry: Dict[str, Playbook],
        knowledge_base: Optional[Any] = None,
        dependency_map: Optional[Dict[str, List[str]]] = None
    ):
        super().__init__(
            name="assessment",
            system_prompt=ASSESSMENT_AGENT_PROMPT,
            knowledge_base=knowledge_base
        )
        self.playbook_registry = playbook_registry
        self.dependency_map = dependency_map or {}

    async def process(self, vulnerability: Vulnerability) -> AssessmentResult:
        """
        Assess a single vulnerability.

        Args:
            vulnerability: The vulnerability to assess

        Returns:
            Complete assessment result
        """
        self._update_state(
            status=AgentStatus.RUNNING,
            current_task=f"Assessing {vulnerability.id}"
        )

        try:
            # Step 1: Calculate risk score
            risk_score, risk_factors = await self._calculate_risk_score(vulnerability)

            # Step 2: Perform impact assessment
            impact = await self._assess_impact(vulnerability)

            # Step 3: Get playbook recommendation
            playbook_rec = await self._recommend_playbook(vulnerability)

            # Step 4: Determine approval chain
            approval_chain, auto_approve = await self._determine_approval_chain(
                vulnerability, impact
            )

            # Build assessment result
            result = AssessmentResult(
                vulnerability_id=vulnerability.id,
                risk_score=risk_score,
                risk_factors=risk_factors,
                impact_assessment=impact,
                suggested_remediation=playbook_rec,
                approval_required=len(approval_chain) > 0,
                approval_chain=approval_chain,
                auto_approve_eligible=auto_approve,
                auto_approve_reason="Low risk, no restart required" if auto_approve else None
            )

            # Use LLM to validate and enhance assessment
            enhanced = await self._enhance_with_llm(vulnerability, result)

            await self.log_activity(
                action="assessment_complete",
                message=f"Completed assessment for {vulnerability.id}. Risk score: {risk_score}",
                vulnerability_id=vulnerability.id,
                details={
                    "risk_score": risk_score,
                    "approval_required": result.approval_required,
                    "playbook": playbook_rec.playbook_id
                }
            )

            self._update_state(
                status=AgentStatus.IDLE,
                current_task=None,
                metrics_update={"last_risk_score": risk_score}
            )

            return enhanced

        except Exception as e:
            logger.error(f"Assessment failed for {vulnerability.id}", error=str(e))
            self._update_state(status=AgentStatus.ERROR, error_message=str(e))
            raise

    async def run_cycle(self) -> Dict[str, Any]:
        """
        Run assessment cycle for pending vulnerabilities.

        Returns:
            Summary of assessments performed
        """
        # This would typically query the database for NEW vulnerabilities
        # For MVP, we'll just return the method signature
        return {
            "action": "assessment_cycle_complete",
            "timestamp": datetime.utcnow().isoformat(),
            "assessments_completed": 0,
            "pending_review": 0
        }

    async def _calculate_risk_score(
        self,
        vulnerability: Vulnerability
    ) -> tuple[float, Dict[str, Any]]:
        """
        Calculate the business risk score (0-100).

        Formula:
        Risk Score = (CVSS × Asset_Multiplier × Exposure_Factor) + Business_Adjustment

        Args:
            vulnerability: The vulnerability to score

        Returns:
            Tuple of (risk_score, risk_factors_dict)
        """
        # Asset Criticality Multiplier
        multipliers = {
            AssetCriticality.TIER1: 1.5,
            AssetCriticality.TIER2: 1.2,
            AssetCriticality.TIER3: 1.0
        }
        asset_multiplier = multipliers.get(vulnerability.asset.criticality, 1.0)

        # Exposure Factor (simplified - would check network exposure in production)
        # Assuming internal network by default
        exposure_factor = 1.0

        # Business Impact Adjustment
        business_adjustment = 0

        # Transaction volume adjustment
        if vulnerability.business_context.transaction_volume >= 1_000_000_000:
            business_adjustment += 15

        # Data classification adjustment
        if vulnerability.business_context.data_classification.value in ['pci', 'phi']:
            business_adjustment += 10

        # Compliance frameworks adjustment
        if len(vulnerability.business_context.compliance_frameworks) > 0:
            business_adjustment += 5

        # Calculate base score
        base_score = vulnerability.cvss * asset_multiplier * exposure_factor

        # Cap and add business adjustment
        risk_score = min(100, base_score + business_adjustment)

        risk_factors = {
            "cvss_base": vulnerability.cvss,
            "asset_multiplier": asset_multiplier,
            "exposure_factor": exposure_factor,
            "business_adjustment": business_adjustment,
            "calculation": f"({vulnerability.cvss} × {asset_multiplier} × {exposure_factor}) + {business_adjustment} = {risk_score:.1f}"
        }

        return round(risk_score, 1), risk_factors

    async def _assess_impact(self, vulnerability: Vulnerability) -> ImpactAssessment:
        """
        Assess the operational impact of remediation.

        Args:
            vulnerability: The vulnerability to assess

        Returns:
            Impact assessment details
        """
        # Determine service impact
        if vulnerability.remediation.requires_restart:
            service_impact = ServiceImpact.OUTAGE
        else:
            service_impact = ServiceImpact.NONE

        # Calculate estimated downtime
        base_downtime = vulnerability.remediation.estimated_downtime
        if vulnerability.asset.criticality == AssetCriticality.TIER1:
            # Add buffer for Tier 1 assets
            estimated_downtime = int(base_downtime * 1.5)
        else:
            estimated_downtime = base_downtime

        # Round up to nearest 15 minutes
        if estimated_downtime > 0:
            estimated_downtime = ((estimated_downtime + 14) // 15) * 15

        # Get affected dependencies
        affected_deps = self.dependency_map.get(vulnerability.asset.hostname, [])

        # Calculate cascading impact
        cascading_impact = None
        if affected_deps:
            cascading_impact = f"{len(affected_deps)} dependent services affected"

        # Calculate revenue at risk (for Tier 1 high-transaction systems)
        revenue_at_risk = None
        if vulnerability.business_context.transaction_volume >= 1_000_000_000:
            hourly_volume = vulnerability.business_context.transaction_volume / 24
            if estimated_downtime > 0:
                at_risk = (estimated_downtime / 60) * hourly_volume
                revenue_at_risk = f"${at_risk / 1_000_000:.1f}M/hour during outage"

        # Recommend maintenance window
        recommended_window = self._recommend_window(vulnerability)

        return ImpactAssessment(
            service_impact=service_impact,
            estimated_downtime_minutes=estimated_downtime,
            requires_restart=vulnerability.remediation.requires_restart,
            requires_reboot=False,  # Would check based on vulnerability type
            affected_dependencies=affected_deps,
            cascading_impact=cascading_impact,
            revenue_at_risk=revenue_at_risk,
            recommended_window=recommended_window
        )

    async def _recommend_playbook(
        self,
        vulnerability: Vulnerability
    ) -> PlaybookRecommendation:
        """
        Recommend the best playbook for remediation.

        Args:
            vulnerability: The vulnerability to remediate

        Returns:
            Playbook recommendation with alternatives
        """
        # Query knowledge base for similar past remediations
        similar_remediations = await self._query_knowledge_base(
            query=f"{vulnerability.title} {vulnerability.cve}",
            collection="remediation_knowledge",
            top_k=5
        )

        # Filter playbooks by target platform
        compatible_playbooks = []
        for pb_id, playbook in self.playbook_registry.items():
            # Check platform compatibility
            asset_type = vulnerability.asset.type.value
            if asset_type in [p.lower() for p in playbook.target_platforms]:
                compatible_playbooks.append(playbook)

        # Sort by success rate
        compatible_playbooks.sort(key=lambda p: p.success_rate, reverse=True)

        if compatible_playbooks:
            recommended = compatible_playbooks[0]
            alternatives = [p.id for p in compatible_playbooks[1:3]]
        else:
            # Default playbook
            recommended = Playbook(
                id="pb-generic-patch",
                name="Generic Security Patch",
                description="Generic patch application playbook",
                target_platforms=["Linux", "Windows"],
                requires_restart=True,
                estimated_duration=30,
                supports_check_mode=True,
                supports_rollback=True,
                success_rate=0.85
            )
            alternatives = []

        # Determine pre/post checks based on vulnerability type
        pre_checks = self._get_pre_checks(vulnerability, recommended)
        post_checks = self._get_post_checks(vulnerability, recommended)

        return PlaybookRecommendation(
            playbook_id=recommended.id,
            playbook_name=recommended.name,
            confidence=recommended.success_rate,
            alternatives=alternatives,
            pre_checks=pre_checks,
            post_checks=post_checks,
            rollback_procedure=f"Restore from pre-{recommended.id} snapshot"
        )

    async def _determine_approval_chain(
        self,
        vulnerability: Vulnerability,
        impact: ImpactAssessment
    ) -> tuple[List[Dict[str, Any]], bool]:
        """
        Determine the required approval chain based on asset tier and risk.

        Args:
            vulnerability: The vulnerability being remediated
            impact: The impact assessment

        Returns:
            Tuple of (approval_chain, auto_approve_eligible)
        """
        approval_chain = []
        auto_approve = False

        tier = vulnerability.asset.criticality
        severity = vulnerability.severity
        requires_restart = impact.requires_restart

        if tier == AssetCriticality.TIER1:
            # TIER 1: ALWAYS requires human approval
            if severity == Severity.CRITICAL and requires_restart:
                approval_chain = [
                    {"role": ApproverRole.CISO.value, "required": True},
                    {"role": ApproverRole.BUSINESS_OWNER.value, "required": True},
                    {"role": ApproverRole.CAB.value, "required": True}
                ]
            elif severity in [Severity.CRITICAL, Severity.HIGH]:
                approval_chain = [
                    {"role": ApproverRole.SECURITY_LEAD.value, "required": True},
                    {"role": ApproverRole.BUSINESS_OWNER.value, "required": True}
                ]
            else:
                approval_chain = [
                    {"role": ApproverRole.SECURITY_LEAD.value, "required": True}
                ]

        elif tier == AssetCriticality.TIER2:
            if requires_restart:
                approval_chain = [
                    {"role": ApproverRole.SECURITY_LEAD.value, "required": True}
                ]
            else:
                # Can auto-approve with logging
                auto_approve = True

        else:  # TIER3
            if requires_restart:
                approval_chain = [
                    {"role": ApproverRole.SECURITY_LEAD.value, "required": True}
                ]
            else:
                # Can auto-approve with logging
                auto_approve = True

        return approval_chain, auto_approve

    async def _enhance_with_llm(
        self,
        vulnerability: Vulnerability,
        assessment: AssessmentResult
    ) -> AssessmentResult:
        """
        Use LLM to validate and potentially enhance the assessment.

        Args:
            vulnerability: Original vulnerability
            assessment: Initial assessment

        Returns:
            Enhanced assessment result
        """
        prompt = f"""
        Review this vulnerability assessment and provide any additional insights:

        Vulnerability:
        - ID: {vulnerability.id}
        - Title: {vulnerability.title}
        - CVE: {vulnerability.cve}
        - CVSS: {vulnerability.cvss}
        - Asset: {vulnerability.asset.hostname} ({vulnerability.asset.criticality.value})

        Current Assessment:
        - Risk Score: {assessment.risk_score}
        - Service Impact: {assessment.impact_assessment.service_impact.value}
        - Requires Restart: {assessment.impact_assessment.requires_restart}
        - Recommended Playbook: {assessment.suggested_remediation.playbook_id}
        - Approval Required: {assessment.approval_required}

        Are there any additional considerations or risks I should flag?
        Should the approval chain be modified?

        Respond with a JSON object containing:
        - additional_risks: string[] (any additional risks to consider)
        - approval_modifications: string[] (any changes to approval chain)
        - confidence_adjustment: number (-0.1 to 0.1, adjustment to playbook confidence)
        """

        try:
            response = await self._invoke_llm(prompt)

            # Parse response and apply any adjustments
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                enhancements = json.loads(json_match.group())

                # Apply confidence adjustment
                if 'confidence_adjustment' in enhancements:
                    new_confidence = assessment.suggested_remediation.confidence + enhancements['confidence_adjustment']
                    assessment.suggested_remediation.confidence = max(0, min(1, new_confidence))

        except Exception as e:
            logger.warning(f"LLM enhancement failed, using base assessment", error=str(e))

        return assessment

    def _recommend_window(self, vulnerability: Vulnerability) -> str:
        """Recommend a maintenance window based on asset tier"""
        if vulnerability.asset.criticality == AssetCriticality.TIER1:
            return "Sunday 2:00-6:00 AM EST (standard weekly window)"
        elif vulnerability.asset.criticality == AssetCriticality.TIER2:
            return "Saturday 11:00 PM - Sunday 3:00 AM EST"
        else:
            return "Next available window"

    def _get_pre_checks(
        self,
        vulnerability: Vulnerability,
        playbook: Playbook
    ) -> List[str]:
        """Get pre-execution checks for the playbook"""
        checks = [
            "Verify target host connectivity",
            "Confirm backup/snapshot capability",
            "Check disk space availability"
        ]

        if vulnerability.asset.criticality == AssetCriticality.TIER1:
            checks.extend([
                "Verify HA failover is configured",
                "Confirm on-call team availability",
                "Validate rollback procedure"
            ])

        if playbook.requires_restart:
            checks.append("Notify dependent service owners")

        return checks

    def _get_post_checks(
        self,
        vulnerability: Vulnerability,
        playbook: Playbook
    ) -> List[str]:
        """Get post-execution checks for the playbook"""
        checks = [
            "Verify service status",
            "Run health check endpoints",
            "Check application logs for errors"
        ]

        if vulnerability.business_context.transaction_volume > 0:
            checks.append("Monitor transaction processing")

        # Add vulnerability-specific checks
        if 'tls' in vulnerability.title.lower():
            checks.append("Verify TLS version with SSL test")
        if 'cipher' in vulnerability.title.lower():
            checks.append("Verify cipher suite configuration")

        return checks

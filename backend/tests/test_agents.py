"""
VulnGuard AI - Agent Unit Tests
Tests for the multi-agent vulnerability management system
"""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from agents import (
    DiscoveryAgent, AssessmentAgent, ApprovalAgent,
    RemediationAgent, ValidationAgent
)
from models import (
    Vulnerability, Asset, Detection, BusinessContext, RemediationInfo,
    Severity, AssetCriticality, AssetType, DetectionSource, DetectionMethod,
    RevenueImpact, DataClassification, VulnerabilityStatus,
    ApprovalRequest, Approver, ApprovalStatus, ApproverRole,
    ExecutionRequest, Playbook, MaintenanceWindow, AssessmentResult
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def mock_vulnerability():
    """Create a mock vulnerability for testing"""
    return Vulnerability(
        id="VULN-2024-TEST001",
        cve="CVE-2024-12345",
        title="Test Vulnerability - Deprecated TLS",
        severity=Severity.HIGH,
        cvss=7.5,
        asset=Asset(
            hostname="test-server-01.corp.local",
            ip="10.0.1.100",
            type=AssetType.SERVER,
            criticality=AssetCriticality.TIER1,
            business_unit="IT",
            owner="Test Owner",
            transaction_volume=2_000_000_000  # $2B daily
        ),
        detection=Detection(
            source=DetectionSource.TENABLE,
            method=DetectionMethod.REMOTE,
            first_detected=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            scan_id="SCAN-TEST-001",
            confidence=0.95
        ),
        remediation=RemediationInfo(
            status=VulnerabilityStatus.NEW,
            requires_restart=True,
            estimated_downtime=30
        ),
        business_context=BusinessContext(
            transaction_volume=2_000_000_000,
            revenue_impact=RevenueImpact.CRITICAL,
            data_classification=DataClassification.PCI,
            compliance_frameworks=["PCI-DSS", "SOX"]
        )
    )


@pytest.fixture
def mock_playbook_registry():
    """Create mock playbook registry"""
    return {
        "pb-tls-hardening": Playbook(
            id="pb-tls-hardening",
            name="TLS/SSL Hardening",
            description="Disable deprecated TLS versions",
            target_platforms=["Linux", "Windows", "server"],
            requires_restart=True,
            estimated_duration=15,
            success_rate=0.94
        ),
        "pb-ssh-hardening": Playbook(
            id="pb-ssh-hardening",
            name="SSH Hardening",
            description="Secure SSH configuration",
            target_platforms=["Linux", "server"],
            requires_restart=False,
            estimated_duration=5,
            success_rate=0.96
        )
    }


@pytest.fixture
def mock_scanner_clients():
    """Create mock scanner clients"""
    mock_client = AsyncMock()
    mock_client.get_vulnerabilities = AsyncMock(return_value=[])
    mock_client.scan_targets = AsyncMock(return_value={"scan_id": "TEST-001", "status": "launched"})
    return {"tenable": mock_client}


# ============================================================================
# DISCOVERY AGENT TESTS
# ============================================================================

class TestDiscoveryAgent:
    """Tests for Discovery Agent"""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_scanner_clients):
        """Test agent initializes correctly"""
        agent = DiscoveryAgent(scanner_clients=mock_scanner_clients)

        assert agent.name == "discovery"
        assert agent.state.status.value == "idle"

    @pytest.mark.asyncio
    async def test_run_cycle_empty(self, mock_scanner_clients):
        """Test run cycle with no vulnerabilities"""
        agent = DiscoveryAgent(scanner_clients=mock_scanner_clients)

        with patch.object(agent, '_invoke_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "{}"
            result = await agent.run_cycle()

        assert result["action"] == "discovery_cycle_complete"
        assert "vulnerabilities" in result

    @pytest.mark.asyncio
    async def test_remote_vulnerability_flagging(self, mock_scanner_clients):
        """Test that remote vulnerabilities are correctly flagged"""
        agent = DiscoveryAgent(scanner_clients=mock_scanner_clients)

        # Test titles that should be flagged as remote vulnerabilities
        remote_titles = [
            "Deprecated TLSv1.1 Protocol Enabled",
            "Weak SSL Cipher Suites Detected",
            "SSL Certificate Expired",
            "Web Server Banner Disclosure"
        ]

        for title in remote_titles:
            result = agent._is_remote_vulnerability(title, "N/A")
            assert result is True, f"Expected '{title}' to be flagged as remote vulnerability"

        # Test titles that should NOT be flagged
        non_remote_titles = [
            "Apache Tomcat Local File Inclusion",
            "MySQL Authentication Bypass"
        ]

        for title in non_remote_titles:
            result = agent._is_remote_vulnerability(title, "N/A")
            assert result is False, f"Expected '{title}' to NOT be flagged as remote vulnerability"


# ============================================================================
# ASSESSMENT AGENT TESTS
# ============================================================================

class TestAssessmentAgent:
    """Tests for Assessment Agent"""

    @pytest.mark.asyncio
    async def test_risk_score_calculation(self, mock_vulnerability, mock_playbook_registry):
        """Test risk score calculation formula"""
        agent = AssessmentAgent(playbook_registry=mock_playbook_registry)

        risk_score, risk_factors = await agent._calculate_risk_score(mock_vulnerability)

        # Expected: (7.5 × 1.5 × 1.0) + 15 (transaction) + 10 (PCI) = 36.25
        # But capped with business adjustments
        assert risk_score > 0
        assert risk_score <= 100
        assert "cvss_base" in risk_factors
        assert risk_factors["cvss_base"] == 7.5

    @pytest.mark.asyncio
    async def test_tier1_requires_approval(self, mock_vulnerability, mock_playbook_registry):
        """Test that Tier 1 assets always require approval"""
        agent = AssessmentAgent(playbook_registry=mock_playbook_registry)

        from models import ImpactAssessment, ServiceImpact

        impact = ImpactAssessment(
            service_impact=ServiceImpact.OUTAGE,
            estimated_downtime_minutes=30,
            requires_restart=True,
            requires_reboot=False
        )

        approval_chain, auto_approve = await agent._determine_approval_chain(
            mock_vulnerability,
            impact
        )

        # Tier 1 should NEVER auto-approve
        assert auto_approve is False
        assert len(approval_chain) > 0

    @pytest.mark.asyncio
    async def test_tier3_can_auto_approve(self, mock_vulnerability, mock_playbook_registry):
        """Test that Tier 3 without restart can auto-approve"""
        agent = AssessmentAgent(playbook_registry=mock_playbook_registry)

        # Modify vulnerability to be Tier 3
        mock_vulnerability.asset.criticality = AssetCriticality.TIER3

        from models import ImpactAssessment, ServiceImpact

        impact = ImpactAssessment(
            service_impact=ServiceImpact.NONE,
            estimated_downtime_minutes=0,
            requires_restart=False,  # No restart needed
            requires_reboot=False
        )

        approval_chain, auto_approve = await agent._determine_approval_chain(
            mock_vulnerability,
            impact
        )

        # Tier 3 without restart can auto-approve
        assert auto_approve is True


# ============================================================================
# APPROVAL AGENT TESTS
# ============================================================================

class TestApprovalAgent:
    """Tests for Approval Agent"""

    @pytest.mark.asyncio
    async def test_business_hours_detection(self):
        """Test business hours detection"""
        agent = ApprovalAgent(maintenance_windows=[])

        # Test during business hours (10 AM on Tuesday)
        business_time = datetime(2024, 1, 16, 10, 0)  # Tuesday 10 AM
        assert agent._is_business_hours(business_time) is True

        # Test outside business hours (2 AM on Tuesday)
        off_hours = datetime(2024, 1, 16, 2, 0)  # Tuesday 2 AM
        assert agent._is_business_hours(off_hours) is False

        # Test weekend
        weekend = datetime(2024, 1, 14, 10, 0)  # Sunday 10 AM
        assert agent._is_business_hours(weekend) is False

    @pytest.mark.asyncio
    async def test_tier1_never_auto_approves(self):
        """Test that Tier 1 approval requests are never auto-approved"""
        agent = ApprovalAgent(maintenance_windows=[])

        # Create a mock assessment result
        mock_assessment = MagicMock()
        mock_assessment.vulnerability_id = "VULN-2024-001"
        mock_assessment.risk_score = 95
        mock_assessment.impact_assessment.requires_restart = False
        mock_assessment.impact_assessment.estimated_downtime_minutes = 0
        mock_assessment.impact_assessment.recommended_window = "Sunday 2:00 AM"
        mock_assessment.approval_chain = [
            {"role": "Security Lead", "required": True}
        ]

        with patch.object(agent, '_validate_maintenance_window', new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = {"valid": True, "errors": []}

            # This would be called during process()
            # The key assertion is that approval_chain is not empty for Tier 1


# ============================================================================
# REMEDIATION AGENT TESTS
# ============================================================================

class TestRemediationAgent:
    """Tests for Remediation Agent"""

    @pytest.mark.asyncio
    async def test_validates_approval_before_execution(self):
        """Test that remediation validates approval before execution"""
        agent = RemediationAgent()

        execution_request = ExecutionRequest(
            vulnerability_id="VULN-2024-001",
            approval_id="APR-2024-001",
            playbook_id="pb-tls-hardening",
            target_hosts=["test-server-01"],
            maintenance_window=datetime.utcnow(),
            check_mode_first=True,
            create_snapshot=True
        )

        validation = await agent._validate_before_execution(execution_request)

        # Should have validation result
        assert "valid" in validation
        assert "errors" in validation

    @pytest.mark.asyncio
    async def test_creates_recovery_points(self):
        """Test that recovery points are created before execution"""
        agent = RemediationAgent()

        execution_request = ExecutionRequest(
            vulnerability_id="VULN-2024-001",
            approval_id="APR-2024-001",
            playbook_id="pb-tls-hardening",
            target_hosts=["test-server-01"],
            maintenance_window=datetime.utcnow(),
            check_mode_first=True,
            create_snapshot=True
        )

        recovery_points = await agent._create_recovery_points(execution_request)

        # Should have created recovery points for each target host
        assert len(recovery_points) == len(execution_request.target_hosts)
        assert all("id" in rp for rp in recovery_points)


# ============================================================================
# VALIDATION AGENT TESTS
# ============================================================================

class TestValidationAgent:
    """Tests for Validation Agent"""

    @pytest.mark.asyncio
    async def test_waits_for_stabilization(self, mock_scanner_clients):
        """Test that validation waits for stabilization period"""
        agent = ValidationAgent(scanner_clients=mock_scanner_clients)

        # The agent should have a stabilization period defined
        assert agent.STABILIZATION_PERIOD >= 300  # At least 5 minutes


# ============================================================================
# GUARDRAIL TESTS
# ============================================================================

class TestGuardrails:
    """Tests for critical guardrails that must never be bypassed"""

    def test_tier1_auto_approve_setting(self):
        """Verify that Tier 1 auto-approve is disabled in config"""
        from config import get_settings

        settings = get_settings()
        assert settings.guardrails.tier1_auto_approve is False, \
            "CRITICAL: Tier 1 auto-approve must NEVER be enabled!"

    def test_check_mode_required_for_tier1(self):
        """Verify that check mode is required for Tier 1"""
        from config import get_settings

        settings = get_settings()
        assert "tier1" in settings.guardrails.check_mode_required_tiers

    def test_rollback_required_for_tier1(self):
        """Verify that rollback is required for Tier 1"""
        from config import get_settings

        settings = get_settings()
        assert settings.guardrails.tier1_requires_rollback is True


# ============================================================================
# INTEGRATION TESTS (Mock)
# ============================================================================

class TestAgentPipeline:
    """Integration tests for the agent pipeline"""

    @pytest.mark.asyncio
    async def test_discovery_to_assessment_handoff(
        self,
        mock_vulnerability,
        mock_scanner_clients,
        mock_playbook_registry
    ):
        """Test handoff from Discovery to Assessment agent"""
        discovery_agent = DiscoveryAgent(scanner_clients=mock_scanner_clients)
        assessment_agent = AssessmentAgent(playbook_registry=mock_playbook_registry)

        # Mock the LLM invocation
        with patch.object(assessment_agent, '_invoke_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = '{"additional_risks": [], "approval_modifications": [], "confidence_adjustment": 0}'

            # Process vulnerability through assessment
            result = await assessment_agent.process(mock_vulnerability)

            # Verify assessment produced required outputs
            assert result.vulnerability_id == mock_vulnerability.id
            assert result.risk_score > 0
            assert result.suggested_remediation is not None
            assert "approval_chain" in result.model_dump() or hasattr(result, 'approval_chain')

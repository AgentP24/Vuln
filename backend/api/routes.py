"""
VulnGuard AI - API Routes
FastAPI routes for the vulnerability management system
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel

from models import (
    Vulnerability, VulnerabilityCreate, VulnerabilityStatus,
    ApprovalRequest, ApprovalDecision, ApprovalStatus,
    ExecutionRequest, ExecutionResult,
    ValidationResult,
    AssessmentResult,
    AgentStates, AgentState, AgentStatus,
    DashboardStats, PaginatedResponse, AgentActivityLog,
    Playbook, MaintenanceWindow,
    Severity, AssetCriticality
)

# Create routers
vulnerabilities_router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])
approvals_router = APIRouter(prefix="/approvals", tags=["Approvals"])
executions_router = APIRouter(prefix="/executions", tags=["Executions"])
agents_router = APIRouter(prefix="/agents", tags=["Agents"])
playbooks_router = APIRouter(prefix="/playbooks", tags=["Playbooks"])
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ============================================================================
# VULNERABILITY ROUTES
# ============================================================================

@vulnerabilities_router.get("", response_model=PaginatedResponse)
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[Severity] = None,
    status: Optional[VulnerabilityStatus] = None,
    source: Optional[str] = None,
    asset_tier: Optional[AssetCriticality] = None
):
    """
    List vulnerabilities with filtering and pagination.
    """
    # Would query database in production
    # For MVP, return mock data
    mock_vulns = [
        {
            "id": "VULN-2024-001",
            "cve": "CVE-2024-21762",
            "title": "Fortinet FortiOS Out-of-Bound Write",
            "severity": "critical",
            "cvss": 9.8,
            "asset": {
                "hostname": "prod-fw-01.corp.local",
                "ip": "10.0.1.1",
                "type": "network",
                "criticality": "tier1",
                "business_unit": "Infrastructure",
                "owner": "Network Team"
            },
            "detection": {
                "source": "tenable",
                "method": "remote",
                "first_detected": "2024-01-15T08:00:00Z",
                "last_seen": "2024-01-20T14:30:00Z",
                "scan_id": "SCN-78234",
                "confidence": 0.95
            },
            "remediation": {
                "status": "assessed",
                "suggested_fix": "Upgrade FortiOS to 7.4.3 or later",
                "playbook_id": "pb-fortios-upgrade",
                "requires_restart": True,
                "estimated_downtime": 30
            },
            "business_context": {
                "transaction_volume": 0,
                "revenue_impact": "high",
                "data_classification": "pci",
                "compliance_frameworks": ["PCI-DSS", "SOX"]
            },
            "risk_score": 94
        }
    ]

    return PaginatedResponse(
        items=mock_vulns,
        total=len(mock_vulns),
        page=page,
        page_size=page_size,
        pages=1
    )


@vulnerabilities_router.get("/{vuln_id}")
async def get_vulnerability(vuln_id: str):
    """
    Get a specific vulnerability by ID.
    """
    # Would query database
    # For MVP, return mock
    return {
        "id": vuln_id,
        "cve": "CVE-2024-21762",
        "title": "Fortinet FortiOS Out-of-Bound Write",
        "severity": "critical",
        "status": "assessed"
    }


@vulnerabilities_router.post("/{vuln_id}/assess")
async def trigger_assessment(
    vuln_id: str,
    background_tasks: BackgroundTasks
):
    """
    Trigger assessment for a vulnerability.
    """
    # Would trigger Assessment Agent
    background_tasks.add_task(_run_assessment, vuln_id)

    return {
        "message": f"Assessment triggered for {vuln_id}",
        "status": "processing"
    }


async def _run_assessment(vuln_id: str):
    """Background task to run assessment"""
    # Would call AssessmentAgent.process()
    pass


# ============================================================================
# APPROVAL ROUTES
# ============================================================================

@approvals_router.get("", response_model=List[ApprovalRequest])
async def list_approvals(
    status: Optional[ApprovalStatus] = None,
    vulnerability_id: Optional[str] = None
):
    """
    List approval requests.
    """
    return []


@approvals_router.get("/{approval_id}")
async def get_approval(approval_id: str):
    """
    Get a specific approval request.
    """
    return {"id": approval_id, "status": "pending"}


@approvals_router.post("/{approval_id}/decide")
async def submit_decision(
    approval_id: str,
    decision: ApprovalDecision
):
    """
    Submit an approval decision.

    This is where human approvers approve or deny remediation requests.
    """
    # Would call ApprovalAgent.process_decision()
    return {
        "approval_id": approval_id,
        "decision": decision.decision.value,
        "status": "recorded"
    }


@approvals_router.post("/{approval_id}/schedule")
async def schedule_remediation(
    approval_id: str,
    window_id: str = Query(..., description="Maintenance window ID")
):
    """
    Schedule an approved remediation for a maintenance window.
    """
    return {
        "approval_id": approval_id,
        "window_id": window_id,
        "status": "scheduled"
    }


# ============================================================================
# EXECUTION ROUTES
# ============================================================================

@executions_router.get("")
async def list_executions(
    status: Optional[str] = None,
    vulnerability_id: Optional[str] = None
):
    """
    List remediation executions.
    """
    return []


@executions_router.get("/{execution_id}")
async def get_execution(execution_id: str):
    """
    Get execution details.
    """
    return {"id": execution_id, "status": "pending"}


@executions_router.post("/{execution_id}/start")
async def start_execution(
    execution_id: str,
    background_tasks: BackgroundTasks
):
    """
    Start a scheduled execution.

    GUARDRAILS:
    - Must have valid approval
    - Must be within maintenance window
    """
    background_tasks.add_task(_run_execution, execution_id)
    return {"execution_id": execution_id, "status": "starting"}


async def _run_execution(execution_id: str):
    """Background task to run execution"""
    # Would call RemediationAgent.process()
    pass


@executions_router.post("/{execution_id}/cancel")
async def cancel_execution(execution_id: str):
    """
    Cancel a running execution.
    """
    return {"execution_id": execution_id, "status": "canceled"}


# ============================================================================
# AGENT ROUTES
# ============================================================================

@agents_router.get("/status")
async def get_agent_status() -> AgentStates:
    """
    Get current status of all agents.
    """
    return AgentStates(
        discovery=AgentState(
            agent_name="discovery",
            status=AgentStatus.RUNNING,
            last_run=datetime.utcnow(),
            metrics={"vulns_found": 6, "sources_polled": 4}
        ),
        assessment=AgentState(
            agent_name="assessment",
            status=AgentStatus.IDLE,
            metrics={"pending_review": 2}
        ),
        approval=AgentState(
            agent_name="approval",
            status=AgentStatus.AWAITING,
            metrics={"pending_approvals": 3}
        ),
        remediation=AgentState(
            agent_name="remediation",
            status=AgentStatus.SCHEDULED,
            metrics={"active_jobs": 1}
        ),
        validation=AgentState(
            agent_name="validation",
            status=AgentStatus.IDLE,
            metrics={"pending_validation": 1}
        )
    )


@agents_router.get("/activity")
async def get_agent_activity(
    limit: int = Query(50, ge=1, le=200),
    agent: Optional[str] = None
) -> List[AgentActivityLog]:
    """
    Get recent agent activity logs.
    """
    # Would query activity log table
    return [
        AgentActivityLog(
            timestamp=datetime.utcnow(),
            agent="discovery",
            action="vulnerability_discovered",
            message="Retrieved 3 new findings from Tenable scan",
            vulnerability_id="VULN-2024-001"
        )
    ]


@agents_router.post("/{agent_name}/trigger")
async def trigger_agent_cycle(
    agent_name: str,
    background_tasks: BackgroundTasks
):
    """
    Manually trigger an agent cycle.
    """
    valid_agents = ["discovery", "assessment", "approval", "remediation", "validation"]
    if agent_name not in valid_agents:
        raise HTTPException(status_code=400, detail=f"Invalid agent: {agent_name}")

    background_tasks.add_task(_run_agent_cycle, agent_name)

    return {
        "agent": agent_name,
        "status": "triggered"
    }


async def _run_agent_cycle(agent_name: str):
    """Background task to run agent cycle"""
    # Would call agent.run_cycle()
    pass


@agents_router.get("/{agent_name}/prompt")
async def get_agent_prompt(agent_name: str) -> dict:
    """
    Get the system prompt for an agent.
    """
    from agents import (
        DISCOVERY_AGENT_PROMPT, ASSESSMENT_AGENT_PROMPT,
        APPROVAL_AGENT_PROMPT, REMEDIATION_AGENT_PROMPT,
        VALIDATION_AGENT_PROMPT
    )

    prompts = {
        "discovery": DISCOVERY_AGENT_PROMPT,
        "assessment": ASSESSMENT_AGENT_PROMPT,
        "approval": APPROVAL_AGENT_PROMPT,
        "remediation": REMEDIATION_AGENT_PROMPT,
        "validation": VALIDATION_AGENT_PROMPT
    }

    if agent_name not in prompts:
        raise HTTPException(status_code=404, detail=f"Agent {agent_name} not found")

    return {
        "agent": agent_name,
        "prompt": prompts[agent_name]
    }


# ============================================================================
# PLAYBOOK ROUTES
# ============================================================================

@playbooks_router.get("", response_model=List[Playbook])
async def list_playbooks():
    """
    List available Ansible playbooks.
    """
    return [
        Playbook(
            id="pb-tls-hardening",
            name="TLS/SSL Hardening",
            description="Disable deprecated TLS versions and weak cipher suites",
            target_platforms=["Linux", "Windows"],
            requires_restart=True,
            estimated_duration=15,
            supports_check_mode=True,
            supports_rollback=True,
            success_rate=0.94,
            tags=["tls", "ssl", "cipher", "security"]
        ),
        Playbook(
            id="pb-ssh-hardening",
            name="SSH Configuration Hardening",
            description="Remove weak ciphers and enforce secure SSH configuration",
            target_platforms=["Linux"],
            requires_restart=False,
            estimated_duration=5,
            supports_check_mode=True,
            supports_rollback=True,
            success_rate=0.96,
            tags=["ssh", "cipher", "security"]
        ),
        Playbook(
            id="pb-nginx-http2-fix",
            name="Nginx HTTP/2 Security Patch",
            description="Apply HTTP/2 Rapid Reset mitigation and rate limiting",
            target_platforms=["Linux"],
            requires_restart=True,
            estimated_duration=10,
            supports_check_mode=True,
            supports_rollback=True,
            success_rate=0.92,
            tags=["nginx", "http2", "dos", "security"]
        )
    ]


@playbooks_router.get("/{playbook_id}")
async def get_playbook(playbook_id: str) -> Playbook:
    """
    Get playbook details.
    """
    playbooks = await list_playbooks()
    for pb in playbooks:
        if pb.id == playbook_id:
            return pb
    raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")


# ============================================================================
# DASHBOARD ROUTES
# ============================================================================

@dashboard_router.get("/stats")
async def get_dashboard_stats() -> DashboardStats:
    """
    Get dashboard statistics.
    """
    return DashboardStats(
        total_vulnerabilities=156,
        critical_count=12,
        high_count=34,
        medium_count=67,
        low_count=43,
        pending_approval=8,
        scheduled=5,
        in_progress=2,
        resolved_this_week=23,
        mttr_hours=48.5
    )


@dashboard_router.get("/maintenance-windows")
async def get_maintenance_windows() -> List[MaintenanceWindow]:
    """
    Get upcoming maintenance windows.
    """
    return [
        MaintenanceWindow(
            id="mw-weekly-sunday",
            name="Standard Weekly Window",
            start_time=datetime(2024, 1, 21, 2, 0),
            end_time=datetime(2024, 1, 21, 6, 0),
            recurring=True,
            recurrence_pattern="weekly:sunday"
        ),
        MaintenanceWindow(
            id="mw-saturday-night",
            name="Saturday Night Window",
            start_time=datetime(2024, 1, 20, 23, 0),
            end_time=datetime(2024, 1, 21, 3, 0),
            recurring=True,
            recurrence_pattern="weekly:saturday"
        )
    ]

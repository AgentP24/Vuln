"""
VulnGuard AI - Pydantic Schemas
Data models for API requests/responses and internal processing
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


# ============================================================================
# ENUMS
# ============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetCriticality(str, Enum):
    TIER1 = "tier1"
    TIER2 = "tier2"
    TIER3 = "tier3"


class AssetType(str, Enum):
    SERVER = "server"
    DATABASE = "database"
    CLOUD = "cloud"
    NETWORK = "network"


class DetectionSource(str, Enum):
    QUALYS = "qualys"
    TENABLE = "tenable"
    RAPID7 = "rapid7"
    GUARDIUM = "guardium"


class DetectionMethod(str, Enum):
    AGENT = "agent"
    REMOTE = "remote"
    UNAUTHENTICATED = "unauthenticated"


class VulnerabilityStatus(str, Enum):
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


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApproverRole(str, Enum):
    SECURITY_LEAD = "Security Lead"
    BUSINESS_OWNER = "Business Owner"
    CAB = "CAB"
    CISO = "CISO"
    CHANGE_MANAGER = "Change Manager"


class RevenueImpact(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataClassification(str, Enum):
    PII = "pii"
    PCI = "pci"
    PHI = "phi"
    PUBLIC = "public"


class ServiceImpact(str, Enum):
    NONE = "none"
    DEGRADED = "degraded"
    OUTAGE = "outage"


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    AWAITING = "awaiting"
    SCHEDULED = "scheduled"
    EXECUTING = "executing"


# ============================================================================
# ASSET SCHEMAS
# ============================================================================

class Asset(BaseModel):
    """Asset information from CMDB"""
    hostname: str
    ip: str
    asset_type: AssetType = Field(alias="type")
    criticality: AssetCriticality
    business_unit: str
    owner: str
    transaction_volume: Optional[float] = 0  # Daily transaction volume in USD

    class Config:
        populate_by_name = True


# ============================================================================
# DETECTION SCHEMAS
# ============================================================================

class Detection(BaseModel):
    """How the vulnerability was detected"""
    source: DetectionSource
    method: DetectionMethod
    first_detected: datetime
    last_seen: datetime
    scan_id: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)


# ============================================================================
# BUSINESS CONTEXT SCHEMAS
# ============================================================================

class BusinessContext(BaseModel):
    """Business impact context"""
    transaction_volume: float = 0  # Daily USD
    revenue_impact: RevenueImpact
    data_classification: DataClassification
    compliance_frameworks: List[str] = []


# ============================================================================
# REMEDIATION SCHEMAS
# ============================================================================

class RemediationInfo(BaseModel):
    """Remediation status and plan"""
    status: VulnerabilityStatus = VulnerabilityStatus.NEW
    suggested_fix: Optional[str] = None
    playbook_id: Optional[str] = None
    requires_restart: bool = False
    estimated_downtime: int = 0  # minutes
    maintenance_window: Optional[datetime] = None


# ============================================================================
# VULNERABILITY SCHEMAS
# ============================================================================

class VulnerabilityBase(BaseModel):
    """Base vulnerability model"""
    cve: str = "N/A"
    title: str
    severity: Severity
    cvss: float = Field(ge=0.0, le=10.0)


class VulnerabilityCreate(VulnerabilityBase):
    """Schema for creating a new vulnerability"""
    asset: Asset
    detection: Detection
    business_context: Optional[BusinessContext] = None


class Vulnerability(VulnerabilityBase):
    """Full vulnerability model"""
    id: str
    asset: Asset
    detection: Detection
    remediation: RemediationInfo = Field(default_factory=RemediationInfo)
    business_context: BusinessContext
    risk_score: Optional[float] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True


# ============================================================================
# APPROVAL SCHEMAS
# ============================================================================

class Approver(BaseModel):
    """Individual approver in the approval chain"""
    role: ApproverRole
    name: Optional[str] = None
    email: Optional[str] = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    timestamp: Optional[datetime] = None
    comments: Optional[str] = None
    conditions: List[str] = []


class ApprovalRequest(BaseModel):
    """Approval request for remediation"""
    id: str
    vulnerability_id: str
    risk_score: float
    asset_tier: AssetCriticality
    requires_restart: bool
    estimated_downtime: int
    approval_chain: List[Approver]
    requested_window: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


class ApprovalDecision(BaseModel):
    """Schema for submitting an approval decision"""
    approval_id: str
    approver_role: ApproverRole
    decision: ApprovalStatus
    comments: Optional[str] = None
    conditions: List[str] = []
    scheduled_window: Optional[datetime] = None


# ============================================================================
# IMPACT ASSESSMENT SCHEMAS
# ============================================================================

class ImpactAssessment(BaseModel):
    """Detailed impact assessment from Assessment Agent"""
    service_impact: ServiceImpact
    estimated_downtime_minutes: int
    requires_restart: bool
    requires_reboot: bool = False
    affected_dependencies: List[str] = []
    cascading_impact: Optional[str] = None
    revenue_at_risk: Optional[str] = None
    recommended_window: Optional[str] = None


class PlaybookRecommendation(BaseModel):
    """Playbook recommendation from Assessment Agent"""
    playbook_id: str
    playbook_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    alternatives: List[str] = []
    pre_checks: List[str] = []
    post_checks: List[str] = []
    rollback_procedure: Optional[str] = None


class AssessmentResult(BaseModel):
    """Complete assessment result"""
    vulnerability_id: str
    risk_score: float = Field(ge=0, le=100)
    risk_factors: Dict[str, Any]
    impact_assessment: ImpactAssessment
    suggested_remediation: PlaybookRecommendation
    approval_required: bool
    approval_chain: List[Dict[str, Any]]
    auto_approve_eligible: bool = False
    auto_approve_reason: Optional[str] = None


# ============================================================================
# EXECUTION SCHEMAS
# ============================================================================

class ExecutionRequest(BaseModel):
    """Request to execute a remediation"""
    vulnerability_id: str
    approval_id: str
    playbook_id: str
    target_hosts: List[str]
    maintenance_window: datetime
    check_mode_first: bool = True
    create_snapshot: bool = True


class ExecutionResult(BaseModel):
    """Result of remediation execution"""
    execution_id: str
    vulnerability_id: str
    approval_id: str
    playbook_id: str
    target_hosts: List[str]
    status: str  # success, failed, rolled_back
    check_mode_results: Optional[Dict[str, Any]] = None
    apply_results: Optional[Dict[str, Any]] = None
    health_checks: Optional[Dict[str, Any]] = None
    recovery_points: List[Dict[str, Any]] = []
    rollback_executed: bool = False
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


# ============================================================================
# VALIDATION SCHEMAS
# ============================================================================

class ValidationResult(BaseModel):
    """Result of post-remediation validation"""
    validation_id: str
    vulnerability_id: str
    execution_id: str
    scan_results: Dict[str, Any]
    validation_status: str  # resolved, partially_resolved, persists, new_issues
    health_checks: Dict[str, Any]
    regression_check: Dict[str, Any]
    playbook_effectiveness: Dict[str, Any]
    follow_up_required: bool = False
    follow_up_reason: Optional[str] = None
    validated_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# AGENT STATE SCHEMAS
# ============================================================================

class AgentState(BaseModel):
    """Current state of an AI agent"""
    agent_name: str
    status: AgentStatus
    last_run: Optional[datetime] = None
    metrics: Dict[str, Any] = {}
    current_task: Optional[str] = None
    error_message: Optional[str] = None


class AgentStates(BaseModel):
    """All agent states"""
    discovery: AgentState
    assessment: AgentState
    approval: AgentState
    remediation: AgentState
    validation: AgentState


# ============================================================================
# PLAYBOOK SCHEMAS
# ============================================================================

class Playbook(BaseModel):
    """Ansible playbook definition"""
    id: str
    name: str
    description: str
    target_platforms: List[str]
    requires_restart: bool
    estimated_duration: int  # minutes
    supports_check_mode: bool = True
    supports_rollback: bool = True
    success_rate: float = Field(ge=0.0, le=1.0, default=0.0)
    last_used: Optional[datetime] = None
    tags: List[str] = []


# ============================================================================
# MAINTENANCE WINDOW SCHEMAS
# ============================================================================

class MaintenanceWindow(BaseModel):
    """Maintenance window definition"""
    id: str
    name: str
    start_time: datetime
    end_time: datetime
    business_unit: Optional[str] = None
    recurring: bool = False
    recurrence_pattern: Optional[str] = None  # e.g., "weekly:sunday"


# ============================================================================
# API RESPONSE SCHEMAS
# ============================================================================

class PaginatedResponse(BaseModel):
    """Generic paginated response"""
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int


class AgentActivityLog(BaseModel):
    """Activity log entry from agents"""
    timestamp: datetime
    agent: str
    action: str
    message: str
    vulnerability_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    pending_approval: int
    scheduled: int
    in_progress: int
    resolved_this_week: int
    mttr_hours: float  # Mean Time To Remediate

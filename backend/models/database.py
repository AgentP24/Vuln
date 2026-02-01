"""
VulnGuard AI - SQLAlchemy Database Models
Database ORM models for persistent storage
"""
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, JSON, Enum as SQLEnum, Index
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import enum

Base = declarative_base()


# ============================================================================
# ENUMS (Matching Pydantic schemas)
# ============================================================================

class SeverityEnum(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetCriticalityEnum(enum.Enum):
    TIER1 = "tier1"
    TIER2 = "tier2"
    TIER3 = "tier3"


class VulnerabilityStatusEnum(enum.Enum):
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


class ApprovalStatusEnum(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


# ============================================================================
# ASSET MODEL
# ============================================================================

class AssetModel(Base):
    """Asset/Host information"""
    __tablename__ = "assets"

    id = Column(String(64), primary_key=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    asset_type = Column(String(50), nullable=False)
    criticality = Column(SQLEnum(AssetCriticalityEnum), nullable=False, index=True)
    business_unit = Column(String(100), nullable=False)
    owner = Column(String(255), nullable=False)
    transaction_volume = Column(Float, default=0)
    data_classification = Column(String(50))
    compliance_frameworks = Column(JSON, default=list)
    cmdb_id = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerabilities = relationship("VulnerabilityModel", back_populates="asset")

    __table_args__ = (
        Index("ix_assets_hostname_ip", "hostname", "ip_address"),
    )


# ============================================================================
# VULNERABILITY MODEL
# ============================================================================

class VulnerabilityModel(Base):
    """Vulnerability findings"""
    __tablename__ = "vulnerabilities"

    id = Column(String(64), primary_key=True)  # VULN-YYYY-XXXX
    cve = Column(String(50), index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(SeverityEnum), nullable=False, index=True)
    cvss = Column(Float, nullable=False)
    risk_score = Column(Float)

    # Asset relationship
    asset_id = Column(String(64), ForeignKey("assets.id"), nullable=False)
    asset = relationship("AssetModel", back_populates="vulnerabilities")

    # Detection info
    detection_source = Column(String(50), nullable=False)  # qualys, tenable, etc.
    detection_method = Column(String(50), nullable=False)  # agent, remote, unauthenticated
    scan_id = Column(String(100))
    first_detected = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    detection_confidence = Column(Float, default=0.9)

    # Remediation info
    status = Column(SQLEnum(VulnerabilityStatusEnum), default=VulnerabilityStatusEnum.NEW, index=True)
    suggested_fix = Column(Text)
    playbook_id = Column(String(100), ForeignKey("playbooks.id"))
    requires_restart = Column(Boolean, default=False)
    estimated_downtime = Column(Integer, default=0)  # minutes
    scheduled_window = Column(DateTime)

    # Business context
    revenue_impact = Column(String(50))

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    approvals = relationship("ApprovalModel", back_populates="vulnerability")
    executions = relationship("ExecutionModel", back_populates="vulnerability")
    playbook = relationship("PlaybookModel", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vuln_severity_status", "severity", "status"),
        Index("ix_vuln_detection", "detection_source", "first_detected"),
    )


# ============================================================================
# APPROVAL MODEL
# ============================================================================

class ApprovalModel(Base):
    """Approval requests and decisions"""
    __tablename__ = "approvals"

    id = Column(String(64), primary_key=True)  # APR-YYYY-XXXX
    vulnerability_id = Column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    vulnerability = relationship("VulnerabilityModel", back_populates="approvals")

    # Request details
    risk_score = Column(Float, nullable=False)
    asset_tier = Column(SQLEnum(AssetCriticalityEnum), nullable=False)
    requires_restart = Column(Boolean, default=False)
    estimated_downtime = Column(Integer, default=0)

    # Approval chain (JSON array of approvers)
    approval_chain = Column(JSON, nullable=False)

    # Status
    status = Column(SQLEnum(ApprovalStatusEnum), default=ApprovalStatusEnum.PENDING, index=True)

    # Scheduling
    requested_window = Column(DateTime)
    approved_window = Column(DateTime)
    conditions = Column(JSON, default=list)  # Conditions attached by approvers

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    completed_at = Column(DateTime)

    __table_args__ = (
        Index("ix_approval_status_created", "status", "created_at"),
    )


# ============================================================================
# EXECUTION MODEL
# ============================================================================

class ExecutionModel(Base):
    """Remediation execution records"""
    __tablename__ = "executions"

    id = Column(String(64), primary_key=True)  # EXEC-YYYY-XXXX
    vulnerability_id = Column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    vulnerability = relationship("VulnerabilityModel", back_populates="executions")

    approval_id = Column(String(64), ForeignKey("approvals.id"), nullable=False)
    playbook_id = Column(String(100), ForeignKey("playbooks.id"), nullable=False)

    # Execution details
    target_hosts = Column(JSON, nullable=False)
    maintenance_window_start = Column(DateTime, nullable=False)
    maintenance_window_end = Column(DateTime, nullable=False)

    # Results
    status = Column(String(50), default="pending")  # pending, running, success, failed, rolled_back
    check_mode_results = Column(JSON)
    apply_results = Column(JSON)
    health_checks = Column(JSON)
    recovery_points = Column(JSON, default=list)
    rollback_executed = Column(Boolean, default=False)
    error_message = Column(Text)

    # Ansible job tracking
    ansible_job_id = Column(String(100))
    ansible_job_status = Column(String(50))

    # Timestamps
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    playbook = relationship("PlaybookModel")

    __table_args__ = (
        Index("ix_exec_status_started", "status", "started_at"),
    )


# ============================================================================
# VALIDATION MODEL
# ============================================================================

class ValidationModel(Base):
    """Post-remediation validation records"""
    __tablename__ = "validations"

    id = Column(String(64), primary_key=True)  # VAL-YYYY-XXXX
    vulnerability_id = Column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    execution_id = Column(String(64), ForeignKey("executions.id"), nullable=False)

    # Scan results
    scanner_used = Column(String(50), nullable=False)
    scan_id = Column(String(100))
    pre_fix_state = Column(JSON)
    post_fix_state = Column(JSON)

    # Validation status
    status = Column(String(50), nullable=False)  # resolved, partially_resolved, persists, new_issues

    # Health checks
    health_check_results = Column(JSON)
    regression_detected = Column(Boolean, default=False)
    new_vulnerabilities = Column(JSON, default=list)

    # Playbook feedback
    playbook_success = Column(Boolean)
    playbook_effectiveness_score = Column(Float)

    # Follow-up
    follow_up_required = Column(Boolean, default=False)
    follow_up_reason = Column(Text)

    # Timestamps
    validated_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


# ============================================================================
# PLAYBOOK MODEL
# ============================================================================

class PlaybookModel(Base):
    """Ansible playbook registry"""
    __tablename__ = "playbooks"

    id = Column(String(100), primary_key=True)  # pb-tls-hardening
    name = Column(String(255), nullable=False)
    description = Column(Text)
    target_platforms = Column(JSON, nullable=False)  # ['Linux', 'Windows']
    requires_restart = Column(Boolean, default=False)
    estimated_duration = Column(Integer, default=30)  # minutes
    supports_check_mode = Column(Boolean, default=True)
    supports_rollback = Column(Boolean, default=True)

    # Effectiveness tracking
    total_executions = Column(Integer, default=0)
    successful_executions = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)
    average_duration = Column(Float)

    # Metadata
    tags = Column(JSON, default=list)
    ansible_tower_template_id = Column(Integer)
    last_used = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vulnerabilities = relationship("VulnerabilityModel", back_populates="playbook")


# ============================================================================
# MAINTENANCE WINDOW MODEL
# ============================================================================

class MaintenanceWindowModel(Base):
    """Maintenance window definitions"""
    __tablename__ = "maintenance_windows"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    business_unit = Column(String(100))
    asset_tier = Column(SQLEnum(AssetCriticalityEnum))
    recurring = Column(Boolean, default=False)
    recurrence_pattern = Column(String(100))  # weekly:sunday, monthly:first_sunday
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ============================================================================
# AUDIT LOG MODEL
# ============================================================================

class AuditLogModel(Base):
    """Audit trail for all actions"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    agent = Column(String(50), nullable=False, index=True)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(50))  # vulnerability, approval, execution
    entity_id = Column(String(64))
    user_id = Column(String(100))
    details = Column(JSON)
    ip_address = Column(String(45))

    __table_args__ = (
        Index("ix_audit_agent_action", "agent", "action"),
        Index("ix_audit_entity", "entity_type", "entity_id"),
    )


# ============================================================================
# DATABASE SESSION MANAGEMENT
# ============================================================================

class DatabaseManager:
    """Async database session manager"""

    def __init__(self, database_url: str):
        self.engine = create_async_engine(
            database_url,
            echo=False,
            pool_size=10,
            max_overflow=20
        )
        self.async_session = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    async def create_tables(self):
        """Create all tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def get_session(self) -> AsyncSession:
        """Get a new database session"""
        async with self.async_session() as session:
            yield session

-- VulnGuard AI - Database Initialization Script
-- This script sets up the initial database schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum types
CREATE TYPE severity_enum AS ENUM ('critical', 'high', 'medium', 'low');
CREATE TYPE asset_criticality_enum AS ENUM ('tier1', 'tier2', 'tier3');
CREATE TYPE vulnerability_status_enum AS ENUM (
    'new', 'assessed', 'pending_approval', 'approved',
    'scheduled', 'in_progress', 'completed', 'validated',
    'exception', 'failed'
);
CREATE TYPE approval_status_enum AS ENUM ('pending', 'approved', 'denied', 'expired');

-- Assets table
CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    asset_type VARCHAR(50) NOT NULL,
    criticality asset_criticality_enum NOT NULL,
    business_unit VARCHAR(100) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    transaction_volume FLOAT DEFAULT 0,
    data_classification VARCHAR(50),
    compliance_frameworks JSONB DEFAULT '[]',
    cmdb_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_assets_hostname_ip ON assets(hostname, ip_address);
CREATE INDEX idx_assets_criticality ON assets(criticality);

-- Playbooks table
CREATE TABLE IF NOT EXISTS playbooks (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_platforms JSONB NOT NULL,
    requires_restart BOOLEAN DEFAULT FALSE,
    estimated_duration INTEGER DEFAULT 30,
    supports_check_mode BOOLEAN DEFAULT TRUE,
    supports_rollback BOOLEAN DEFAULT TRUE,
    total_executions INTEGER DEFAULT 0,
    successful_executions INTEGER DEFAULT 0,
    success_rate FLOAT DEFAULT 0.0,
    average_duration FLOAT,
    tags JSONB DEFAULT '[]',
    ansible_tower_template_id INTEGER,
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id VARCHAR(64) PRIMARY KEY,
    cve VARCHAR(50),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity_enum NOT NULL,
    cvss FLOAT NOT NULL,
    risk_score FLOAT,
    asset_id VARCHAR(64) REFERENCES assets(id),
    detection_source VARCHAR(50) NOT NULL,
    detection_method VARCHAR(50) NOT NULL,
    scan_id VARCHAR(100),
    first_detected TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    detection_confidence FLOAT DEFAULT 0.9,
    status vulnerability_status_enum DEFAULT 'new',
    suggested_fix TEXT,
    playbook_id VARCHAR(100) REFERENCES playbooks(id),
    requires_restart BOOLEAN DEFAULT FALSE,
    estimated_downtime INTEGER DEFAULT 0,
    scheduled_window TIMESTAMP,
    revenue_impact VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vuln_severity_status ON vulnerabilities(severity, status);
CREATE INDEX idx_vuln_detection ON vulnerabilities(detection_source, first_detected);
CREATE INDEX idx_vuln_cve ON vulnerabilities(cve);

-- Approvals table
CREATE TABLE IF NOT EXISTS approvals (
    id VARCHAR(64) PRIMARY KEY,
    vulnerability_id VARCHAR(64) REFERENCES vulnerabilities(id),
    risk_score FLOAT NOT NULL,
    asset_tier asset_criticality_enum NOT NULL,
    requires_restart BOOLEAN DEFAULT FALSE,
    estimated_downtime INTEGER DEFAULT 0,
    approval_chain JSONB NOT NULL,
    status approval_status_enum DEFAULT 'pending',
    requested_window TIMESTAMP,
    approved_window TIMESTAMP,
    conditions JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_approval_status ON approvals(status, created_at);

-- Executions table
CREATE TABLE IF NOT EXISTS executions (
    id VARCHAR(64) PRIMARY KEY,
    vulnerability_id VARCHAR(64) REFERENCES vulnerabilities(id),
    approval_id VARCHAR(64) REFERENCES approvals(id),
    playbook_id VARCHAR(100) REFERENCES playbooks(id),
    target_hosts JSONB NOT NULL,
    maintenance_window_start TIMESTAMP NOT NULL,
    maintenance_window_end TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    check_mode_results JSONB,
    apply_results JSONB,
    health_checks JSONB,
    recovery_points JSONB DEFAULT '[]',
    rollback_executed BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    ansible_job_id VARCHAR(100),
    ansible_job_status VARCHAR(50),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_exec_status ON executions(status, started_at);

-- Validations table
CREATE TABLE IF NOT EXISTS validations (
    id VARCHAR(64) PRIMARY KEY,
    vulnerability_id VARCHAR(64) REFERENCES vulnerabilities(id),
    execution_id VARCHAR(64) REFERENCES executions(id),
    scanner_used VARCHAR(50) NOT NULL,
    scan_id VARCHAR(100),
    pre_fix_state JSONB,
    post_fix_state JSONB,
    status VARCHAR(50) NOT NULL,
    health_check_results JSONB,
    regression_detected BOOLEAN DEFAULT FALSE,
    new_vulnerabilities JSONB DEFAULT '[]',
    playbook_success BOOLEAN,
    playbook_effectiveness_score FLOAT,
    follow_up_required BOOLEAN DEFAULT FALSE,
    follow_up_reason TEXT,
    validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Maintenance windows table
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    business_unit VARCHAR(100),
    asset_tier asset_criticality_enum,
    recurring BOOLEAN DEFAULT FALSE,
    recurrence_pattern VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    agent VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id VARCHAR(64),
    user_id VARCHAR(100),
    details JSONB,
    ip_address VARCHAR(45)
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_agent ON audit_logs(agent, action);
CREATE INDEX idx_audit_entity ON audit_logs(entity_type, entity_id);

-- Insert default playbooks
INSERT INTO playbooks (id, name, description, target_platforms, requires_restart, estimated_duration, success_rate, tags)
VALUES
    ('pb-tls-hardening', 'TLS/SSL Hardening', 'Disable deprecated TLS versions and weak cipher suites', '["Linux", "Windows"]', true, 15, 0.94, '["tls", "ssl", "cipher"]'),
    ('pb-ssh-hardening', 'SSH Configuration Hardening', 'Remove weak ciphers and enforce secure SSH configuration', '["Linux"]', false, 5, 0.96, '["ssh", "cipher"]'),
    ('pb-nginx-http2-fix', 'Nginx HTTP/2 Security Patch', 'Apply HTTP/2 Rapid Reset mitigation and rate limiting', '["Linux"]', true, 10, 0.92, '["nginx", "http2"]'),
    ('pb-fortios-upgrade', 'FortiOS Firmware Upgrade', 'Upgrade FortiOS to latest security patch version', '["FortiGate"]', true, 30, 0.88, '["fortinet", "firmware"]'),
    ('pb-generic-patch', 'Generic Security Patch', 'Generic patch application playbook', '["Linux", "Windows"]', true, 30, 0.85, '["generic", "patch"]')
ON CONFLICT (id) DO NOTHING;

-- Insert default maintenance windows
INSERT INTO maintenance_windows (id, name, description, start_time, end_time, recurring, recurrence_pattern)
VALUES
    ('mw-weekly-sunday', 'Standard Weekly Window', 'Primary maintenance window - Sunday early morning', '2024-01-21 02:00:00', '2024-01-21 06:00:00', true, 'weekly:sunday'),
    ('mw-saturday-night', 'Saturday Night Window', 'Secondary maintenance window', '2024-01-20 23:00:00', '2024-01-21 03:00:00', true, 'weekly:saturday')
ON CONFLICT (id) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vulnguard;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vulnguard;

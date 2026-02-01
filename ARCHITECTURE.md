# VulnGuard AI: Multi-Agent Vulnerability Management System
## Architecture Documentation v1.0 (MVP)

---

## Executive Summary

VulnGuard AI is a multi-agent system designed to automate vulnerability management while maintaining strict human oversight for production environments. The system addresses the core challenge: **vulnerabilities are easily detected but hard to fix safely**, especially remote vulnerabilities like deprecated TLS versions, weak ciphers, and web server misconfigurations.

### Key Design Principles

1. **Human-in-the-Loop for Critical Decisions** - No autonomous changes to Tier 1 production systems
2. **Maintenance Window Awareness** - All remediations scheduled around business impact
3. **Ansible as the Remediation Bridge** - Standardized, auditable playbooks
4. **Multi-Source Aggregation** - Unified view from Qualys, Tenable, Rapid7, Guardium
5. **Continuous Validation Loop** - Feedback mechanism to verify fixes

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VulnGuard AI Platform                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│   │  Discovery  │───▶│ Assessment  │───▶│  Approval   │───▶│ Remediation │  │
│   │    Agent    │    │    Agent    │    │    Agent    │    │    Agent    │  │
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘  │
│          │                  │                  │                  │         │
│          │                  │                  │                  │         │
│          ▼                  ▼                  ▼                  ▼         │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                    Shared Knowledge Base                         │      │
│   │  • Vulnerability Database    • Asset Inventory (CMDB)           │      │
│   │  • Business Context          • Remediation History               │      │
│   │  • Playbook Registry         • Approval Audit Log               │      │
│   └──────────────────────────────────────────────────────────────────┘      │
│          │                                                     │            │
│          ▼                                                     ▼            │
│   ┌─────────────┐                                       ┌─────────────┐     │
│   │ Validation  │◀──────── Feedback Loop ───────────────│   Ansible   │     │
│   │    Agent    │                                       │   Tower     │     │
│   └─────────────┘                                       └─────────────┘     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                                    │
                    ▼                                    ▼
        ┌───────────────────────┐            ┌───────────────────────┐
        │   Scanning Platforms   │            │    ITSM Integration   │
        │  • Qualys              │            │  • ServiceNow         │
        │  • Tenable             │            │  • Jira               │
        │  • Rapid7              │            │  • Change Management  │
        │  • IBM Guardium        │            │  • Maintenance Cal.   │
        └───────────────────────┘            └───────────────────────┘
```

---

## The Five-Agent Architecture

Based on your diagram and requirements, the system implements five specialized AI agents that work in a pipeline, with human checkpoints at critical junctures:

### Agent 1: Discovery Agent

**Role**: Continuously retrieve and normalize vulnerability data from scanning platforms.

**Why This Agent Exists**: 
- Scanner platforms (Qualys, Tenable, Rapid7, Guardium) each have different APIs, data formats, and detection capabilities
- Agent-based scanning detects different vulnerabilities than remote/unauthenticated scans
- Need unified view regardless of source

**Data Sources**:
| Platform | Detection Method | Primary Use Case |
|----------|-----------------|------------------|
| Qualys | Agents, Connectors, Network Scanners | OS vulns, compliance |
| Tenable | Agents, Nessus Scanners | Network vulns, CVEs |
| Rapid7 | Agents, InsightVM | Web app vulns, exposure |
| IBM Guardium | S-TAP, VA Module | Database vulnerabilities |

**Special Focus - Remote Vulnerabilities**:
These are flagged for special handling because they're "easily detected but hard to fix":
- Weak cipher suites (RC4, DES, 3DES)
- Deprecated SSL/TLS versions (SSLv3, TLSv1.0, TLSv1.1)
- Web server vulnerabilities
- Banner grabbing vulnerabilities
- Certificate issues

---

### Agent 2: Assessment Agent

**Role**: Analyze vulnerabilities and determine business impact and remediation complexity.

**Why This Agent Exists**:
- CVSS scores alone don't capture business context
- A medium CVSS vuln on a $1B/day transaction server is more critical than a high CVSS on a dev box
- Need to understand if fix requires restart (service interruption)
- Must identify correct Ansible playbook

**Risk Scoring Formula**:
```
Risk Score = (CVSS_Base × Asset_Criticality_Multiplier × Exposure_Factor) 
             + Business_Impact_Adjustment

Asset_Criticality_Multiplier:
  - Tier 1 (>$1B daily): 1.5
  - Tier 2 (critical services): 1.2  
  - Tier 3 (non-critical): 1.0

Exposure_Factor:
  - Internet-facing: 1.3
  - Internal only: 1.0
  - Isolated: 0.8

Business_Impact_Adjustment:
  - Transaction volume > $1B/day: +15
  - PCI/PHI data: +10
  - Customer-facing: +5
```

---

### Agent 3: Approval Agent

**Role**: Manage human approval workflow and enforce guardrails.

**Why This Agent Exists (CRITICAL)**:
Per your requirements, agents cannot "blindly go in and fix stuff" because:
- Production services process billions in transactions
- Fixes may require service restarts
- Changes must be coordinated with business
- Maintenance windows must be respected

**Approval Matrix**:
| Asset Tier | Severity | Restart Required | Required Approvers |
|------------|----------|-----------------|-------------------|
| Tier 1 | Critical | Yes | CISO + Business Owner + CAB |
| Tier 1 | Critical | No | Security Lead + Business Owner |
| Tier 1 | High | Yes | Security Lead + Business Owner |
| Tier 1 | High | No | Security Lead |
| Tier 2 | Critical | Yes | Security Lead + Change Manager |
| Tier 2 | Critical | No | Security Lead |
| Tier 2 | High | Yes | Security Lead |
| Tier 2 | High | No | Auto-approve (logged) |
| Tier 3 | Any | Yes | Security Lead |
| Tier 3 | Any | No | Auto-approve (logged) |

---

### Agent 4: Remediation Agent

**Role**: Execute approved remediations via Ansible playbooks.

**Why This Agent Exists**:
- Ansible playbooks are the "bridge" for remediation
- Provides standardized, auditable, repeatable fixes
- Supports check mode (dry run) before actual execution
- Enables rollback if things go wrong

**Execution Workflow**:
```
1. Validate all approvals are in place ✓
2. Confirm maintenance window is active ✓
3. Run pre-flight checks (connectivity, disk space, service status)
4. Create system snapshot/backup
5. Execute playbook in CHECK MODE first (for Tier 1/2)
6. Review check mode output
7. Execute playbook in APPLY MODE
8. Run post-execution health checks
9. If failure: Execute rollback procedure
10. Report completion to Validation Agent
```

**Ansible Tower API Integration**:
```python
POST /api/v2/job_templates/{template_id}/launch/
{
    "inventory": [target_hosts],
    "extra_vars": {
        "vulnerability_id": "VULN-2024-001",
        "backup_enabled": true,
        "rollback_on_failure": true
    },
    "job_type": "check"  # or "run"
}
```

---

### Agent 5: Validation Agent

**Role**: Verify remediation success and maintain feedback loop.

**Why This Agent Exists**:
- Need to confirm fixes actually worked
- Some remediations fail silently
- Prevents "false completion" status
- Feeds back to improve playbook effectiveness

**Validation Checks**:
1. **Rescan Verification** - Trigger targeted scan of affected asset
2. **Service Health** - Verify services responding normally
3. **Performance Baseline** - Compare metrics pre/post change
4. **Regression Check** - Ensure no new vulnerabilities introduced
5. **Configuration Drift** - Verify expected state

**Feedback Loop**:
If vulnerability persists after remediation:
1. Notify Assessment Agent for re-analysis
2. Flag playbook for review
3. Escalate to human analyst
4. Update playbook effectiveness metrics

---

## Critical Guardrails

These rules are **NEVER** bypassed by any agent:

```python
class RemediationGuardrails:
    """
    Safety guardrails that protect production systems.
    These rules are non-negotiable.
    """
    
    # RULE 1: No production changes during business hours
    BUSINESS_HOURS = {'start': '08:00', 'end': '18:00', 'tz': 'America/New_York'}
    
    # RULE 2: Tier 1 assets ALWAYS require human approval
    TIER1_AUTO_APPROVE = False  # Never set to True
    
    # RULE 3: Restarts require maintenance window
    RESTART_REQUIRES_WINDOW = True
    
    # RULE 4: High-value systems need extended windows
    HIGH_VALUE_THRESHOLD = 1_000_000_000  # $1B daily transactions
    MIN_WINDOW_DURATION = 120  # minutes for high-value systems
    
    # RULE 5: Rollback must be available for Tier 1
    TIER1_REQUIRES_ROLLBACK = True
    
    # RULE 6: Check mode before apply for Tier 1/2
    CHECK_MODE_REQUIRED = ['tier1', 'tier2']
```

---

## Data Schemas

### Vulnerability Schema
```typescript
interface Vulnerability {
  id: string;                          // "VULN-2024-001"
  cve: string;                         // "CVE-2024-21762" or "N/A"
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss: number;                        // 0.0 - 10.0
  
  asset: {
    hostname: string;
    ip: string;
    type: 'server' | 'database' | 'cloud' | 'network';
    criticality: 'tier1' | 'tier2' | 'tier3';
    businessUnit: string;
    owner: string;
  };
  
  detection: {
    source: 'qualys' | 'tenable' | 'rapid7' | 'guardium';
    method: 'agent' | 'remote' | 'unauthenticated';
    firstDetected: Date;
    lastSeen: Date;
  };
  
  remediation: {
    status: 'new' | 'assessed' | 'approved' | 'scheduled' | 
            'in_progress' | 'completed' | 'validated' | 'exception';
    playbookId: string;
    requiresRestart: boolean;
    estimatedDowntime: number;  // minutes
    maintenanceWindow: Date | null;
    approvals: Approval[];
  };
  
  businessContext: {
    transactionVolume: number;  // daily $
    revenueImpact: 'critical' | 'high' | 'medium' | 'low';
    dataClassification: 'pii' | 'pci' | 'phi' | 'public';
    complianceFrameworks: string[];
  };
}
```

### Approval Schema
```typescript
interface Approval {
  approver: string;
  role: 'Security Lead' | 'Business Owner' | 'CAB' | 'CISO';
  status: 'pending' | 'approved' | 'denied';
  timestamp: Date | null;
  comments: string;
  conditions: string[];
}
```

### Playbook Schema
```typescript
interface AnsiblePlaybook {
  id: string;                         // "pb-tls-hardening"
  name: string;
  description: string;
  targetPlatforms: string[];          // ['Linux', 'Windows']
  requiresRestart: boolean;
  estimatedDuration: number;          // minutes
  supportsCheckMode: boolean;
  supportsRollback: boolean;
  successRate: number;                // historical
}
```

---

## API Integrations

### Scanner Platform APIs

```yaml
# Qualys VM API
Endpoint: https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/
Auth: Basic Authentication
Poll Interval: 15 minutes

# Tenable.io API  
Endpoint: https://cloud.tenable.com/vulns/export
Auth: X-ApiKeys header
Poll Interval: 15 minutes

# Rapid7 InsightVM API
Endpoint: https://insightvm.example.com/api/3/vulnerabilities
Auth: Basic Authentication
Poll Interval: 15 minutes

# IBM Guardium API
Endpoint: https://guardium.example.com/restAPI/grdapi
Auth: Session token
Poll Interval: 30 minutes
```

### Ansible Tower Integration

```yaml
# Execute Playbook
POST /api/v2/job_templates/{id}/launch/
Headers:
  Authorization: Bearer {token}
Body:
  inventory: [target_hosts]
  extra_vars: {variables}
  job_type: 'check' | 'run'

# Monitor Job
GET /api/v2/jobs/{job_id}/
Response:
  status: 'pending' | 'running' | 'successful' | 'failed'
  stdout: execution_log
```

---

## Deployment

### Container Services
```yaml
services:
  api-gateway:        # Main API, authentication
  discovery-agent:    # Scanner integrations
  assessment-agent:   # Risk analysis
  approval-agent:     # Workflow management
  remediation-agent:  # Ansible execution
  validation-agent:   # Verification
  postgres:           # Main database
  redis:              # Caching, queues
  vector-db:          # RAG embeddings
  web-ui:             # React dashboard
```

---

## MVP Implementation Timeline

### Phase 1: Core Infrastructure (Week 1-2)
- Database and API setup
- Base agent framework
- React dashboard skeleton

### Phase 2: Discovery Integration (Week 3-4)
- Qualys + Tenable API integration
- Deduplication logic
- Asset enrichment

### Phase 3: Assessment & Approval (Week 5-6)
- Risk scoring engine
- Approval workflow
- ITSM integration

### Phase 4: Remediation & Validation (Week 7-8)
- Ansible Tower integration
- Guardrail enforcement
- Feedback loop

### Phase 5: Hardening (Week 9-10)
- Testing
- Security review
- Documentation

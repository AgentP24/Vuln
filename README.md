# VulnGuard AI

**Multi-Agent Vulnerability Management System**

A sophisticated AI-powered system that automates vulnerability management while maintaining strict human oversight for production environments. Built with Claude AI, FastAPI, and Ansible.

## Overview

VulnGuard AI addresses the core challenge in enterprise security: **vulnerabilities are easily detected but hard to fix safely**, especially in production environments processing billions in daily transactions.

### Key Design Principles

1. **Human-in-the-Loop for Critical Decisions** - No autonomous changes to Tier 1 production systems
2. **Maintenance Window Awareness** - All remediations scheduled around business impact
3. **Ansible as the Remediation Bridge** - Standardized, auditable playbooks
4. **Multi-Source Aggregation** - Unified view from Qualys, Tenable, Rapid7, Guardium
5. **Continuous Validation Loop** - Feedback mechanism to verify fixes

## Architecture

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
```

## The Five-Agent System

### 1. Discovery Agent
Continuously retrieves and normalizes vulnerability data from scanning platforms.
- Polls Qualys, Tenable, Rapid7, and IBM Guardium APIs
- Normalizes data to unified schema
- Deduplicates findings across platforms
- Enriches with CMDB business context
- Flags "hard to fix" remote vulnerabilities (TLS, ciphers)

### 2. Assessment Agent
Analyzes vulnerabilities and determines business impact.
- Calculates risk score (CVSS × Asset Criticality × Exposure + Business Impact)
- Determines if fix requires restart/outage
- Recommends appropriate Ansible playbook
- Sets approval chain based on asset tier

### 3. Approval Agent
Manages human approval workflow with strict guardrails.
- Routes approvals to appropriate stakeholders
- Validates maintenance windows
- Tracks approval SLAs
- **NEVER bypasses approval for Tier 1 assets**

### 4. Remediation Agent
Executes approved remediations via Ansible.
- Validates all preconditions before execution
- Creates snapshots/backups
- Runs check mode first (Tier 1/2)
- Monitors execution and health checks
- Executes rollback on failure

### 5. Validation Agent
Verifies remediation success.
- Triggers targeted rescan
- Compares before/after states
- Checks for regressions
- Updates playbook effectiveness metrics
- Feeds back failures for re-assessment

## Critical Guardrails

These rules are **NEVER** bypassed by any agent:

```python
class RemediationGuardrails:
    # RULE 1: No production changes during business hours
    BUSINESS_HOURS = {'start': '08:00', 'end': '18:00', 'tz': 'America/New_York'}

    # RULE 2: Tier 1 assets ALWAYS require human approval
    TIER1_AUTO_APPROVE = False  # Never set to True

    # RULE 3: Restarts require maintenance window
    RESTART_REQUIRES_WINDOW = True

    # RULE 4: High-value systems need extended windows
    HIGH_VALUE_THRESHOLD = 1_000_000_000  # $1B daily transactions
    MIN_WINDOW_DURATION = 120  # minutes

    # RULE 5: Rollback must be available for Tier 1
    TIER1_REQUIRES_ROLLBACK = True

    # RULE 6: Check mode before apply for Tier 1/2
    CHECK_MODE_REQUIRED = ['tier1', 'tier2']
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Anthropic API key (for Claude)

### 1. Clone and Configure

```bash
cd vulnguard-ai

# Copy environment template
cp .env.example .env

# Edit .env and add your API keys
# At minimum, set: AI_ANTHROPIC_API_KEY
```

### 2. Start with Docker Compose

```bash
# Start all services
docker-compose up -d

# Check health
curl http://localhost:8000/health

# View logs
docker-compose logs -f api
```

### 3. Access the System

- **API Documentation**: http://localhost:8000/docs
- **Frontend Dashboard**: http://localhost:3000 (if enabled)
- **API Health Check**: http://localhost:8000/health

### Local Development (without Docker)

```bash
# Create virtual environment
cd backend
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export AI_ANTHROPIC_API_KEY=your-key-here

# Run the API
uvicorn main:app --reload --port 8000
```

## API Endpoints

### Vulnerabilities
- `GET /api/v1/vulnerabilities` - List vulnerabilities (with filters)
- `GET /api/v1/vulnerabilities/{id}` - Get vulnerability details
- `POST /api/v1/vulnerabilities/{id}/assess` - Trigger assessment

### Approvals
- `GET /api/v1/approvals` - List pending approvals
- `POST /api/v1/approvals/{id}/decide` - Submit approval decision
- `POST /api/v1/approvals/{id}/schedule` - Schedule for maintenance window

### Executions
- `GET /api/v1/executions` - List executions
- `POST /api/v1/executions/{id}/start` - Start scheduled execution
- `POST /api/v1/executions/{id}/cancel` - Cancel execution

### Agents
- `GET /api/v1/agents/status` - Get all agent states
- `GET /api/v1/agents/activity` - Get activity logs
- `POST /api/v1/agents/{name}/trigger` - Manually trigger agent cycle
- `GET /api/v1/agents/{name}/prompt` - Get agent system prompt

### Dashboard
- `GET /api/v1/dashboard/stats` - Get dashboard statistics
- `GET /api/v1/dashboard/maintenance-windows` - Get upcoming windows

## Configuration

### Scanner Integration

Configure your scanner credentials in `.env`:

```env
# Qualys
SCANNER_QUALYS_API_URL=https://qualysapi.qualys.com
SCANNER_QUALYS_USERNAME=your-username
SCANNER_QUALYS_PASSWORD=your-password

# Tenable
SCANNER_TENABLE_API_URL=https://cloud.tenable.com
SCANNER_TENABLE_ACCESS_KEY=your-access-key
SCANNER_TENABLE_SECRET_KEY=your-secret-key
```

### Ansible Tower Integration

```env
ANSIBLE_TOWER_URL=https://ansible-tower.example.com
ANSIBLE_TOWER_TOKEN=your-token
```

### Guardrails Configuration

```env
# Business hours protection
GUARDRAIL_BUSINESS_HOURS_START=08:00
GUARDRAIL_BUSINESS_HOURS_END=18:00
GUARDRAIL_BUSINESS_HOURS_TZ=America/New_York

# NEVER set this to true
GUARDRAIL_TIER1_AUTO_APPROVE=false

# Approval SLAs (hours)
GUARDRAIL_CRITICAL_APPROVAL_SLA=4
GUARDRAIL_HIGH_APPROVAL_SLA=24
```

## Project Structure

```
vulnguard-ai/
├── backend/
│   ├── agents/              # AI Agent implementations
│   │   ├── base.py         # Base agent class
│   │   ├── discovery.py    # Discovery Agent
│   │   ├── assessment.py   # Assessment Agent
│   │   ├── approval.py     # Approval Agent
│   │   ├── remediation.py  # Remediation Agent
│   │   ├── validation.py   # Validation Agent
│   │   └── prompts.py      # System prompts
│   ├── api/                # FastAPI routes
│   ├── config/             # Configuration
│   ├── integrations/       # External integrations
│   │   ├── scanners/       # Scanner clients
│   │   └── ansible.py      # Ansible Tower client
│   ├── models/             # Data models
│   ├── main.py             # Application entry point
│   └── requirements.txt
├── frontend/               # React dashboard (optional)
├── ansible/
│   └── playbooks/          # Remediation playbooks
├── docker/                 # Docker configurations
├── scripts/                # Utility scripts
├── docker-compose.yml
├── .env.example
└── README.md
```

## Approval Matrix

| Asset Tier | Severity | Restart | Required Approvers |
|------------|----------|---------|-------------------|
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

## Risk Scoring Formula

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

## Development

### Running Tests

```bash
cd backend
pytest tests/ -v
```

### Adding a New Scanner Integration

1. Create a new client in `backend/integrations/scanners/`
2. Extend `BaseScannerClient`
3. Implement `get_vulnerabilities()` and `scan_targets()`
4. Add to scanner clients in `main.py`

### Adding a New Playbook

1. Create the Ansible playbook
2. Register in `backend/models/database.py` or via API
3. Map vulnerability types to playbook in Assessment Agent

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions, please open a GitHub issue.

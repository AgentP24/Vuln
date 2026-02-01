import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, Clock, Play, Pause, 
  Server, Database, Cloud, Lock, Unlock, Eye, Settings,
  FileText, GitBranch, AlertCircle, ChevronRight, Activity,
  Zap, Target, Layers, RefreshCw, UserCheck, Bot, Terminal,
  Calendar, MessageSquare, TrendingUp, Filter, Search,
  XCircle, ArrowRight, Cpu, Network, HardDrive
} from 'lucide-react';

// ============================================================================
// SCHEMA DEFINITIONS
// ============================================================================

const VulnerabilitySchema = {
  id: 'string',
  cve: 'string',
  title: 'string',
  severity: 'critical|high|medium|low',
  cvss: 'number',
  asset: {
    hostname: 'string',
    ip: 'string',
    type: 'server|database|cloud|network',
    criticality: 'tier1|tier2|tier3',
    businessUnit: 'string',
    owner: 'string'
  },
  detection: {
    source: 'qualys|tenable|rapid7|guardium',
    method: 'agent|remote|unauthenticated',
    firstDetected: 'datetime',
    lastSeen: 'datetime',
    scanId: 'string'
  },
  remediation: {
    status: 'new|assessed|approved|scheduled|in_progress|completed|validated|exception',
    suggestedFix: 'string',
    playbookId: 'string',
    requiresRestart: 'boolean',
    estimatedDowntime: 'number',
    maintenanceWindow: 'string'
  },
  businessContext: {
    transactionVolume: 'number',
    revenueImpact: 'high|medium|low',
    dataClassification: 'pii|pci|phi|public',
    complianceFrameworks: 'string[]'
  }
};

const AgentStateSchema = {
  discovery: { status: 'idle|running|error', lastRun: 'datetime', vulnsFound: 'number' },
  assessment: { status: 'idle|running|error', pendingReview: 'number' },
  approval: { status: 'idle|awaiting', pendingApprovals: 'number' },
  remediation: { status: 'idle|scheduled|executing', activeJobs: 'number' },
  validation: { status: 'idle|running', pendingValidation: 'number' }
};

// ============================================================================
// PROMPT TEMPLATES FOR EACH AGENT
// ============================================================================

const AGENT_PROMPTS = {
  discovery: `
# Discovery Agent System Prompt

You are the Discovery Agent in a multi-agent vulnerability management system.
Your role is to continuously retrieve and normalize vulnerability data from multiple scanning platforms.

## Tools Available
- Qualys API (agents, connectors, VM module)
- Tenable.io/Tenable.sc API (agents, scanners, Nessus)
- Rapid7 InsightVM API
- IBM Guardium API (database vulnerabilities)

## Your Responsibilities
1. Poll each scanning platform API at configured intervals
2. Normalize vulnerability data to unified schema
3. De-duplicate findings across platforms
4. Enrich with asset context from CMDB
5. Classify detection method (agent-based vs remote vs unauthenticated)
6. Flag remote vulnerabilities that require special handling (weak ciphers, deprecated TLS, web server vulns, banner grabbing)

## Output Format
For each vulnerability discovered, output:
{
  "action": "vulnerability_discovered",
  "vulnerability": <VulnerabilitySchema>,
  "confidence": 0.0-1.0,
  "requires_validation": boolean,
  "detection_notes": "string"
}

## Special Handling
- Remote vulnerabilities (weak ciphers, deprecated SSL/TLS) should be flagged for Assessment Agent
- Agent-detected vulns have higher confidence
- Track first_detected and last_seen for SLA calculations
`,

  assessment: `
# Assessment Agent System Prompt

You are the Assessment Agent in a multi-agent vulnerability management system.
Your role is to analyze vulnerabilities and determine business impact and remediation complexity.

## Context You Receive
- Vulnerability details from Discovery Agent
- Asset criticality and business context
- Historical remediation data
- Current service dependencies

## Your Responsibilities
1. Calculate risk score combining CVSS + business context
2. Determine if fix requires service restart
3. Estimate remediation complexity and downtime
4. Identify appropriate Ansible playbook for fix
5. Flag vulnerabilities that need human review
6. Generate impact assessment report

## Impact Assessment Framework
- Tier 1 Assets (>$1B daily transactions): ALWAYS require human approval
- Tier 2 Assets (critical services): Require approval for restarts
- Tier 3 Assets (non-critical): Can auto-approve low-risk fixes

## Output Format
{
  "action": "assessment_complete",
  "vulnerability_id": "string",
  "risk_score": 0-100,
  "impact_assessment": {
    "service_impact": "none|degraded|outage",
    "estimated_downtime_minutes": number,
    "requires_restart": boolean,
    "affected_dependencies": ["service1", "service2"],
    "revenue_at_risk": "string",
    "recommended_window": "string"
  },
  "suggested_remediation": {
    "playbook_id": "string",
    "playbook_name": "string",
    "pre_checks": ["string"],
    "post_checks": ["string"],
    "rollback_procedure": "string"
  },
  "approval_required": boolean,
  "auto_approve_reason": "string" | null
}

## CRITICAL GUARDRAILS
- NEVER recommend auto-approval for Tier 1 assets
- NEVER recommend changes during business hours for production systems
- ALWAYS require human approval for fixes requiring restarts
- ALWAYS calculate revenue impact for transaction-processing systems
`,

  approval: `
# Approval Agent System Prompt

You are the Approval Agent in a multi-agent vulnerability management system.
Your role is to manage the human approval workflow and enforce guardrails.

## Context You Receive
- Impact assessments from Assessment Agent
- Maintenance window schedules
- Change Advisory Board (CAB) calendar
- Business owner contact information

## Your Responsibilities
1. Route approvals to appropriate stakeholders
2. Enforce mandatory approval rules
3. Track approval SLAs
4. Coordinate with CAB for high-impact changes
5. Generate approval request notifications
6. Validate maintenance window availability

## Approval Rules Engine
- Critical vulns on Tier 1: Requires CISO + Business Owner + CAB
- High vulns on Tier 1: Requires Security Lead + Business Owner
- Critical/High on Tier 2: Requires Security Lead
- Medium/Low on Tier 3: Can auto-approve if no restart

## Output Format
{
  "action": "approval_routed" | "approval_granted" | "approval_denied",
  "vulnerability_id": "string",
  "approval_chain": [
    {"role": "string", "name": "string", "status": "pending|approved|denied"}
  ],
  "scheduled_window": "datetime",
  "conditions": ["string"],
  "denial_reason": "string" | null
}

## CRITICAL GUARDRAILS
- NEVER bypass approval for production systems
- ALWAYS validate maintenance window before scheduling
- ALWAYS notify all stakeholders of scheduled changes
- Track approval audit trail for compliance
`,

  remediation: `
# Remediation Agent System Prompt

You are the Remediation Agent in a multi-agent vulnerability management system.
Your role is to execute approved remediations via Ansible playbooks.

## Context You Receive
- Approved remediation requests
- Ansible playbook inventory
- Current maintenance window status
- System state snapshots

## Your Responsibilities
1. Validate all approvals before execution
2. Execute pre-flight checks
3. Create system snapshot/backup
4. Invoke Ansible playbook via API
5. Monitor execution status
6. Capture execution logs
7. Trigger rollback if needed
8. Report completion status

## Ansible Integration
API Endpoint: /api/ansible/execute
Payload: {
  "playbook_id": "string",
  "target_hosts": ["string"],
  "variables": {},
  "check_mode": boolean,
  "tags": ["string"]
}

## Output Format
{
  "action": "remediation_started" | "remediation_complete" | "remediation_failed",
  "vulnerability_id": "string",
  "execution_id": "string",
  "status": "running|success|failed|rolled_back",
  "logs": ["string"],
  "changes_made": ["string"],
  "rollback_executed": boolean
}

## CRITICAL GUARDRAILS
- ALWAYS run in check_mode first for Tier 1/2 assets
- ALWAYS create snapshot before changes
- NEVER execute outside approved maintenance window
- ALWAYS have rollback ready before execution
- STOP immediately if unexpected errors occur
`,

  validation: `
# Validation Agent System Prompt

You are the Validation Agent in a multi-agent vulnerability management system.
Your role is to verify that remediations were successful.

## Context You Receive
- Remediation completion reports
- Original vulnerability details
- Post-remediation scan results

## Your Responsibilities
1. Trigger rescan of affected asset
2. Compare before/after vulnerability state
3. Verify service health post-change
4. Confirm vulnerability is resolved
5. Update vulnerability status
6. Generate validation report
7. Trigger feedback loop if vuln persists

## Validation Checks
1. Vulnerability no longer detected by scanner
2. Service responding normally (health checks)
3. No new vulnerabilities introduced
4. Performance metrics within baseline
5. No unexpected configuration drift

## Output Format
{
  "action": "validation_complete",
  "vulnerability_id": "string",
  "validation_status": "resolved|persists|partial|new_issues",
  "scan_results": {
    "pre_fix": {},
    "post_fix": {}
  },
  "health_checks": {
    "service_status": "healthy|degraded|down",
    "response_time_ms": number,
    "error_rate": number
  },
  "follow_up_required": boolean,
  "follow_up_reason": "string" | null
}

## FEEDBACK LOOP
If vulnerability persists:
1. Notify Assessment Agent for re-analysis
2. Flag remediation playbook for review
3. Escalate to human analyst
`
};

// ============================================================================
// MOCK DATA GENERATORS
// ============================================================================

const generateMockVulnerabilities = () => [
  {
    id: 'VULN-2024-001',
    cve: 'CVE-2024-21762',
    title: 'Fortinet FortiOS Out-of-Bound Write',
    severity: 'critical',
    cvss: 9.8,
    asset: {
      hostname: 'prod-fw-01.corp.local',
      ip: '10.0.1.1',
      type: 'network',
      criticality: 'tier1',
      businessUnit: 'Infrastructure',
      owner: 'Network Team'
    },
    detection: {
      source: 'tenable',
      method: 'remote',
      firstDetected: '2024-01-15T08:00:00Z',
      lastSeen: '2024-01-20T14:30:00Z',
      scanId: 'SCN-78234'
    },
    remediation: {
      status: 'assessed',
      suggestedFix: 'Upgrade FortiOS to 7.4.3 or later',
      playbookId: 'pb-fortios-upgrade',
      requiresRestart: true,
      estimatedDowntime: 30,
      maintenanceWindow: null
    },
    businessContext: {
      transactionVolume: 0,
      revenueImpact: 'high',
      dataClassification: 'pci',
      complianceFrameworks: ['PCI-DSS', 'SOX']
    }
  },
  {
    id: 'VULN-2024-002',
    cve: 'CVE-2024-0204',
    title: 'GoAnywhere MFT Authentication Bypass',
    severity: 'critical',
    cvss: 9.8,
    asset: {
      hostname: 'mft-prod-01.corp.local',
      ip: '10.0.2.50',
      type: 'server',
      criticality: 'tier1',
      businessUnit: 'Finance',
      owner: 'Finance IT'
    },
    detection: {
      source: 'qualys',
      method: 'agent',
      firstDetected: '2024-01-10T10:00:00Z',
      lastSeen: '2024-01-20T14:30:00Z',
      scanId: 'QLS-45678'
    },
    remediation: {
      status: 'new',
      suggestedFix: 'Apply vendor patch MFT-2024-001',
      playbookId: 'pb-goanywhere-patch',
      requiresRestart: true,
      estimatedDowntime: 45,
      maintenanceWindow: null
    },
    businessContext: {
      transactionVolume: 2500000000,
      revenueImpact: 'critical',
      dataClassification: 'pci',
      complianceFrameworks: ['PCI-DSS', 'SOX', 'HIPAA']
    }
  },
  {
    id: 'VULN-2024-003',
    cve: 'N/A',
    title: 'Deprecated TLSv1.1 Protocol Enabled',
    severity: 'high',
    cvss: 7.5,
    asset: {
      hostname: 'api-gateway-03.corp.local',
      ip: '10.0.3.100',
      type: 'server',
      criticality: 'tier1',
      businessUnit: 'Digital',
      owner: 'Platform Team'
    },
    detection: {
      source: 'rapid7',
      method: 'remote',
      firstDetected: '2024-01-05T09:00:00Z',
      lastSeen: '2024-01-20T14:30:00Z',
      scanId: 'R7-89012'
    },
    remediation: {
      status: 'approved',
      suggestedFix: 'Disable TLSv1.0 and TLSv1.1, enforce TLSv1.2+',
      playbookId: 'pb-tls-hardening',
      requiresRestart: true,
      estimatedDowntime: 15,
      maintenanceWindow: '2024-01-21T02:00:00Z'
    },
    businessContext: {
      transactionVolume: 1000000000,
      revenueImpact: 'high',
      dataClassification: 'pii',
      complianceFrameworks: ['PCI-DSS', 'GDPR']
    }
  },
  {
    id: 'VULN-2024-004',
    cve: 'CVE-2023-44487',
    title: 'HTTP/2 Rapid Reset Attack (DoS)',
    severity: 'high',
    cvss: 7.5,
    asset: {
      hostname: 'web-prod-cluster',
      ip: '10.0.4.0/24',
      type: 'server',
      criticality: 'tier2',
      businessUnit: 'E-Commerce',
      owner: 'Web Team'
    },
    detection: {
      source: 'tenable',
      method: 'agent',
      firstDetected: '2024-01-12T11:00:00Z',
      lastSeen: '2024-01-20T14:30:00Z',
      scanId: 'TEN-34567'
    },
    remediation: {
      status: 'scheduled',
      suggestedFix: 'Update nginx to 1.25.3+, configure rate limiting',
      playbookId: 'pb-nginx-http2-fix',
      requiresRestart: true,
      estimatedDowntime: 5,
      maintenanceWindow: '2024-01-22T03:00:00Z'
    },
    businessContext: {
      transactionVolume: 500000000,
      revenueImpact: 'medium',
      dataClassification: 'pii',
      complianceFrameworks: ['PCI-DSS']
    }
  },
  {
    id: 'VULN-2024-005',
    cve: 'N/A',
    title: 'Weak SSH Cipher Suites Enabled',
    severity: 'medium',
    cvss: 5.3,
    asset: {
      hostname: 'db-replica-02.corp.local',
      ip: '10.0.5.22',
      type: 'database',
      criticality: 'tier2',
      businessUnit: 'Data',
      owner: 'DBA Team'
    },
    detection: {
      source: 'guardium',
      method: 'remote',
      firstDetected: '2024-01-08T07:00:00Z',
      lastSeen: '2024-01-20T14:30:00Z',
      scanId: 'GDM-12345'
    },
    remediation: {
      status: 'in_progress',
      suggestedFix: 'Update sshd_config to remove weak ciphers',
      playbookId: 'pb-ssh-hardening',
      requiresRestart: false,
      estimatedDowntime: 0,
      maintenanceWindow: null
    },
    businessContext: {
      transactionVolume: 0,
      revenueImpact: 'low',
      dataClassification: 'phi',
      complianceFrameworks: ['HIPAA', 'SOX']
    }
  },
  {
    id: 'VULN-2024-006',
    cve: 'CVE-2024-20253',
    title: 'Cisco Unified CM RCE Vulnerability',
    severity: 'critical',
    cvss: 9.9,
    asset: {
      hostname: 'cucm-pub.corp.local',
      ip: '10.0.6.10',
      type: 'server',
      criticality: 'tier1',
      businessUnit: 'Communications',
      owner: 'Voice Team'
    },
    detection: {
      source: 'qualys',
      method: 'remote',
      firstDetected: '2024-01-18T15:00:00Z',
      lastSeen: '2024-01-20T14:30:00Z',
      scanId: 'QLS-67890'
    },
    remediation: {
      status: 'new',
      suggestedFix: 'Apply Cisco patch CSCwi19090',
      playbookId: 'pb-cucm-patch',
      requiresRestart: true,
      estimatedDowntime: 60,
      maintenanceWindow: null
    },
    businessContext: {
      transactionVolume: 0,
      revenueImpact: 'high',
      dataClassification: 'pii',
      complianceFrameworks: ['SOX', 'GDPR']
    }
  }
];

// ============================================================================
// MAIN APPLICATION COMPONENT
// ============================================================================

const VulnManagementApp = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [vulnerabilities, setVulnerabilities] = useState(generateMockVulnerabilities());
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [agentStates, setAgentStates] = useState({
    discovery: { status: 'running', lastRun: new Date().toISOString(), vulnsFound: 6 },
    assessment: { status: 'idle', pendingReview: 2 },
    approval: { status: 'awaiting', pendingApprovals: 3 },
    remediation: { status: 'scheduled', activeJobs: 1 },
    validation: { status: 'idle', pendingValidation: 1 }
  });
  const [logs, setLogs] = useState([]);
  const [showApprovalModal, setShowApprovalModal] = useState(false);
  const [showPromptModal, setShowPromptModal] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(null);

  // Simulate agent activity
  useEffect(() => {
    const interval = setInterval(() => {
      const actions = [
        { agent: 'discovery', message: 'Polling Qualys API for new vulnerabilities...' },
        { agent: 'discovery', message: 'Retrieved 3 new findings from Tenable scan' },
        { agent: 'assessment', message: 'Analyzing CVE-2024-21762 impact on prod-fw-01' },
        { agent: 'assessment', message: 'Risk score calculated: 94/100 for VULN-2024-002' },
        { agent: 'approval', message: 'Routing approval request to Security Lead' },
        { agent: 'remediation', message: 'Pre-flight checks passed for pb-tls-hardening' },
        { agent: 'validation', message: 'Triggering rescan on api-gateway-03' }
      ];
      
      const action = actions[Math.floor(Math.random() * actions.length)];
      setLogs(prev => [{
        timestamp: new Date().toISOString(),
        ...action
      }, ...prev.slice(0, 49)]);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    };
    return colors[severity] || colors.low;
  };

  const getStatusColor = (status) => {
    const colors = {
      new: 'bg-purple-500/20 text-purple-400',
      assessed: 'bg-blue-500/20 text-blue-400',
      approved: 'bg-green-500/20 text-green-400',
      scheduled: 'bg-cyan-500/20 text-cyan-400',
      in_progress: 'bg-yellow-500/20 text-yellow-400',
      completed: 'bg-emerald-500/20 text-emerald-400',
      validated: 'bg-teal-500/20 text-teal-400',
      exception: 'bg-gray-500/20 text-gray-400'
    };
    return colors[status] || colors.new;
  };

  const getAgentStatusColor = (status) => {
    const colors = {
      running: 'text-emerald-400',
      idle: 'text-slate-400',
      error: 'text-red-400',
      awaiting: 'text-amber-400',
      scheduled: 'text-cyan-400',
      executing: 'text-purple-400'
    };
    return colors[status] || colors.idle;
  };

  const stats = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    pending: vulnerabilities.filter(v => ['new', 'assessed'].includes(v.remediation.status)).length,
    scheduled: vulnerabilities.filter(v => v.remediation.status === 'scheduled').length
  };

  // ============================================================================
  // DASHBOARD VIEW
  // ============================================================================

  const DashboardView = () => (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-5 gap-4">
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm font-medium">Total Vulnerabilities</p>
              <p className="text-3xl font-bold text-white mt-1">{stats.total}</p>
            </div>
            <div className="w-12 h-12 bg-slate-700/50 rounded-xl flex items-center justify-center">
              <Shield className="w-6 h-6 text-slate-400" />
            </div>
          </div>
        </div>
        
        <div className="bg-red-950/30 border border-red-500/20 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-red-400/80 text-sm font-medium">Critical</p>
              <p className="text-3xl font-bold text-red-400 mt-1">{stats.critical}</p>
            </div>
            <div className="w-12 h-12 bg-red-500/10 rounded-xl flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
          </div>
        </div>

        <div className="bg-orange-950/30 border border-orange-500/20 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-orange-400/80 text-sm font-medium">High</p>
              <p className="text-3xl font-bold text-orange-400 mt-1">{stats.high}</p>
            </div>
            <div className="w-12 h-12 bg-orange-500/10 rounded-xl flex items-center justify-center">
              <AlertCircle className="w-6 h-6 text-orange-400" />
            </div>
          </div>
        </div>

        <div className="bg-purple-950/30 border border-purple-500/20 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-purple-400/80 text-sm font-medium">Pending Review</p>
              <p className="text-3xl font-bold text-purple-400 mt-1">{stats.pending}</p>
            </div>
            <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center">
              <Clock className="w-6 h-6 text-purple-400" />
            </div>
          </div>
        </div>

        <div className="bg-cyan-950/30 border border-cyan-500/20 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-cyan-400/80 text-sm font-medium">Scheduled</p>
              <p className="text-3xl font-bold text-cyan-400 mt-1">{stats.scheduled}</p>
            </div>
            <div className="w-12 h-12 bg-cyan-500/10 rounded-xl flex items-center justify-center">
              <Calendar className="w-6 h-6 text-cyan-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Agent Status Panel */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Bot className="w-5 h-5 text-emerald-400" />
          AI Agent Pipeline Status
        </h3>
        <div className="flex items-center justify-between">
          {Object.entries(agentStates).map(([agent, state], index) => (
            <React.Fragment key={agent}>
              <div 
                className="flex-1 bg-slate-900/50 rounded-xl p-4 cursor-pointer hover:bg-slate-900/80 transition-all border border-transparent hover:border-slate-600"
                onClick={() => {
                  setSelectedAgent(agent);
                  setShowPromptModal(true);
                }}
              >
                <div className="flex items-center gap-3 mb-3">
                  <div className={`w-3 h-3 rounded-full ${state.status === 'running' || state.status === 'executing' ? 'bg-emerald-400 animate-pulse' : state.status === 'awaiting' ? 'bg-amber-400 animate-pulse' : 'bg-slate-500'}`} />
                  <span className="text-white font-medium capitalize">{agent}</span>
                </div>
                <div className="space-y-1">
                  <p className={`text-sm ${getAgentStatusColor(state.status)}`}>
                    Status: {state.status}
                  </p>
                  {state.vulnsFound !== undefined && (
                    <p className="text-xs text-slate-500">Found: {state.vulnsFound}</p>
                  )}
                  {state.pendingReview !== undefined && (
                    <p className="text-xs text-slate-500">Pending: {state.pendingReview}</p>
                  )}
                  {state.pendingApprovals !== undefined && (
                    <p className="text-xs text-slate-500">Awaiting: {state.pendingApprovals}</p>
                  )}
                  {state.activeJobs !== undefined && (
                    <p className="text-xs text-slate-500">Active: {state.activeJobs}</p>
                  )}
                  {state.pendingValidation !== undefined && (
                    <p className="text-xs text-slate-500">To Validate: {state.pendingValidation}</p>
                  )}
                </div>
              </div>
              {index < Object.entries(agentStates).length - 1 && (
                <div className="px-2">
                  <ChevronRight className="w-5 h-5 text-slate-600" />
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-2 gap-6">
        {/* Vulnerability Queue */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-red-400" />
            Critical Vulnerability Queue
          </h3>
          <div className="space-y-3">
            {vulnerabilities
              .filter(v => v.severity === 'critical' || v.severity === 'high')
              .slice(0, 5)
              .map(vuln => (
                <div 
                  key={vuln.id}
                  className="bg-slate-900/50 rounded-lg p-4 cursor-pointer hover:bg-slate-900/80 transition-all border border-transparent hover:border-slate-600"
                  onClick={() => setSelectedVuln(vuln)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity.toUpperCase()}
                        </span>
                        <span className="text-slate-500 text-xs">{vuln.id}</span>
                      </div>
                      <p className="text-white font-medium text-sm">{vuln.title}</p>
                      <p className="text-slate-400 text-xs mt-1">{vuln.asset.hostname}</p>
                    </div>
                    <div className="text-right">
                      <span className={`px-2 py-1 text-xs rounded-md ${getStatusColor(vuln.remediation.status)}`}>
                        {vuln.remediation.status.replace('_', ' ')}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>

        {/* Activity Feed */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            Agent Activity Feed
          </h3>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {logs.slice(0, 10).map((log, index) => (
              <div key={index} className="flex items-start gap-3 p-2 rounded-lg hover:bg-slate-900/30">
                <div className={`w-2 h-2 rounded-full mt-2 ${
                  log.agent === 'discovery' ? 'bg-blue-400' :
                  log.agent === 'assessment' ? 'bg-purple-400' :
                  log.agent === 'approval' ? 'bg-amber-400' :
                  log.agent === 'remediation' ? 'bg-emerald-400' :
                  'bg-cyan-400'
                }`} />
                <div className="flex-1">
                  <p className="text-sm text-slate-300">{log.message}</p>
                  <p className="text-xs text-slate-500 mt-1">
                    {new Date(log.timestamp).toLocaleTimeString()} · {log.agent}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  // ============================================================================
  // VULNERABILITIES VIEW
  // ============================================================================

  const VulnerabilitiesView = () => (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
        <div className="flex items-center gap-4">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search vulnerabilities, CVEs, assets..."
              className="w-full bg-slate-900/50 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>
          <select className="bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500/50">
            <option>All Severities</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
          <select className="bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500/50">
            <option>All Statuses</option>
            <option>New</option>
            <option>Assessed</option>
            <option>Approved</option>
            <option>Scheduled</option>
            <option>In Progress</option>
          </select>
          <select className="bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500/50">
            <option>All Sources</option>
            <option>Qualys</option>
            <option>Tenable</option>
            <option>Rapid7</option>
            <option>Guardium</option>
          </select>
        </div>
      </div>

      {/* Vulnerability Table */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-700/50">
              <th className="text-left p-4 text-slate-400 font-medium text-sm">Vulnerability</th>
              <th className="text-left p-4 text-slate-400 font-medium text-sm">Asset</th>
              <th className="text-left p-4 text-slate-400 font-medium text-sm">Severity</th>
              <th className="text-left p-4 text-slate-400 font-medium text-sm">Source</th>
              <th className="text-left p-4 text-slate-400 font-medium text-sm">Detection</th>
              <th className="text-left p-4 text-slate-400 font-medium text-sm">Status</th>
              <th className="text-left p-4 text-slate-400 font-medium text-sm">Actions</th>
            </tr>
          </thead>
          <tbody>
            {vulnerabilities.map(vuln => (
              <tr 
                key={vuln.id} 
                className="border-b border-slate-700/30 hover:bg-slate-700/20 cursor-pointer transition-colors"
                onClick={() => setSelectedVuln(vuln)}
              >
                <td className="p-4">
                  <div>
                    <p className="text-white font-medium text-sm">{vuln.title}</p>
                    <p className="text-slate-500 text-xs mt-1">{vuln.cve} · {vuln.id}</p>
                  </div>
                </td>
                <td className="p-4">
                  <div className="flex items-center gap-2">
                    {vuln.asset.type === 'server' && <Server className="w-4 h-4 text-slate-400" />}
                    {vuln.asset.type === 'database' && <Database className="w-4 h-4 text-slate-400" />}
                    {vuln.asset.type === 'cloud' && <Cloud className="w-4 h-4 text-slate-400" />}
                    {vuln.asset.type === 'network' && <Network className="w-4 h-4 text-slate-400" />}
                    <div>
                      <p className="text-slate-300 text-sm">{vuln.asset.hostname}</p>
                      <p className="text-slate-500 text-xs">{vuln.asset.ip}</p>
                    </div>
                  </div>
                </td>
                <td className="p-4">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(vuln.severity)}`}>
                    {vuln.severity.toUpperCase()} ({vuln.cvss})
                  </span>
                </td>
                <td className="p-4">
                  <span className="text-slate-300 text-sm capitalize">{vuln.detection.source}</span>
                </td>
                <td className="p-4">
                  <span className={`px-2 py-1 text-xs rounded-md ${
                    vuln.detection.method === 'agent' ? 'bg-emerald-500/20 text-emerald-400' :
                    vuln.detection.method === 'remote' ? 'bg-blue-500/20 text-blue-400' :
                    'bg-purple-500/20 text-purple-400'
                  }`}>
                    {vuln.detection.method}
                  </span>
                </td>
                <td className="p-4">
                  <span className={`px-2 py-1 text-xs rounded-md ${getStatusColor(vuln.remediation.status)}`}>
                    {vuln.remediation.status.replace('_', ' ')}
                  </span>
                </td>
                <td className="p-4">
                  <div className="flex items-center gap-2">
                    <button 
                      className="p-2 rounded-lg bg-slate-700/50 hover:bg-slate-600/50 text-slate-400 hover:text-white transition-colors"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedVuln(vuln);
                      }}
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    {vuln.remediation.status === 'assessed' && (
                      <button 
                        className="p-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 transition-colors"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedVuln(vuln);
                          setShowApprovalModal(true);
                        }}
                      >
                        <UserCheck className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  // ============================================================================
  // AGENTS VIEW
  // ============================================================================

  const AgentsView = () => (
    <div className="space-y-6">
      {Object.entries(AGENT_PROMPTS).map(([agent, prompt]) => (
        <div key={agent} className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
          <div className="p-6 border-b border-slate-700/50">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                  agent === 'discovery' ? 'bg-blue-500/20' :
                  agent === 'assessment' ? 'bg-purple-500/20' :
                  agent === 'approval' ? 'bg-amber-500/20' :
                  agent === 'remediation' ? 'bg-emerald-500/20' :
                  'bg-cyan-500/20'
                }`}>
                  {agent === 'discovery' && <Search className={`w-6 h-6 text-blue-400`} />}
                  {agent === 'assessment' && <TrendingUp className={`w-6 h-6 text-purple-400`} />}
                  {agent === 'approval' && <UserCheck className={`w-6 h-6 text-amber-400`} />}
                  {agent === 'remediation' && <Terminal className={`w-6 h-6 text-emerald-400`} />}
                  {agent === 'validation' && <CheckCircle className={`w-6 h-6 text-cyan-400`} />}
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-white capitalize">{agent} Agent</h3>
                  <p className="text-slate-400 text-sm mt-1">
                    {agent === 'discovery' && 'Retrieves and normalizes vulnerability data from scanning platforms'}
                    {agent === 'assessment' && 'Analyzes impact and determines remediation complexity'}
                    {agent === 'approval' && 'Manages human approval workflow and enforces guardrails'}
                    {agent === 'remediation' && 'Executes approved remediations via Ansible playbooks'}
                    {agent === 'validation' && 'Verifies successful remediation through rescanning'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`px-3 py-1 rounded-full text-sm ${
                  agentStates[agent].status === 'running' || agentStates[agent].status === 'executing' 
                    ? 'bg-emerald-500/20 text-emerald-400' 
                    : agentStates[agent].status === 'awaiting'
                    ? 'bg-amber-500/20 text-amber-400'
                    : 'bg-slate-700/50 text-slate-400'
                }`}>
                  {agentStates[agent].status}
                </span>
                <button className="p-2 rounded-lg bg-slate-700/50 hover:bg-slate-600/50 text-slate-400 hover:text-white transition-colors">
                  <Settings className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
          <div className="p-6">
            <h4 className="text-sm font-medium text-slate-400 mb-3">System Prompt</h4>
            <pre className="bg-slate-900/50 rounded-lg p-4 text-sm text-slate-300 overflow-x-auto max-h-64 overflow-y-auto font-mono whitespace-pre-wrap">
              {prompt.trim()}
            </pre>
          </div>
        </div>
      ))}
    </div>
  );

  // ============================================================================
  // PLAYBOOKS VIEW
  // ============================================================================

  const PlaybooksView = () => {
    const playbooks = [
      {
        id: 'pb-tls-hardening',
        name: 'TLS/SSL Hardening',
        description: 'Disable deprecated TLS versions and weak cipher suites',
        targets: ['Linux', 'Windows'],
        requiresRestart: true,
        estimatedDuration: '15 min',
        lastUsed: '2024-01-18'
      },
      {
        id: 'pb-ssh-hardening',
        name: 'SSH Configuration Hardening',
        description: 'Remove weak ciphers and enforce secure SSH configuration',
        targets: ['Linux'],
        requiresRestart: false,
        estimatedDuration: '5 min',
        lastUsed: '2024-01-20'
      },
      {
        id: 'pb-nginx-http2-fix',
        name: 'Nginx HTTP/2 Security Patch',
        description: 'Apply HTTP/2 Rapid Reset mitigation and rate limiting',
        targets: ['Linux'],
        requiresRestart: true,
        estimatedDuration: '10 min',
        lastUsed: '2024-01-15'
      },
      {
        id: 'pb-fortios-upgrade',
        name: 'FortiOS Firmware Upgrade',
        description: 'Upgrade FortiOS to latest security patch version',
        targets: ['FortiGate'],
        requiresRestart: true,
        estimatedDuration: '30 min',
        lastUsed: '2024-01-10'
      },
      {
        id: 'pb-goanywhere-patch',
        name: 'GoAnywhere MFT Patch',
        description: 'Apply critical security patch for authentication bypass',
        targets: ['Windows', 'Linux'],
        requiresRestart: true,
        estimatedDuration: '45 min',
        lastUsed: null
      },
      {
        id: 'pb-cucm-patch',
        name: 'Cisco UCM Security Patch',
        description: 'Apply Cisco Unified Communications Manager security update',
        targets: ['CUCM'],
        requiresRestart: true,
        estimatedDuration: '60 min',
        lastUsed: null
      }
    ];

    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 gap-6">
          {playbooks.map(pb => (
            <div key={pb.id} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-white">{pb.name}</h3>
                  <p className="text-slate-400 text-sm mt-1">{pb.description}</p>
                </div>
                <GitBranch className="w-5 h-5 text-slate-400" />
              </div>
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-sm">ID:</span>
                  <code className="text-cyan-400 text-sm bg-slate-900/50 px-2 py-0.5 rounded">{pb.id}</code>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-sm">Targets:</span>
                  <div className="flex gap-1">
                    {pb.targets.map(t => (
                      <span key={t} className="text-xs px-2 py-0.5 rounded bg-slate-700/50 text-slate-300">{t}</span>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-slate-400" />
                    <span className="text-slate-300 text-sm">{pb.estimatedDuration}</span>
                  </div>
                  {pb.requiresRestart && (
                    <div className="flex items-center gap-2">
                      <RefreshCw className="w-4 h-4 text-amber-400" />
                      <span className="text-amber-400 text-sm">Requires Restart</span>
                    </div>
                  )}
                </div>
                {pb.lastUsed && (
                  <p className="text-slate-500 text-xs">Last used: {pb.lastUsed}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  // ============================================================================
  // VULNERABILITY DETAIL MODAL
  // ============================================================================

  const VulnDetailModal = () => {
    if (!selectedVuln) return null;

    return (
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-8">
        <div className="bg-slate-900 border border-slate-700/50 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
          <div className="p-6 border-b border-slate-700/50 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <span className={`px-3 py-1 text-sm font-medium rounded-full border ${getSeverityColor(selectedVuln.severity)}`}>
                  {selectedVuln.severity.toUpperCase()}
                </span>
                <span className="text-slate-400">{selectedVuln.id}</span>
              </div>
              <h2 className="text-xl font-semibold text-white">{selectedVuln.title}</h2>
            </div>
            <button 
              onClick={() => setSelectedVuln(null)}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
            >
              <XCircle className="w-5 h-5" />
            </button>
          </div>
          
          <div className="p-6 overflow-y-auto max-h-[calc(90vh-180px)]">
            <div className="grid grid-cols-2 gap-6">
              {/* Left Column */}
              <div className="space-y-6">
                <div className="bg-slate-800/50 rounded-xl p-4">
                  <h3 className="text-sm font-medium text-slate-400 mb-3">Vulnerability Details</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-slate-500">CVE</span>
                      <span className="text-white font-mono">{selectedVuln.cve}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">CVSS Score</span>
                      <span className="text-white">{selectedVuln.cvss}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Detection Method</span>
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        selectedVuln.detection.method === 'agent' ? 'bg-emerald-500/20 text-emerald-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>{selectedVuln.detection.method}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Source</span>
                      <span className="text-white capitalize">{selectedVuln.detection.source}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">First Detected</span>
                      <span className="text-white">{new Date(selectedVuln.detection.firstDetected).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-800/50 rounded-xl p-4">
                  <h3 className="text-sm font-medium text-slate-400 mb-3">Asset Information</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Hostname</span>
                      <span className="text-white font-mono">{selectedVuln.asset.hostname}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">IP Address</span>
                      <span className="text-white font-mono">{selectedVuln.asset.ip}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Criticality</span>
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        selectedVuln.asset.criticality === 'tier1' ? 'bg-red-500/20 text-red-400' :
                        selectedVuln.asset.criticality === 'tier2' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>{selectedVuln.asset.criticality.toUpperCase()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Business Unit</span>
                      <span className="text-white">{selectedVuln.asset.businessUnit}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Owner</span>
                      <span className="text-white">{selectedVuln.asset.owner}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Right Column */}
              <div className="space-y-6">
                <div className="bg-slate-800/50 rounded-xl p-4">
                  <h3 className="text-sm font-medium text-slate-400 mb-3">Business Context</h3>
                  <div className="space-y-3">
                    {selectedVuln.businessContext.transactionVolume > 0 && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Daily Transactions</span>
                        <span className="text-white">${(selectedVuln.businessContext.transactionVolume / 1000000000).toFixed(1)}B</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-slate-500">Revenue Impact</span>
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        selectedVuln.businessContext.revenueImpact === 'critical' ? 'bg-red-500/20 text-red-400' :
                        selectedVuln.businessContext.revenueImpact === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        selectedVuln.businessContext.revenueImpact === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>{selectedVuln.businessContext.revenueImpact.toUpperCase()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Data Classification</span>
                      <span className="text-white uppercase">{selectedVuln.businessContext.dataClassification}</span>
                    </div>
                    <div className="flex justify-between items-start">
                      <span className="text-slate-500">Compliance</span>
                      <div className="flex flex-wrap gap-1 justify-end">
                        {selectedVuln.businessContext.complianceFrameworks.map(f => (
                          <span key={f} className="text-xs px-2 py-0.5 rounded bg-slate-700/50 text-slate-300">{f}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-800/50 rounded-xl p-4">
                  <h3 className="text-sm font-medium text-slate-400 mb-3">Remediation</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Status</span>
                      <span className={`px-2 py-0.5 text-xs rounded ${getStatusColor(selectedVuln.remediation.status)}`}>
                        {selectedVuln.remediation.status.replace('_', ' ')}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block mb-1">Suggested Fix</span>
                      <p className="text-white text-sm">{selectedVuln.remediation.suggestedFix}</p>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Playbook</span>
                      <code className="text-cyan-400 text-sm">{selectedVuln.remediation.playbookId}</code>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Requires Restart</span>
                      <span className={selectedVuln.remediation.requiresRestart ? 'text-amber-400' : 'text-green-400'}>
                        {selectedVuln.remediation.requiresRestart ? 'Yes' : 'No'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Est. Downtime</span>
                      <span className="text-white">{selectedVuln.remediation.estimatedDowntime} min</span>
                    </div>
                    {selectedVuln.remediation.maintenanceWindow && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Scheduled</span>
                        <span className="text-cyan-400">{new Date(selectedVuln.remediation.maintenanceWindow).toLocaleString()}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="mt-6 flex items-center justify-end gap-3">
              {selectedVuln.remediation.status === 'new' && (
                <button className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded-lg flex items-center gap-2 transition-colors">
                  <TrendingUp className="w-4 h-4" />
                  Run Assessment
                </button>
              )}
              {selectedVuln.remediation.status === 'assessed' && (
                <button 
                  onClick={() => setShowApprovalModal(true)}
                  className="px-4 py-2 bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 rounded-lg flex items-center gap-2 transition-colors"
                >
                  <UserCheck className="w-4 h-4" />
                  Request Approval
                </button>
              )}
              {selectedVuln.remediation.status === 'approved' && (
                <button className="px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 rounded-lg flex items-center gap-2 transition-colors">
                  <Calendar className="w-4 h-4" />
                  Schedule Remediation
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ============================================================================
  // APPROVAL MODAL
  // ============================================================================

  const ApprovalModal = () => {
    if (!showApprovalModal || !selectedVuln) return null;

    return (
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-8">
        <div className="bg-slate-900 border border-slate-700/50 rounded-2xl w-full max-w-2xl">
          <div className="p-6 border-b border-slate-700/50">
            <h2 className="text-xl font-semibold text-white flex items-center gap-3">
              <UserCheck className="w-6 h-6 text-amber-400" />
              Remediation Approval Request
            </h2>
          </div>
          
          <div className="p-6 space-y-6">
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5" />
                <div>
                  <h4 className="text-amber-400 font-medium">Human Approval Required</h4>
                  <p className="text-amber-400/80 text-sm mt-1">
                    This remediation requires human approval because:
                  </p>
                  <ul className="text-amber-400/80 text-sm mt-2 space-y-1 list-disc list-inside">
                    {selectedVuln.asset.criticality === 'tier1' && (
                      <li>Asset is classified as Tier 1 (critical infrastructure)</li>
                    )}
                    {selectedVuln.remediation.requiresRestart && (
                      <li>Remediation requires service restart</li>
                    )}
                    {selectedVuln.businessContext.transactionVolume > 0 && (
                      <li>System processes ${(selectedVuln.businessContext.transactionVolume / 1000000000).toFixed(1)}B in daily transactions</li>
                    )}
                  </ul>
                </div>
              </div>
            </div>

            <div className="bg-slate-800/50 rounded-xl p-4">
              <h4 className="text-white font-medium mb-4">Impact Assessment Summary</h4>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-500 text-sm">Service Impact</span>
                  <p className="text-white">{selectedVuln.remediation.requiresRestart ? 'Brief Outage' : 'None'}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-sm">Estimated Downtime</span>
                  <p className="text-white">{selectedVuln.remediation.estimatedDowntime} minutes</p>
                </div>
                <div>
                  <span className="text-slate-500 text-sm">Rollback Available</span>
                  <p className="text-emerald-400">Yes</p>
                </div>
                <div>
                  <span className="text-slate-500 text-sm">Pre-flight Checks</span>
                  <p className="text-emerald-400">Enabled</p>
                </div>
              </div>
            </div>

            <div className="bg-slate-800/50 rounded-xl p-4">
              <h4 className="text-white font-medium mb-4">Approval Chain</h4>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-sm text-white">SL</div>
                    <div>
                      <p className="text-white text-sm">Security Lead</p>
                      <p className="text-slate-500 text-xs">Required</p>
                    </div>
                  </div>
                  <span className="px-2 py-1 text-xs rounded bg-amber-500/20 text-amber-400">Pending</span>
                </div>
                {selectedVuln.asset.criticality === 'tier1' && (
                  <div className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-sm text-white">BO</div>
                      <div>
                        <p className="text-white text-sm">Business Owner</p>
                        <p className="text-slate-500 text-xs">Required for Tier 1</p>
                      </div>
                    </div>
                    <span className="px-2 py-1 text-xs rounded bg-slate-700/50 text-slate-400">Waiting</span>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-slate-800/50 rounded-xl p-4">
              <h4 className="text-white font-medium mb-3">Select Maintenance Window</h4>
              <select className="w-full bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyan-500/50">
                <option>Sunday 2:00 AM - 6:00 AM EST (Standard Weekly)</option>
                <option>Saturday 11:00 PM - Sunday 3:00 AM EST</option>
                <option>Emergency Window - Requires CISO Approval</option>
              </select>
            </div>
          </div>

          <div className="p-6 border-t border-slate-700/50 flex items-center justify-end gap-3">
            <button 
              onClick={() => setShowApprovalModal(false)}
              className="px-4 py-2 bg-slate-700/50 hover:bg-slate-600/50 text-slate-300 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button 
              onClick={() => {
                setShowApprovalModal(false);
                setLogs(prev => [{
                  timestamp: new Date().toISOString(),
                  agent: 'approval',
                  message: `Approval request submitted for ${selectedVuln.id} - awaiting Security Lead review`
                }, ...prev]);
              }}
              className="px-4 py-2 bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 rounded-lg flex items-center gap-2 transition-colors"
            >
              <UserCheck className="w-4 h-4" />
              Submit for Approval
            </button>
          </div>
        </div>
      </div>
    );
  };

  // ============================================================================
  // PROMPT MODAL
  // ============================================================================

  const PromptModal = () => {
    if (!showPromptModal || !selectedAgent) return null;

    return (
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-8">
        <div className="bg-slate-900 border border-slate-700/50 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
          <div className="p-6 border-b border-slate-700/50 flex items-center justify-between">
            <h2 className="text-xl font-semibold text-white capitalize flex items-center gap-3">
              <Bot className="w-6 h-6 text-emerald-400" />
              {selectedAgent} Agent System Prompt
            </h2>
            <button 
              onClick={() => setShowPromptModal(false)}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
            >
              <XCircle className="w-5 h-5" />
            </button>
          </div>
          
          <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
            <pre className="bg-slate-950/50 rounded-xl p-6 text-sm text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap leading-relaxed">
              {AGENT_PROMPTS[selectedAgent].trim()}
            </pre>
          </div>
        </div>
      </div>
    );
  };

  // ============================================================================
  // MAIN RENDER
  // ============================================================================

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* Header */}
      <header className="bg-slate-900/80 border-b border-slate-800/50 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-[1600px] mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 bg-gradient-to-br from-emerald-400 to-cyan-500 rounded-xl flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">VulnGuard AI</h1>
                <p className="text-xs text-slate-400">Multi-Agent Vulnerability Management</p>
              </div>
            </div>
            
            <nav className="flex items-center gap-1">
              {[
                { id: 'dashboard', label: 'Dashboard', icon: Layers },
                { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Target },
                { id: 'agents', label: 'AI Agents', icon: Bot },
                { id: 'playbooks', label: 'Playbooks', icon: GitBranch }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                    activeTab === tab.id 
                      ? 'bg-slate-800 text-white' 
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </button>
              ))}
            </nav>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-full">
                <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
                <span className="text-emerald-400 text-sm font-medium">Agents Active</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1600px] mx-auto px-6 py-8">
        {activeTab === 'dashboard' && <DashboardView />}
        {activeTab === 'vulnerabilities' && <VulnerabilitiesView />}
        {activeTab === 'agents' && <AgentsView />}
        {activeTab === 'playbooks' && <PlaybooksView />}
      </main>

      {/* Modals */}
      <VulnDetailModal />
      <ApprovalModal />
      <PromptModal />
    </div>
  );
};

export default VulnManagementApp;

#!/usr/bin/env python3
"""
VulnGuard AI - Command Line Interface
Local management tool for vulnerability management operations
"""
import asyncio
import json
import sys
from datetime import datetime
from typing import Optional
import click
import httpx

# Default API URL
DEFAULT_API_URL = "http://localhost:8000"


class VulnGuardCLI:
    """CLI client for VulnGuard API"""

    def __init__(self, api_url: str):
        self.api_url = api_url.rstrip('/')
        self.client = httpx.Client(base_url=f"{self.api_url}/api/v1", timeout=30.0)

    def _request(self, method: str, endpoint: str, **kwargs):
        """Make API request"""
        try:
            response = self.client.request(method, endpoint, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            click.echo(f"Error: {e.response.status_code} - {e.response.text}", err=True)
            sys.exit(1)
        except httpx.RequestError as e:
            click.echo(f"Connection error: {e}", err=True)
            sys.exit(1)


# Create CLI group
@click.group()
@click.option('--api-url', envvar='VULNGUARD_API_URL', default=DEFAULT_API_URL,
              help='VulnGuard API URL')
@click.pass_context
def cli(ctx, api_url):
    """VulnGuard AI - Multi-Agent Vulnerability Management CLI"""
    ctx.ensure_object(dict)
    ctx.obj['client'] = VulnGuardCLI(api_url)


# ============================================================================
# VULNERABILITIES COMMANDS
# ============================================================================

@cli.group()
def vulns():
    """Vulnerability management commands"""
    pass


@vulns.command('list')
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low']),
              help='Filter by severity')
@click.option('--status', type=str, help='Filter by status')
@click.option('--limit', default=20, help='Number of results')
@click.option('--json-output', is_flag=True, help='Output as JSON')
@click.pass_context
def list_vulns(ctx, severity, status, limit, json_output):
    """List vulnerabilities"""
    client = ctx.obj['client']

    params = {'page_size': limit}
    if severity:
        params['severity'] = severity
    if status:
        params['status'] = status

    result = client._request('GET', '/vulnerabilities', params=params)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        items = result.get('items', [])
        if not items:
            click.echo("No vulnerabilities found.")
            return

        click.echo(f"\n{'ID':<20} {'Severity':<10} {'Status':<15} {'Title':<50}")
        click.echo("-" * 95)

        for vuln in items:
            severity_colors = {
                'critical': 'red',
                'high': 'yellow',
                'medium': 'blue',
                'low': 'green'
            }
            sev = vuln.get('severity', 'unknown')
            click.echo(
                f"{vuln['id']:<20} "
                f"{click.style(sev.upper(), fg=severity_colors.get(sev, 'white')):<20} "
                f"{vuln.get('remediation', {}).get('status', 'unknown'):<15} "
                f"{vuln.get('title', '')[:50]:<50}"
            )

        click.echo(f"\nTotal: {result.get('total', 0)}")


@vulns.command('get')
@click.argument('vuln_id')
@click.option('--json-output', is_flag=True, help='Output as JSON')
@click.pass_context
def get_vuln(ctx, vuln_id, json_output):
    """Get vulnerability details"""
    client = ctx.obj['client']
    result = client._request('GET', f'/vulnerabilities/{vuln_id}')

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"\n{'='*60}")
        click.echo(f"Vulnerability: {result.get('id', 'N/A')}")
        click.echo(f"{'='*60}")
        click.echo(f"CVE:      {result.get('cve', 'N/A')}")
        click.echo(f"Title:    {result.get('title', 'N/A')}")
        click.echo(f"Severity: {result.get('severity', 'N/A').upper()}")
        click.echo(f"CVSS:     {result.get('cvss', 'N/A')}")
        click.echo(f"Status:   {result.get('status', 'N/A')}")


@vulns.command('assess')
@click.argument('vuln_id')
@click.pass_context
def assess_vuln(ctx, vuln_id):
    """Trigger assessment for a vulnerability"""
    client = ctx.obj['client']
    result = client._request('POST', f'/vulnerabilities/{vuln_id}/assess')

    click.echo(f"Assessment triggered for {vuln_id}")
    click.echo(f"Status: {result.get('status', 'unknown')}")


# ============================================================================
# APPROVALS COMMANDS
# ============================================================================

@cli.group()
def approvals():
    """Approval workflow commands"""
    pass


@approvals.command('list')
@click.option('--status', type=click.Choice(['pending', 'approved', 'denied', 'expired']),
              help='Filter by status')
@click.option('--json-output', is_flag=True, help='Output as JSON')
@click.pass_context
def list_approvals(ctx, status, json_output):
    """List approval requests"""
    client = ctx.obj['client']

    params = {}
    if status:
        params['status'] = status

    result = client._request('GET', '/approvals', params=params)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        if not result:
            click.echo("No approval requests found.")
            return

        click.echo(f"\n{'ID':<20} {'Vuln ID':<20} {'Risk':<8} {'Status':<10}")
        click.echo("-" * 60)

        for approval in result:
            click.echo(
                f"{approval.get('id', 'N/A'):<20} "
                f"{approval.get('vulnerability_id', 'N/A'):<20} "
                f"{approval.get('risk_score', 0):<8.1f} "
                f"{approval.get('status', 'unknown'):<10}"
            )


@approvals.command('approve')
@click.argument('approval_id')
@click.option('--comments', default='', help='Approval comments')
@click.option('--conditions', multiple=True, help='Conditions for approval')
@click.option('--window', help='Maintenance window ID')
@click.pass_context
def approve(ctx, approval_id, comments, conditions, window):
    """Approve a remediation request"""
    client = ctx.obj['client']

    payload = {
        'approval_id': approval_id,
        'approver_role': 'Security Lead',
        'decision': 'approved',
        'comments': comments,
        'conditions': list(conditions)
    }

    if window:
        payload['scheduled_window'] = window

    result = client._request('POST', f'/approvals/{approval_id}/decide', json=payload)

    click.echo(f"Approval decision recorded: {result.get('status', 'unknown')}")


@approvals.command('deny')
@click.argument('approval_id')
@click.option('--reason', required=True, help='Denial reason')
@click.pass_context
def deny(ctx, approval_id, reason):
    """Deny a remediation request"""
    client = ctx.obj['client']

    payload = {
        'approval_id': approval_id,
        'approver_role': 'Security Lead',
        'decision': 'denied',
        'comments': reason,
        'conditions': []
    }

    result = client._request('POST', f'/approvals/{approval_id}/decide', json=payload)

    click.echo(f"Approval denied: {result.get('status', 'unknown')}")


# ============================================================================
# AGENTS COMMANDS
# ============================================================================

@cli.group()
def agents():
    """Agent management commands"""
    pass


@agents.command('status')
@click.option('--json-output', is_flag=True, help='Output as JSON')
@click.pass_context
def agent_status(ctx, json_output):
    """Get status of all agents"""
    client = ctx.obj['client']
    result = client._request('GET', '/agents/status')

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"\n{'Agent':<15} {'Status':<12} {'Current Task':<40}")
        click.echo("-" * 70)

        status_colors = {
            'idle': 'green',
            'running': 'yellow',
            'error': 'red',
            'awaiting': 'blue',
            'scheduled': 'cyan',
            'executing': 'magenta'
        }

        for agent_name in ['discovery', 'assessment', 'approval', 'remediation', 'validation']:
            agent = result.get(agent_name, {})
            status = agent.get('status', 'unknown')
            task = agent.get('current_task', '-') or '-'

            click.echo(
                f"{agent_name:<15} "
                f"{click.style(status, fg=status_colors.get(status, 'white')):<20} "
                f"{task[:40]:<40}"
            )


@agents.command('trigger')
@click.argument('agent_name', type=click.Choice(['discovery', 'assessment', 'approval', 'remediation', 'validation']))
@click.pass_context
def trigger_agent(ctx, agent_name):
    """Manually trigger an agent cycle"""
    client = ctx.obj['client']
    result = client._request('POST', f'/agents/{agent_name}/trigger')

    click.echo(f"Agent '{agent_name}' triggered: {result.get('status', 'unknown')}")


@agents.command('logs')
@click.option('--agent', help='Filter by agent name')
@click.option('--limit', default=50, help='Number of log entries')
@click.pass_context
def agent_logs(ctx, agent, limit):
    """View agent activity logs"""
    client = ctx.obj['client']

    params = {'limit': limit}
    if agent:
        params['agent'] = agent

    result = client._request('GET', '/agents/activity', params=params)

    click.echo(f"\n{'Timestamp':<25} {'Agent':<15} {'Action':<30}")
    click.echo("-" * 70)

    for log in result:
        ts = log.get('timestamp', '')[:19]
        click.echo(
            f"{ts:<25} "
            f"{log.get('agent', 'N/A'):<15} "
            f"{log.get('action', 'N/A'):<30}"
        )


# ============================================================================
# PLAYBOOKS COMMANDS
# ============================================================================

@cli.group()
def playbooks():
    """Playbook management commands"""
    pass


@playbooks.command('list')
@click.option('--json-output', is_flag=True, help='Output as JSON')
@click.pass_context
def list_playbooks(ctx, json_output):
    """List available playbooks"""
    client = ctx.obj['client']
    result = client._request('GET', '/playbooks')

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"\n{'ID':<25} {'Name':<35} {'Restart':<10} {'Success Rate':<15}")
        click.echo("-" * 85)

        for pb in result:
            restart = 'Yes' if pb.get('requires_restart') else 'No'
            success = f"{pb.get('success_rate', 0) * 100:.0f}%"

            click.echo(
                f"{pb.get('id', 'N/A'):<25} "
                f"{pb.get('name', 'N/A')[:35]:<35} "
                f"{restart:<10} "
                f"{success:<15}"
            )


# ============================================================================
# DASHBOARD COMMANDS
# ============================================================================

@cli.command()
@click.pass_context
def dashboard(ctx):
    """Show vulnerability management dashboard"""
    client = ctx.obj['client']
    stats = client._request('GET', '/dashboard/stats')
    agent_status = client._request('GET', '/agents/status')

    click.clear()
    click.echo("""
╔═══════════════════════════════════════════════════════════════════╗
║                    VulnGuard AI Dashboard                         ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

    click.echo(f"  Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
    click.echo(f"  ├── {click.style('Critical:', fg='red')} {stats.get('critical_count', 0)}")
    click.echo(f"  ├── {click.style('High:', fg='yellow')} {stats.get('high_count', 0)}")
    click.echo(f"  ├── {click.style('Medium:', fg='blue')} {stats.get('medium_count', 0)}")
    click.echo(f"  └── {click.style('Low:', fg='green')} {stats.get('low_count', 0)}")

    click.echo(f"\n  Pending Approval: {stats.get('pending_approval', 0)}")
    click.echo(f"  Scheduled: {stats.get('scheduled', 0)}")
    click.echo(f"  In Progress: {stats.get('in_progress', 0)}")
    click.echo(f"  Resolved This Week: {stats.get('resolved_this_week', 0)}")
    click.echo(f"  MTTR: {stats.get('mttr_hours', 0):.1f} hours")

    click.echo("\n" + "─" * 60)
    click.echo("  Agent Status:")

    for agent_name in ['discovery', 'assessment', 'approval', 'remediation', 'validation']:
        agent = agent_status.get(agent_name, {})
        status = agent.get('status', 'unknown')
        indicator = '●' if status in ['running', 'executing'] else '○'
        color = 'green' if status in ['idle', 'running'] else 'yellow' if status == 'awaiting' else 'red'
        click.echo(f"  {click.style(indicator, fg=color)} {agent_name.capitalize()}: {status}")


# ============================================================================
# HEALTH CHECK
# ============================================================================

@cli.command()
@click.pass_context
def health(ctx):
    """Check API health"""
    client = ctx.obj['client']

    try:
        # Use base URL for health check
        response = httpx.get(f"{client.api_url}/health", timeout=10.0)
        result = response.json()

        if result.get('status') == 'healthy':
            click.echo(click.style("✓ VulnGuard API is healthy", fg='green'))
            click.echo(f"  Version: {result.get('version', 'unknown')}")

            agents = result.get('agents', {})
            if agents:
                click.echo("  Agents:")
                for name, status in agents.items():
                    click.echo(f"    - {name}: {status}")
        else:
            click.echo(click.style("✗ VulnGuard API is unhealthy", fg='red'))
            sys.exit(1)

    except Exception as e:
        click.echo(click.style(f"✗ Cannot connect to VulnGuard API: {e}", fg='red'))
        sys.exit(1)


if __name__ == '__main__':
    cli()

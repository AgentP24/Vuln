"""
VulnGuard AI - Discovery Agent
Continuously retrieves and normalizes vulnerability data from scanning platforms
"""
import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4
import structlog

from .base import BaseAgent
from .prompts import DISCOVERY_AGENT_PROMPT
from models import (
    AgentStatus, Vulnerability, VulnerabilityCreate, VulnerabilityStatus,
    Asset, Detection, BusinessContext, RemediationInfo,
    Severity, AssetCriticality, AssetType, DetectionSource, DetectionMethod,
    RevenueImpact, DataClassification
)

logger = structlog.get_logger()


class DiscoveryAgent(BaseAgent):
    """
    Discovery Agent: Retrieves, normalizes, and enriches vulnerability data
    from multiple scanning platforms (Qualys, Tenable, Rapid7, Guardium).
    """

    def __init__(
        self,
        scanner_clients: Dict[str, Any],
        cmdb_client: Optional[Any] = None,
        knowledge_base: Optional[Any] = None
    ):
        super().__init__(
            name="discovery",
            system_prompt=DISCOVERY_AGENT_PROMPT,
            knowledge_base=knowledge_base
        )
        self.scanner_clients = scanner_clients
        self.cmdb_client = cmdb_client
        self._last_poll_times: Dict[str, datetime] = {}
        self._vulnerability_cache: Dict[str, Vulnerability] = {}

    async def process(self, input_data: Any) -> Dict[str, Any]:
        """
        Process raw vulnerability data from scanners.

        Args:
            input_data: Raw scan data from a scanner

        Returns:
            Normalized vulnerability data
        """
        self._update_state(status=AgentStatus.RUNNING, current_task="Processing vulnerability data")

        try:
            # Let the LLM help normalize and enrich the data
            prompt = f"""
            Analyze and normalize the following vulnerability scan data:

            {json.dumps(input_data, indent=2, default=str)}

            Extract and normalize to our schema:
            1. Identify the CVE (if any)
            2. Determine severity based on CVSS
            3. Classify detection method (agent/remote/unauthenticated)
            4. Flag if this is a remote vulnerability (weak ciphers, deprecated TLS, etc.)

            Return a JSON object with the normalized vulnerability data.
            """

            response = await self._invoke_llm(prompt)

            # Parse the response
            try:
                normalized = json.loads(response)
            except json.JSONDecodeError:
                # Extract JSON from response if embedded in text
                import re
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    normalized = json.loads(json_match.group())
                else:
                    normalized = {"raw_response": response}

            await self.log_activity(
                action="vulnerability_normalized",
                message=f"Normalized vulnerability data from {input_data.get('source', 'unknown')}",
                details={"original_count": 1, "normalized": bool(normalized)}
            )

            return normalized

        except Exception as e:
            logger.error("Error processing vulnerability data", error=str(e))
            self._update_state(status=AgentStatus.ERROR, error_message=str(e))
            raise

    async def run_cycle(self) -> Dict[str, Any]:
        """
        Run a complete discovery cycle across all configured scanners.

        Returns:
            Summary of discovered vulnerabilities
        """
        self._update_state(
            status=AgentStatus.RUNNING,
            current_task="Running discovery cycle"
        )

        cycle_results = {
            "action": "discovery_cycle_complete",
            "timestamp": datetime.utcnow().isoformat(),
            "sources_polled": [],
            "results": {
                "new_vulnerabilities": 0,
                "updated_vulnerabilities": 0,
                "duplicates_merged": 0,
                "unknown_assets_flagged": 0
            },
            "vulnerabilities": [],
            "errors": []
        }

        try:
            # Poll each scanner
            for scanner_name, client in self.scanner_clients.items():
                try:
                    await self.log_activity(
                        action="polling_scanner",
                        message=f"Polling {scanner_name} for vulnerabilities"
                    )

                    # Get vulnerabilities from scanner
                    raw_vulns = await self._poll_scanner(scanner_name, client)
                    cycle_results["sources_polled"].append(scanner_name)

                    # Process each vulnerability
                    for raw_vuln in raw_vulns:
                        processed = await self._process_vulnerability(raw_vuln, scanner_name)

                        if processed:
                            # Check for duplicates
                            dedup_key = self._get_dedup_key(processed)

                            if dedup_key in self._vulnerability_cache:
                                # Merge with existing
                                await self._merge_vulnerability(
                                    self._vulnerability_cache[dedup_key],
                                    processed
                                )
                                cycle_results["results"]["duplicates_merged"] += 1
                            else:
                                # New vulnerability
                                self._vulnerability_cache[dedup_key] = processed
                                cycle_results["vulnerabilities"].append(processed.model_dump())
                                cycle_results["results"]["new_vulnerabilities"] += 1

                except Exception as e:
                    logger.error(f"Error polling {scanner_name}", error=str(e))
                    cycle_results["errors"].append({
                        "scanner": scanner_name,
                        "error": str(e)
                    })

            self._update_state(
                status=AgentStatus.IDLE,
                current_task=None,
                metrics_update={
                    "last_cycle_vulns": cycle_results["results"]["new_vulnerabilities"],
                    "total_cached": len(self._vulnerability_cache)
                }
            )
            self._state.last_run = datetime.utcnow()

            await self.log_activity(
                action="discovery_cycle_complete",
                message=f"Discovery cycle complete. Found {cycle_results['results']['new_vulnerabilities']} new vulnerabilities",
                details=cycle_results["results"]
            )

            return cycle_results

        except Exception as e:
            logger.error("Discovery cycle failed", error=str(e))
            self._update_state(status=AgentStatus.ERROR, error_message=str(e))
            cycle_results["errors"].append({"general": str(e)})
            return cycle_results

    async def _poll_scanner(self, scanner_name: str, client: Any) -> List[Dict[str, Any]]:
        """
        Poll a specific scanner for vulnerabilities.

        Args:
            scanner_name: Name of the scanner
            client: Scanner API client

        Returns:
            List of raw vulnerability data
        """
        # Get last poll time for incremental fetching
        last_poll = self._last_poll_times.get(scanner_name)

        try:
            # Call the appropriate scanner API
            if hasattr(client, 'get_vulnerabilities'):
                vulns = await client.get_vulnerabilities(since=last_poll)
            else:
                # Mock response for development
                vulns = self._get_mock_vulnerabilities(scanner_name)

            self._last_poll_times[scanner_name] = datetime.utcnow()
            return vulns

        except Exception as e:
            logger.error(f"Failed to poll {scanner_name}", error=str(e))
            raise

    async def _process_vulnerability(
        self,
        raw_vuln: Dict[str, Any],
        source: str
    ) -> Optional[Vulnerability]:
        """
        Process and normalize a single vulnerability.

        Args:
            raw_vuln: Raw vulnerability data
            source: Scanner source name

        Returns:
            Normalized Vulnerability object
        """
        try:
            # Generate unique ID
            vuln_id = f"VULN-{datetime.utcnow().year}-{str(uuid4())[:8].upper()}"

            # Extract and normalize fields
            cve = raw_vuln.get('cve', raw_vuln.get('CVE', 'N/A'))
            title = raw_vuln.get('title', raw_vuln.get('plugin_name', 'Unknown Vulnerability'))
            cvss = float(raw_vuln.get('cvss', raw_vuln.get('cvss_score', 5.0)))

            # Determine severity from CVSS
            if cvss >= 9.0:
                severity = Severity.CRITICAL
            elif cvss >= 7.0:
                severity = Severity.HIGH
            elif cvss >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Determine detection method
            method_raw = raw_vuln.get('detection_method', 'remote')
            if method_raw in ['agent', 'local']:
                detection_method = DetectionMethod.AGENT
            elif method_raw in ['unauthenticated', 'external']:
                detection_method = DetectionMethod.UNAUTHENTICATED
            else:
                detection_method = DetectionMethod.REMOTE

            # Get asset info (or create placeholder)
            asset_data = raw_vuln.get('asset', {})
            hostname = asset_data.get('hostname', raw_vuln.get('hostname', 'unknown'))
            ip = asset_data.get('ip', raw_vuln.get('ip', '0.0.0.0'))

            # Enrich from CMDB if available
            cmdb_data = await self._enrich_from_cmdb(hostname, ip)

            asset = Asset(
                hostname=hostname,
                ip=ip,
                type=AssetType(cmdb_data.get('type', 'server')),
                criticality=AssetCriticality(cmdb_data.get('criticality', 'tier3')),
                business_unit=cmdb_data.get('business_unit', 'Unknown'),
                owner=cmdb_data.get('owner', 'Unknown'),
                transaction_volume=cmdb_data.get('transaction_volume', 0)
            )

            detection = Detection(
                source=DetectionSource(source),
                method=detection_method,
                first_detected=datetime.fromisoformat(
                    raw_vuln.get('first_detected', datetime.utcnow().isoformat())
                ),
                last_seen=datetime.utcnow(),
                scan_id=raw_vuln.get('scan_id', str(uuid4())),
                confidence=0.95 if detection_method == DetectionMethod.AGENT else 0.85
            )

            business_context = BusinessContext(
                transaction_volume=asset.transaction_volume,
                revenue_impact=self._calculate_revenue_impact(asset.transaction_volume),
                data_classification=DataClassification(cmdb_data.get('data_classification', 'public')),
                compliance_frameworks=cmdb_data.get('compliance_frameworks', [])
            )

            # Check if this is a "hard to fix" remote vulnerability
            is_remote_vuln = self._is_remote_vulnerability(title, cve)

            remediation = RemediationInfo(
                status=VulnerabilityStatus.NEW,
                suggested_fix=raw_vuln.get('solution', None),
                requires_restart=self._requires_restart(title, raw_vuln.get('solution', '')),
                estimated_downtime=0
            )

            vulnerability = Vulnerability(
                id=vuln_id,
                cve=cve,
                title=title,
                severity=severity,
                cvss=cvss,
                asset=asset,
                detection=detection,
                remediation=remediation,
                business_context=business_context
            )

            if is_remote_vuln:
                await self.log_activity(
                    action="remote_vulnerability_flagged",
                    message=f"Flagged remote vulnerability: {title}",
                    vulnerability_id=vuln_id,
                    details={"reason": "Remote vulnerability requiring special handling"}
                )

            return vulnerability

        except Exception as e:
            logger.error("Failed to process vulnerability", error=str(e))
            return None

    async def _enrich_from_cmdb(self, hostname: str, ip: str) -> Dict[str, Any]:
        """Enrich asset data from CMDB"""
        if self.cmdb_client:
            try:
                return await self.cmdb_client.get_asset(hostname=hostname, ip=ip)
            except Exception:
                pass

        # Return defaults if CMDB not available
        return {
            "type": "server",
            "criticality": "tier3",
            "business_unit": "Unknown",
            "owner": "Unknown",
            "transaction_volume": 0,
            "data_classification": "public",
            "compliance_frameworks": []
        }

    def _get_dedup_key(self, vuln: Vulnerability) -> str:
        """Generate deduplication key for a vulnerability"""
        return f"{vuln.asset.hostname}:{vuln.asset.ip}:{vuln.cve}:{vuln.title}"

    async def _merge_vulnerability(
        self,
        existing: Vulnerability,
        new: Vulnerability
    ):
        """Merge new vulnerability data into existing record"""
        # Update last_seen
        existing.detection.last_seen = new.detection.last_seen

        # Keep highest confidence
        if new.detection.confidence > existing.detection.confidence:
            existing.detection.confidence = new.detection.confidence

        # Update if severity increased
        severity_order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3
        }
        if severity_order[new.severity] > severity_order[existing.severity]:
            existing.severity = new.severity
            existing.cvss = new.cvss

    def _is_remote_vulnerability(self, title: str, cve: str) -> bool:
        """Check if this is a 'hard to fix' remote vulnerability"""
        remote_indicators = [
            'tls', 'ssl', 'cipher', 'certificate', 'banner',
            'deprecated', 'weak', 'insecure protocol'
        ]
        title_lower = title.lower()
        return any(indicator in title_lower for indicator in remote_indicators)

    def _requires_restart(self, title: str, solution: str) -> bool:
        """Determine if remediation requires service/system restart"""
        restart_indicators = [
            'restart', 'reboot', 'reload', 'upgrade', 'firmware',
            'kernel', 'service configuration'
        ]
        combined = (title + ' ' + solution).lower()
        return any(indicator in combined for indicator in restart_indicators)

    def _calculate_revenue_impact(self, transaction_volume: float) -> RevenueImpact:
        """Calculate revenue impact based on transaction volume"""
        if transaction_volume >= 1_000_000_000:
            return RevenueImpact.CRITICAL
        elif transaction_volume >= 100_000_000:
            return RevenueImpact.HIGH
        elif transaction_volume >= 10_000_000:
            return RevenueImpact.MEDIUM
        else:
            return RevenueImpact.LOW

    def _get_mock_vulnerabilities(self, scanner: str) -> List[Dict[str, Any]]:
        """Generate mock vulnerabilities for testing"""
        mock_vulns = [
            {
                "cve": "CVE-2024-21762",
                "title": "Fortinet FortiOS Out-of-Bound Write",
                "cvss_score": 9.8,
                "detection_method": "remote",
                "hostname": "prod-fw-01.corp.local",
                "ip": "10.0.1.1",
                "scan_id": f"{scanner.upper()}-{uuid4().hex[:8]}",
                "solution": "Upgrade FortiOS to 7.4.3 or later",
                "first_detected": datetime.utcnow().isoformat()
            },
            {
                "cve": "N/A",
                "title": "Deprecated TLSv1.1 Protocol Enabled",
                "cvss_score": 7.5,
                "detection_method": "remote",
                "hostname": "api-gateway-03.corp.local",
                "ip": "10.0.3.100",
                "scan_id": f"{scanner.upper()}-{uuid4().hex[:8]}",
                "solution": "Disable TLSv1.0 and TLSv1.1, enforce TLSv1.2+",
                "first_detected": datetime.utcnow().isoformat()
            }
        ]
        return mock_vulns[:1]  # Return just one for testing

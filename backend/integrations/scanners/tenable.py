"""
VulnGuard AI - Tenable Scanner Integration
Client for Tenable.io API
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
import structlog

from .base import BaseScannerClient

logger = structlog.get_logger()


class TenableClient(BaseScannerClient):
    """
    Tenable.io API client.

    Supports:
    - Vulnerability export API
    - Asset inventory
    - Scan management
    """

    def __init__(
        self,
        api_url: str,
        access_key: str,
        secret_key: str,
        **kwargs
    ):
        super().__init__(api_url, **kwargs)
        self.access_key = access_key
        self.secret_key = secret_key

    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get Tenable API key headers"""
        return {
            "X-ApiKeys": f"accessKey={self.access_key};secretKey={self.secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def get_vulnerabilities(
        self,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities using Tenable's export API.

        Args:
            since: Only get vulnerabilities detected since this time

        Returns:
            List of normalized vulnerability data
        """
        try:
            # Start vulnerability export
            export_filters = {
                "filters": {
                    "severity": ["critical", "high", "medium"]
                }
            }

            if since:
                export_filters["filters"]["first_found"] = since.timestamp()

            # Request export
            export_response = await self._request(
                "POST",
                "/vulns/export",
                json=export_filters
            )

            export_uuid = export_response.json().get("export_uuid")

            # Wait for export to complete
            vulnerabilities = await self._wait_for_export(export_uuid)

            # Normalize each vulnerability
            normalized = [
                self._normalize_tenable_vulnerability(v)
                for v in vulnerabilities
            ]

            logger.info(f"Retrieved {len(normalized)} vulnerabilities from Tenable")
            return normalized

        except Exception as e:
            logger.error("Failed to get Tenable vulnerabilities", error=str(e))
            raise

    async def _wait_for_export(self, export_uuid: str) -> List[Dict[str, Any]]:
        """Wait for export to complete and download chunks"""
        import asyncio

        vulnerabilities = []
        max_attempts = 60  # 5 minutes max wait

        for _ in range(max_attempts):
            status_response = await self._request(
                "GET",
                f"/vulns/export/{export_uuid}/status"
            )
            status = status_response.json()

            if status.get("status") == "FINISHED":
                # Download all chunks
                for chunk_id in status.get("chunks_available", []):
                    chunk_response = await self._request(
                        "GET",
                        f"/vulns/export/{export_uuid}/chunks/{chunk_id}"
                    )
                    vulnerabilities.extend(chunk_response.json())
                break

            elif status.get("status") == "ERROR":
                raise Exception(f"Tenable export failed: {status.get('error')}")

            await asyncio.sleep(5)

        return vulnerabilities

    async def scan_targets(
        self,
        targets: List[str],
        scan_type: str = "targeted"
    ) -> Dict[str, Any]:
        """
        Launch a scan on specified targets.

        Args:
            targets: List of IPs or hostnames
            scan_type: Type of scan

        Returns:
            Scan result
        """
        try:
            # Create scan
            scan_config = {
                "uuid": "template-uuid",  # Would use actual template in production
                "settings": {
                    "name": f"VulnGuard Validation {datetime.utcnow().isoformat()}",
                    "text_targets": ",".join(targets),
                    "launch": "ON_DEMAND"
                }
            }

            # Create the scan
            create_response = await self._request(
                "POST",
                "/scans",
                json=scan_config
            )

            scan_id = create_response.json().get("scan", {}).get("id")

            # Launch the scan
            await self._request(
                "POST",
                f"/scans/{scan_id}/launch"
            )

            return {
                "scan_id": f"TEN-{scan_id}",
                "status": "launched",
                "targets": targets
            }

        except Exception as e:
            logger.error("Failed to launch Tenable scan", error=str(e))
            raise

    async def get_asset_details(self, ip: str) -> Dict[str, Any]:
        """Get asset details from Tenable"""
        try:
            response = await self._request(
                "GET",
                f"/assets",
                params={"filter.0.filter": "ipv4", "filter.0.quality": "eq", "filter.0.value": ip}
            )

            assets = response.json().get("assets", [])
            if assets:
                return self._normalize_tenable_asset(assets[0])

            return {}

        except Exception as e:
            logger.error("Failed to get Tenable asset", error=str(e))
            return {}

    def _normalize_tenable_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Tenable vulnerability data to common schema"""
        asset = vuln.get("asset", {})
        plugin = vuln.get("plugin", {})
        severity = vuln.get("severity", "medium")

        # Map severity to CVSS-like score
        severity_cvss = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 0.0
        }

        # Determine detection method based on plugin family
        plugin_family = plugin.get("family", "")
        if "local" in plugin_family.lower() or vuln.get("asset", {}).get("agent_uuid"):
            method = "agent"
        elif "remote" in plugin_family.lower():
            method = "remote"
        else:
            method = "unauthenticated"

        return {
            "cve": plugin.get("cve", ["N/A"])[0] if plugin.get("cve") else "N/A",
            "title": plugin.get("name", "Unknown"),
            "plugin_id": plugin.get("id"),
            "cvss_score": float(plugin.get("cvss_base_score", severity_cvss.get(severity, 5.0))),
            "severity": severity,
            "detection_method": method,
            "hostname": asset.get("hostname", asset.get("fqdn", "")),
            "ip": asset.get("ipv4", [""])[0] if asset.get("ipv4") else "",
            "os": asset.get("operating_system", [""])[0] if asset.get("operating_system") else "",
            "first_detected": vuln.get("first_found"),
            "last_detected": vuln.get("last_found"),
            "scan_id": vuln.get("scan", {}).get("uuid", ""),
            "solution": plugin.get("solution", ""),
            "description": plugin.get("description", ""),
            "source": "tenable"
        }

    def _normalize_tenable_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Tenable asset data"""
        return {
            "hostname": asset.get("hostname", [None])[0],
            "ip": asset.get("ipv4", [None])[0],
            "os": asset.get("operating_system", [None])[0],
            "last_scan": asset.get("last_authenticated_scan_date"),
            "agent_uuid": asset.get("agent_uuid"),
            "has_agent": bool(asset.get("has_agent"))
        }

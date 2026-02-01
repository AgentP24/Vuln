"""
VulnGuard AI - Rapid7 InsightVM Scanner Integration
Client for Rapid7 InsightVM API
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
import structlog

from .base import BaseScannerClient

logger = structlog.get_logger()


class Rapid7Client(BaseScannerClient):
    """
    Rapid7 InsightVM API client.

    Supports:
    - Vulnerability retrieval
    - Asset management
    - Scan scheduling
    - Remediation tracking
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        **kwargs
    ):
        super().__init__(api_url, **kwargs)
        self.api_key = api_key

    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get Rapid7 API authentication headers"""
        return {
            "Authorization": f"Basic {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def get_vulnerabilities(
        self,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities from InsightVM.

        Args:
            since: Only get vulnerabilities detected since this time

        Returns:
            List of normalized vulnerability data
        """
        try:
            # Build query parameters
            params = {
                "page": 0,
                "size": 500,
                "sort": "riskScore,DESC"
            }

            all_vulnerabilities = []
            page = 0

            while True:
                params["page"] = page

                response = await self._request(
                    "GET",
                    "/api/3/vulnerabilities",
                    params=params
                )

                data = response.json()
                resources = data.get("resources", [])

                if not resources:
                    break

                # Get affected assets for each vulnerability
                for vuln in resources:
                    affected_assets = await self._get_affected_assets(vuln["id"])

                    for asset in affected_assets:
                        normalized = self._normalize_rapid7_vulnerability(vuln, asset)

                        # Filter by date if specified
                        if since:
                            first_found = normalized.get("first_detected")
                            if first_found and datetime.fromisoformat(first_found.replace("Z", "")) < since:
                                continue

                        all_vulnerabilities.append(normalized)

                # Check for more pages
                if page >= data.get("page", {}).get("totalPages", 1) - 1:
                    break

                page += 1

            logger.info(f"Retrieved {len(all_vulnerabilities)} vulnerabilities from Rapid7")
            return all_vulnerabilities

        except Exception as e:
            logger.error("Failed to get Rapid7 vulnerabilities", error=str(e))
            raise

    async def _get_affected_assets(self, vuln_id: str) -> List[Dict[str, Any]]:
        """Get assets affected by a specific vulnerability"""
        try:
            response = await self._request(
                "GET",
                f"/api/3/vulnerabilities/{vuln_id}/assets"
            )

            return response.json().get("resources", [])

        except Exception as e:
            logger.warning(f"Failed to get affected assets for {vuln_id}", error=str(e))
            return []

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
            # Create ad-hoc scan
            scan_config = {
                "name": f"VulnGuard Validation {datetime.utcnow().isoformat()}",
                "assets": {
                    "includedTargets": {
                        "addresses": targets
                    }
                },
                "scanTemplateId": "discovery",  # Would use appropriate template
                "engineId": None  # Use default engine
            }

            response = await self._request(
                "POST",
                "/api/3/sites/adhoc/scans",
                json=scan_config
            )

            scan_data = response.json()

            return {
                "scan_id": f"R7-{scan_data.get('id', 'unknown')}",
                "status": "launched",
                "targets": targets
            }

        except Exception as e:
            logger.error("Failed to launch Rapid7 scan", error=str(e))
            raise

    async def get_asset_details(self, asset_id: str) -> Dict[str, Any]:
        """Get asset details from InsightVM"""
        try:
            response = await self._request(
                "GET",
                f"/api/3/assets/{asset_id}"
            )

            return self._normalize_rapid7_asset(response.json())

        except Exception as e:
            logger.error("Failed to get Rapid7 asset", error=str(e))
            return {}

    async def get_remediation_projects(self) -> List[Dict[str, Any]]:
        """Get active remediation projects"""
        try:
            response = await self._request(
                "GET",
                "/api/3/remediation_projects"
            )

            return response.json().get("resources", [])

        except Exception as e:
            logger.warning("Failed to get remediation projects", error=str(e))
            return []

    def _normalize_rapid7_vulnerability(
        self,
        vuln: Dict[str, Any],
        asset: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize Rapid7 vulnerability data to common schema"""
        # Extract CVE references
        cves = vuln.get("cves", [])
        primary_cve = cves[0] if cves else "N/A"

        # Map risk score to CVSS-like value (Rapid7 uses 0-1000)
        risk_score = vuln.get("riskScore", 0)
        cvss = min(10.0, risk_score / 100)

        # Determine severity
        severity_score = vuln.get("severity", 0)
        if severity_score >= 8:
            severity = "critical"
        elif severity_score >= 5:
            severity = "high"
        elif severity_score >= 3:
            severity = "medium"
        else:
            severity = "low"

        # Determine detection method
        if asset.get("assessedForVulnerabilities"):
            method = "agent" if asset.get("agent") else "remote"
        else:
            method = "unauthenticated"

        return {
            "cve": primary_cve,
            "title": vuln.get("title", "Unknown"),
            "vuln_id": vuln.get("id"),
            "cvss_score": cvss,
            "severity": severity,
            "risk_score": risk_score,
            "detection_method": method,
            "hostname": asset.get("hostName", ""),
            "ip": asset.get("ip", ""),
            "os": asset.get("os", {}).get("description", ""),
            "first_detected": asset.get("history", [{}])[0].get("date") if asset.get("history") else None,
            "last_detected": datetime.utcnow().isoformat(),
            "solution": vuln.get("remedies", [{}])[0].get("fix") if vuln.get("remedies") else "",
            "description": vuln.get("description", {}).get("text", ""),
            "categories": vuln.get("categories", []),
            "exploits": len(vuln.get("exploits", [])),
            "malware_kits": len(vuln.get("malwareKits", [])),
            "source": "rapid7"
        }

    def _normalize_rapid7_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Rapid7 asset data"""
        return {
            "asset_id": asset.get("id"),
            "hostname": asset.get("hostName"),
            "ip": asset.get("ip"),
            "os": asset.get("os", {}).get("description"),
            "os_family": asset.get("os", {}).get("family"),
            "last_scan": asset.get("history", [{}])[-1].get("date") if asset.get("history") else None,
            "risk_score": asset.get("riskScore", 0),
            "vulnerability_count": asset.get("vulnerabilities", {}).get("total", 0),
            "critical_vulns": asset.get("vulnerabilities", {}).get("critical", 0),
            "has_agent": bool(asset.get("agent"))
        }

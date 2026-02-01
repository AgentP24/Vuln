"""
VulnGuard AI - Qualys Scanner Integration
Client for Qualys VM API
"""
import base64
from datetime import datetime
from typing import Any, Dict, List, Optional
import structlog

from .base import BaseScannerClient

logger = structlog.get_logger()


class QualysClient(BaseScannerClient):
    """
    Qualys Vulnerability Management API client.

    Supports:
    - Host VM Detection API for vulnerabilities
    - Asset Management API for host details
    - Compliance scanning
    """

    def __init__(
        self,
        api_url: str,
        username: str,
        password: str,
        **kwargs
    ):
        super().__init__(api_url, **kwargs)
        self.username = username
        self.password = password
        self._session_token: Optional[str] = None

    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get Qualys Basic Auth headers"""
        credentials = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()

        return {
            "Authorization": f"Basic {credentials}",
            "X-Requested-With": "VulnGuard AI",
            "Content-Type": "application/xml"
        }

    async def get_vulnerabilities(
        self,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities from Qualys VM module.

        Args:
            since: Only get vulnerabilities detected since this time

        Returns:
            List of normalized vulnerability data
        """
        try:
            # Build API parameters
            params = {
                "action": "list",
                "show_igs": "1",
                "show_results": "1",
                "output_format": "JSON"
            }

            if since:
                params["detection_updated_since"] = since.strftime("%Y-%m-%d")

            response = await self._request(
                "GET",
                "/api/2.0/fo/asset/host/vm/detection/",
                params=params
            )

            data = response.json()

            # Normalize vulnerabilities
            vulnerabilities = []
            for host in data.get("HOST_LIST", {}).get("HOST", []):
                for detection in host.get("DETECTION_LIST", {}).get("DETECTION", []):
                    vuln = self._normalize_qualys_vulnerability(host, detection)
                    vulnerabilities.append(vuln)

            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities from Qualys")
            return vulnerabilities

        except Exception as e:
            logger.error("Failed to get Qualys vulnerabilities", error=str(e))
            raise

    async def scan_targets(
        self,
        targets: List[str],
        scan_type: str = "targeted"
    ) -> Dict[str, Any]:
        """
        Launch a VM scan on specified targets.

        Args:
            targets: List of IPs or hostnames
            scan_type: Type of scan

        Returns:
            Scan launch response
        """
        try:
            # Build scan request
            target_str = ",".join(targets)

            params = {
                "action": "launch",
                "scan_title": f"VulnGuard Validation Scan {datetime.utcnow().isoformat()}",
                "ip": target_str,
                "option_id": "default",  # Would use specific scan option in production
                "priority": "1"  # High priority
            }

            response = await self._request(
                "POST",
                "/api/2.0/fo/scan/",
                params=params
            )

            # Parse response
            # Qualys returns XML, would parse in production
            return {
                "scan_id": f"QLS-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "status": "launched",
                "targets": targets
            }

        except Exception as e:
            logger.error("Failed to launch Qualys scan", error=str(e))
            raise

    async def get_asset_details(self, ip: str) -> Dict[str, Any]:
        """
        Get asset details from Qualys Asset Management.

        Args:
            ip: IP address of the asset

        Returns:
            Asset details
        """
        try:
            params = {
                "action": "list",
                "ips": ip,
                "details": "All"
            }

            response = await self._request(
                "GET",
                "/api/2.0/fo/asset/host/",
                params=params
            )

            data = response.json()
            hosts = data.get("HOST_LIST", {}).get("HOST", [])

            if hosts:
                return self._normalize_qualys_asset(hosts[0])

            return {}

        except Exception as e:
            logger.error("Failed to get Qualys asset details", error=str(e))
            return {}

    def _normalize_qualys_vulnerability(
        self,
        host: Dict[str, Any],
        detection: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize Qualys vulnerability data to common schema"""
        qid = detection.get("QID", "")
        severity = detection.get("SEVERITY", 2)

        # Map Qualys severity (1-5) to CVSS-like scale
        cvss_map = {1: 2.0, 2: 4.0, 3: 6.0, 4: 8.0, 5: 10.0}
        cvss = cvss_map.get(int(severity), 5.0)

        # Determine detection method
        if detection.get("TYPE") == "Confirmed":
            method = "agent" if host.get("AGENT_INFO") else "remote"
        else:
            method = "unauthenticated"

        return {
            "cve": detection.get("CVE_ID_LIST", {}).get("CVE_ID", ["N/A"])[0] if detection.get("CVE_ID_LIST") else "N/A",
            "title": detection.get("TITLE", f"QID {qid}"),
            "qid": qid,
            "cvss_score": cvss,
            "severity": int(severity),
            "detection_method": method,
            "hostname": host.get("DNS", host.get("NETBIOS", "")),
            "ip": host.get("IP", ""),
            "os": host.get("OS", ""),
            "first_detected": detection.get("FIRST_FOUND_DATETIME"),
            "last_detected": detection.get("LAST_FOUND_DATETIME"),
            "scan_id": detection.get("SCAN_ID", ""),
            "solution": detection.get("SOLUTION", ""),
            "results": detection.get("RESULTS", ""),
            "source": "qualys"
        }

    def _normalize_qualys_asset(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Qualys asset data"""
        return {
            "hostname": host.get("DNS", host.get("NETBIOS", "")),
            "ip": host.get("IP", ""),
            "os": host.get("OS", ""),
            "last_scan": host.get("LAST_SCAN_DATETIME"),
            "tracking_method": host.get("TRACKING_METHOD"),
            "agent_info": host.get("AGENT_INFO", {})
        }

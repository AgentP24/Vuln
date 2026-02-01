"""
VulnGuard AI - IBM Guardium Scanner Integration
Client for IBM Guardium Data Protection API
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
import structlog

from .base import BaseScannerClient

logger = structlog.get_logger()


class GuardiumClient(BaseScannerClient):
    """
    IBM Guardium Data Protection API client.

    Supports:
    - Database vulnerability assessment
    - Configuration compliance
    - Sensitive data discovery
    - Database activity monitoring
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
        """Get Guardium session authentication headers"""
        if not self._session_token:
            await self._authenticate()

        return {
            "Authorization": f"Bearer {self._session_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def _authenticate(self):
        """Authenticate and obtain session token"""
        import httpx

        async with httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=self.timeout
        ) as client:
            response = await client.post(
                "/restAPI/oauth/token",
                data={
                    "grant_type": "password",
                    "username": self.username,
                    "password": self.password,
                    "client_id": "GuardiumVA"
                }
            )
            response.raise_for_status()

            data = response.json()
            self._session_token = data.get("access_token")

            logger.info("Authenticated with Guardium")

    async def get_vulnerabilities(
        self,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get database vulnerabilities from Guardium VA module.

        Args:
            since: Only get vulnerabilities detected since this time

        Returns:
            List of normalized vulnerability data
        """
        try:
            # Get VA assessment results
            params = {}
            if since:
                params["startDate"] = since.strftime("%Y-%m-%d")

            response = await self._request(
                "GET",
                "/restAPI/va/assessments",
                params=params
            )

            assessments = response.json().get("assessments", [])
            all_vulnerabilities = []

            for assessment in assessments:
                # Get findings for each assessment
                findings = await self._get_assessment_findings(assessment["id"])

                for finding in findings:
                    normalized = self._normalize_guardium_vulnerability(
                        finding,
                        assessment
                    )
                    all_vulnerabilities.append(normalized)

            logger.info(f"Retrieved {len(all_vulnerabilities)} vulnerabilities from Guardium")
            return all_vulnerabilities

        except Exception as e:
            logger.error("Failed to get Guardium vulnerabilities", error=str(e))
            raise

    async def _get_assessment_findings(self, assessment_id: str) -> List[Dict[str, Any]]:
        """Get findings for a specific assessment"""
        try:
            response = await self._request(
                "GET",
                f"/restAPI/va/assessments/{assessment_id}/findings"
            )

            return response.json().get("findings", [])

        except Exception as e:
            logger.warning(f"Failed to get findings for assessment {assessment_id}", error=str(e))
            return []

    async def scan_targets(
        self,
        targets: List[str],
        scan_type: str = "targeted"
    ) -> Dict[str, Any]:
        """
        Trigger a database vulnerability assessment.

        Args:
            targets: List of database server IPs/hostnames
            scan_type: Type of scan

        Returns:
            Scan result
        """
        try:
            # Create assessment task
            assessment_config = {
                "name": f"VulnGuard Assessment {datetime.utcnow().isoformat()}",
                "datasources": targets,
                "assessmentType": "VULNERABILITY",
                "runNow": True
            }

            response = await self._request(
                "POST",
                "/restAPI/va/assessments",
                json=assessment_config
            )

            assessment_data = response.json()

            return {
                "scan_id": f"GRD-{assessment_data.get('id', 'unknown')}",
                "status": "launched",
                "targets": targets
            }

        except Exception as e:
            logger.error("Failed to launch Guardium assessment", error=str(e))
            raise

    async def get_datasources(self) -> List[Dict[str, Any]]:
        """Get configured database datasources"""
        try:
            response = await self._request(
                "GET",
                "/restAPI/datasources"
            )

            return response.json().get("datasources", [])

        except Exception as e:
            logger.warning("Failed to get datasources", error=str(e))
            return []

    async def get_compliance_status(self, datasource_id: str) -> Dict[str, Any]:
        """Get compliance status for a datasource"""
        try:
            response = await self._request(
                "GET",
                f"/restAPI/compliance/datasources/{datasource_id}/status"
            )

            return response.json()

        except Exception as e:
            logger.warning(f"Failed to get compliance status for {datasource_id}", error=str(e))
            return {}

    def _normalize_guardium_vulnerability(
        self,
        finding: Dict[str, Any],
        assessment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize Guardium vulnerability data to common schema"""
        # Map Guardium severity to standard values
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "low"
        }

        severity = severity_map.get(finding.get("severity", "MEDIUM"), "medium")

        # Map to CVSS-like score
        cvss_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5
        }
        cvss = cvss_map.get(severity, 5.0)

        # Get database details
        datasource = assessment.get("datasource", {})

        return {
            "cve": finding.get("cveId", "N/A"),
            "title": finding.get("testName", "Unknown Database Vulnerability"),
            "test_id": finding.get("testId"),
            "cvss_score": cvss,
            "severity": severity,
            "detection_method": "agent",  # Guardium uses S-TAP agents
            "hostname": datasource.get("hostname", ""),
            "ip": datasource.get("ip", ""),
            "database_type": datasource.get("databaseType", ""),
            "database_name": datasource.get("databaseName", ""),
            "database_version": datasource.get("version", ""),
            "first_detected": assessment.get("startTime"),
            "last_detected": assessment.get("endTime", datetime.utcnow().isoformat()),
            "scan_id": assessment.get("id"),
            "solution": finding.get("remediation", ""),
            "description": finding.get("description", ""),
            "category": finding.get("category", "Database Security"),
            "compliance_impact": finding.get("complianceImpact", []),
            "affected_objects": finding.get("affectedObjects", []),
            "source": "guardium"
        }

    def _normalize_guardium_datasource(self, datasource: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Guardium datasource data"""
        return {
            "datasource_id": datasource.get("id"),
            "hostname": datasource.get("hostname"),
            "ip": datasource.get("ip"),
            "database_type": datasource.get("databaseType"),
            "database_name": datasource.get("databaseName"),
            "version": datasource.get("version"),
            "port": datasource.get("port"),
            "last_assessment": datasource.get("lastAssessmentDate"),
            "stap_installed": datasource.get("stapInstalled", False),
            "classification": datasource.get("classification", "Unknown")
        }

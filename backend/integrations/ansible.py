"""
VulnGuard AI - Ansible Tower/AWX Integration
Client for executing playbooks via Ansible Automation Platform
"""
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
import httpx
import structlog

logger = structlog.get_logger()


class AnsibleTowerClient:
    """
    Ansible Tower/AWX API client.

    Provides:
    - Job template management
    - Job launch and monitoring
    - Inventory management
    - Credential handling
    """

    def __init__(
        self,
        tower_url: str,
        token: str,
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        self.tower_url = tower_url.rstrip('/')
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=f"{self.tower_url}/api/v2",
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json"
                }
            )
        return self._client

    async def close(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def launch_job(
        self,
        template_id: str,
        inventory: List[str],
        extra_vars: Optional[Dict[str, Any]] = None,
        job_type: str = "run",
        limit: Optional[str] = None
    ) -> "AnsibleJob":
        """
        Launch a job from a job template.

        Args:
            template_id: Job template ID or name
            inventory: List of hosts to target
            extra_vars: Extra variables to pass to the playbook
            job_type: "run" for apply, "check" for dry-run
            limit: Optional host pattern limit

        Returns:
            AnsibleJob object for tracking
        """
        client = await self._get_client()

        # Get template ID if name provided
        if not template_id.isdigit():
            template_id = await self._get_template_id(template_id)

        payload = {
            "extra_vars": extra_vars or {},
            "job_type": job_type
        }

        if limit:
            payload["limit"] = limit
        elif inventory:
            # Use inventory as limit if specific hosts provided
            payload["limit"] = ",".join(inventory)

        try:
            response = await client.post(
                f"/job_templates/{template_id}/launch/",
                json=payload
            )
            response.raise_for_status()

            job_data = response.json()

            logger.info(
                f"Launched Ansible job",
                job_id=job_data.get("id"),
                template=template_id,
                job_type=job_type
            )

            return AnsibleJob(
                id=job_data["id"],
                name=job_data.get("name", ""),
                status=job_data.get("status", "pending"),
                started=job_data.get("started"),
                client=self
            )

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to launch job", error=str(e))
            raise

    async def get_job_status(self, job_id: int) -> str:
        """
        Get current status of a job.

        Args:
            job_id: Ansible job ID

        Returns:
            Job status string
        """
        client = await self._get_client()

        try:
            response = await client.get(f"/jobs/{job_id}/")
            response.raise_for_status()
            return response.json().get("status", "unknown")

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get job status", job_id=job_id, error=str(e))
            raise

    async def get_job_stdout(self, job_id: int) -> str:
        """
        Get job stdout/output.

        Args:
            job_id: Ansible job ID

        Returns:
            Job output as string
        """
        client = await self._get_client()

        try:
            response = await client.get(
                f"/jobs/{job_id}/stdout/",
                params={"format": "txt"}
            )
            response.raise_for_status()
            return response.text

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get job stdout", job_id=job_id, error=str(e))
            return ""

    async def cancel_job(self, job_id: int) -> bool:
        """
        Cancel a running job.

        Args:
            job_id: Ansible job ID

        Returns:
            True if canceled successfully
        """
        client = await self._get_client()

        try:
            response = await client.post(f"/jobs/{job_id}/cancel/")
            response.raise_for_status()
            logger.warning(f"Canceled Ansible job {job_id}")
            return True

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to cancel job", job_id=job_id, error=str(e))
            return False

    async def wait_for_job(
        self,
        job_id: int,
        timeout: int = 3600,
        poll_interval: int = 10
    ) -> Dict[str, Any]:
        """
        Wait for a job to complete.

        Args:
            job_id: Ansible job ID
            timeout: Maximum wait time in seconds
            poll_interval: Time between status checks

        Returns:
            Final job status and results
        """
        terminal_states = ["successful", "failed", "canceled", "error"]
        elapsed = 0

        while elapsed < timeout:
            status = await self.get_job_status(job_id)

            if status in terminal_states:
                stdout = await self.get_job_stdout(job_id)
                return {
                    "job_id": job_id,
                    "status": status,
                    "stdout": stdout,
                    "elapsed_seconds": elapsed
                }

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        # Timeout reached
        await self.cancel_job(job_id)
        return {
            "job_id": job_id,
            "status": "timeout",
            "stdout": await self.get_job_stdout(job_id),
            "elapsed_seconds": elapsed
        }

    async def _get_template_id(self, template_name: str) -> str:
        """Get job template ID from name"""
        client = await self._get_client()

        response = await client.get(
            "/job_templates/",
            params={"name": template_name}
        )
        response.raise_for_status()

        results = response.json().get("results", [])
        if results:
            return str(results[0]["id"])

        raise ValueError(f"Job template '{template_name}' not found")

    async def get_inventories(self) -> List[Dict[str, Any]]:
        """Get available inventories"""
        client = await self._get_client()

        response = await client.get("/inventories/")
        response.raise_for_status()

        return response.json().get("results", [])

    async def get_job_templates(self) -> List[Dict[str, Any]]:
        """Get available job templates"""
        client = await self._get_client()

        response = await client.get("/job_templates/")
        response.raise_for_status()

        return response.json().get("results", [])


class AnsibleJob:
    """Represents an Ansible job for tracking"""

    def __init__(
        self,
        id: int,
        name: str,
        status: str,
        started: Optional[str],
        client: AnsibleTowerClient
    ):
        self.id = id
        self.name = name
        self.status = status
        self.started = started
        self._client = client

    async def refresh(self) -> "AnsibleJob":
        """Refresh job status"""
        self.status = await self._client.get_job_status(self.id)
        return self

    async def wait(self, timeout: int = 3600) -> Dict[str, Any]:
        """Wait for job completion"""
        return await self._client.wait_for_job(self.id, timeout)

    async def cancel(self) -> bool:
        """Cancel the job"""
        return await self._client.cancel_job(self.id)

    async def get_output(self) -> str:
        """Get job output"""
        return await self._client.get_job_stdout(self.id)

    @property
    def is_complete(self) -> bool:
        """Check if job is in terminal state"""
        return self.status in ["successful", "failed", "canceled", "error"]

    @property
    def is_successful(self) -> bool:
        """Check if job completed successfully"""
        return self.status == "successful"

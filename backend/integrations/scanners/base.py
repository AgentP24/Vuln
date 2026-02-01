"""
VulnGuard AI - Base Scanner Client
Abstract base class for scanner integrations
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

logger = structlog.get_logger()


class BaseScannerClient(ABC):
    """
    Abstract base class for vulnerability scanner API clients.
    Provides common functionality for HTTP requests, authentication,
    and retry logic.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        verify_ssl: bool = True
    ):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None
        self._last_poll: Optional[datetime] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=await self._get_auth_headers()
            )
        return self._client

    async def close(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    @abstractmethod
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers. Must be implemented by subclasses."""
        pass

    @abstractmethod
    async def get_vulnerabilities(
        self,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve vulnerabilities from the scanner.

        Args:
            since: Only get vulnerabilities detected since this time

        Returns:
            List of vulnerability data
        """
        pass

    @abstractmethod
    async def scan_targets(
        self,
        targets: List[str],
        scan_type: str = "targeted"
    ) -> Dict[str, Any]:
        """
        Trigger a scan on specific targets.

        Args:
            targets: List of hosts/IPs to scan
            scan_type: Type of scan to perform

        Returns:
            Scan results
        """
        pass

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30)
    )
    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> httpx.Response:
        """
        Make an HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            **kwargs: Additional request arguments

        Returns:
            HTTP response
        """
        client = await self._get_client()

        try:
            response = await client.request(method, endpoint, **kwargs)
            response.raise_for_status()
            return response

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                # Rate limited - will be retried
                retry_after = int(e.response.headers.get('Retry-After', 60))
                logger.warning(f"Rate limited, waiting {retry_after}s")
                raise
            elif e.response.status_code == 401:
                # Authentication failed
                logger.error("Authentication failed - check credentials")
                raise
            else:
                logger.error(f"HTTP error: {e.response.status_code}")
                raise

        except httpx.RequestError as e:
            logger.error(f"Request failed: {str(e)}")
            raise

    def _normalize_severity(self, value: Any) -> str:
        """Normalize severity to standard values"""
        if isinstance(value, (int, float)):
            if value >= 9.0:
                return "critical"
            elif value >= 7.0:
                return "high"
            elif value >= 4.0:
                return "medium"
            else:
                return "low"

        value_str = str(value).lower()
        if value_str in ["critical", "4", "urgent"]:
            return "critical"
        elif value_str in ["high", "3", "serious"]:
            return "high"
        elif value_str in ["medium", "2", "moderate"]:
            return "medium"
        else:
            return "low"

    def _normalize_vulnerability(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize raw vulnerability data to common schema.
        Can be overridden by subclasses for specific normalization.
        """
        return raw

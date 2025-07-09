"""
Wazuh API client for MCP server.
"""

import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from .config import WazuhConfig

logger = logging.getLogger(__name__)


class WazuhClient:
    """Async HTTP client for Wazuh Manager API."""

    def __init__(self, config: WazuhConfig) -> None:
        self.config = config
        self._token: Optional[str] = None
        self._expiry: float = 0.0
        self._basic = (config.username, config.password)
        self._client = httpx.AsyncClient(
            base_url=config.url,
            verify=config.ssl_verify,
            timeout=config.timeout,
            http2=True,
        )

    async def _refresh_token(self) -> None:
        """Refresh JWT token if needed."""
        if self._token and self._expiry - time.time() > 60:
            return

        try:
            response = await self._client.post("/security/user/authenticate", auth=self._basic)
            response.raise_for_status()
            data = response.json()
            self._token = data["data"]["token"]
            self._expiry = time.time() + 900  # 15 minutes
            logger.debug("New JWT token obtained (expires in %d seconds)", 900)
        except httpx.HTTPStatusError as e:
            logger.error("Failed to authenticate with Wazuh: %s", e)
            raise
        except Exception as e:
            logger.error("Unexpected error during authentication: %s", e)
            raise

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make authenticated request to Wazuh API."""
        await self._refresh_token()

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"

        try:
            response = await self._client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            logger.error("Wazuh API request failed: %s %s - %s", method, url, e)
            raise
        except Exception as e:
            logger.error("Unexpected error during request: %s", e)
            raise

    async def get_agents(
        self,
        status: Optional[list] = None,
        limit: int = 500,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get agents from Wazuh Manager."""
        params = {"limit": limit, "offset": offset}

        if status:
            params["status"] = ",".join(status)

        response = await self.request("GET", "/agents", params=params)
        return response.json()

    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Get specific agent by ID."""
        response = await self.request("GET", f"/agents/{agent_id}")
        return response.json()

    async def get_agent_ports(
        self,
        agent_id: str,
        limit: int = 500,
        offset: int = 0,
        protocol: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_port: Optional[str] = None,
        remote_ip: Optional[str] = None,
        state: Optional[str] = None,
        process: Optional[str] = None,
        pid: Optional[str] = None,
        tx_queue: Optional[str] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False,
    ) -> Dict[str, Any]:
        """Get agent ports information from syscollector."""
        params = {"limit": limit, "offset": offset}

        if protocol:
            params["protocol"] = protocol
        if local_ip:
            params["local.ip"] = local_ip
        if local_port:
            params["local.port"] = local_port
        if remote_ip:
            params["remote.ip"] = remote_ip
        if state:
            params["state"] = state
        if process:
            params["process"] = process
        if pid:
            params["pid"] = pid
        if tx_queue:
            params["tx_queue"] = tx_queue
        if sort:
            params["sort"] = sort
        if search:
            params["search"] = search
        if select:
            params["select"] = ",".join(select)
        if q:
            params["q"] = q
        if distinct:
            params["distinct"] = distinct

        response = await self.request("GET", f"/syscollector/{agent_id}/ports", params=params)
        return response.json()

    async def authenticate(self) -> Dict[str, Any]:
        """Force token refresh and return status."""
        self._token = None  # Force refresh
        await self._refresh_token()
        return {"status": "authenticated", "token_expiry": self._expiry}

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

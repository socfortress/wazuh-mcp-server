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
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False,
    ) -> Dict[str, Any]:
        """Get agents from Wazuh Manager."""
        params = {"limit": limit, "offset": offset}

        if status:
            params["status"] = ",".join(status)
        if sort:
            params["sort"] = sort
        if search:
            params["search"] = search
        if select:
            params["select"] = ",".join(select)
        if q:
            params["q"] = q
        if distinct:
            params["distinct"] = "true"

        response = await self.request("GET", "/agents", params=params)
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

    async def get_agent_packages(
        self,
        agent_id: str,
        limit: int = 500,
        offset: int = 0,
        vendor: Optional[str] = None,
        name: Optional[str] = None,
        architecture: Optional[str] = None,
        format: Optional[str] = None,
        version: Optional[str] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get agent packages information from syscollector.

        Args:
            agent_id: Agent ID to get packages from
            limit: Maximum number of packages to return (default: 500)
            offset: Offset for pagination (default: 0)
            vendor: Filter by vendor
            name: Filter by package name
            architecture: Filter by architecture
            format: Filter by file format (e.g., 'deb')
            version: Filter by package version
            sort: Sort results by field(s)
            search: Search for elements containing the specified string
            select: Select which fields to return
            q: Query to filter results by
            distinct: Look for distinct values

        Returns:
            Dict containing agent packages information
        """
        params = {
            "limit": limit,
            "offset": offset,
        }

        if vendor:
            params["vendor"] = vendor
        if name:
            params["name"] = name
        if architecture:
            params["architecture"] = architecture
        if format:
            params["format"] = format
        if version:
            params["version"] = version
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

        response = await self.request("GET", f"/syscollector/{agent_id}/packages", params=params)
        return response.json()

    async def get_agent_processes(
        self,
        agent_id: str,
        limit: int = 500,
        offset: int = 0,
        pid: Optional[str] = None,
        state: Optional[str] = None,
        ppid: Optional[str] = None,
        egroup: Optional[str] = None,
        euser: Optional[str] = None,
        fgroup: Optional[str] = None,
        name: Optional[str] = None,
        nlwp: Optional[str] = None,
        pgrp: Optional[str] = None,
        priority: Optional[str] = None,
        rgroup: Optional[str] = None,
        ruser: Optional[str] = None,
        sgroup: Optional[str] = None,
        suser: Optional[str] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False,
    ) -> Dict[str, Any]:
        """Get agent processes information."""
        params = {"limit": limit, "offset": offset}

        if pid:
            params["pid"] = pid
        if state:
            params["state"] = state
        if ppid:
            params["ppid"] = ppid
        if egroup:
            params["egroup"] = egroup
        if euser:
            params["euser"] = euser
        if fgroup:
            params["fgroup"] = fgroup
        if name:
            params["name"] = name
        if nlwp:
            params["nlwp"] = nlwp
        if pgrp:
            params["pgrp"] = pgrp
        if priority:
            params["priority"] = priority
        if rgroup:
            params["rgroup"] = rgroup
        if ruser:
            params["ruser"] = ruser
        if sgroup:
            params["sgroup"] = sgroup
        if suser:
            params["suser"] = suser
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

        response = await self.request("GET", f"/syscollector/{agent_id}/processes", params=params)
        return response.json()

    async def list_rules(
        self,
        rule_ids: Optional[List[int]] = None,
        limit: int = 500,
        offset: int = 0,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        status: Optional[str] = None,
        group: Optional[str] = None,
        level: Optional[str] = None,
        filename: Optional[List[str]] = None,
        relative_dirname: Optional[str] = None,
        pci_dss: Optional[str] = None,
        gdpr: Optional[str] = None,
        gpg13: Optional[str] = None,
        hipaa: Optional[str] = None,
        nist_800_53: Optional[str] = None,
        tsc: Optional[str] = None,
        mitre: Optional[str] = None,
        distinct: Optional[bool] = False,
    ) -> Dict[str, Any]:
        """Get rules from Wazuh Manager."""
        params = {"limit": limit, "offset": offset}

        if rule_ids:
            params["rule_ids"] = ",".join(map(str, rule_ids))
        if select:
            params["select"] = ",".join(select)
        if sort:
            params["sort"] = sort
        if search:
            params["search"] = search
        if q:
            params["q"] = q
        if status:
            params["status"] = status
        if group:
            params["group"] = group
        if level:
            params["level"] = level
        if filename:
            params["filename"] = ",".join(filename)
        if relative_dirname:
            params["relative_dirname"] = relative_dirname
        if pci_dss:
            params["pci_dss"] = pci_dss
        if gdpr:
            params["gdpr"] = gdpr
        if gpg13:
            params["gpg13"] = gpg13
        if hipaa:
            params["hipaa"] = hipaa
        if nist_800_53:
            params["nist-800-53"] = nist_800_53
        if tsc:
            params["tsc"] = tsc
        if mitre:
            params["mitre"] = mitre
        if distinct:
            params["distinct"] = distinct

        response = await self.request("GET", "/rules", params=params)
        return response.json()

    async def get_rule_file_content(
        self,
        filename: str,
        raw: Optional[bool] = False,
        relative_dirname: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get rule file content from Wazuh Manager."""
        params = {}

        if raw:
            params["raw"] = "true"  # Ensure it's a string
        if relative_dirname:
            params["relative_dirname"] = relative_dirname

        response = await self.request("GET", f"/rules/files/{filename}", params=params)

        # Handle both raw text and JSON responses
        if raw:
            # When raw=True, the API returns plain text (XML content)
            content = response.text  # Get raw text content
            return {"content": content, "raw": True, "filename": filename}
        else:
            # When raw=False (default), the API returns JSON
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

    async def get_agent_sca(
        self,
        agent_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        references: Optional[str] = None,
        limit: int = 500,
        offset: int = 0,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False,
    ) -> Dict[str, Any]:
        """Get SCA (Security Configuration Assessment) results for an agent."""
        params = {"limit": limit, "offset": offset}

        if name:
            params["name"] = name
        if description:
            params["description"] = description
        if references:
            params["references"] = references
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

        response = await self.request("GET", f"/sca/{agent_id}", params=params)
        return response.json()

    async def get_sca_policy_checks(
        self,
        agent_id: str,
        policy_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        rationale: Optional[str] = None,
        remediation: Optional[str] = None,
        command: Optional[str] = None,
        reason: Optional[str] = None,
        file: Optional[str] = None,
        process: Optional[str] = None,
        directory: Optional[str] = None,
        registry: Optional[str] = None,
        references: Optional[str] = None,
        result: Optional[str] = None,
        condition: Optional[str] = None,
        limit: int = 500,
        offset: int = 0,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False,
    ) -> Dict[str, Any]:
        """Get SCA policy check details for a specific policy on an agent."""
        params = {"limit": limit, "offset": offset}

        if title:
            params["title"] = title
        if description:
            params["description"] = description
        if rationale:
            params["rationale"] = rationale
        if remediation:
            params["remediation"] = remediation
        if command:
            params["command"] = command
        if reason:
            params["reason"] = reason
        if file:
            params["file"] = file
        if process:
            params["process"] = process
        if directory:
            params["directory"] = directory
        if registry:
            params["registry"] = registry
        if references:
            params["references"] = references
        if result:
            params["result"] = result
        if condition:
            params["condition"] = condition
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

        response = await self.request("GET", f"/sca/{agent_id}/checks/{policy_id}", params=params)
        return response.json()

    async def get_rule_files(
        self,
        pretty: Optional[bool] = False,
        wait_for_complete: Optional[bool] = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        filename: Optional[List[str]] = None,
        status: Optional[str] = None,
        q: Optional[str] = None,
        select: Optional[List[str]] = None,
        distinct: Optional[bool] = False,
    ) -> Dict[str, Any]:
        """Get rule files from Wazuh Manager."""
        params = {"limit": limit, "offset": offset}
        if pretty:
            params["pretty"] = "true"
        if wait_for_complete:
            params["wait_for_complete"] = "true"
        if sort:
            params["sort"] = sort
        if search:
            params["search"] = search
        if relative_dirname:
            params["relative_dirname"] = relative_dirname
        if filename:
            params["filename"] = ",".join(filename)
        if status:
            params["status"] = status
        if q:
            params["q"] = q
        if select:
            params["select"] = ",".join(select)
        if distinct:
            params["distinct"] = "true"
        response = await self.request("GET", "/rules/files", params=params)
        return response.json()

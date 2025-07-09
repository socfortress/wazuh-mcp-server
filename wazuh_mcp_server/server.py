"""
Main MCP server implementation.
"""

import json
import logging
from typing import List, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from .client import WazuhClient
from .config import Config

logger = logging.getLogger(__name__)


# Pydantic models for tool parameters
class AuthenticateArgs(BaseModel):
    """Arguments for authentication tool (no parameters needed)."""

    pass


class GetAgentsArgs(BaseModel):
    """Arguments for getting agents from Wazuh Manager."""

    status: Optional[List[str]] = Field(
        None,
        description="Filter by agent status",
        examples=[["active"]],
    )
    limit: Optional[int] = Field(500, description="Maximum number of agents to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")


class GetAgentArgs(BaseModel):
    """Arguments for getting a specific agent."""

    agent_id: str = Field(..., description="The agent ID to retrieve")


class GetAgentPortsArgs(BaseModel):
    """Arguments for getting agent ports information."""

    agent_id: str = Field(..., description="Agent ID to get ports from")
    limit: Optional[int] = Field(500, description="Maximum number of ports to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    protocol: Optional[str] = Field(None, description="Filter by protocol (tcp, udp)")
    local_ip: Optional[str] = Field(None, description="Filter by local IP address")
    local_port: Optional[str] = Field(None, description="Filter by local port")
    remote_ip: Optional[str] = Field(None, description="Filter by remote IP address")
    state: Optional[str] = Field(None, description="Filter by state (listening, established, etc.)")
    process: Optional[str] = Field(None, description="Filter by process name")
    pid: Optional[str] = Field(None, description="Filter by process ID")
    tx_queue: Optional[str] = Field(None, description="Filter by tx_queue")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetAgentPackagesArgs(BaseModel):
    """Arguments for getting agent packages information."""

    agent_id: str = Field(..., description="Agent ID to get packages from")
    limit: Optional[int] = Field(500, description="Maximum number of packages to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    vendor: Optional[str] = Field(None, description="Filter by vendor")
    name: Optional[str] = Field(None, description="Filter by package name")
    architecture: Optional[str] = Field(None, description="Filter by architecture")
    format: Optional[str] = Field(None, description="Filter by file format (e.g., 'deb')")
    version: Optional[str] = Field(None, description="Filter by package version")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetAgentProcessesArgs(BaseModel):
    """Arguments for getting agent processes information."""

    agent_id: str = Field(..., description="Agent ID to get processes from")
    limit: Optional[int] = Field(500, description="Maximum number of processes to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    pid: Optional[str] = Field(None, description="Filter by process PID")
    state: Optional[str] = Field(None, description="Filter by process state")
    ppid: Optional[str] = Field(None, description="Filter by process parent PID")
    egroup: Optional[str] = Field(None, description="Filter by process egroup")
    euser: Optional[str] = Field(None, description="Filter by process euser")
    fgroup: Optional[str] = Field(None, description="Filter by process fgroup")
    name: Optional[str] = Field(None, description="Filter by process name")
    nlwp: Optional[str] = Field(None, description="Filter by process nlwp")
    pgrp: Optional[str] = Field(None, description="Filter by process pgrp")
    priority: Optional[str] = Field(None, description="Filter by process priority")
    rgroup: Optional[str] = Field(None, description="Filter by process rgroup")
    ruser: Optional[str] = Field(None, description="Filter by process ruser")
    sgroup: Optional[str] = Field(None, description="Filter by process sgroup")
    suser: Optional[str] = Field(None, description="Filter by process suser")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class ListRulesArgs(BaseModel):
    """Arguments for listing rules."""

    rule_ids: Optional[List[int]] = Field(None, description="List of rule IDs to filter by")
    limit: Optional[int] = Field(500, description="Maximum number of rules to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    q: Optional[str] = Field(None, description="Query to filter results by")
    status: Optional[str] = Field(None, description="Filter by status (enabled, disabled, all)")
    group: Optional[str] = Field(None, description="Filter by rule group")
    level: Optional[str] = Field(None, description="Filter by rule level (e.g., '4' or '2-4')")
    filename: Optional[List[str]] = Field(None, description="Filter by filename")
    relative_dirname: Optional[str] = Field(None, description="Filter by relative directory name")
    pci_dss: Optional[str] = Field(None, description="Filter by PCI_DSS requirement")
    gdpr: Optional[str] = Field(None, description="Filter by GDPR requirement")
    gpg13: Optional[str] = Field(None, description="Filter by GPG13 requirement")
    hipaa: Optional[str] = Field(None, description="Filter by HIPAA requirement")
    nist_800_53: Optional[str] = Field(None, description="Filter by NIST-800-53 requirement")
    tsc: Optional[str] = Field(None, description="Filter by TSC requirement")
    mitre: Optional[str] = Field(None, description="Filter by MITRE technique ID")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetRuleFileContentArgs(BaseModel):
    """Arguments for getting rule file content."""

    filename: str = Field(..., description="Filename of the rule file to get content from")
    raw: Optional[bool] = Field(False, description="Format response in plain text")
    relative_dirname: Optional[str] = Field(None, description="Filter by relative directory name")


class WazuhMCPServer:
    """Main MCP server for Wazuh integration."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client: Optional[WazuhClient] = None
        self.app = FastMCP(name="Wazuh MCP Server", version="0.1.0")

        # Register tools
        self._register_tools()

    def _get_client(self) -> WazuhClient:
        """Get or create Wazuh client."""
        if self._client is None:
            self._client = WazuhClient(self.config.wazuh)
        return self._client

    def _register_tools(self) -> None:
        """Register all available tools."""

        if "AuthenticateTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="AuthenticateTool")
            async def authenticate_tool(args: AuthenticateArgs):
                """Force a new JWT token acquisition from Wazuh Manager."""
                try:
                    client = self._get_client()
                    result = await client.authenticate()
                    return [
                        {
                            "type": "text",
                            "text": f"Authentication successful: {json.dumps(result)}",
                        },
                    ]
                except Exception as e:
                    logger.error("Authentication failed: %s", e)
                    return [{"type": "text", "text": f"Authentication failed: {str(e)}"}]

        if "GetAgentsTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="GetAgentsTool")
            async def get_agents_tool(args: GetAgentsArgs):
                """Return agents from Wazuh Manager matching optional filters."""
                try:
                    client = self._get_client()
                    data = await client.get_agents(
                        status=args.status,
                        limit=args.limit,
                        offset=args.offset,
                    )
                    return [
                        {"type": "text", "text": self._safe_truncate(json.dumps(data, indent=2))},
                    ]
                except Exception as e:
                    logger.error("Failed to get agents: %s", e)
                    return [{"type": "text", "text": f"Error retrieving agents: {str(e)}"}]

        if "GetAgentTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="GetAgentTool")
            async def get_agent_tool(args: GetAgentArgs):
                """Get specific agent by ID."""
                try:
                    client = self._get_client()
                    data = await client.get_agent(args.agent_id)
                    return [
                        {"type": "text", "text": self._safe_truncate(json.dumps(data, indent=2))},
                    ]
                except Exception as e:
                    logger.error("Failed to get agent %s: %s", args.agent_id, e)
                    return [
                        {
                            "type": "text",
                            "text": f"Error retrieving agent {args.agent_id}: {str(e)}",
                        },
                    ]

        if "GetAgentPortsTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="GetAgentPortsTool")
            async def get_agent_ports_tool(args: GetAgentPortsArgs):
                """Get agents ports information from syscollector."""
                try:
                    client = self._get_client()
                    data = await client.get_agent_ports(
                        agent_id=args.agent_id,
                        limit=args.limit,
                        offset=args.offset,
                        protocol=args.protocol,
                        local_ip=args.local_ip,
                        local_port=args.local_port,
                        remote_ip=args.remote_ip,
                        state=args.state,
                        process=args.process,
                        pid=args.pid,
                        tx_queue=args.tx_queue,
                        sort=args.sort,
                        search=args.search,
                        select=args.select,
                        q=args.q,
                        distinct=args.distinct,
                    )
                    return [
                        {"type": "text", "text": self._safe_truncate(json.dumps(data, indent=2))},
                    ]
                except Exception as e:
                    logger.error("Failed to get agent ports: %s", e)
                    return [{"type": "text", "text": f"Error retrieving agent ports: {str(e)}"}]

        if "GetAgentPackagesTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="GetAgentPackagesTool")
            async def get_agent_packages_tool(args: GetAgentPackagesArgs):
                """Get agents packages information from syscollector."""
                try:
                    client = self._get_client()
                    data = await client.get_agent_packages(
                        agent_id=args.agent_id,
                        limit=args.limit,
                        offset=args.offset,
                        vendor=args.vendor,
                        name=args.name,
                        architecture=args.architecture,
                        format=args.format,
                        version=args.version,
                        sort=args.sort,
                        search=args.search,
                        select=args.select,
                        q=args.q,
                        distinct=args.distinct,
                    )
                    return [
                        {"type": "text", "text": self._safe_truncate(json.dumps(data, indent=2))},
                    ]
                except Exception as e:
                    logger.error("Failed to get agent packages: %s", e)
                    return [{"type": "text", "text": f"Error retrieving agent packages: {str(e)}"}]

        if "GetAgentProcessesTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="GetAgentProcessesTool")
            async def get_agent_processes_tool(args: GetAgentProcessesArgs):
                """Get agents processes information from syscollector."""
                try:
                    client = self._get_client()
                    data = await client.get_agent_processes(
                        agent_id=args.agent_id,
                        limit=args.limit,
                        offset=args.offset,
                        pid=args.pid,
                        state=args.state,
                        ppid=args.ppid,
                        egroup=args.egroup,
                        euser=args.euser,
                        fgroup=args.fgroup,
                        name=args.name,
                        nlwp=args.nlwp,
                        pgrp=args.pgrp,
                        priority=args.priority,
                        rgroup=args.rgroup,
                        ruser=args.ruser,
                        sgroup=args.sgroup,
                        suser=args.suser,
                        sort=args.sort,
                        search=args.search,
                        select=args.select,
                        q=args.q,
                        distinct=args.distinct,
                    )
                    return [
                        {"type": "text", "text": self._safe_truncate(json.dumps(data, indent=2))},
                    ]
                except Exception as e:
                    logger.error("Failed to get agent processes: %s", e)
                    return [{"type": "text", "text": f"Error retrieving agent processes: {str(e)}"}]

        if "ListRulesTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="ListRulesTool")
            async def list_rules_tool(args: ListRulesArgs):
                """List rules from Wazuh Manager matching optional filters."""
                try:
                    client = self._get_client()
                    data = await client.list_rules(
                        rule_ids=args.rule_ids,
                        limit=args.limit,
                        offset=args.offset,
                        select=args.select,
                        sort=args.sort,
                        search=args.search,
                        q=args.q,
                        status=args.status,
                        group=args.group,
                        level=args.level,
                        filename=args.filename,
                        relative_dirname=args.relative_dirname,
                        pci_dss=args.pci_dss,
                        gdpr=args.gdpr,
                        gpg13=args.gpg13,
                        hipaa=args.hipaa,
                        nist_800_53=args.nist_800_53,
                        tsc=args.tsc,
                        mitre=args.mitre,
                        distinct=args.distinct,
                    )
                    return [
                        {"type": "text", "text": self._safe_truncate(json.dumps(data, indent=2))},
                    ]
                except Exception as e:
                    logger.error("Failed to list rules: %s", e)
                    return [{"type": "text", "text": f"Error listing rules: {str(e)}"}]

        if "GetRuleFileContentTool" not in self.config.server.disabled_tools:

            @self.app.tool(name="GetRuleFileContentTool")
            async def get_rule_file_content_tool(args: GetRuleFileContentArgs):
                """Get the content of a specific rule file."""
                try:
                    client = self._get_client()
                    data = await client.get_rule_file_content(
                        filename=args.filename,
                        raw=args.raw,
                        relative_dirname=args.relative_dirname,
                    )
                    return [
                        {"type": "text", "text": self._safe_truncate(json.dumps(data, indent=2))},
                    ]
                except Exception as e:
                    logger.error("Failed to get rule file content: %s", e)
                    return [{"type": "text", "text": f"Error retrieving rule file content: {str(e)}"}]

    def _safe_truncate(self, text: str, max_length: int = 32000) -> str:
        """Truncate text to avoid overwhelming the client."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + f"\\n\\n[... truncated {len(text) - max_length} characters ...]"

    def start(self, host: str = None, port: int = None) -> None:
        """Start the MCP server."""
        import uvicorn

        host = host or self.config.server.host
        port = port or self.config.server.port

        logger.info("Starting Wazuh MCP Server on %s:%d", host, port)
        logger.info("Wazuh URL: %s", self.config.wazuh.url)
        logger.info("SSL Verify: %s", self.config.wazuh.ssl_verify)

        # Start server with SSE transport
        uvicorn.run(
            self.app.sse_app,
            host=host,
            port=port,
            log_level=self.config.server.log_level.lower(),
        )

    async def close(self) -> None:
        """Close the server and cleanup resources."""
        if self._client:
            await self._client.close()


def create_server(config: Config = None) -> WazuhMCPServer:
    """Factory function to create a WazuhMCPServer instance."""
    if config is None:
        config = Config.from_env()

    config.validate()
    config.setup_logging()

    return WazuhMCPServer(config)

"""
Main MCP server implementation.
"""

import hmac
import json
import logging
from typing import Dict, List, Optional, Tuple

import uvicorn
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

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
    limit: Optional[int] = Field(50, description="Maximum number of agents to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetAgentPortsArgs(BaseModel):
    """Arguments for getting agent ports information."""

    agent_id: str = Field(..., description="Agent ID to get ports from")
    limit: Optional[int] = Field(50, description="Maximum number of ports to return")
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
    limit: Optional[int] = Field(50, description="Maximum number of packages to return")
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
    limit: Optional[int] = Field(50, description="Maximum number of processes to return")
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
    limit: Optional[int] = Field(50, description="Maximum number of rules to return")
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


class GetAgentSCAArgs(BaseModel):
    """Arguments for getting agent SCA results."""

    agent_id: str = Field(..., description="Agent ID to get SCA results from")
    name: Optional[str] = Field(None, description="Filter by policy name")
    description: Optional[str] = Field(None, description="Filter by policy description")
    references: Optional[str] = Field(None, description="Filter by references")
    limit: Optional[int] = Field(50, description="Maximum number of SCA policies to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetSCAPolicyChecksArgs(BaseModel):
    """Arguments for getting SCA policy check details."""

    agent_id: str = Field(..., description="Agent ID to get SCA policy checks from")
    policy_id: str = Field(..., description="Policy ID to get checks for")
    title: Optional[str] = Field(None, description="Filter by check title")
    description: Optional[str] = Field(None, description="Filter by check description")
    rationale: Optional[str] = Field(None, description="Filter by rationale")
    remediation: Optional[str] = Field(None, description="Filter by remediation")
    command: Optional[str] = Field(None, description="Filter by command")
    reason: Optional[str] = Field(None, description="Filter by reason")
    file: Optional[str] = Field(None, description="Filter by file path")
    process: Optional[str] = Field(None, description="Filter by process name")
    directory: Optional[str] = Field(None, description="Filter by directory")
    registry: Optional[str] = Field(None, description="Filter by registry")
    references: Optional[str] = Field(None, description="Filter by references")
    result: Optional[str] = Field(
        None,
        description="Filter by result (passed, failed, not_applicable)",
    )
    condition: Optional[str] = Field(None, description="Filter by condition")
    limit: Optional[int] = Field(50, description="Maximum number of checks to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetRuleFilesArgs(BaseModel):
    """Arguments for getting rule files."""

    pretty: Optional[bool] = Field(False, description="Show results in human-readable format")
    wait_for_complete: Optional[bool] = Field(False, description="Disable timeout response")
    offset: Optional[int] = Field(0, description="First element to return in the collection")
    limit: Optional[int] = Field(50, description="Maximum number of elements to return")
    sort: Optional[str] = Field(None, description="Sort the collection by a field or fields")
    search: Optional[str] = Field(
        None,
        description="Look for elements containing the specified string",
    )
    relative_dirname: Optional[str] = Field(None, description="Filter by relative directory name")
    filename: Optional[List[str]] = Field(
        None,
        description="Filter by filename of one or more rule or decoder files",
    )
    status: Optional[str] = Field(
        None,
        description="Filter by list status (enabled, disabled, all)",
    )
    q: Optional[str] = Field(None, description="Query to filter results by")
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


# Tool name -> (category, writes). `writes` marks tools that change state on the Wazuh manager;
# they are not registered when WAZUH_READ_ONLY is true. Every current tool only reads.
# AuthenticateTool only refreshes this server's own JWT.
TOOL_META: Dict[str, Tuple[str, bool]] = {
    "AuthenticateTool": ("auth", False),
    "GetAgentsTool": ("agents", False),
    "GetAgentPortsTool": ("agents", False),
    "GetAgentPackagesTool": ("agents", False),
    "GetAgentProcessesTool": ("agents", False),
    "ListRulesTool": ("rules", False),
    "GetRuleFileContentTool": ("rules", False),
    "GetRuleFilesTool": ("rules", False),
    "GetAgentSCATool": ("sca", False),
    "GetSCAPolicyChecksTool": ("sca", False),
}


class BearerAuthMiddleware:
    """Require `Authorization: Bearer <MCP_AUTH_TOKEN>` on every HTTP path except /healthz."""

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.token = token.encode()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        header = dict(scope.get("headers") or []).get(b"authorization", b"")
        scheme, _, presented = header.partition(b" ")
        if scheme.lower() != b"bearer" or not hmac.compare_digest(presented.strip(), self.token):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b'{"error":"Unauthorized"}'})
            return
        await self.app(scope, receive, send)


class WazuhMCPServer:
    """Main MCP server for Wazuh integration."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client: Optional[WazuhClient] = None
        self.app = FastMCP(name="Wazuh MCP Server", version="0.2.0")

        # Register tools
        self._register_tools()

        @self.app.custom_route("/healthz", methods=["GET"], include_in_schema=False)
        async def healthz(_request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

    def _enabled(self, name: str) -> bool:
        """Whether a tool should be registered, given disabled tools, categories and read-only mode."""
        category, writes = TOOL_META.get(name, ("other", True))
        server = self.config.server
        if name in server.disabled_tools or category in server.disabled_categories:
            logger.info("Tool %s disabled by configuration", name)
            return False
        if server.read_only and writes:
            logger.info("Tool %s not registered: WAZUH_READ_ONLY is set", name)
            return False
        return True

    def _get_client(self) -> WazuhClient:
        """Get or create Wazuh client."""
        if self._client is None:
            self._client = WazuhClient(self.config.wazuh)
        return self._client

    def _register_tools(self) -> None:
        """Register all available tools."""

        if self._enabled("AuthenticateTool"):

            @self.app.tool(
                name="AuthenticateTool",
                description="Force a new JWT token acquisition from Wazuh Manager. This tool requires no parameters and will refresh the authentication token for subsequent API calls.",
            )
            async def authenticate_tool(args: AuthenticateArgs):
                """Force a new JWT token acquisition from Wazuh Manager.

                This tool does not require any parameters. Simply call it to refresh
                the authentication token for subsequent Wazuh API operations.

                Returns:
                    Success message with authentication details or error message.
                """
                try:
                    client = self._get_client()
                    result = await client.authenticate()
                    return f"Authentication successful: {json.dumps(result)}"
                except Exception as e:
                    logger.error("Authentication failed: %s", e)
                    raise ToolError(f"Authentication failed: {str(e)}") from e

        if self._enabled("GetAgentsTool"):

            @self.app.tool(
                name="GetAgentsTool",
                description="Retrieve a list of Wazuh agents with optional filtering. Use this to get information about all agents or filter by status (active, disconnected, never_connected). Parameters should be passed in an 'args' object with 'status', 'limit', and 'offset' fields.",
            )
            async def get_agents_tool(args: GetAgentsArgs):
                """Return agents from Wazuh Manager matching optional filters.

                Args:
                    args: An object containing:
                        - status (optional): List of strings to filter by agent status (e.g., ["active"])
                        - limit (optional): Maximum number of agents to return (default: 50)
                        - offset (optional): Offset for pagination (default: 0)
                        - sort (optional): Sort results by field(s) (e.g., "name", "-id")
                        - search (optional): Search for elements containing the specified string
                        - select (optional): List of fields to return (e.g., ["id", "name", "status"])
                        - q (optional): Query to filter results by (e.g., "name=agent_name")
                        - distinct (optional): Look for distinct values (default: false)

                Example usage:
                    {"args": {"q": "name=agent_name"}}
                    {"args": {"search": "agent_name"}}
                    {"args": {"status": ["active"], "limit": 100}}
                    {"args": {"offset": 50}}
                    {"args": {}} for all agents

                Returns:
                    JSON list of agents with their details including ID, name, status, IP, etc.
                """
                try:
                    client = self._get_client()
                    data = await client.get_agents(
                        status=args.status,
                        limit=args.limit,
                        offset=args.offset,
                        sort=args.sort,
                        search=args.search,
                        select=args.select,
                        q=args.q,
                        distinct=args.distinct,
                    )
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to get agents: %s", e)
                    raise ToolError(f"Error retrieving agents: {str(e)}") from e

        if self._enabled("GetAgentPortsTool"):

            @self.app.tool(
                name="GetAgentPortsTool",
                description="Get network port information for a specific Wazuh agent from syscollector. Requires agent_id in 'args' object. Optional filters include protocol (tcp/udp), local_ip, local_port, remote_ip, state (listening/established), process name, etc.",
            )
            async def get_agent_ports_tool(args: GetAgentPortsArgs):
                """Get agents ports information from syscollector.

                Args:
                    args: An object containing:
                        - agent_id (required): Agent ID to get ports from (e.g., "000", "001")
                        - limit (optional): Maximum number of ports to return (default: 50)
                        - offset (optional): Offset for pagination (default: 0)
                        - protocol (optional): Filter by protocol ("tcp", "udp")
                        - local_ip (optional): Filter by local IP address
                        - local_port (optional): Filter by local port number
                        - remote_ip (optional): Filter by remote IP address
                        - state (optional): Filter by connection state ("listening", "established")
                        - process (optional): Filter by process name
                        - pid (optional): Filter by process ID
                        - sort, search, select, q, distinct (optional): Additional filtering

                Example usage:
                    {"args": {"agent_id": "000"}}
                    {"args": {"agent_id": "001", "protocol": "tcp", "state": "listening"}}
                    {"args": {"agent_id": "000", "local_port": "80"}}

                Returns:
                    JSON list of network ports with local/remote IPs, ports, protocols, states, etc.
                """
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
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to get agent ports: %s", e)
                    raise ToolError(f"Error retrieving agent ports: {str(e)}") from e

        if self._enabled("GetAgentPackagesTool"):

            @self.app.tool(
                name="GetAgentPackagesTool",
                description="Get installed package information for a specific Wazuh agent from syscollector. Requires agent_id in 'args' object. Optional filters include vendor, package name, architecture, format (deb/rpm), version, etc.",
            )
            async def get_agent_packages_tool(args: GetAgentPackagesArgs):
                """Get agents packages information from syscollector.

                Args:
                    args: An object containing:
                        - agent_id (required): Agent ID to get packages from (e.g., "000", "001")
                        - limit (optional): Maximum number of packages to return (default: 50)
                        - offset (optional): Offset for pagination (default: 0)
                        - vendor (optional): Filter by package vendor
                        - name (optional): Filter by package name
                        - architecture (optional): Filter by architecture (e.g., "amd64", "x86_64")
                        - format (optional): Filter by package format (e.g., "deb", "rpm")
                        - version (optional): Filter by package version
                        - sort, search, select, q, distinct (optional): Additional filtering

                Example usage:
                    {"args": {"agent_id": "000"}}
                    {"args": {"agent_id": "001", "name": "nginx", "format": "deb"}}
                    {"args": {"agent_id": "000", "vendor": "Ubuntu"}}

                Returns:
                    JSON list of installed packages with names, versions, architectures, sizes, etc.
                """
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
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to get agent packages: %s", e)
                    raise ToolError(f"Error retrieving agent packages: {str(e)}") from e

        if self._enabled("GetAgentProcessesTool"):

            @self.app.tool(
                name="GetAgentProcessesTool",
                description="Get running process information for a specific Wazuh agent from syscollector. Requires agent_id in 'args' object. Optional filters include PID, process name, state, user/group information, priority, etc.",
            )
            async def get_agent_processes_tool(args: GetAgentProcessesArgs):
                """Get agents processes information from syscollector.

                Args:
                    args: An object containing:
                        - agent_id (required): Agent ID to get processes from (e.g., "000", "001")
                        - limit (optional): Maximum number of processes to return (default: 50)
                        - offset (optional): Offset for pagination (default: 0)
                        - pid (optional): Filter by process ID
                        - name (optional): Filter by process name
                        - state (optional): Filter by process state
                        - ppid (optional): Filter by parent process ID
                        - euser, ruser, suser (optional): Filter by effective/real/saved user
                        - egroup, rgroup, sgroup, fgroup (optional): Filter by group information
                        - priority (optional): Filter by process priority
                        - sort, search, select, q, distinct (optional): Additional filtering

                Example usage:
                    {"args": {"agent_id": "000"}}
                    {"args": {"agent_id": "001", "name": "nginx", "state": "S"}}
                    {"args": {"agent_id": "000", "euser": "root"}}

                Returns:
                    JSON list of running processes with PIDs, names, states, memory usage, etc.
                """
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
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to get agent processes: %s", e)
                    raise ToolError(f"Error retrieving agent processes: {str(e)}") from e

        if self._enabled("ListRulesTool"):

            @self.app.tool(
                name="ListRulesTool",
                description="List Wazuh detection rules with optional filtering. All parameters should be passed in an 'args' object. Use filters like 'search' for text search, 'group' for rule categories, 'level' for severity, 'status' for enabled/disabled rules, compliance filters (pci_dss, gdpr, hipaa, mitre), etc.",
            )
            async def list_rules_tool(args: ListRulesArgs):
                """List rules from Wazuh Manager matching optional filters.

                Args:
                    args: An object containing:
                        - rule_ids (optional): List of specific rule IDs to retrieve
                        - limit (optional): Maximum number of rules to return (default: 50)
                        - offset (optional): Offset for pagination (default: 0)
                        - search (optional): Text search in rule descriptions/content
                        - group (optional): Filter by rule group (e.g., "sysmon", "windows")
                        - level (optional): Filter by rule level/severity (e.g., "4" or "2-4")
                        - status (optional): Filter by status ("enabled", "disabled", "all")
                        - filename (optional): Filter by rule filename
                        - pci_dss, gdpr, hipaa, nist_800_53, tsc, mitre (optional): Compliance filters
                        - sort, select, q, distinct (optional): Additional filtering

                Example usage:
                    {"args": {"search": "sysmon"}}
                    {"args": {"group": "windows", "level": "4"}}
                    {"args": {"status": "enabled", "mitre": "T1055"}}
                    {"args": {"filename": ["0020-syslog_rules.xml"]}}

                Returns:
                    JSON list of rules with IDs, descriptions, levels, groups, compliance mappings, etc.
                """
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
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to list rules: %s", e)
                    raise ToolError(f"Error listing rules: {str(e)}") from e

        if self._enabled("GetRuleFileContentTool"):

            @self.app.tool(
                name="GetRuleFileContentTool",
                description="Get the raw XML content of a specific Wazuh rule file. Requires 'filename' in 'args' object. Use 'raw=true' for plain text format. Useful for examining rule definitions and syntax.",
            )
            async def get_rule_file_content_tool(args: GetRuleFileContentArgs):
                """Get the content of a specific rule file.

                Args:
                    args: An object containing:
                        - filename (required): Name of the rule file (e.g., "0020-syslog_rules.xml")
                        - raw (optional): Format response in plain text (default: false)
                        - relative_dirname (optional): Filter by relative directory name

                Example usage:
                    {"args": {"filename": "0020-syslog_rules.xml"}}
                    {"args": {"filename": "0100-windows_rules.xml", "raw": true}}
                    {"args": {"filename": "custom_rules.xml", "relative_dirname": "etc/rules"}}

                Returns:
                    Raw XML content of the rule file or formatted JSON structure.
                """
                try:
                    client = self._get_client()
                    data = await client.get_rule_file_content(
                        filename=args.filename,
                        raw=args.raw,
                        relative_dirname=args.relative_dirname,
                    )

                    # Handle different response formats
                    if args.raw and isinstance(data, dict) and "content" in data:
                        # For raw responses, return the plain text content directly
                        return self._safe_truncate(data["content"])
                    else:
                        # For JSON responses, format as JSON
                        return self._format(data)
                except Exception as e:
                    logger.error("Failed to get rule file content: %s", e)
                    raise ToolError(f"Error retrieving rule file content: {str(e)}") from e

        if self._enabled("GetAgentSCATool"):

            @self.app.tool(
                name="GetAgentSCATool",
                description="Get Security Configuration Assessment (SCA) results for a specific Wazuh agent. Requires agent_id in 'args' object. SCA provides security compliance scanning results for various benchmarks (CIS, PCI DSS, etc.). Optional filters include policy name, description, references.",
            )
            async def get_agent_sca_tool(args: GetAgentSCAArgs):
                """Get SCA (Security Configuration Assessment) results for an agent.

                Args:
                    args: An object containing:
                        - agent_id (required): Agent ID to get SCA results from (e.g., "000", "001")
                        - name (optional): Filter by policy name
                        - description (optional): Filter by policy description
                        - references (optional): Filter by references
                        - limit (optional): Maximum number of SCA policies to return (default: 50)
                        - offset (optional): Offset for pagination (default: 0)
                        - sort, search, select, q, distinct (optional): Additional filtering

                Example usage:
                    {"args": {"agent_id": "000"}}
                    {"args": {"agent_id": "001", "name": "CIS benchmark"}}
                    {"args": {"agent_id": "000", "description": "Ubuntu"}}

                Returns:
                    JSON list of SCA policy results with compliance scores, pass/fail counts, etc.
                """
                try:
                    client = self._get_client()
                    data = await client.get_agent_sca(
                        agent_id=args.agent_id,
                        name=args.name,
                        description=args.description,
                        references=args.references,
                        limit=args.limit,
                        offset=args.offset,
                        sort=args.sort,
                        search=args.search,
                        select=args.select,
                        q=args.q,
                        distinct=args.distinct,
                    )
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to get agent SCA: %s", e)
                    raise ToolError(f"Error retrieving agent SCA: {str(e)}") from e

        if self._enabled("GetSCAPolicyChecksTool"):

            @self.app.tool(
                name="GetSCAPolicyChecksTool",
                description="Get detailed SCA policy check results for a specific policy on a Wazuh agent. Requires agent_id and policy_id in 'args' object. Shows individual security checks with pass/fail status, remediation steps, compliance mappings, etc. Use result filter to focus on failed checks.",
            )
            async def get_sca_policy_checks_tool(args: GetSCAPolicyChecksArgs):
                """Get detailed SCA policy check results for a specific policy.

                Args:
                    args: An object containing:
                        - agent_id (required): Agent ID to get SCA policy checks from (e.g., "000", "001")
                        - policy_id (required): Policy ID to get checks for (e.g., "cis_ubuntu20-04")
                        - title (optional): Filter by check title
                        - description (optional): Filter by check description
                        - rationale (optional): Filter by rationale
                        - remediation (optional): Filter by remediation steps
                        - command (optional): Filter by command used for check
                        - reason (optional): Filter by reason for check result
                        - file (optional): Filter by file path
                        - process (optional): Filter by process name
                        - directory (optional): Filter by directory
                        - registry (optional): Filter by registry key
                        - references (optional): Filter by references
                        - result (optional): Filter by result ("passed", "failed", "not_applicable")
                        - condition (optional): Filter by condition type
                        - limit (optional): Maximum number of checks to return (default: 50)
                        - offset (optional): Offset for pagination (default: 0)
                        - sort, search, select, q, distinct (optional): Additional filtering

                Example usage:
                    {"args": {"agent_id": "000", "policy_id": "cis_ubuntu20-04"}}
                    {"args": {"agent_id": "001", "policy_id": "cis_ubuntu20-04", "result": "failed"}}
                    {"args": {"agent_id": "000", "policy_id": "cis_ubuntu20-04", "title": "filesystem"}}

                Returns:
                    JSON list of detailed policy checks with compliance status, remediation, rules, etc.
                """
                try:
                    client = self._get_client()
                    data = await client.get_sca_policy_checks(
                        agent_id=args.agent_id,
                        policy_id=args.policy_id,
                        title=args.title,
                        description=args.description,
                        rationale=args.rationale,
                        remediation=args.remediation,
                        command=args.command,
                        reason=args.reason,
                        file=args.file,
                        process=args.process,
                        directory=args.directory,
                        registry=args.registry,
                        references=args.references,
                        result=args.result,
                        condition=args.condition,
                        limit=args.limit,
                        offset=args.offset,
                        sort=args.sort,
                        search=args.search,
                        select=args.select,
                        q=args.q,
                        distinct=args.distinct,
                    )
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to get SCA policy checks: %s", e)
                    raise ToolError(f"Error retrieving SCA policy checks: {str(e)}") from e

        if self._enabled("GetRuleFilesTool"):

            @self.app.tool(
                name="GetRuleFilesTool",
                description="Get a list of all rule files and their status from Wazuh Manager. Supports filtering, sorting, and field selection.",
            )
            async def get_rule_files_tool(args: GetRuleFilesArgs):
                """Get rule files from Wazuh Manager.

                Args:
                    args: An object containing all supported query parameters for /rules/files.

                Example usage:
                    {"args": {"limit": 10, "status": "enabled"}}
                    {"args": {"filename": ["0020-syslog_rules.xml"]}}
                    {"args": {"search": "ruleset"}}

                Returns:
                    JSON list of rule files with their status and directory info.
                """
                try:
                    client = self._get_client()
                    data = await client.get_rule_files(
                        pretty=args.pretty,
                        wait_for_complete=args.wait_for_complete,
                        offset=args.offset,
                        limit=args.limit,
                        sort=args.sort,
                        search=args.search,
                        relative_dirname=args.relative_dirname,
                        filename=args.filename,
                        status=args.status,
                        q=args.q,
                        select=args.select,
                        distinct=args.distinct,
                    )
                    return self._format(data)
                except Exception as e:
                    logger.error("Failed to get rule files: %s", e)
                    raise ToolError(f"Error retrieving rule files: {str(e)}") from e

    def _safe_truncate(self, text: str, max_length: Optional[int] = None) -> str:
        """Cut text to the output limit, saying how much was cut."""
        max_length = max_length or self.config.server.max_output_chars
        if len(text) <= max_length:
            return text
        return (
            text[:max_length] + f"\n\n[truncated: showing {max_length} of {len(text)} characters]"
        )

    @staticmethod
    def _raise_if_failed(data) -> None:
        """Wazuh reports total failure as HTTP 200 with "error": 1; surface that as a tool error.

        Partial failures ("error": 2) keep their data, and their failed_items stay in the output.
        """
        if not isinstance(data, dict) or data.get("error") != 1:
            return
        body = data.get("data") or {}
        if body.get("affected_items"):
            return
        reasons = []
        for item in body.get("failed_items") or []:
            err = item.get("error") or {}
            ids = ",".join(str(i) for i in (item.get("id") or []))
            reasons.append(f"{err.get('message', 'failed')} (code {err.get('code')}; ids {ids})")
        raise ToolError(f"Wazuh API: {data.get('message', 'request failed')}: {'; '.join(reasons)}")

    def _format(self, data) -> str:
        """Compact JSON, cut to the output limit.

        Wazuh responses carry their items in data.affected_items. When the output is too long, whole
        items are dropped and a `truncated` object records how many were returned out of how many,
        so a partial answer is never mistaken for a complete one.
        """
        self._raise_if_failed(data)
        limit = self.config.server.max_output_chars
        text = json.dumps(data, separators=(",", ":"), default=str)
        if len(text) <= limit:
            return text
        items = data.get("data", {}).get("affected_items") if isinstance(data, dict) else None
        if not isinstance(items, list) or not items:
            return self._safe_truncate(text, limit)
        original_chars, original_items = len(text), len(items)
        total = data["data"].get("total_affected_items", original_items)
        kept = list(items)
        while kept:
            kept = kept[: max(len(kept) * 3 // 4, len(kept) - 1)] if len(kept) > 1 else []
            trimmed = {
                **data,
                "data": {**data["data"], "affected_items": kept},
                "truncated": {
                    "returned_items": len(kept),
                    "original_items": original_items,
                    "total_affected_items": total,
                    "original_chars": original_chars,
                    "hint": "lower 'limit', use 'select' for fewer fields, or page with 'offset'",
                },
            }
            text = json.dumps(trimmed, separators=(",", ":"), default=str)
            if len(text) <= limit:
                return text
        return self._safe_truncate(text, limit)

    def _normalize_args(self, raw_args, model_class):
        """Normalize arguments to handle both direct and wrapped formats."""
        if isinstance(raw_args, dict):
            # If it has an 'args' key, use that
            if "args" in raw_args:
                return model_class(**raw_args["args"])
            # Otherwise, assume the dict itself contains the arguments
            else:
                return model_class(**raw_args)
        # If it's already a model instance, return as-is
        elif hasattr(raw_args, "__dict__"):
            return raw_args
        else:
            # Fallback to empty model
            return model_class()

    def http_app(self):
        """Streamable HTTP app at /mcp with bearer-token auth and an open /healthz."""
        token = self.config.server.auth_token
        if not token:
            raise ValueError("MCP_AUTH_TOKEN is required for the HTTP transport")
        return self.app.http_app(
            path="/mcp", middleware=[Middleware(BearerAuthMiddleware, token=token)]
        )

    def start(self, host: str = None, port: int = None) -> None:
        """Start the MCP server on the configured transport (stdio by default)."""
        server = self.config.server
        logger.info("Wazuh URL: %s", self.config.wazuh.url)
        logger.info("SSL Verify: %s", self.config.wazuh.ssl_verify)

        if server.transport == "http":
            host = host or server.host
            port = port or server.port
            logger.info("Starting Wazuh MCP Server (HTTP transport) on %s:%s/mcp", host, port)
            uvicorn.run(self.http_app(), host=host, port=port, log_level=server.log_level.lower())
            return

        # stdio is what MCP clients use when they launch the server as a subprocess (.mcp.json).
        logger.info("Starting Wazuh MCP Server (stdio transport)")
        self.app.run()

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

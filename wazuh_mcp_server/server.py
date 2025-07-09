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

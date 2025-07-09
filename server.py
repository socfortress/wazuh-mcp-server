#!/usr/bin/env python3
"""
Minimal Wazuh MCP Server using FastMCP
Exposes AuthenticateTool and GetAgentsTool for Wazuh Manager integration.

Usage:
  python server.py

Environment Variables:
  WAZUH_PROD_URL     - Wazuh Manager API URL (e.g., https://your-wazuh-manager:55000)
  WAZUH_PROD_USERNAME - Wazuh username
  WAZUH_PROD_PASSWORD - Wazuh password
  WAZUH_PROD_SSL_VERIFY - SSL verification (true/false, default: true)
"""

import json
import logging
import os
import time
from typing import List, Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
_log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Pydantic Models for Tool Parameters
# ------------------------------------------------------------------ #


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


# ------------------------------------------------------------------ #
# Wazuh Client
# ------------------------------------------------------------------ #


class WazuhClient:
    _token: Optional[str] = None
    _expiry: float = 0.0

    def __init__(self) -> None:
        url = os.getenv("WAZUH_PROD_URL")
        user = os.getenv("WAZUH_PROD_USERNAME")
        pwd = os.getenv("WAZUH_PROD_PASSWORD")

        if not all((url, user, pwd)):
            raise RuntimeError(
                "WAZUH_PROD_URL, WAZUH_PROD_USERNAME, and WAZUH_PROD_PASSWORD must be set",
            )

        verify = os.getenv("WAZUH_PROD_SSL_VERIFY", "true").lower() not in {"0", "false", "no"}
        self._basic = (user, pwd)
        self._cli = httpx.AsyncClient(base_url=url, verify=verify, timeout=30, http2=True)

    async def _refresh_token(self) -> None:
        if self._token and self._expiry - time.time() > 60:
            return

        r = await self._cli.post("/security/user/authenticate", auth=self._basic)
        r.raise_for_status()
        self._token = r.json()["data"]["token"]
        self._expiry = time.time() + 900
        _log.debug("New JWT obtained (exp %d)", self._expiry)

    async def request(self, method: str, url: str, **kw):
        await self._refresh_token()
        headers = kw.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        return await self._cli.request(method, url, headers=headers, **kw)


# Singleton client
_client: Optional[WazuhClient] = None


def get_client() -> WazuhClient:
    global _client
    if _client is None:
        _client = WazuhClient()
    return _client


# ------------------------------------------------------------------ #
# Helper Functions
# ------------------------------------------------------------------ #


def safe_truncate(text: str, max_length: int = 32000) -> str:
    """Truncate text to avoid overwhelming the client."""
    if len(text) <= max_length:
        return text
    return text[:max_length] + f"\n\n[... truncated {len(text) - max_length} characters ...]"


async def list_agents(params: dict) -> dict:
    """List agents from Wazuh Manager."""
    client = get_client()

    # Build query parameters
    query_params = {}
    if params.get("status"):
        query_params["status"] = ",".join(params["status"])
    if params.get("limit"):
        query_params["limit"] = params["limit"]
    if params.get("offset"):
        query_params["offset"] = params["offset"]

    response = await client.request("GET", "/agents", params=query_params)
    response.raise_for_status()
    return response.json()


# ------------------------------------------------------------------ #
# FastMCP App and Tools
# ------------------------------------------------------------------ #

# Create FastMCP app
app = FastMCP(name="Wazuh MCP Server", version="0.1.0")


@app.tool(name="AuthenticateTool")
async def authenticate_tool(args: AuthenticateArgs):
    """Force a new JWT token acquisition from Wazuh Manager."""
    client = get_client()
    client._token = None  # Force token refresh
    await client._refresh_token()
    return [{"type": "text", "text": "New token acquired successfully."}]


@app.tool(name="GetAgentsTool")
async def get_agents_tool(args: GetAgentsArgs):
    """Return agents from Wazuh Manager matching optional filters."""
    try:
        data = await list_agents(args.model_dump(exclude_none=True))
        return [{"type": "text", "text": safe_truncate(json.dumps(data, indent=2))}]
    except Exception as e:
        return [{"type": "text", "text": f"Error retrieving agents: {str(e)}"}]


# ------------------------------------------------------------------ #
# Main Function
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import uvicorn

    # Check environment variables
    required_vars = ["WAZUH_PROD_URL", "WAZUH_PROD_USERNAME", "WAZUH_PROD_PASSWORD"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("\nRequired environment variables:")
        for var in required_vars:
            print(f"  {var}")
        print("\nOptional environment variables:")
        print("  WAZUH_PROD_SSL_VERIFY (default: true)")
        exit(1)

    print("Starting Wazuh MCP Server...")
    print(f"Wazuh API URL: {os.getenv('WAZUH_PROD_URL')}")
    print(f"Username: {os.getenv('WAZUH_PROD_USERNAME')}")
    print(f"SSL Verify: {os.getenv('WAZUH_PROD_SSL_VERIFY', 'true')}")

    # Start server with SSE transport for LangChain/OpenAI compatibility
    uvicorn.run(app.sse_app, host="127.0.0.1", port=8010, log_level="info")

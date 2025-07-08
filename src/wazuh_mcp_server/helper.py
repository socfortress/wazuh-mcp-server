"""
Thin wrappers around Wazuh endpoints.
"""
from typing import Dict, Any
from .client import get_client

async def list_agents(params: Dict[str, Any]) -> Dict[str, Any]:
    cli = get_client()
    resp = await cli.request("GET", "/agents", params=params)
    resp.raise_for_status()
    return resp.json()
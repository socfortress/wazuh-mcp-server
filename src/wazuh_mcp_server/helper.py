import json, logging
from .client import get_client
from typing import Dict, Any

_LOG = logging.getLogger(__name__)

async def list_agents(cluster_name: str, registry, params: Dict[str, Any]) -> Dict[str, Any]:
    cli = get_client(cluster_name, registry)
    resp = await cli.request("GET", "/agents", params=params)
    resp.raise_for_status()
    return resp.json()
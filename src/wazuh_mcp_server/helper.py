import json, logging
from .client import get_client
from typing import Dict, Any

_LOG = logging.getLogger(__name__)

async def list_agents(registry=None, params: Dict[str, Any] = None) -> Dict[str, Any]:
    cli = get_client(registry=registry)
    resp = await cli.request("GET", "/agents", params=params or {})
    resp.raise_for_status()
    return resp.json()
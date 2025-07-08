import json
from typing import Dict, Callable, Any
from .tool_params import AuthenticateArgs, GetAgentsArgs
from wazuh_mcp_server.client import get_client
from wazuh_mcp_server.helper import list_agents
from .utils import safe_truncate

TOOL_REGISTRY: Dict[str, Callable] = {}


def register(name: str):
    def _decor(fn):
        TOOL_REGISTRY[name] = fn
        return fn
    return _decor


# ------------------------------------------------------------------ #
@register("AuthenticateTool")
async def auth_tool(args: AuthenticateArgs):
    """Force a new JWT token."""
    cli = get_client()
    cli._token = None                         # type: ignore[attr-defined]
    await cli._refresh_token()               # type: ignore[attr-defined]
    return [{"type": "text", "text": "New token acquired."}]


@register("GetAgentsTool")
async def get_agents_tool(args: GetAgentsArgs):
    """Return agents matching optional filters."""
    data = await list_agents(args.model_dump(exclude_none=True))
    return [{"type": "text",
             "text": safe_truncate(json.dumps(data, indent=2))}]
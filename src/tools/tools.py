import json
from typing import Any, Dict
from .tool_params import AuthenticateArgs, GetAgentsArgs
from wazuh_mcp_server.client import get_client
from wazuh_mcp_server.helper import list_agents

TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {}

def register(name: str):
    def _decor(fn):
        TOOL_REGISTRY[name] = fn
        return fn
    return _decor

@register("AuthenticateTool")
async def auth_tool(args: AuthenticateArgs, registry, **_):
    cli = get_client(args.cluster, registry)
    # force a token refresh
    cli._token = None
    await cli._refresh_token()
    return [{
        "type": "text",
        "text": f"New token acquired for cluster '{args.cluster}'."
    }]

@register("GetAgentsTool")
async def get_agents_tool(args: GetAgentsArgs, registry, **_):
    data = await list_agents(args.cluster, registry, params=args.model_dump(exclude_none=True, exclude={"cluster"}))
    pretty = json.dumps(data, indent=2)[:16000]  # truncate long output
    return [{
        "type": "text",
        "text": pretty
    }]
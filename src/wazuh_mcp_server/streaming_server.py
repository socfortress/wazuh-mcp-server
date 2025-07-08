from __future__ import annotations
import os, json, logging
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp.server import Server
from tools import TOOL_REGISTRY                      # full catalogue
from tools.tool_filter import get_enabled_tools      # filtering logic

_LOG = logging.getLogger(__name__)


def serve_streaming(host: str, port: int) -> None:
    # Load environment variables
    from .env_config import get_mcp_config
    
    config = get_mcp_config()
    
    # Create a simple registry with the single cluster
    registry = {
        "default": config.clusters[0]  # Use the first (and only) cluster
    }

    # --------------------------------------------------------------------- #
    # 2. Filter the tool catalogue                                          #
    # --------------------------------------------------------------------- #
    filter_yaml = os.getenv("WAZUH_FILTER_YAML")          # optional path
    ENABLED_TOOLS = get_enabled_tools(TOOL_REGISTRY, filter_yaml)
    _LOG.info("Enabled %d / %d tools", len(ENABLED_TOOLS), len(TOOL_REGISTRY))

    # --------------------------------------------------------------------- #
    # 3. MCP server                                                         #
    # --------------------------------------------------------------------- #
    mcp = Server("wazuh-mcp-server", version="0.1.0")

    @mcp.list_tools()
    async def list_tools():
        """Return only the tools that survived filtering."""
        return [
            {
                "name": n,
                "description": (fn.__doc__ or "").strip(),
            }
            for n, fn in ENABLED_TOOLS.items()
        ]

    @mcp.call_tool()
    async def call_tool(name: str, arguments: dict):
        fn = ENABLED_TOOLS.get(name)
        if fn is None:
            raise ValueError(f"Tool '{name}' is disabled or unknown")
        return await fn(arguments, registry=registry)

    # --------------------------------------------------------------------- #
    # 4. Transport endpoints (HTTP/JSON)                                     #
    # --------------------------------------------------------------------- #
    async def messages_endpoint(request):
        """Handle OpenAI-compatible chat completions"""
        try:
            body = await request.json()
            messages = body.get("messages", [])
            
            # Check if this is a tool listing request
            if messages and messages[0].get("content") == "list_tools":
                tools = await list_tools()
                return JSONResponse({
                    "id": "chatcmpl-tools",
                    "object": "chat.completion",
                    "created": 1234567890,
                    "model": "wazuh-mcp-server",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(tools)
                        },
                        "finish_reason": "stop"
                    }]
                })
            
            # Handle regular chat messages
            last_message = messages[-1] if messages else {}
            user_content = last_message.get("content", "")
            
            # Simple response for now
            return JSONResponse({
                "id": "chatcmpl-response",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "wazuh-mcp-server",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Received: {user_content}"
                    },
                    "finish_reason": "stop"
                }]
            })
            
        except Exception as e:
            _LOG.error(f"Error handling messages endpoint: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    async def tools_endpoint(request):
        """Handle tool listing requests"""
        try:
            tools = await list_tools()
            return JSONResponse({"tools": tools})
        except Exception as e:
            _LOG.error(f"Error handling tools endpoint: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    async def health(_):
        return JSONResponse({"status": "ok"})

    app = Starlette(
        routes=[
            Route("/tools", tools_endpoint),
            Route("/messages", messages_endpoint, methods=["POST"]),
            Route("/health", health),
        ]
    )

    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
from __future__ import annotations
import os, json, logging
from starlette.applications import Starlette
from starlette.responses import JSONResponse, EventSourceResponse
from starlette.routing import Route

from mcp_server_core import Server
from .clusters_information import load_clusters_from_yaml
from tools import TOOL_REGISTRY                      # full catalogue
from tools.tool_filter import get_enabled_tools      # filtering logic

_LOG = logging.getLogger(__name__)


def serve_streaming(host: str, port: int, config_path: str | None) -> None:
    # --------------------------------------------------------------------- #
    # 1. Multi-cluster registry                                             #
    # --------------------------------------------------------------------- #
    registry = load_clusters_from_yaml(config_path)

    # --------------------------------------------------------------------- #
    # 2. Filter the tool catalogue                                          #
    # --------------------------------------------------------------------- #
    filter_yaml = os.getenv("WAZUH_FILTER_YAML")          # optional path
    ENABLED_TOOLS = get_enabled_tools(TOOL_REGISTRY, filter_yaml)
    _LOG.info("Enabled %d / %d tools", len(ENABLED_TOOLS), len(TOOL_REGISTRY))

    # --------------------------------------------------------------------- #
    # 3. MCP server                                                         #
    # --------------------------------------------------------------------- #
    mcp = Server()

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
    # 4. Transport endpoints (SSE / OpenAI Streamable)                       #
    # --------------------------------------------------------------------- #
    async def sse_endpoint(request):
        async def event_generator():
            async for message in mcp.streaming_adapter(request):
                yield {"data": json.dumps(message)}
        return EventSourceResponse(event_generator())

    async def oa_endpoint(request):
        return await mcp.openai_streamable_adapter(request)

    async def health(_):
        return JSONResponse({"status": "ok"})

    app = Starlette(
        routes=[
            Route("/sse", sse_endpoint),
            Route("/messages", oa_endpoint, methods=["POST"]),
            Route("/health", health),
        ]
    )

    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
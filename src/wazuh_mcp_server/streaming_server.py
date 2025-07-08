from __future__ import annotations
import os, logging
from fastmcp import FastMCP

import sys
from pathlib import Path
# Add the parent directory to the path to allow importing tools
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools import TOOL_REGISTRY
from tools.tool_filter import get_enabled_tools

_log = logging.getLogger(__name__)


def build_app() -> FastMCP:
    enabled = get_enabled_tools(TOOL_REGISTRY, os.getenv("WAZUH_FILTER_YAML"))
    _log.info("Enabled %d / %d tools", len(enabled), len(TOOL_REGISTRY))

    # Create FastMCP app
    app = FastMCP(
        name="Wazuh MCP Server", 
        version="0.1.0"
    )

    # Register each enabled tool with FastMCP directly
    for name, fn in enabled.items():
        # Register the tool function directly with FastMCP
        app.tool(name=name)(fn)

    return app
"""
Wazuh MCP Server - A Model Context Protocol server for Wazuh Manager integration.
"""

__version__ = "0.1.0"
__author__ = "SOCFortress"
__email__ = "info@socfortress.co"
__description__ = "MCP server for Wazuh Manager integration with LLMs"

from .client import WazuhClient
from .config import Config
from .server import WazuhMCPServer

__all__ = ["WazuhMCPServer", "WazuhClient", "Config"]

"""
Wazuh MCP Server - A Model Context Protocol server for Wazuh Manager integration.
"""

__version__ = "0.1.0"
__author__ = "SOCFortress"
__email__ = "info@socfortress.co"
__description__ = "MCP server for Wazuh Manager integration with LLMs"

from .server import WazuhMCPServer
from .client import WazuhClient
from .config import Config

__all__ = ["WazuhMCPServer", "WazuhClient", "Config"]

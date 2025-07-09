"""
Exception classes for Wazuh MCP Server.
"""


class WazuhMCPError(Exception):
    """Base exception for Wazuh MCP Server."""

    pass


class WazuhAuthenticationError(WazuhMCPError):
    """Raised when authentication with Wazuh fails."""

    pass


class WazuhAPIError(WazuhMCPError):
    """Raised when Wazuh API returns an error."""

    pass


class ConfigurationError(WazuhMCPError):
    """Raised when configuration is invalid."""

    pass

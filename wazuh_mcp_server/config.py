"""
Configuration management for Wazuh MCP Server.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class WazuhConfig:
    """Configuration for a Wazuh Manager instance."""

    url: str
    username: str
    password: str
    ssl_verify: bool = True
    timeout: int = 30

    @classmethod
    def from_env(cls, prefix: str = "WAZUH_PROD") -> "WazuhConfig":
        """Create configuration from environment variables."""
        return cls(
            url=os.getenv(f"{prefix}_URL", ""),
            username=os.getenv(f"{prefix}_USERNAME", ""),
            password=os.getenv(f"{prefix}_PASSWORD", ""),
            ssl_verify=os.getenv(f"{prefix}_SSL_VERIFY", "true").lower()
            not in {"0", "false", "no"},
            timeout=int(os.getenv(f"{prefix}_TIMEOUT", "30")),
        )

    def validate(self) -> None:
        """Validate configuration."""
        if not self.url:
            raise ValueError("Wazuh URL is required")
        if not self.username:
            raise ValueError("Wazuh username is required")
        if not self.password:
            raise ValueError("Wazuh password is required")


@dataclass
class ServerConfig:
    """Configuration for the MCP server."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    disabled_tools: List[str] = field(default_factory=list)
    disabled_categories: List[str] = field(default_factory=list)
    read_only: bool = False

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables."""
        disabled_tools = []
        if tools_str := os.getenv("WAZUH_DISABLED_TOOLS"):
            disabled_tools = [tool.strip() for tool in tools_str.split(",")]

        disabled_categories = []
        if categories_str := os.getenv("WAZUH_DISABLED_CATEGORIES"):
            disabled_categories = [cat.strip() for cat in categories_str.split(",")]

        return cls(
            host=os.getenv("MCP_SERVER_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_SERVER_PORT", "8000")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            disabled_tools=disabled_tools,
            disabled_categories=disabled_categories,
            read_only=os.getenv("WAZUH_READ_ONLY", "false").lower() in {"1", "true", "yes"},
        )


@dataclass
class Config:
    """Main configuration class."""

    wazuh: WazuhConfig
    server: ServerConfig

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        return cls(wazuh=WazuhConfig.from_env(), server=ServerConfig.from_env())

    def validate(self) -> None:
        """Validate all configuration."""
        self.wazuh.validate()

    def setup_logging(self) -> None:
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.server.log_level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

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
class IndexerConfig:
    """Configuration for the Wazuh Indexer (OpenSearch), where alerts are stored.

    Optional: when no URL is set, the alert tools are not registered.
    """

    url: str = ""
    username: str = ""
    password: str = ""
    ssl_verify: bool = True
    timeout: int = 30
    alerts_index: str = "wazuh-alerts-*"

    @classmethod
    def from_env(cls, prefix: str = "WAZUH_INDEXER") -> "IndexerConfig":
        """Create configuration from environment variables."""
        return cls(
            url=os.getenv(f"{prefix}_URL", ""),
            username=os.getenv(f"{prefix}_USERNAME", ""),
            password=os.getenv(f"{prefix}_PASSWORD", ""),
            ssl_verify=os.getenv(f"{prefix}_SSL_VERIFY", "true").lower()
            not in {"0", "false", "no"},
            timeout=int(os.getenv(f"{prefix}_TIMEOUT", "30")),
            alerts_index=os.getenv(f"{prefix}_ALERTS_INDEX", "wazuh-alerts-*"),
        )

    @property
    def enabled(self) -> bool:
        """Whether an indexer is configured."""
        return bool(self.url)

    def validate(self) -> None:
        """Validate configuration (only when an indexer URL is set)."""
        if not self.url:
            return
        if not self.username:
            raise ValueError("Wazuh Indexer username is required when WAZUH_INDEXER_URL is set")
        if not self.password:
            raise ValueError("Wazuh Indexer password is required when WAZUH_INDEXER_URL is set")


@dataclass
class ServerConfig:
    """Configuration for the MCP server."""

    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    disabled_tools: List[str] = field(default_factory=list)
    disabled_categories: List[str] = field(default_factory=list)
    read_only: bool = False
    transport: str = "stdio"
    auth_token: str = ""
    max_output_chars: int = 32000

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
            transport=os.getenv("MCP_TRANSPORT", "stdio").lower(),
            auth_token=os.getenv("MCP_AUTH_TOKEN", ""),
            max_output_chars=int(os.getenv("MCP_MAX_OUTPUT_CHARS", "32000")),
        )


@dataclass
class Config:
    """Main configuration class."""

    wazuh: WazuhConfig
    server: ServerConfig
    indexer: IndexerConfig = field(default_factory=IndexerConfig)

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        return cls(
            wazuh=WazuhConfig.from_env(),
            server=ServerConfig.from_env(),
            indexer=IndexerConfig.from_env(),
        )

    def validate(self) -> None:
        """Validate all configuration."""
        self.wazuh.validate()
        self.indexer.validate()

    def setup_logging(self) -> None:
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.server.log_level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

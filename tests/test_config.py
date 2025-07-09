"""
Tests for configuration management.
"""

import os
from unittest.mock import patch

import pytest

from wazuh_mcp_server.config import Config, ServerConfig, WazuhConfig


class TestWazuhConfig:
    """Test Wazuh configuration."""

    def test_init(self):
        """Test WazuhConfig initialization."""
        config = WazuhConfig(
            url="https://test:55000",
            username="user",
            password="pass",
            ssl_verify=False,
            timeout=30,
        )

        assert config.url == "https://test:55000"
        assert config.username == "user"
        assert config.password == "pass"
        assert config.ssl_verify is False
        assert config.timeout == 30

    def test_from_env(self):
        """Test WazuhConfig from environment variables."""
        env_vars = {
            "WAZUH_PROD_URL": "https://env-test:55000",
            "WAZUH_PROD_USERNAME": "env-user",
            "WAZUH_PROD_PASSWORD": "env-pass",
            "WAZUH_PROD_SSL_VERIFY": "false",
            "WAZUH_PROD_TIMEOUT": "60",
        }

        with patch.dict(os.environ, env_vars):
            config = WazuhConfig.from_env()

            assert config.url == "https://env-test:55000"
            assert config.username == "env-user"
            assert config.password == "env-pass"
            assert config.ssl_verify is False
            assert config.timeout == 60

    def test_validate_success(self):
        """Test successful validation."""
        config = WazuhConfig(url="https://test:55000", username="user", password="pass")

        # Should not raise an exception
        config.validate()

    def test_validate_missing_url(self):
        """Test validation with missing URL."""
        config = WazuhConfig(url="", username="user", password="pass")

        with pytest.raises(ValueError, match="Wazuh URL is required"):
            config.validate()

    def test_validate_missing_username(self):
        """Test validation with missing username."""
        config = WazuhConfig(url="https://test:55000", username="", password="pass")

        with pytest.raises(ValueError, match="Wazuh username is required"):
            config.validate()

    def test_validate_missing_password(self):
        """Test validation with missing password."""
        config = WazuhConfig(url="https://test:55000", username="user", password="")

        with pytest.raises(ValueError, match="Wazuh password is required"):
            config.validate()


class TestServerConfig:
    """Test server configuration."""

    def test_init(self):
        """Test ServerConfig initialization."""
        config = ServerConfig(
            host="0.0.0.0",
            port=8080,
            log_level="DEBUG",
            disabled_tools=["AuthenticateTool"],
            disabled_categories=["dangerous"],
            read_only=True,
        )

        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.log_level == "DEBUG"
        assert config.disabled_tools == ["AuthenticateTool"]
        assert config.disabled_categories == ["dangerous"]
        assert config.read_only is True

    def test_from_env(self):
        """Test ServerConfig from environment variables."""
        env_vars = {
            "MCP_SERVER_HOST": "0.0.0.0",
            "MCP_SERVER_PORT": "8080",
            "LOG_LEVEL": "DEBUG",
            "WAZUH_DISABLED_TOOLS": "AuthenticateTool,GetAgentsTool",
            "WAZUH_DISABLED_CATEGORIES": "dangerous,write",
            "WAZUH_READ_ONLY": "true",
        }

        with patch.dict(os.environ, env_vars):
            config = ServerConfig.from_env()

            assert config.host == "0.0.0.0"
            assert config.port == 8080
            assert config.log_level == "DEBUG"
            assert config.disabled_tools == ["AuthenticateTool", "GetAgentsTool"]
            assert config.disabled_categories == ["dangerous", "write"]
            assert config.read_only is True


class TestConfig:
    """Test main configuration."""

    def test_init(self, wazuh_config, server_config):
        """Test Config initialization."""
        config = Config(wazuh=wazuh_config, server=server_config)

        assert config.wazuh == wazuh_config
        assert config.server == server_config

    def test_validate_success(self, config):
        """Test successful validation."""
        # Should not raise an exception
        config.validate()

    def test_validate_invalid_wazuh_config(self, server_config):
        """Test validation with invalid Wazuh config."""
        invalid_wazuh_config = WazuhConfig(
            url="",
            username="user",
            password="pass",  # Invalid empty URL
        )

        config = Config(wazuh=invalid_wazuh_config, server=server_config)

        with pytest.raises(ValueError, match="Wazuh URL is required"):
            config.validate()

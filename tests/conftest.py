"""
Test configuration for pytest.
"""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from wazuh_mcp_server.client import WazuhClient
from wazuh_mcp_server.config import Config, ServerConfig, WazuhConfig


@pytest.fixture
def wazuh_config():
    """Create a test Wazuh configuration."""
    return WazuhConfig(
        url="https://test-wazuh:55000",
        username="test-user",
        password="test-password",
        ssl_verify=False,
        timeout=10,
    )


@pytest.fixture
def server_config():
    """Create a test server configuration."""
    return ServerConfig(
        host="127.0.0.1",
        port=8000,
        log_level="INFO",
        disabled_tools=[],
        disabled_categories=[],
        read_only=False,
    )


@pytest.fixture
def config(wazuh_config, server_config):
    """Create a test configuration."""
    return Config(wazuh=wazuh_config, server=server_config)


@pytest.fixture
def mock_httpx_client():
    """Create a mock httpx client."""
    client = Mock()
    client.post = AsyncMock()
    client.request = AsyncMock()
    client.aclose = AsyncMock()
    return client


@pytest.fixture
def wazuh_client(wazuh_config, mock_httpx_client):
    """Create a test Wazuh client."""
    client = WazuhClient(wazuh_config)
    client._client = mock_httpx_client
    return client


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

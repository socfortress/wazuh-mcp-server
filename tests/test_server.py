"""
Tests for the main server.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from wazuh_mcp_server.config import Config
from wazuh_mcp_server.server import WazuhMCPServer, create_server


class TestWazuhMCPServer:
    """Test Wazuh MCP server."""

    def test_init(self, config):
        """Test WazuhMCPServer initialization."""
        server = WazuhMCPServer(config)

        assert server.config == config
        assert server._client is None
        assert server.app is not None
        assert server.app.name == "Wazuh MCP Server"

    def test_get_client(self, config):
        """Test _get_client method."""
        server = WazuhMCPServer(config)

        # First call should create client
        client1 = server._get_client()
        assert client1 is not None
        assert server._client is client1

        # Second call should return same client
        client2 = server._get_client()
        assert client2 is client1

    def test_safe_truncate_short_text(self, config):
        """Test _safe_truncate with short text."""
        server = WazuhMCPServer(config)

        short_text = "This is a short text"
        result = server._safe_truncate(short_text)

        assert result == short_text

    def test_safe_truncate_long_text(self, config):
        """Test _safe_truncate with long text."""
        server = WazuhMCPServer(config)

        long_text = "A" * 50000  # 50k characters
        result = server._safe_truncate(long_text, max_length=1000)

        assert len(result) > 1000  # Should include truncation message
        assert result.startswith("A" * 1000)
        assert "truncated" in result

    @pytest.mark.asyncio
    async def test_close(self, config):
        """Test server close method."""
        server = WazuhMCPServer(config)

        # Mock client
        mock_client = Mock()
        mock_client.close = AsyncMock()
        server._client = mock_client

        await server.close()

        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_no_client(self, config):
        """Test server close method with no client."""
        server = WazuhMCPServer(config)

        # Should not raise an exception
        await server.close()

    @pytest.mark.asyncio
    async def test_get_agent_ports_tool_registration(self, config):
        """Test that GetAgentPortsTool is registered when not disabled."""
        server = WazuhMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentPortsTool" in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_ports_tool_disabled(self, config):
        """Test that GetAgentPortsTool is not registered when disabled."""
        config.server.disabled_tools = ["GetAgentPortsTool"]
        server = WazuhMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentPortsTool" not in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_packages_tool_registration(self, config):
        """Test that GetAgentPackagesTool is registered when not disabled."""
        server = WazuhMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentPackagesTool" in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_packages_tool_disabled(self, config):
        """Test that GetAgentPackagesTool is not registered when disabled."""
        config.server.disabled_tools = ["GetAgentPackagesTool"]
        server = WazuhMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentPackagesTool" not in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_processes_tool_registration(self, config):
        """Test that GetAgentProcessesTool is registered when not disabled."""
        server = WazuhMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentProcessesTool" in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_processes_tool_disabled(self, config):
        """Test that GetAgentProcessesTool is not registered when disabled."""
        config.server.disabled_tools = ["GetAgentProcessesTool"]
        server = WazuhMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentProcessesTool" not in tool_names

    @pytest.mark.asyncio
    async def test_list_rules_tool_registration(self, config):
        """Test that ListRulesTool is registered when not disabled."""
        server = WazuhMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListRulesTool" in tool_names

    @pytest.mark.asyncio
    async def test_list_rules_tool_disabled(self, config):
        """Test that ListRulesTool is not registered when disabled."""
        config.server.disabled_tools = ["ListRulesTool"]
        server = WazuhMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListRulesTool" not in tool_names

    @pytest.mark.asyncio
    async def test_get_rule_file_content_tool_registration(self, config):
        """Test that GetRuleFileContentTool is registered when not disabled."""
        server = WazuhMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetRuleFileContentTool" in tool_names

    @pytest.mark.asyncio
    async def test_get_rule_file_content_tool_disabled(self, config):
        """Test that GetRuleFileContentTool is not registered when disabled."""
        config.server.disabled_tools = ["GetRuleFileContentTool"]
        server = WazuhMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetRuleFileContentTool" not in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_sca_tool_registration(self, config):
        """Test that GetAgentSCATool is registered when not disabled."""
        server = WazuhMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentSCATool" in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_sca_tool_disabled(self, config):
        """Test that GetAgentSCATool is not registered when disabled."""
        config.server.disabled_tools = ["GetAgentSCATool"]
        server = WazuhMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentSCATool" not in tool_names

    @pytest.mark.asyncio
    async def test_get_sca_policy_checks_tool_registration(self, config):
        """Test that GetSCAPolicyChecksTool is registered when not disabled."""
        server = WazuhMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetSCAPolicyChecksTool" in tool_names

    @pytest.mark.asyncio
    async def test_get_sca_policy_checks_tool_disabled(self, config):
        """Test that GetSCAPolicyChecksTool is not registered when disabled."""
        config.server.disabled_tools = ["GetSCAPolicyChecksTool"]
        server = WazuhMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetSCAPolicyChecksTool" not in tool_names


class TestCreateServer:
    """Test create_server factory function."""

    def test_create_server_with_config(self, config):
        """Test create_server with provided config."""
        server = create_server(config)

        assert isinstance(server, WazuhMCPServer)
        assert server.config == config

    @patch("wazuh_mcp_server.server.Config.from_env")
    def test_create_server_without_config(self, mock_from_env, config):
        """Test create_server without config (uses env)."""
        mock_from_env.return_value = config

        server = create_server()

        assert isinstance(server, WazuhMCPServer)
        mock_from_env.assert_called_once()

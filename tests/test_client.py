"""
Tests for Wazuh client.
"""

import pytest
import json
from unittest.mock import Mock, AsyncMock, patch
from wazuh_mcp_server.client import WazuhClient
from wazuh_mcp_server.config import WazuhConfig


class TestWazuhClient:
    """Test Wazuh client."""
    
    @pytest.mark.asyncio
    async def test_init(self, wazuh_config):
        """Test WazuhClient initialization."""
        client = WazuhClient(wazuh_config)
        
        assert client.config == wazuh_config
        assert client._token is None
        assert client._expiry == 0.0
        assert client._basic == (wazuh_config.username, wazuh_config.password)
    
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, wazuh_client, mock_httpx_client):
        """Test successful token refresh."""
        # Mock response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {"token": "test-token-123"}
        }
        mock_httpx_client.post.return_value = mock_response
        
        await wazuh_client._refresh_token()
        
        assert wazuh_client._token == "test-token-123"
        assert wazuh_client._expiry > 0
        mock_httpx_client.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_refresh_token_skip_if_valid(self, wazuh_client, mock_httpx_client):
        """Test token refresh is skipped if token is still valid."""
        # Set a valid token
        wazuh_client._token = "valid-token"
        wazuh_client._expiry = 9999999999  # Far future
        
        await wazuh_client._refresh_token()
        
        # Should not call post since token is valid
        mock_httpx_client.post.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_request_success(self, wazuh_client, mock_httpx_client):
        """Test successful API request."""
        # Mock token refresh
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {"token": "test-token"}
        }
        mock_httpx_client.post.return_value = mock_response
        
        # Mock API request
        mock_api_response = Mock()
        mock_api_response.raise_for_status = Mock()
        mock_httpx_client.request.return_value = mock_api_response
        
        result = await wazuh_client.request("GET", "/test")
        
        assert result == mock_api_response
        mock_httpx_client.request.assert_called_once_with(
            "GET", "/test", headers={"Authorization": "Bearer test-token"}
        )
    
    @pytest.mark.asyncio
    async def test_get_agents_success(self, wazuh_client, mock_httpx_client):
        """Test successful get_agents call."""
        # Mock token refresh
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {"token": "test-token"}
        }
        mock_httpx_client.post.return_value = mock_response
        
        # Mock agents request
        mock_agents_response = Mock()
        mock_agents_response.raise_for_status = Mock()
        mock_agents_response.json.return_value = {
            "data": {"affected_items": [{"id": "001", "name": "agent1"}]}
        }
        mock_httpx_client.request.return_value = mock_agents_response
        
        result = await wazuh_client.get_agents(status=["active"], limit=100, offset=0)
        
        expected_data = {"data": {"affected_items": [{"id": "001", "name": "agent1"}]}}
        assert result == expected_data
        
        # Check that request was made with correct parameters
        mock_httpx_client.request.assert_called_once_with(
            "GET", "/agents", 
            headers={"Authorization": "Bearer test-token"},
            params={"status": "active", "limit": 100, "offset": 0}
        )
    
    @pytest.mark.asyncio
    async def test_get_agent_success(self, wazuh_client, mock_httpx_client):
        """Test successful get_agent call."""
        # Mock token refresh
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {"token": "test-token"}
        }
        mock_httpx_client.post.return_value = mock_response
        
        # Mock agent request
        mock_agent_response = Mock()
        mock_agent_response.raise_for_status = Mock()
        mock_agent_response.json.return_value = {
            "data": {"affected_items": [{"id": "001", "name": "agent1"}]}
        }
        mock_httpx_client.request.return_value = mock_agent_response
        
        result = await wazuh_client.get_agent("001")
        
        expected_data = {"data": {"affected_items": [{"id": "001", "name": "agent1"}]}}
        assert result == expected_data
        
        # Check that request was made with correct URL
        mock_httpx_client.request.assert_called_once_with(
            "GET", "/agents/001", 
            headers={"Authorization": "Bearer test-token"}
        )
    
    @pytest.mark.asyncio
    async def test_authenticate_success(self, wazuh_client, mock_httpx_client):
        """Test successful authenticate call."""
        # Mock token refresh
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {"token": "test-token"}
        }
        mock_httpx_client.post.return_value = mock_response
        
        result = await wazuh_client.authenticate()
        
        assert result["status"] == "authenticated"
        assert "token_expiry" in result
        assert result["token_expiry"] > 0
    
    @pytest.mark.asyncio
    async def test_close(self, wazuh_client, mock_httpx_client):
        """Test client close."""
        await wazuh_client.close()
        
        mock_httpx_client.aclose.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_context_manager(self, wazuh_config, mock_httpx_client):
        """Test async context manager."""
        client = WazuhClient(wazuh_config)
        client._client = mock_httpx_client
        
        async with client as c:
            assert c == client
        
        mock_httpx_client.aclose.assert_called_once()

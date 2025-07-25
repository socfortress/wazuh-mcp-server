"""
Tests for Wazuh client.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

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
        mock_response.json.return_value = {"data": {"token": "test-token-123"}}
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
        mock_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_response

        # Mock API request
        mock_api_response = Mock()
        mock_api_response.raise_for_status = Mock()
        mock_httpx_client.request.return_value = mock_api_response

        result = await wazuh_client.request("GET", "/test")

        assert result == mock_api_response
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/test",
            headers={"Authorization": "Bearer test-token"},
        )

    @pytest.mark.asyncio
    async def test_get_agents_success(self, wazuh_client, mock_httpx_client):
        """Test successful get_agents call."""
        # Mock token refresh
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_response

        # Mock agents request
        mock_agents_response = Mock()
        mock_agents_response.raise_for_status = Mock()
        mock_agents_response.json.return_value = {
            "data": {"affected_items": [{"id": "001", "name": "agent1"}]},
        }
        mock_httpx_client.request.return_value = mock_agents_response

        result = await wazuh_client.get_agents(status=["active"], limit=100, offset=0)

        expected_data = {"data": {"affected_items": [{"id": "001", "name": "agent1"}]}}
        assert result == expected_data

        # Check that request was made with correct parameters
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/agents",
            headers={"Authorization": "Bearer test-token"},
            params={"status": "active", "limit": 100, "offset": 0},
        )

    @pytest.mark.asyncio
    async def test_get_agents_with_all_parameters(self, wazuh_client, mock_httpx_client):
        """Test get_agents call with all parameters."""
        # Mock token refresh
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_response

        # Mock agents request
        mock_agents_response = Mock()
        mock_agents_response.raise_for_status = Mock()
        mock_agents_response.json.return_value = {
            "data": {"affected_items": [{"id": "001", "name": "agent1"}]},
        }
        mock_httpx_client.request.return_value = mock_agents_response

        result = await wazuh_client.get_agents(
            status=["active"],
            limit=100,
            offset=10,
            sort="name",
            search="agent",
            select=["id", "name", "status"],
            q="name=agent1",
            distinct=True,
        )

        expected_data = {"data": {"affected_items": [{"id": "001", "name": "agent1"}]}}
        assert result == expected_data

        # Check that request was made with correct parameters
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/agents",
            headers={"Authorization": "Bearer test-token"},
            params={
                "status": "active",
                "limit": 100,
                "offset": 10,
                "sort": "name",
                "search": "agent",
                "select": "id,name,status",
                "q": "name=agent1",
                "distinct": "true",
            },
        )

    @pytest.mark.asyncio
    async def test_get_agent_ports_success(self, wazuh_client, mock_httpx_client):
        """Test successful agent ports retrieval."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock agent ports response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {
                "affected_items": [
                    {
                        "local": {"ip": "127.0.0.1", "port": 80},
                        "remote": {"ip": "0.0.0.0", "port": 0},
                        "protocol": "tcp",
                        "state": "listening",
                    },
                ],
                "total_affected_items": 1,
            },
        }
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_ports("000")

        assert "data" in result
        assert "affected_items" in result["data"]
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/syscollector/000/ports",
            headers={"Authorization": "Bearer test-token"},
            params={"limit": 500, "offset": 0},
        )

    @pytest.mark.asyncio
    async def test_get_agent_ports_with_filters(self, wazuh_client, mock_httpx_client):
        """Test agent ports retrieval with filters."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock agent ports response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_ports(
            agent_id="001",
            protocol="tcp",
            local_ip="127.0.0.1",
            state="listening",
            limit=100,
        )

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/syscollector/001/ports",
            headers={"Authorization": "Bearer test-token"},
            params={
                "limit": 100,
                "offset": 0,
                "protocol": "tcp",
                "local.ip": "127.0.0.1",
                "state": "listening",
            },
        )

    @pytest.mark.asyncio
    async def test_authenticate_success(self, wazuh_client, mock_httpx_client):
        """Test successful authenticate call."""
        # Mock token refresh
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"token": "test-token"}}
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

    @pytest.mark.asyncio
    async def test_get_agent_packages_success(self, wazuh_client, mock_httpx_client):
        """Test successful agent packages retrieval."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock agent packages response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {
                "affected_items": [
                    {
                        "name": "openssh-client",
                        "version": "1:8.2p1-4ubuntu0.2",
                        "architecture": "amd64",
                        "format": "deb",
                        "vendor": "Ubuntu Developers",
                        "agent_id": "001",
                    },
                ],
                "total_affected_items": 1,
            },
        }
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_packages("001")

        assert "data" in result
        assert "affected_items" in result["data"]
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/syscollector/001/packages",
            headers={"Authorization": "Bearer test-token"},
            params={"limit": 500, "offset": 0},
        )

    @pytest.mark.asyncio
    async def test_get_agent_packages_with_filters(self, wazuh_client, mock_httpx_client):
        """Test agent packages retrieval with filters."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock agent packages response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_packages(
            agent_id="001",
            vendor="Ubuntu",
            name="openssh",
            architecture="amd64",
            format="deb",
            limit=100,
        )

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/syscollector/001/packages",
            headers={"Authorization": "Bearer test-token"},
            params={
                "limit": 100,
                "offset": 0,
                "vendor": "Ubuntu",
                "name": "openssh",
                "architecture": "amd64",
                "format": "deb",
            },
        )

    @pytest.mark.asyncio
    async def test_get_agent_processes_success(self, wazuh_client, mock_httpx_client):
        """Test successful agent processes retrieval."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock agent processes response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_processes("001")

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/syscollector/001/processes",
            headers={"Authorization": "Bearer test-token"},
            params={"limit": 500, "offset": 0},
        )

    @pytest.mark.asyncio
    async def test_get_agent_processes_with_filters(self, wazuh_client, mock_httpx_client):
        """Test agent processes retrieval with filters."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock agent processes response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_processes(
            agent_id="001",
            pid="1234",
            state="S",
            name="bash",
            euser="root",
            limit=100,
        )

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/syscollector/001/processes",
            headers={"Authorization": "Bearer test-token"},
            params={
                "limit": 100,
                "offset": 0,
                "pid": "1234",
                "state": "S",
                "name": "bash",
                "euser": "root",
            },
        )

    @pytest.mark.asyncio
    async def test_list_rules_success(self, wazuh_client, mock_httpx_client):
        """Test successful list_rules call."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock rules request
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.list_rules()

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/rules",
            headers={"Authorization": "Bearer test-token"},
            params={"limit": 500, "offset": 0},
        )

    @pytest.mark.asyncio
    async def test_list_rules_with_filters(self, wazuh_client, mock_httpx_client):
        """Test list_rules with various filters."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock rules request
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.list_rules(
            rule_ids=[1001, 1002],
            status="enabled",
            group="authentication",
            level="5",
            filename=["0020-syslog_rules.xml"],
            pci_dss="0.2.4",
            limit=100,
        )

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/rules",
            headers={"Authorization": "Bearer test-token"},
            params={
                "limit": 100,
                "offset": 0,
                "rule_ids": "1001,1002",
                "status": "enabled",
                "group": "authentication",
                "level": "5",
                "filename": "0020-syslog_rules.xml",
                "pci_dss": "0.2.4",
            },
        )

    @pytest.mark.asyncio
    async def test_get_rule_file_content_success(self, wazuh_client, mock_httpx_client):
        """Test successful get_rule_file_content call."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock rule file content request
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_rule_file_content("0020-syslog_rules.xml")

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/rules/files/0020-syslog_rules.xml",
            headers={"Authorization": "Bearer test-token"},
            params={},
        )

    @pytest.mark.asyncio
    async def test_get_rule_file_content_with_options(self, wazuh_client, mock_httpx_client):
        """Test get_rule_file_content with raw=True option."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock rule file content request for raw response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.text = "<xml>rule content</xml>"  # Raw XML content
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_rule_file_content(
            filename="0020-syslog_rules.xml",
            raw=True,
            relative_dirname="ruleset/rules",
        )

        assert "content" in result
        assert result["content"] == "<xml>rule content</xml>"
        assert result["raw"] is True
        assert result["filename"] == "0020-syslog_rules.xml"
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/rules/files/0020-syslog_rules.xml",
            headers={"Authorization": "Bearer test-token"},
            params={
                "raw": "true",  # Should be string
                "relative_dirname": "ruleset/rules",
            },
        )

    @pytest.mark.asyncio
    async def test_get_rule_file_content_raw_format(self, wazuh_client, mock_httpx_client):
        """Test get_rule_file_content with raw format returning XML."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock rule file content request for raw XML response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.text = (
            '<?xml version="1.0"?><group name="sysmon"><rule id="60004">...</rule></group>'
        )
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_rule_file_content(
            filename="0575-win-base_rules.xml",
            raw=True,
        )

        assert "content" in result
        assert result["raw"] is True
        assert result["filename"] == "0575-win-base_rules.xml"
        assert "<?xml" in result["content"]
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/rules/files/0575-win-base_rules.xml",
            headers={"Authorization": "Bearer test-token"},
            params={"raw": "true"},
        )

    @pytest.mark.asyncio
    async def test_get_agent_sca_success(self, wazuh_client, mock_httpx_client):
        """Test successful get_agent_sca call."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock SCA request
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_sca("001")

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/sca/001",
            headers={"Authorization": "Bearer test-token"},
            params={"limit": 500, "offset": 0},
        )

    @pytest.mark.asyncio
    async def test_get_agent_sca_with_filters(self, wazuh_client, mock_httpx_client):
        """Test get_agent_sca with various filters."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock SCA request
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_agent_sca(
            agent_id="001",
            name="CIS benchmark",
            description="Ubuntu",
            references="https://www.cisecurity.org",
            limit=100,
        )

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/sca/001",
            headers={"Authorization": "Bearer test-token"},
            params={
                "limit": 100,
                "offset": 0,
                "name": "CIS benchmark",
                "description": "Ubuntu",
                "references": "https://www.cisecurity.org",
            },
        )

    @pytest.mark.asyncio
    async def test_get_sca_policy_checks_success(self, wazuh_client, mock_httpx_client):
        """Test successful get_sca_policy_checks call."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock SCA policy checks request
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_sca_policy_checks("001", "cis_ubuntu20-04")

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/sca/001/checks/cis_ubuntu20-04",
            headers={"Authorization": "Bearer test-token"},
            params={"limit": 500, "offset": 0},
        )

    @pytest.mark.asyncio
    async def test_get_sca_policy_checks_with_filters(self, wazuh_client, mock_httpx_client):
        """Test get_sca_policy_checks with various filters."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock SCA policy checks request
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"data": {"affected_items": []}}
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_sca_policy_checks(
            agent_id="001",
            policy_id="cis_ubuntu20-04",
            title="filesystem",
            result="failed",
            remediation="Edit",
            limit=100,
        )

        assert "data" in result
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/sca/001/checks/cis_ubuntu20-04",
            headers={"Authorization": "Bearer test-token"},
            params={
                "limit": 100,
                "offset": 0,
                "title": "filesystem",
                "result": "failed",
                "remediation": "Edit",
            },
        )

    @pytest.mark.asyncio
    async def test_get_rule_files_success(self, wazuh_client, mock_httpx_client):
        """Test successful get_rule_files call."""
        # Mock token refresh
        mock_auth_response = Mock()
        mock_auth_response.raise_for_status = Mock()
        mock_auth_response.json.return_value = {"data": {"token": "test-token"}}
        mock_httpx_client.post.return_value = mock_auth_response

        # Mock rule files response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {
            "data": {
                "affected_items": [
                    {
                        "file": "0010-rules_config.xml",
                        "relative_dirname": "ruleset/rules",
                        "status": "enabled",
                    },
                    {
                        "file": "0020-syslog_rules.xml",
                        "relative_dirname": "ruleset/rules",
                        "status": "enabled",
                    },
                ],
                "total_affected_items": 2,
                "total_failed_items": 0,
                "failed_items": [],
            },
            "message": "All rules files were returned",
            "error": 0,
        }
        mock_httpx_client.request.return_value = mock_response

        result = await wazuh_client.get_rule_files(limit=2, status="enabled")

        assert "data" in result
        assert "affected_items" in result["data"]
        assert result["data"]["total_affected_items"] == 2
        mock_httpx_client.request.assert_called_once_with(
            "GET",
            "/rules/files",
            headers={"Authorization": "Bearer test-token"},
            params={"limit": 2, "offset": 0, "status": "enabled"},
        )

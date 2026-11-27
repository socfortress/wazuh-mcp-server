"""
Tests for the Wazuh Indexer alert client and alert tools.
"""

import json
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from wazuh_mcp_server.config import Config, IndexerConfig
from wazuh_mcp_server.indexer import IndexerClient, IndexerError
from wazuh_mcp_server.server import WazuhMCPServer


@pytest.fixture
def indexer_config():
    return IndexerConfig(
        url="https://test-indexer:9200",
        username="admin",
        password="secret",
        ssl_verify=False,
    )


@pytest.fixture
def indexer_client(indexer_config):
    client = IndexerClient(indexer_config)
    client._client = Mock()
    client._client.post = AsyncMock()
    client._client.aclose = AsyncMock()
    return client


def _response(payload):
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = payload
    return response


SEARCH_RESPONSE = {
    "hits": {
        "total": {"value": 42, "relation": "eq"},
        "hits": [
            {
                "_id": "abc",
                "_source": {
                    "timestamp": "2025-01-01T00:00:00.000+0000",
                    "agent": {"id": "001", "name": "web01"},
                    "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login"},
                },
            }
        ],
    }
}


class TestIndexerConfig:
    def test_from_env_defaults(self, monkeypatch):
        for var in ("URL", "USERNAME", "PASSWORD", "ALERTS_INDEX", "SSL_VERIFY"):
            monkeypatch.delenv(f"WAZUH_INDEXER_{var}", raising=False)
        config = IndexerConfig.from_env()
        assert not config.enabled
        assert config.alerts_index == "wazuh-alerts-*"
        config.validate()  # no URL: nothing required

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://idx:9200")
        monkeypatch.setenv("WAZUH_INDEXER_USERNAME", "u")
        monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "p")
        monkeypatch.setenv("WAZUH_INDEXER_SSL_VERIFY", "false")
        monkeypatch.setenv("WAZUH_INDEXER_ALERTS_INDEX", "custom-alerts-*")
        config = IndexerConfig.from_env()
        assert config.enabled
        assert config.ssl_verify is False
        assert config.alerts_index == "custom-alerts-*"
        config.validate()

    def test_validate_requires_credentials_with_url(self):
        with pytest.raises(ValueError, match="username"):
            IndexerConfig(url="https://idx:9200").validate()
        with pytest.raises(ValueError, match="password"):
            IndexerConfig(url="https://idx:9200", username="u").validate()


class TestBuildFilters:
    def test_default_time_range(self):
        query = IndexerClient.build_filters()
        assert query == {
            "bool": {"filter": [{"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}}]}
        }

    def test_all_filters(self):
        query = IndexerClient.build_filters(
            start="now-1h",
            end=None,
            agent_id="001",
            agent_name="web01",
            rule_ids=["5710", 5712],
            min_level=10,
            max_level=15,
            rule_groups=["sshd"],
            mitre_ids=["T1110"],
            srcip="10.0.0.5",
            query="data.dstuser:root",
        )
        filters = query["bool"]["filter"]
        assert {"range": {"timestamp": {"gte": "now-1h"}}} in filters
        assert {"term": {"agent.id": "001"}} in filters
        assert {"term": {"agent.name": "web01"}} in filters
        assert {"terms": {"rule.id": ["5710", "5712"]}} in filters
        assert {"range": {"rule.level": {"gte": 10, "lte": 15}}} in filters
        assert {"terms": {"rule.groups": ["sshd"]}} in filters
        assert {"terms": {"rule.mitre.id": ["T1110"]}} in filters
        assert {"term": {"data.srcip": "10.0.0.5"}} in filters
        assert query["bool"]["must"][0]["query_string"]["query"] == "data.dstuser:root"

    def test_min_level_zero_is_kept(self):
        query = IndexerClient.build_filters(start=None, end=None, min_level=0)
        assert query["bool"]["filter"] == [{"range": {"rule.level": {"gte": 0}}}]


class TestIndexerClient:
    @pytest.mark.asyncio
    async def test_search_alerts(self, indexer_client):
        indexer_client._client.post.return_value = _response(SEARCH_RESPONSE)

        result = await indexer_client.search_alerts(
            limit=5, offset=10, select=["rule.id"], agent_id="001"
        )

        url = indexer_client._client.post.call_args.args[0]
        body = indexer_client._client.post.call_args.kwargs["json"]
        assert url == "/wazuh-alerts-*/_search"
        assert body["size"] == 5
        assert body["from"] == 10
        assert body["_source"] == ["rule.id"]
        assert body["sort"] == [{"timestamp": {"order": "desc"}}]
        assert body["track_total_hits"] is True
        assert result["data"]["total_affected_items"] == 42
        assert result["data"]["affected_items"][0]["_id"] == "abc"
        assert result["data"]["affected_items"][0]["rule"]["id"] == "5710"

    @pytest.mark.asyncio
    async def test_summarize_alerts(self, indexer_client):
        indexer_client._client.post.return_value = _response(
            {
                "hits": {"total": {"value": 100}},
                "aggregations": {
                    "by_field": {
                        "buckets": [
                            {
                                "key": "5710",
                                "doc_count": 60,
                                "description": {"buckets": [{"key": "sshd: Attempt to login"}]},
                                "level": {"value": 5.0},
                            }
                        ]
                    },
                    "by_level": {"buckets": [{"key": 5, "doc_count": 60}]},
                },
            }
        )

        result = await indexer_client.summarize_alerts(group_by="rule.id", top=3)

        body = indexer_client._client.post.call_args.kwargs["json"]
        assert body["size"] == 0
        assert body["aggs"]["by_field"]["terms"] == {"field": "rule.id", "size": 3}
        assert result["data"]["total_alerts"] == 100
        assert result["data"]["groups"] == [
            {
                "rule.id": "5710",
                "count": 60,
                "rule.description": "sshd: Attempt to login",
                "rule.level": 5,
            }
        ]
        assert result["data"]["by_level"] == {"5": 60}

    @pytest.mark.asyncio
    async def test_summarize_rejects_unknown_field(self, indexer_client):
        with pytest.raises(IndexerError, match="group_by"):
            await indexer_client.summarize_alerts(group_by="full_log")
        indexer_client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_http_error_reports_reason(self, indexer_client):
        request = httpx.Request("POST", "https://test-indexer:9200/wazuh-alerts-*/_search")
        response = httpx.Response(
            400,
            request=request,
            json={"error": {"root_cause": [{"reason": "Failed to parse query"}]}},
        )
        indexer_client._client.post.return_value = response

        with pytest.raises(IndexerError, match="400: Failed to parse query"):
            await indexer_client.search_alerts(query="((")


class TestAlertTools:
    def _tool_names(self, server):
        import asyncio

        return {t.name for t in asyncio.run(server.app.get_tools()).values()}

    def test_not_registered_without_indexer(self, config):
        server = WazuhMCPServer(config)
        names = self._tool_names(server)
        assert "SearchAlertsTool" not in names
        assert "GetAlertsSummaryTool" not in names
        assert "GetAgentsTool" in names

    def test_registered_with_indexer(self, wazuh_config, server_config, indexer_config):
        server = WazuhMCPServer(
            Config(wazuh=wazuh_config, server=server_config, indexer=indexer_config)
        )
        names = self._tool_names(server)
        assert {"SearchAlertsTool", "GetAlertsSummaryTool"} <= names

    def test_category_can_be_disabled(self, wazuh_config, server_config, indexer_config):
        server_config.disabled_categories = ["alerts"]
        server = WazuhMCPServer(
            Config(wazuh=wazuh_config, server=server_config, indexer=indexer_config)
        )
        assert "SearchAlertsTool" not in self._tool_names(server)

    @pytest.mark.asyncio
    async def test_search_alerts_tool_call(self, wazuh_config, server_config, indexer_config):
        server = WazuhMCPServer(
            Config(wazuh=wazuh_config, server=server_config, indexer=indexer_config)
        )
        indexer = server._get_indexer()
        indexer._client = Mock()
        indexer._client.post = AsyncMock(return_value=_response(SEARCH_RESPONSE))

        async with Client(server.app) as client:
            result = await client.call_tool(
                "SearchAlertsTool", {"args": {"min_level": 5, "start": "now-1h"}}
            )

        data = json.loads(result.content[0].text)
        assert data["data"]["total_affected_items"] == 42
        body = indexer._client.post.call_args.kwargs["json"]
        assert {"range": {"rule.level": {"gte": 5}}} in body["query"]["bool"]["filter"]

    @pytest.mark.asyncio
    async def test_search_alerts_tool_error(self, wazuh_config, server_config, indexer_config):
        server = WazuhMCPServer(
            Config(wazuh=wazuh_config, server=server_config, indexer=indexer_config)
        )
        indexer = server._get_indexer()
        indexer._client = Mock()
        indexer._client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        async with Client(server.app) as client:
            with pytest.raises(ToolError, match="Error searching alerts"):
                await client.call_tool("SearchAlertsTool", {"args": {}})

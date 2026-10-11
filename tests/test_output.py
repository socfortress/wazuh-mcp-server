"""Tests for MCP-5 (compact, bounded output) and MCP-8 (structured tool errors)."""

import asyncio
import json
from unittest.mock import AsyncMock, Mock

import pytest
from fastmcp.exceptions import ToolError

from wazuh_mcp_server.server import WazuhMCPServer


def agents(n):
    return {
        "data": {
            "affected_items": [
                {"id": f"{i:03d}", "name": f"agent-{i}", "pad": "x" * 200} for i in range(n)
            ],
            "total_affected_items": n * 10,
            "total_failed_items": 0,
            "failed_items": [],
        },
        "message": "ok",
        "error": 0,
    }


def server_with(config, **client_methods):
    server = WazuhMCPServer(config)
    client = Mock()
    for name, value in client_methods.items():
        setattr(client, name, value)
    server._client = client
    return server, asyncio.run(server.app.get_tools())


def test_output_is_compact_json(config):
    server = WazuhMCPServer(config)
    text = server._format(agents(2))
    assert "\n" not in text and ": " not in text
    assert json.loads(text)["data"]["affected_items"][0]["id"] == "000"


def test_large_output_drops_items_and_says_so(config):
    config.server.max_output_chars = 3000
    server = WazuhMCPServer(config)
    out = json.loads(server._format(agents(100)))
    assert len(json.dumps(out, separators=(",", ":"))) <= 3000
    marker = out["truncated"]
    assert marker["original_items"] == 100 and marker["total_affected_items"] == 1000
    assert marker["returned_items"] == len(out["data"]["affected_items"]) < 100
    assert marker["original_chars"] > 3000


def test_plain_text_truncation_states_sizes(config):
    server = WazuhMCPServer(config)
    out = server._safe_truncate("A" * 5000, max_length=1000)
    assert out.endswith("[truncated: showing 1000 of 5000 characters]")
    assert "\\n" not in out  # no literal backslash-n


def test_default_list_limit_is_50(config):
    from wazuh_mcp_server.server import GetAgentsArgs

    assert GetAgentsArgs().limit == 50


def test_backend_error_is_a_tool_error(config):
    _, tools = server_with(
        config, get_agents=AsyncMock(side_effect=RuntimeError("401 Unauthorized"))
    )
    with pytest.raises(ToolError, match="Error retrieving agents: 401 Unauthorized"):
        asyncio.run(tools["GetAgentsTool"].run({"args": {}}))


def test_success_uses_compact_format(config):
    _, tools = server_with(config, get_agents=AsyncMock(return_value=agents(1)))
    result = asyncio.run(tools["GetAgentsTool"].run({"args": {}}))
    assert "\n" not in result.content[0].text


def test_total_wazuh_failure_is_a_tool_error(config):
    failed = {
        "data": {
            "affected_items": [],
            "total_affected_items": 0,
            "failed_items": [
                {"error": {"code": 1701, "message": "Agent does not exist"}, "id": ["999"]}
            ],
            "total_failed_items": 1,
        },
        "message": "No syscollector information was returned",
        "error": 1,
    }
    _, tools = server_with(config, get_agent_processes=AsyncMock(return_value=failed))
    with pytest.raises(ToolError, match="Agent does not exist .code 1701; ids 999"):
        asyncio.run(tools["GetAgentProcessesTool"].run({"args": {"agent_id": "999"}}))


def test_partial_wazuh_failure_keeps_data(config):
    partial = agents(1) | {"error": 2}
    assert json.loads(WazuhMCPServer(config)._format(partial))["data"]["affected_items"]

"""Tests for the HTTP transport, bearer auth, /healthz and read-only tool gating (MCP-1/2/3)."""

import asyncio

import httpx
import pytest

from wazuh_mcp_server import server as server_module
from wazuh_mcp_server.config import Config, ServerConfig
from wazuh_mcp_server.server import TOOL_META, WazuhMCPServer


def make_server(config, **server_overrides):
    for key, value in server_overrides.items():
        setattr(config.server, key, value)
    return WazuhMCPServer(config)


def tool_names(server):
    tools = asyncio.run(server.app.get_tools())
    return set(tools)


def test_every_tool_is_classified(config):
    """New tools must declare a category and whether they write, or read-only mode can't gate them."""
    assert tool_names(make_server(config)) == set(TOOL_META)


def test_read_only_drops_write_tools(config, monkeypatch):
    monkeypatch.setitem(TOOL_META, "GetAgentsTool", ("agents", True))
    names = tool_names(make_server(config, read_only=True))
    assert "GetAgentsTool" not in names and "ListRulesTool" in names


def test_unclassified_tool_is_treated_as_write(config):
    server = make_server(config, read_only=True)
    assert server._enabled("SomeFutureTool") is False
    server.config.server.read_only = False
    assert server._enabled("SomeFutureTool") is True


def test_disabled_categories_are_honoured(config):
    names = tool_names(make_server(config, disabled_categories=["sca"]))
    assert "GetAgentSCATool" not in names and "GetSCAPolicyChecksTool" not in names
    assert "GetAgentsTool" in names


def test_disabled_tools_still_work(config):
    assert "ListRulesTool" not in tool_names(make_server(config, disabled_tools=["ListRulesTool"]))


def test_http_requires_token(config):
    with pytest.raises(ValueError, match="MCP_AUTH_TOKEN"):
        make_server(config, auth_token="").http_app()


@pytest.mark.asyncio
async def test_http_auth_and_health(config):
    app = make_server(config, auth_token="s3cret").http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as client:
        health = await client.get("/healthz")
        assert health.status_code == 200 and health.json() == {"status": "ok"}
        assert (await client.post("/mcp", json={})).status_code == 401
        bad = await client.post("/mcp", json={}, headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401


def test_env_config(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "HTTP")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "tok")
    monkeypatch.setenv("MCP_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("MCP_SERVER_PORT", "9000")
    monkeypatch.setenv("WAZUH_READ_ONLY", "true")
    cfg = ServerConfig.from_env()
    assert (cfg.transport, cfg.auth_token, cfg.host, cfg.port, cfg.read_only) == (
        "http",
        "tok",
        "0.0.0.0",
        9000,
        True,
    )


def test_cli_does_not_override_env_unless_given(monkeypatch):
    """MCP-1: --host/--port defaults used to overwrite MCP_SERVER_HOST/PORT."""
    from wazuh_mcp_server import __main__ as cli

    captured = {}

    class FakeServer:
        def start(self):
            captured["server"] = self

    def fake_create(config):
        captured["config"] = config
        return FakeServer()

    monkeypatch.setenv("WAZUH_PROD_URL", "https://w:55000")
    monkeypatch.setenv("WAZUH_PROD_USERNAME", "u")
    monkeypatch.setenv("WAZUH_PROD_PASSWORD", "p")
    monkeypatch.setenv("MCP_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("MCP_SERVER_PORT", "9001")
    monkeypatch.setattr(cli, "create_server", fake_create)
    monkeypatch.setattr("sys.argv", ["wazuh-mcp-server", "--transport", "http"])
    cli.main()
    server = captured["config"].server
    assert (server.transport, server.host, server.port) == ("http", "0.0.0.0", 9001)

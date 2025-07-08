# wazuh-mcp-server
Repo to hold wazuh manager mcp server
# wazuh-mcp-server

A Model-Context-Protocol tool-server that exposes Wazuh Manager operations to an
LLM via **stream transport** (SSE or OpenAI-compatible `/messages`).

```bash
pip install wazuh-mcp-server

# single cluster
wazuh-mcp-server --config ./clusters.yml --port 8080
```
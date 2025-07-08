# Wazuh MCP Server - Deep Dive Architecture and Usage

## Overview

The Wazuh MCP Server is a sophisticated integration that bridges Wazuh's security monitoring capabilities with modern AI language models through the Model Context Protocol (MCP). This comprehensive client implementation demonstrates how to leverage LangChain and OpenAI to create intelligent, natural language interfaces for Wazuh operations.

## Architecture Deep Dive

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Wazuh MCP Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   User Query    │───▶│ LangChain Agent │───▶│ OpenAI GPT  │ │
│  │ (Natural Lang.) │    │                 │    │   Model     │ │
│  └─────────────────┘    └─────────────────┘    └─────────────┘ │
│                                   │                             │
│                                   ▼                             │
│                        ┌─────────────────┐                     │
│                        │ Tool Selection  │                     │
│                        │ & Execution     │                     │
│                        └─────────────────┘                     │
│                                   │                             │
│                                   ▼                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │ Wazuh MCP      │◀───│ HTTP Client     │◀───│ JSON-RPC    │ │
│  │ Server         │    │ (httpx)         │    │ Messages    │ │
│  └─────────────────┘    └─────────────────┘    └─────────────┘ │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │ Wazuh REST API  │───▶│ JWT Auth        │───▶│ Cluster     │ │
│  │ Tools           │    │ Management      │    │ Management  │ │
│  └─────────────────┘    └─────────────────┘    └─────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Component Details

#### 1. Transport Layer (MCP Server)
- **Streaming Server**: Starlette-based HTTP server with SSE support
- **Endpoints**: `/sse` for streaming, `/messages` for OpenAI compatibility, `/health` for monitoring
- **Protocol**: Implements MCP specification for tool discovery and execution

#### 2. Authentication & Security
- **JWT Management**: Automatic token refresh 60s before expiry
- **Multi-cluster Support**: Manages separate authentication for each cluster
- **TLS Verification**: Configurable SSL verification for different environments

#### 3. Tool System
- **Dynamic Registry**: `@register` decorator for easy tool addition
- **Tool Filtering**: Configurable filtering by name, category, regex patterns
- **Metadata Support**: Tools can specify HTTP methods, categories, and other metadata

#### 4. Client Architecture
- **Server Manager**: Manages MCP server lifecycle
- **MCP Client**: Handles communication with server
- **LangChain Agent**: Provides intelligent query processing
- **Interactive Interface**: User-friendly chat interface

## Available Tools

### Core Tools

#### AuthenticateTool
- **Purpose**: Refresh JWT tokens for Wazuh clusters
- **Parameters**: `cluster` (string) - cluster name from configuration
- **Usage**: Automatically called before other operations or manually for token refresh

#### GetAgentsTool
- **Purpose**: Retrieve agent information with filtering
- **Parameters**:
  - `cluster` (string, required) - cluster name
  - `status` (array, optional) - filter by status ['active', 'pending', 'never_connected', 'disconnected']
  - `limit` (integer, optional) - max results (default: 500)
  - `offset` (integer, optional) - pagination offset (default: 0)
- **Usage**: Primary tool for agent management and monitoring

### Adding Custom Tools

```python
from pydantic import BaseModel
from tools import register

class MyToolArgs(BaseModel):
    cluster: str
    param: str

@register("MyTool")
async def my_tool(args: MyToolArgs, registry, **_):
    """Custom tool description"""
    client = get_client(args.cluster, registry)
    response = await client.request("GET", f"/api/endpoint/{args.param}")
    return [{"type": "text", "text": response.text}]

# Optional metadata
my_tool._meta = {
    "category": "custom",
    "http_method": "GET",
}
```

## Configuration

### Cluster Configuration (clusters.yml)

```yaml
clusters:
  prod:
    name: prod
    api_url: https://wazuh.company.tld:55000
    username: api-user
    password: S3cr3t!
    ssl_verify: true
  
  lab:
    name: lab
    api_url: https://wazuh-lab:55000
    username: wazuh
    password: lab123
    ssl_verify: false
```

### Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `WAZUH_FILTER_YAML` | Path to tool filter configuration | `/etc/wazuh/filter.yml` |
| `WAZUH_DISABLED_TOOLS` | Comma-separated list of disabled tools | `DeleteTool,RestartTool` |
| `WAZUH_DISABLED_CATEGORIES` | Disabled categories | `dangerous,write` |
| `WAZUH_DISABLED_TOOLS_REGEX` | Regex patterns for disabled tools | `^Delete.*,.*Restart.*` |
| `WAZUH_READ_ONLY` | Enable read-only mode | `true` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-...` |
| `LOG_LEVEL` | Logging level | `debug` |

### Filter Configuration (filter.yml)

```yaml
filter:
  disabled_tools:
    - DeleteAgentTool
    - RestartManagerTool
  disabled_categories:
    - dangerous
    - write
  disabled_regex:
    - '^Delete.*'
    - '.*Restart.*'
```

## Usage Patterns

### Natural Language Queries

The client supports sophisticated natural language queries:

```python
# Agent management
"Show me all active agents from the prod cluster"
"How many agents are disconnected in lab?"
"List the first 10 agents from staging"

# Authentication
"Authenticate with the prod cluster"
"Refresh token for lab environment"

# Complex queries
"Compare agent counts between prod and lab"
"Show me agents that haven't connected in staging"
"Get detailed information about offline agents"
```

### Programmatic Usage

```python
import asyncio
from client import WazuhMCPClient, WazuhLangChainAgent

async def query_wazuh():
    async with WazuhMCPClient("http://localhost:8080") as client:
        # Direct tool usage
        result = await client.call_tool("GetAgentsTool", {
            "cluster": "prod",
            "status": ["active"],
            "limit": 10
        })
        
        # LangChain agent usage
        agent = WazuhLangChainAgent(client, "openai-key")
        await agent.initialize_tools()
        response = await agent.query("How many agents are active?")
        
        return response

result = asyncio.run(query_wazuh())
```

## Advanced Features

### Tool Chaining

The LangChain agent can automatically chain tools:

```
Query: "Show me agent details for the prod cluster"
Agent reasoning:
1. First authenticate with prod cluster
2. Then retrieve agent list
3. Format and present results
```

### Error Handling

The system provides comprehensive error handling:

```python
try:
    result = await client.call_tool("GetAgentsTool", {"cluster": "invalid"})
    if not result["success"]:
        handle_error(result["error"])
except Exception as e:
    logger.error(f"Unexpected error: {e}")
```

### Memory and Context

The LangChain agent maintains conversation context:

```
User: "Get agents from prod"
Agent: "I found 150 agents in prod. 140 are active, 10 are disconnected."

User: "Show me the disconnected ones"
Agent: "Here are the 10 disconnected agents from prod..." (remembers context)
```

## Performance Considerations

### Connection Pooling
- HTTP/2 support with connection reuse
- Configurable timeouts and retry logic
- Efficient JWT token caching

### Scaling
- Stateless design for horizontal scaling
- Per-cluster authentication isolation
- Configurable concurrency limits

### Monitoring
- Health endpoints for monitoring
- Comprehensive logging
- Metrics collection points

## Security Best Practices

### Authentication
- JWT tokens with automatic refresh
- Secure credential storage
- Cluster-specific authentication

### Network Security
- TLS verification in production
- Configurable SSL settings
- Rate limiting considerations

### Access Control
- Tool-level access control
- Category-based filtering
- Regex-based tool filtering

## Troubleshooting

### Common Issues

1. **Server startup failures**
   - Check configuration file validity
   - Verify network connectivity
   - Check port availability

2. **Authentication failures**
   - Verify cluster credentials
   - Check API URL accessibility
   - Validate SSL certificate settings

3. **Tool execution errors**
   - Check tool parameters
   - Verify cluster connectivity
   - Review tool filter settings

### Debug Mode

Enable debug logging for detailed information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Health Checks

Monitor server health:

```bash
curl http://localhost:8080/health
```

## Future Enhancements

### Planned Features
- WebSocket support for real-time updates
- Custom tool development framework
- Advanced query caching
- Distributed deployment support

### Integration Possibilities
- Grafana dashboards
- Slack/Teams integration
- Custom webhook support
- API gateway integration

## Contributing

To extend the system:

1. Add new tools using the `@register` decorator
2. Implement proper error handling
3. Add comprehensive testing
4. Update documentation
5. Follow security best practices

This architecture provides a solid foundation for sophisticated Wazuh integrations while maintaining security, scalability, and ease of use.

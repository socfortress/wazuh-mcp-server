# Wazuh MCP Server - Comprehensive Client

A powerful, intelligent client for the Wazuh MCP (Model Context Protocol) server that combines LangChain agents with OpenAI's GPT models to provide natural language interactions with your Wazuh infrastructure.

## 🚀 Features

- **Natural Language Queries**: Ask questions about your Wazuh infrastructure in plain English
- **LangChain Agent Integration**: Intelligent agent that can reason about Wazuh operations
- **OpenAI GPT Integration**: Uses GPT models for understanding and generating responses
- **Automatic Server Management**: Starts and stops the MCP server automatically
- **Multi-cluster Support**: Works with multiple Wazuh clusters simultaneously
- **Interactive Chat Interface**: User-friendly conversational interface
- **Dynamic Tool Discovery**: Automatically discovers available tools from the MCP server
- **Comprehensive Error Handling**: Robust error handling with detailed logging

## 📋 Requirements

- Python 3.11+
- OpenAI API key
- Wazuh MCP server configuration

## 🔧 Installation

1. **Install the client dependencies**:
   ```bash
   pip install -r client_requirements.txt
   ```

2. **Set up your OpenAI API key**:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

3. **Configure your Wazuh clusters** (use `example_clusters.yml` as template):
   ```yaml
   clusters:
     prod:
       name: prod
       api_url: https://wazuh.company.tld:55000
       username: api-user
       password: S3cr3t!
       ssl_verify: true
   ```

## 🎯 Usage

### Basic Usage

```bash
python client.py --config clusters.yml --openai-key YOUR_API_KEY
```

### Advanced Usage

```bash
python client.py \
  --config clusters.yml \
  --openai-key YOUR_API_KEY \
  --model gpt-4 \
  --host 0.0.0.0 \
  --port 8080
```

### Environment Variables

You can also set the OpenAI API key via environment variable:

```bash
export OPENAI_API_KEY="your-api-key-here"
python client.py --config clusters.yml
```

## 💬 Natural Language Examples

Once the client is running, you can ask questions like:

### Authentication
- "Authenticate with the prod cluster"
- "Refresh authentication for lab environment"

### Agent Management
- "Show me all active agents from the prod cluster"
- "How many agents are in the staging environment?"
- "List all disconnected agents from prod"
- "Get the first 10 agents from dev cluster"
- "Show agents with status active and pending from lab"

### General Queries
- "What tools are available?"
- "Tell me about the lab cluster"
- "How many clusters are configured?"

## 🔧 Available Tools

The client automatically discovers tools from the MCP server. Common tools include:

- **AuthenticateTool**: Authenticate with Wazuh clusters
- **GetAgentsTool**: Retrieve agent information with filtering options

## 🏗️ Architecture

The client consists of several key components:

### 1. WazuhMCPServerManager
- Manages the MCP server process lifecycle
- Handles server startup and shutdown
- Monitors server health

### 2. WazuhMCPClient
- Communicates with the MCP server via HTTP
- Handles tool discovery and execution
- Manages server connection and health checks

### 3. WazuhLangChainAgent
- Integrates with LangChain for intelligent query processing
- Uses OpenAI GPT models for natural language understanding
- Maintains conversation memory and context

### 4. InteractiveChat
- Provides user-friendly chat interface
- Handles user input and displays responses
- Offers help and tool information

## 🛠️ Configuration

### Cluster Configuration

Create a `clusters.yml` file with your Wazuh cluster information:

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

### Command Line Options

```
--config          Path to clusters configuration file (default: example_clusters.yml)
--openai-key      OpenAI API key (or set OPENAI_API_KEY env var)
--model           OpenAI model to use (default: gpt-4)
--host            Host for MCP server (default: 0.0.0.0)
--port            Port for MCP server (default: 8080)
--no-interactive  Don't start interactive chat
```

## 📊 Example Session

```
🎉 Welcome to the Wazuh MCP Interactive Client!
======================================================================
This intelligent client uses OpenAI and LangChain to help you
interact with your Wazuh infrastructure using natural language.

Available clusters: prod, lab, staging, dev

Type 'help' for more information or 'quit' to exit.
======================================================================

🤖 Ask me anything about Wazuh: Show me all active agents from prod

🤔 Processing your question...

🎯 Answer: I found 45 active agents in the prod cluster. Here are the details:
- Agent 001: server-web-01 (Active, Last seen: 2024-01-15 10:30:00)
- Agent 002: server-db-01 (Active, Last seen: 2024-01-15 10:29:45)
- Agent 003: server-app-01 (Active, Last seen: 2024-01-15 10:30:15)
...

🤖 Ask me anything about Wazuh: How many agents are disconnected?

🤔 Processing your question...

🎯 Answer: There are 3 disconnected agents in the prod cluster:
- Agent 023: server-backup-01 (Disconnected since: 2024-01-14 15:20:00)
- Agent 031: server-test-02 (Disconnected since: 2024-01-14 09:45:00)
- Agent 044: server-dev-01 (Disconnected since: 2024-01-15 08:00:00)
```

## 🔍 Troubleshooting

### Common Issues

1. **"Required dependencies not installed"**
   - Solution: Install dependencies with `pip install -r client_requirements.txt`

2. **"OpenAI API key is required"**
   - Solution: Set your API key with `--openai-key` or `export OPENAI_API_KEY="your-key"`

3. **"Config file not found"**
   - Solution: Create a `clusters.yml` file or specify path with `--config`

4. **"MCP server failed to start"**
   - Solution: Check that all required dependencies are installed and config is valid

### Logging

The client uses structured logging. For more detailed logs, you can modify the logging level:

```python
logging.basicConfig(level=logging.DEBUG)
```

## 🚀 Advanced Usage

### Programmatic Usage

You can also use the client programmatically:

```python
import asyncio
from client import WazuhMCPClient, WazuhLangChainAgent

async def query_wazuh():
    async with WazuhMCPClient("http://localhost:8080") as client:
        agent = WazuhLangChainAgent(client, "your-openai-key")
        await agent.initialize_tools()
        
        response = await agent.query("Show me all active agents from prod")
        print(response)

asyncio.run(query_wazuh())
```

### Custom Tool Integration

The client automatically discovers and integrates new tools as they're added to the MCP server, making it easy to extend functionality.

## 🤝 Contributing

Feel free to contribute improvements, bug fixes, or new features to this client!

## 📄 License

This project follows the same license as the main Wazuh MCP Server project.

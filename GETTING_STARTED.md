# 🚀 How to Start and Use the Wazuh MCP Server

This guide shows you how to start the MCP server and run the client using your `.env` configuration.

## 📋 Prerequisites

1. **Install Dependencies**:
   ```bash
   pip install -r client_requirements.txt
   ```

2. **Your `.env` file is already configured** ✅
   - ✅ `OPENAI_API_KEY` is set
   - ✅ `WAZUH_PROD_URL`, `WAZUH_PROD_USERNAME`, `WAZUH_PROD_PASSWORD` are set

## 🎯 Step-by-Step Instructions

### Step 1: Start the MCP Server

```bash
python start_mcp.py
```

This will:
- ✅ Load your `.env` configuration
- ✅ Create a temporary `clusters.yml` from your environment variables
- ✅ Start the MCP server on `http://0.0.0.0:8080`
- ✅ Wait for the server to be ready

You'll see output like:
```
🎯 Wazuh MCP Server Startup
========================================
✅ Created temp_clusters.yml with 1 clusters:
  • prod: https://ashwzhma.socfortress.local:55000
🚀 Starting MCP server: python -m wazuh_mcp_server --config temp_clusters.yml --host 0.0.0.0 --port 8080
✅ MCP server is ready!

🎉 MCP server is running at http://0.0.0.0:8080
📋 Health check: http://0.0.0.0:8080/health
📊 Config file: temp_clusters.yml

🤖 Now you can run the client:
python run_client.py

⏸️  Press Ctrl+C to stop the server...
```

**Keep this terminal open** - the server needs to keep running.

### Step 2: Run the Client (in a new terminal)

Open a **new terminal** and run:

```bash
python run_client.py
```

This will:
- ✅ Connect to the running MCP server
- ✅ Initialize LangChain agent with OpenAI
- ✅ Discover available Wazuh tools
- ✅ Start interactive chat interface

You'll see:
```
🤖 Wazuh MCP Client
==============================
🔍 Checking MCP server at http://localhost:8080...
✅ MCP server is running!
✅ MCP server is ready
🤖 Initializing LangChain agent with Wazuh tools...
📋 Discovered 2 available tools

🎉 Welcome to the Wazuh MCP Interactive Client!
======================================================================
This intelligent client uses OpenAI and LangChain to help you
interact with your Wazuh infrastructure using natural language.

You can ask questions like:
• 'Show me all active agents from the prod cluster'
• 'Authenticate with the lab cluster'
• 'How many agents are in the staging environment?'

Available clusters: prod

Type 'help' for more information or 'quit' to exit.
======================================================================

🤖 Ask me anything about Wazuh:
```

### Step 3: Ask Questions!

Now you can ask natural language questions:

**Example 1: Authentication**
```
🤖 Ask me anything about Wazuh: authenticate with prod cluster

🤔 Processing your question...

🎯 Answer: I have successfully authenticated with the prod cluster. The authentication token has been refreshed and is ready for use.
```

**Example 2: Get Agents**
```
🤖 Ask me anything about Wazuh: show me all agents from prod

🤔 Processing your question...

🎯 Answer: Here are all the agents from the prod cluster:

Agent ID: 000
Name: ashwzhma.socfortress.local
IP: 127.0.0.1
Status: active
Last Keep Alive: 2024-01-15T10:30:00Z
Version: Wazuh v4.7.0
...
```

**Example 3: Complex Queries**
```
🤖 Ask me anything about Wazuh: How many active agents are there?

🤔 Processing your question...

🎯 Answer: There are currently 15 active agents in the prod cluster. All agents are reporting properly and are up to date.
```

## 🎮 Alternative Usage Options

### Run Example Queries
```bash
python run_client.py --examples
```

### Test Server Connection
```bash
python run_client.py --test-connection
```

### Run Quick Test
```bash
python test_client.py
```

## 🛠️ Architecture Overview

```
Your Question → LangChain Agent → OpenAI GPT-4 → Tool Selection → MCP Server → Wazuh API
```

1. **You ask**: "Show me active agents from prod"
2. **LangChain Agent**: Understands you want agent information
3. **OpenAI GPT-4**: Decides to use `GetAgentsTool` with prod cluster
4. **MCP Server**: Receives tool call, authenticates with Wazuh
5. **Wazuh API**: Returns agent data
6. **Response**: Formatted, human-readable answer

## 🔍 Available Tools

The system automatically discovers these tools:

- **🔑 AuthenticateTool**: Refresh JWT tokens for clusters
- **👥 GetAgentsTool**: Get agent information with filtering options

## 📊 What's Happening Behind the Scenes

1. **MCP Server** (`start_mcp.py`):
   - Loads your `.env` file
   - Creates temporary YAML config
   - Starts HTTP server with Wazuh tools
   - Handles authentication and API calls

2. **Client** (`run_client.py`):
   - Connects to MCP server via HTTP
   - Initializes LangChain agent with OpenAI
   - Discovers available tools dynamically
   - Provides natural language interface

3. **Tool Execution**:
   - Agent decides which tool to use
   - MCP server executes tool against Wazuh API
   - Results are formatted and returned

## 🚨 Troubleshooting

### Server won't start
```bash
# Check if port is in use
netstat -an | grep 8080

# Try different port
MCP_SERVER_PORT=8081 python start_mcp.py
```

### Client can't connect
```bash
# Test server health
curl http://localhost:8080/health

# Check server logs
python start_mcp.py  # Look for error messages
```

### Authentication errors
- Check your Wazuh credentials in `.env`
- Verify Wazuh server is accessible
- Check SSL settings (`WAZUH_PROD_SSL_VERIFY=false`)

## 🎉 Success!

You now have a fully functional AI-powered Wazuh interface that:
- ✅ Uses natural language to query Wazuh
- ✅ Automatically authenticates with your clusters
- ✅ Provides intelligent responses
- ✅ Maintains conversation context
- ✅ Handles errors gracefully

Ask any questions about your Wazuh infrastructure in plain English!

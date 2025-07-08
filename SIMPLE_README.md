# Wazuh MCP Server - Single Manager Configuration

This is a simplified version of the Wazuh MCP Server that connects to a single Wazuh manager using environment variables.

## ✨ Key Features

- **Single Manager**: Simplified to work with one Wazuh manager
- **Environment Configuration**: Uses `.env` file or environment variables
- **Built-in Tools**: `AuthenticateTool` and `GetAgentsTool`
- **HTTP Endpoints**: `/tools`, `/messages`, `/health`
- **No YAML Configuration**: Uses environment variables directly

## 🚀 Quick Start

### 1. Install Dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.in
pip install -e .
```

### 2. Configure Environment

Create a `.env` file or set these environment variables:

```bash
# Wazuh Manager Configuration
WAZUH_PROD_URL=https://your-wazuh-manager.domain:55000
WAZUH_PROD_USERNAME=your-username
WAZUH_PROD_PASSWORD=your-password
WAZUH_PROD_SSL_VERIFY=false

# MCP Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8080

# Logging
LOG_LEVEL=info
```

### 3. Start the Server

**Option 1: Using the startup script**
```bash
python start_server.py
```

**Option 2: Using the installed command**
```bash
source .venv/bin/activate
wazuh-mcp-server --host 0.0.0.0 --port 8080
```

**Option 3: Using Python module**
```bash
python -m wazuh_mcp_server --host 0.0.0.0 --port 8080
```

### 4. Test the Server

```bash
# Check health
curl http://localhost:8080/health

# List available tools
curl http://localhost:8080/tools

# Use the test client
python client.py
```

## 📋 Available Tools

| Tool | Description |
|------|-------------|
| `AuthenticateTool` | Authenticate with the Wazuh manager and refresh JWT token |
| `GetAgentsTool` | Get a list of agents from the Wazuh manager |

## 🔧 Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `WAZUH_PROD_URL` | Wazuh manager API URL | - | ✅ |
| `WAZUH_PROD_USERNAME` | Wazuh API username | - | ✅ |
| `WAZUH_PROD_PASSWORD` | Wazuh API password | - | ✅ |
| `WAZUH_PROD_SSL_VERIFY` | SSL certificate verification | `true` | ❌ |
| `MCP_SERVER_HOST` | Server host | `0.0.0.0` | ❌ |
| `MCP_SERVER_PORT` | Server port | `8080` | ❌ |
| `LOG_LEVEL` | Logging level | `info` | ❌ |

## 🛠️ Tool Filtering (Optional)

You can disable tools using environment variables:

```bash
# Disable specific tools
WAZUH_DISABLED_TOOLS=AuthenticateTool

# Disable tool categories
WAZUH_DISABLED_CATEGORIES=dangerous,write

# Enable read-only mode
WAZUH_READ_ONLY=true
```

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/tools` | GET | List available tools |
| `/messages` | POST | OpenAI-compatible chat completions |

## 🧪 Testing

The included `client.py` demonstrates how to:

1. Check server health
2. List available tools
3. Call tools with parameters

```bash
python client.py
```

## 🔒 Security Notes

- **Credentials**: Keep your `.env` file secure and never commit it to version control
- **SSL**: Set `WAZUH_PROD_SSL_VERIFY=true` in production
- **Network**: Consider using a reverse proxy for production deployments
- **Authentication**: The server uses JWT tokens that auto-refresh

## 📝 Changes from Original

- ✅ Removed multi-cluster support
- ✅ Simplified to single Wazuh manager
- ✅ Removed YAML configuration requirement
- ✅ Uses environment variables directly
- ✅ Removed cluster parameter from tools
- ✅ Simplified client connection logic

## 🚨 Troubleshooting

**Server won't start:**
- Check that all required environment variables are set
- Verify the virtual environment is activated
- Check that the Wazuh manager is accessible

**Tools return errors:**
- Verify Wazuh manager credentials
- Check network connectivity
- Review server logs for detailed error messages

**Client connection fails:**
- Ensure the server is running on the correct port
- Check firewall settings
- Verify the client is pointing to the correct URL

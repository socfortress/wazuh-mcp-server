# Wazuh MCP Server

A production-ready **Model Context Protocol (MCP) server** for seamless integration between Wazuh SIEM and Large Language Models (LLMs).

[![Build Status](https://github.com/socfortress/wazuh-mcp-server/actions/workflows/publish.yml/badge.svg)](https://github.com/socfortress/wazuh-mcp-server/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UC4EUQtTxeC8wGrKRafI6pZg)](https://www.youtube.com/@taylorwalton_socfortress/videos)
[![Get in Touch](https://img.shields.io/badge/📧%20Get%20in%20Touch-Friendly%20Support%20Awaits!-blue?style=for-the-badge)](https://www.socfortress.co/contact_form.html)

> **Why?**
> Combine the power of Wazuh's comprehensive security monitoring with the reasoning capabilities of large language models—enabling natural language queries and intelligent analysis of your security data.

---

## ✨ Key Features

- 🚀 **Production-ready**: Proper package structure, logging, error handling, and configuration management
- 🔐 **Secure**: JWT token management with automatic refresh
- 🌐 **HTTP/2 Support**: Built on modern async HTTP client with connection pooling
- 📊 **Comprehensive API**: Access Wazuh agents, authentication, and more
- 🎛️ **Configurable**: Environment variables, CLI arguments, and fine-grained tool filtering
- 📦 **Pip installable**: Install directly from GitHub releases or source

---

## Table of Contents
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Available Tools](#available-tools)
- [Development](#development)
- [CI/CD](#continuous-integration)
- [Deployment](#deployment)
- [Security](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

### 1. Install

#### From GitHub (Recommended)
```bash
python -m venv .venv && source .venv/bin/activate
pip install git+https://github.com/socfortress/wazuh-mcp-server.git
```

#### From Release Artifacts
1. Go to the [Releases page](https://github.com/socfortress/wazuh-mcp-server/releases)
2. Download the latest `.whl` file
3. Install with:
```bash
pip install wazuh_mcp_server-*.whl
```

#### From Build Artifacts (Latest Build)
1. Go to the [Actions tab](https://github.com/socfortress/wazuh-mcp-server/actions)
2. Click on the latest successful workflow run
3. Download the `python-package-distributions` artifact
4. Extract and install:
```bash
pip install wazuh_mcp_server-*.whl
```

### 2. Configure Environment

Create a `.env` file in your project directory:

```env
# Wazuh Manager Configuration
WAZUH_PROD_URL=https://your-wazuh-manager:55000
WAZUH_PROD_USERNAME=your-username
WAZUH_PROD_PASSWORD=your-password
WAZUH_PROD_SSL_VERIFY=false
WAZUH_PROD_TIMEOUT=30

# MCP Server Configuration
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8000

# Logging Configuration
LOG_LEVEL=INFO

# Tool Filtering (optional)
# WAZUH_DISABLED_TOOLS=DeleteAgentTool,RestartManagerTool
# WAZUH_DISABLED_CATEGORIES=dangerous,write
# WAZUH_READ_ONLY=false
```

### 3. Run the Server

```bash
# Using the CLI command
wazuh-mcp-server

# Or using the Python module
python -m wazuh_mcp_server

# With custom configuration
wazuh-mcp-server --host 0.0.0.0 --port 8000 --log-level DEBUG
```

The server will start and be available at `http://127.0.0.1:8000` (or your configured host/port).

---

## Installation

### Requirements

- Python 3.11 or higher
- Access to a Wazuh Manager instance
- Network connectivity to your Wazuh Manager

### Development Installation

```bash
git clone https://github.com/socfortress/wazuh-mcp-server.git
cd wazuh-mcp-server

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

---

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `WAZUH_PROD_URL` | Wazuh Manager API URL | None | ✅ |
| `WAZUH_PROD_USERNAME` | Wazuh username | None | ✅ |
| `WAZUH_PROD_PASSWORD` | Wazuh password | None | ✅ |
| `WAZUH_PROD_SSL_VERIFY` | SSL verification | `true` | ❌ |
| `WAZUH_PROD_TIMEOUT` | Request timeout (seconds) | `30` | ❌ |
| `MCP_SERVER_HOST` | Server host | `127.0.0.1` | ❌ |
| `MCP_SERVER_PORT` | Server port | `8000` | ❌ |
| `LOG_LEVEL` | Logging level | `INFO` | ❌ |
| `WAZUH_DISABLED_TOOLS` | Comma-separated list of disabled tools | None | ❌ |
| `WAZUH_DISABLED_CATEGORIES` | Comma-separated list of disabled categories | None | ❌ |
| `WAZUH_READ_ONLY` | Enable read-only mode | `false` | ❌ |

### CLI Options

```bash
wazuh-mcp-server --help
```

Available options:
- `--host`: Host to bind server to (default: 127.0.0.1)
- `--port`: Port to bind server to (default: 8000)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--wazuh-url`: Wazuh Manager URL (overrides env var)
- `--wazuh-username`: Wazuh username (overrides env var)
- `--wazuh-password`: Wazuh password (overrides env var)
- `--no-ssl-verify`: Disable SSL certificate verification

---

## Usage

### Basic Usage

```python
from wazuh_mcp_server import Config, create_server

# Create server with environment configuration
config = Config.from_env()
server = create_server(config)

# Start the server
server.start()
```

### Custom Configuration

```python
from wazuh_mcp_server.config import WazuhConfig, ServerConfig, Config

# Create custom configuration
wazuh_config = WazuhConfig(
    url="https://your-wazuh-manager:55000",
    username="admin",
    password="password",
    ssl_verify=False
)

server_config = ServerConfig(
    host="0.0.0.0",
    port=8080,
    log_level="DEBUG"
)

config = Config(wazuh=wazuh_config, server=server_config)
server = create_server(config)
```

### Integration with LangChain

```python
import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent

async def main():
    # Initialize LLM with hardcoded API key
    model = ChatOpenAI(
        model="gpt-4",
        api_key="sk-your-api-key"  # <-- replace with your actual key
    )

    # Connect to Wazuh MCP server
    client = MultiServerMCPClient({
        "wazuh-mcp-server": {
            "transport": "sse",
            "url": "http://127.0.0.1:8000/sse/",
        }
    })

    # Get tools and create agent
    tools = await client.get_tools()
    agent = initialize_agent(
        tools=tools,
        llm=model,
        agent=AgentType.OPENAI_FUNCTIONS,
        verbose=True
    )

    # Query your Wazuh data
    response = await agent.ainvoke({
        "input": "Show me all active agents and their status"
    })
    print("Active agents response:")
    print(response)

    # Get network ports information
    ports_response = await agent.ainvoke({
        "input": "Show me all listening TCP ports on agent 000"
    })
    print("Ports response:")
    print(ports_response)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Available Tools

The server exposes the following MCP tools:

### 1. AuthenticateTool
- **Purpose**: Force JWT token refresh from Wazuh Manager
- **Parameters**: None
- **Usage**: Ensures fresh authentication tokens

### 2. GetAgentsTool
- **Purpose**: Retrieve agents from Wazuh Manager with filtering
- **Parameters**:
  - `status` (optional): Filter by agent status (e.g., ["active"])
  - `limit` (optional): Maximum number of agents to return (default: 500)
  - `offset` (optional): Offset for pagination (default: 0)


### 3. GetAgentPortsTool
- **Purpose**: Get network ports information from a specific agent using syscollector
- **Parameters**:
  - `agent_id` (required): Agent ID to get ports from
  - `limit` (optional): Maximum number of ports to return (default: 500)
  - `offset` (optional): Offset for pagination (default: 0)
  - `protocol` (optional): Filter by protocol (tcp, udp)
  - `local_ip` (optional): Filter by local IP address
  - `local_port` (optional): Filter by local port
  - `remote_ip` (optional): Filter by remote IP address
  - `state` (optional): Filter by state (listening, established, etc.)
  - `process` (optional): Filter by process name
  - `pid` (optional): Filter by process ID
  - `tx_queue` (optional): Filter by tx_queue
  - `sort` (optional): Sort results by field(s)
  - `search` (optional): Search for elements containing the specified string
  - `select` (optional): Select which fields to return
  - `q` (optional): Query to filter results by
  - `distinct` (optional): Look for distinct values

### 4. GetAgentPackagesTool
- **Purpose**: Get installed packages information from a specific agent using syscollector
- **Parameters**:
  - `agent_id` (required): Agent ID to get packages from
  - `limit` (optional): Maximum number of packages to return (default: 500)
  - `offset` (optional): Offset for pagination (default: 0)
  - `vendor` (optional): Filter by package vendor
  - `name` (optional): Filter by package name
  - `architecture` (optional): Filter by package architecture
  - `format` (optional): Filter by package format (e.g., 'deb', 'rpm')
  - `version` (optional): Filter by package version
  - `sort` (optional): Sort results by field(s)
  - `search` (optional): Search for elements containing the specified string
  - `select` (optional): Select which fields to return
  - `q` (optional): Query to filter results by
  - `distinct` (optional): Look for distinct values

### 5. GetAgentProcessesTool
- **Purpose**: Get running processes information from a specific agent using syscollector
- **Parameters**:
  - `agent_id` (required): Agent ID to get processes from
  - `limit` (optional): Maximum number of processes to return (default: 500)
  - `offset` (optional): Offset for pagination (default: 0)
  - `pid` (optional): Filter by process PID
  - `state` (optional): Filter by process state
  - `ppid` (optional): Filter by process parent PID
  - `egroup` (optional): Filter by process egroup
  - `euser` (optional): Filter by process euser
  - `fgroup` (optional): Filter by process fgroup
  - `name` (optional): Filter by process name
  - `nlwp` (optional): Filter by process nlwp
  - `pgrp` (optional): Filter by process pgrp
  - `priority` (optional): Filter by process priority
  - `rgroup` (optional): Filter by process rgroup
  - `ruser` (optional): Filter by process ruser
  - `sgroup` (optional): Filter by process sgroup
  - `suser` (optional): Filter by process suser
  - `sort` (optional): Sort results by field(s)
  - `search` (optional): Search for elements containing the specified string
  - `select` (optional): Select which fields to return
  - `q` (optional): Query to filter results by
  - `distinct` (optional): Look for distinct values

### 6. ListRulesTool
- **Purpose**: List rules from Wazuh Manager with various filtering options
- **Parameters**:
  - `rule_ids` (optional): List of rule IDs to filter by
  - `limit` (optional): Maximum number of rules to return (default: 500)
  - `offset` (optional): Offset for pagination (default: 0)
  - `select` (optional): Select which fields to return
  - `sort` (optional): Sort results by field(s)
  - `search` (optional): Search for elements containing the specified string
  - `q` (optional): Query to filter results by
  - `status` (optional): Filter by status (enabled, disabled, all)
  - `group` (optional): Filter by rule group
  - `level` (optional): Filter by rule level (e.g., '4' or '2-4')
  - `filename` (optional): Filter by filename
  - `relative_dirname` (optional): Filter by relative directory name
  - `pci_dss` (optional): Filter by PCI_DSS requirement
  - `gdpr` (optional): Filter by GDPR requirement
  - `gpg13` (optional): Filter by GPG13 requirement
  - `hipaa` (optional): Filter by HIPAA requirement
  - `nist_800_53` (optional): Filter by NIST-800-53 requirement
  - `tsc` (optional): Filter by TSC requirement
  - `mitre` (optional): Filter by MITRE technique ID
  - `distinct` (optional): Look for distinct values

### 7. GetRuleFileContentTool
- **Purpose**: Get the content of a specific rule file from the ruleset
- **Parameters**:
  - `filename` (required): Filename of the rule file to get content from
  - `raw` (optional): Format response in plain text (default: false)
  - `relative_dirname` (optional): Filter by relative directory name

### 8. GetRuleFilesTool
- **Purpose**: Get a list of all rule files and their status from Wazuh Manager
- **Parameters**:
  - `pretty` (optional): Show results in human-readable format
  - `wait_for_complete` (optional): Disable timeout response
  - `offset` (optional): First element to return in the collection (default: 0)
  - `limit` (optional): Maximum number of elements to return (default: 500)
  - `sort` (optional): Sort the collection by a field or fields
  - `search` (optional): Look for elements containing the specified string
  - `relative_dirname` (optional): Filter by relative directory name
  - `filename` (optional): Filter by filename of one or more rule or decoder files
  - `status` (optional): Filter by list status (enabled, disabled, all)
  - `q` (optional): Query to filter results by
  - `select` (optional): Select which fields to return
  - `distinct` (optional): Look for distinct values

**Example usage:**
```python
{"args": {"limit": 10, "status": "enabled"}}
{"args": {"filename": ["0020-syslog_rules.xml"]}}
{"args": {"search": "ruleset"}}
```

**Returns:**
- JSON list of rule files with their status and directory info

### 9. GetAgentSCATool
- **Purpose**: Get Security Configuration Assessment (SCA) results for a specific agent
- **Parameters**:
  - `agent_id` (required): Agent ID to get SCA results from
  - `name` (optional): Filter by policy name
  - `description` (optional): Filter by policy description
  - `references` (optional): Filter by references
  - `limit` (optional): Maximum number of SCA policies to return (default: 500)
  - `offset` (optional): Offset for pagination (default: 0)
  - `sort` (optional): Sort results by field(s)
  - `search` (optional): Search for elements containing the specified string
  - `select` (optional): Select which fields to return
  - `q` (optional): Query to filter results by
  - `distinct` (optional): Look for distinct values

---

## Development

### Setting up Development Environment

```bash
git clone https://github.com/socfortress/wazuh-mcp-server.git
cd wazuh-mcp-server

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=wazuh_mcp_server

# Run specific test file
pytest tests/test_client.py

# Run with verbose output
pytest -v
```

### Building the Package

```bash
# Install build dependencies
pip install build twine

# Build the package
python -m build

# Check the package
twine check dist/*

# Test installation
pip install dist/*.whl
```

---

## Continuous Integration

This project uses GitHub Actions for automated building and testing:

- **Automatic builds**: Every push to `main` and `develop` branches triggers a build
- **Quality assurance**: Comprehensive testing including linting, type checking, and unit tests
- **Artifact publishing**: Built packages are available as GitHub releases and workflow artifacts

### Creating a Release

1. Create and push a git tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. The GitHub Action will automatically:
   - Build the package
   - Run all tests
   - Create a GitHub release with downloadable artifacts

### Installing from CI Artifacts

Visit the [Actions page](https://github.com/socfortress/wazuh-mcp-server/actions) and download the `python-package-distributions` artifact from any successful build.

---

## Security Considerations

### Credentials Management
- **Never commit credentials**: Use environment variables or secrets management
- **Use strong passwords**: Ensure Wazuh credentials are secure
- **Rotate tokens**: Regularly update API credentials

### Network Security
- **TLS/SSL**: Always use HTTPS in production (`WAZUH_PROD_SSL_VERIFY=true`)
- **Firewall rules**: Restrict access to necessary ports only
- **VPN/Private networks**: Deploy in secured network environments

### Access Control
- **Least privilege**: Create dedicated Wazuh users with minimal required permissions
- **Read-only mode**: Use `WAZUH_READ_ONLY=true` when write operations aren't needed
- **Tool filtering**: Disable unnecessary tools using `WAZUH_DISABLED_TOOLS`

### Monitoring
- **Logging**: Enable appropriate log levels for monitoring
- **Health checks**: Implement monitoring of the MCP server endpoint
- **Rate limiting**: Consider implementing rate limiting for production deployments

---

## Project Structure

```
wazuh-mcp-server/
├── wazuh_mcp_server/          # Main package
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # CLI entry point
│   ├── client.py             # Wazuh API client
│   ├── config.py             # Configuration management
│   ├── server.py             # MCP server implementation
│   └── exceptions.py         # Custom exceptions
├── tests/                    # Test suite
│   ├── conftest.py          # Test configuration
│   ├── test_client.py       # Client tests
│   ├── test_config.py       # Configuration tests
│   └── test_server.py       # Server tests
├── .github/workflows/        # GitHub Actions
│   └── publish.yml          # CI/CD pipeline
├── requirements.txt          # Dependencies
├── pyproject.toml           # Package configuration
├── .env.example             # Environment template
└── README.md                # This file
```

---

## Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes and add tests
4. **Ensure** tests pass: `pytest`
5. **Check** code quality: `black .`, `isort .`, `flake8 .`
6. **Commit** your changes (`git commit -m 'Add amazing feature'`)
7. **Push** to your branch (`git push origin feature/amazing-feature`)
8. **Open** a Pull Request

### Development Guidelines

- Write tests for new functionality
- Follow existing code style and patterns
- Update documentation for new features
- Ensure all CI checks pass

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Changelog

### v0.1.0 (Latest)
- Initial release
- Basic MCP server functionality
- Wazuh API integration with JWT authentication
- CLI interface with configuration options
- Docker and Kubernetes deployment support
- Comprehensive test suite
- GitHub Actions CI/CD pipeline

---

## Support

- 📖 [Documentation](https://github.com/socfortress/wazuh-mcp-server#readme)
- 🐛 [Issues](https://github.com/socfortress/wazuh-mcp-server/issues)
- 🏢 [SOCFortress](https://socfortress.co)

---

**Made with ❤️ by SOCFortress**

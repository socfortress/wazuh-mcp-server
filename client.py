#!/usr/bin/env python3
"""
Comprehensive Wazuh MCP Server Client with LangChain and OpenAI Integration

This client provides a full-featured interface to interact with the Wazuh MCP server,
combining the power of LangChain agents with OpenAI's language models for natural
language queries about your Wazuh infrastructure.

Features:
- Automatic MCP server management (start/stop)
- LangChain agent integration for natural language queries
- OpenAI GPT integration for intelligent responses
- Dynamic tool discovery from MCP server
- Multi-cluster support
- Interactive chat interface
- Comprehensive error handling and logging

Architecture:
1. WazuhMCPServerManager: Manages the MCP server process
2. WazuhMCPClient: Handles communication with the MCP server
3. WazuhLangChainAgent: Provides LangChain agent with Wazuh tools
4. InteractiveChat: User-friendly chat interface

Usage:
    python client.py --config clusters.yml --openai-key YOUR_API_KEY

Requirements:
    pip install openai langchain httpx pydantic
"""

import asyncio
import json
import logging
import signal
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import httpx
from dataclasses import dataclass
import os

# Import environment configuration
from env_config import get_mcp_config, create_clusters_yaml, validate_config, MCPConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Third-party imports with graceful handling
try:
    from langchain.tools import BaseTool
    from langchain.agents import initialize_agent, AgentType
    from langchain.chat_models import ChatOpenAI
    from langchain.memory import ConversationBufferWindowMemory
except ImportError as e:
    logger.error(f"Required dependencies not installed: {e}")
    logger.error("Install with: pip install openai langchain httpx pydantic")
    sys.exit(1)


@dataclass
class WazuhTool:
    """Represents a Wazuh MCP tool"""
    name: str
    description: str
    schema: Dict[str, Any]
    category: Optional[str] = None
    http_method: Optional[str] = None


class WazuhMCPServerManager:
    """Manages the Wazuh MCP server process"""
    
    def __init__(self, config_path: str, host: str = "0.0.0.0", port: int = 8080):
        self.config_path = config_path
        self.host = host
        self.port = port
        self.process: Optional[subprocess.Popen] = None
        
    async def start(self) -> bool:
        """Start the MCP server"""
        try:
            if not Path(self.config_path).exists():
                logger.error(f"Config file not found: {self.config_path}")
                return False
                
            cmd = [
                sys.executable, "-m", "wazuh_mcp_server",
                "--config", self.config_path,
                "--host", self.host,
                "--port", str(self.port)
            ]
            
            logger.info(f"🚀 Starting MCP server: {' '.join(cmd)}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give server time to start
            await asyncio.sleep(3)
            
            if self.process.poll() is None:
                logger.info("✅ MCP server started successfully")
                return True
            else:
                stdout, stderr = self.process.communicate()
                logger.error("❌ MCP server failed to start.")
                logger.error(f"Stdout: {stdout}")
                logger.error(f"Stderr: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start MCP server: {e}")
            return False
            
    def stop(self):
        """Stop the MCP server"""
        if self.process:
            logger.info("🛑 Stopping MCP server...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("⚠️ MCP server did not stop gracefully, killing...")
                self.process.kill()
                self.process.wait()
            self.process = None
            logger.info("✅ MCP server stopped")


class WazuhMCPClient:
    """Client for interacting with the Wazuh MCP Server"""
    
    def __init__(self, server_url: str = "http://localhost:8080"):
        self.server_url = server_url
        self.client = httpx.AsyncClient(timeout=30.0)
        self.available_tools: List[WazuhTool] = []
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
        
    async def wait_for_server(self, max_attempts: int = 30, delay: float = 1.0) -> bool:
        """Wait for the MCP server to be available"""
        for attempt in range(max_attempts):
            try:
                response = await self.client.get(f"{self.server_url}/health")
                if response.status_code == 200:
                    logger.info("✅ MCP server is ready")
                    return True
            except Exception as e:
                logger.debug(f"Attempt {attempt + 1}: Server not ready - {e}")
                await asyncio.sleep(delay)
        logger.error("❌ MCP server failed to start or is not responding")
        return False
        
    async def list_tools(self) -> List[WazuhTool]:
        """Get available tools from the MCP server"""
        try:
            # Request tools list from the server
            response = await self.client.post(
                f"{self.server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "system", "content": "list_tools"}],
                    "stream": False
                }
            )
            response.raise_for_status()
            
            # Parse response to extract tools
            data = response.json()
            tools = []
            
            # Handle different response formats
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0].get("message", {}).get("content", "")
                try:
                    tool_data = json.loads(content)
                    if isinstance(tool_data, list):
                        for tool_info in tool_data:
                            tools.append(WazuhTool(
                                name=tool_info.get("name", ""),
                                description=tool_info.get("description", ""),
                                schema=tool_info.get("schema", {}),
                                category=tool_info.get("category"),
                                http_method=tool_info.get("http_method")
                            ))
                except json.JSONDecodeError:
                    logger.warning("Could not parse tool list response")
            
            # Fallback to known tools if server doesn't return tool list
            if not tools:
                tools = [
                    WazuhTool(
                        name="AuthenticateTool",
                        description="Authenticate with a Wazuh cluster to refresh JWT tokens",
                        schema={
                            "type": "object",
                            "properties": {
                                "cluster": {
                                    "type": "string",
                                    "description": "Cluster name from clusters.yml"
                                }
                            },
                            "required": ["cluster"]
                        },
                        category="auth",
                        http_method="POST"
                    ),
                    WazuhTool(
                        name="GetAgentsTool",
                        description="Get list of Wazuh agents from a cluster with optional filtering",
                        schema={
                            "type": "object",
                            "properties": {
                                "cluster": {
                                    "type": "string",
                                    "description": "Cluster name from clusters.yml"
                                },
                                "status": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Filter by agent status (e.g., ['active', 'pending'])"
                                },
                                "limit": {
                                    "type": "integer",
                                    "description": "Maximum number of agents to return",
                                    "default": 500
                                },
                                "offset": {
                                    "type": "integer",
                                    "description": "Number of agents to skip",
                                    "default": 0
                                }
                            },
                            "required": ["cluster"]
                        },
                        category="agents",
                        http_method="GET"
                    )
                ]
            
            self.available_tools = tools
            logger.info(f"📋 Discovered {len(tools)} available tools")
            return tools
            
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            return []
            
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a specific tool with arguments"""
        try:
            response = await self.client.post(
                f"{self.server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "system",
                            "content": f"Call tool {tool_name} with arguments: {json.dumps(arguments)}"
                        }
                    ],
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract the actual tool result from the response
                if "choices" in data and len(data["choices"]) > 0:
                    content = data["choices"][0].get("message", {}).get("content", "")
                    try:
                        # Try to parse as JSON if it's a structured response
                        result = json.loads(content)
                        return {"success": True, "data": result}
                    except json.JSONDecodeError:
                        # If not JSON, return as text
                        return {"success": True, "data": content}
                
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            logger.error(f"Failed to call tool {tool_name}: {e}")
            return {"success": False, "error": str(e)}


class WazuhLangChainTool(BaseTool):
    """LangChain tool wrapper for Wazuh MCP tools"""
    
    def __init__(self, wazuh_tool: WazuhTool, mcp_client: WazuhMCPClient):
        self.wazuh_tool = wazuh_tool
        self.mcp_client = mcp_client
        self.name = wazuh_tool.name.lower().replace("tool", "")
        self.description = wazuh_tool.description
        
    def _run(self, **kwargs) -> str:
        """Run the tool synchronously"""
        return asyncio.run(self._arun(**kwargs))
        
    async def _arun(self, **kwargs) -> str:
        """Run the tool asynchronously"""
        try:
            # Handle different input formats
            if len(kwargs) == 1 and "input" in kwargs:
                # Single input parameter - try to parse as JSON
                input_str = kwargs["input"]
                try:
                    args = json.loads(input_str)
                except json.JSONDecodeError:
                    # If not JSON, assume it's a cluster name for most tools
                    args = {"cluster": input_str}
            else:
                # Multiple parameters
                args = kwargs
                
            result = await self.mcp_client.call_tool(self.wazuh_tool.name, args)
            
            if result.get("success"):
                data = result.get("data", {})
                if isinstance(data, dict):
                    return json.dumps(data, indent=2)
                else:
                    return str(data)
            else:
                return f"❌ Error: {result.get('error', 'Unknown error')}"
                
        except Exception as e:
            logger.error(f"Error in {self.name}: {e}")
            return f"❌ Error: {str(e)}"


class WazuhLangChainAgent:
    """LangChain agent that can interact with Wazuh via MCP"""
    
    def __init__(self, mcp_client: WazuhMCPClient, openai_api_key: str, model: str = "gpt-4"):
        self.mcp_client = mcp_client
        self.openai_api_key = openai_api_key
        self.model = model
        self.llm = ChatOpenAI(
            openai_api_key=openai_api_key,
            model_name=model,
            temperature=0.7
        )
        self.memory = ConversationBufferWindowMemory(
            memory_key="chat_history",
            return_messages=True,
            k=5
        )
        self.tools = []
        self.agent = None
        
    async def initialize_tools(self):
        """Initialize tools from the MCP server"""
        wazuh_tools = await self.mcp_client.list_tools()
        
        # Create LangChain tools from Wazuh tools
        self.tools = []
        for wazuh_tool in wazuh_tools:
            langchain_tool = WazuhLangChainTool(wazuh_tool, self.mcp_client)
            self.tools.append(langchain_tool)
            
        logger.info(f"🔧 Initialized {len(self.tools)} tools for LangChain agent")
        
        # Initialize the agent
        self.agent = initialize_agent(
            self.tools,
            self.llm,
            agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=3,
            early_stopping_method="generate"
        )
        
    async def query(self, question: str) -> str:
        """Query the agent with a question"""
        if not self.agent:
            await self.initialize_tools()
            
        try:
            response = await asyncio.to_thread(self.agent.run, question)
            return response
        except Exception as e:
            logger.error(f"Error in agent query: {e}")
            return f"❌ Error processing your question: {str(e)}"
    
    def get_available_clusters(self) -> List[str]:
        """Get available cluster names from the config"""
        # This would ideally come from the server, but for now we'll use common names
        return ["prod", "lab", "staging", "dev"]


class InteractiveChat:
    """Interactive chat interface for the Wazuh MCP client"""
    
    def __init__(self, agent: WazuhLangChainAgent):
        self.agent = agent
        self.running = True
        
    def print_welcome(self):
        """Print welcome message"""
        print("\n" + "="*70)
        print("🎉 Welcome to the Wazuh MCP Interactive Client!")
        print("="*70)
        print("This intelligent client uses OpenAI and LangChain to help you")
        print("interact with your Wazuh infrastructure using natural language.")
        print()
        print("You can ask questions like:")
        print("• 'Show me all active agents from the prod cluster'")
        print("• 'Authenticate with the lab cluster'")
        print("• 'How many agents are in the staging environment?'")
        print("• 'List all disconnected agents from prod'")
        print()
        print("Available clusters:", ", ".join(self.agent.get_available_clusters()))
        print()
        print("Type 'help' for more information or 'quit' to exit.")
        print("="*70)
        
    def print_help(self):
        """Print help message"""
        print("\n📚 Help - Available Commands and Examples:")
        print("-" * 50)
        print("Basic Commands:")
        print("• help - Show this help message")
        print("• quit - Exit the client")
        print("• tools - List available Wazuh tools")
        print()
        print("Natural Language Examples:")
        print("• 'Authenticate with prod cluster'")
        print("• 'Show me all agents from lab'")
        print("• 'List active agents in staging'")
        print("• 'How many agents are disconnected in prod?'")
        print("• 'Get the first 10 agents from dev cluster'")
        print()
        print("Tool-Specific Queries:")
        print("• 'Refresh authentication for prod'")
        print("• 'Show agents with status active and pending from lab'")
        print("• 'Get agents from prod with limit 50'")
        print()
        
    async def list_tools(self):
        """List available tools"""
        tools = await self.agent.mcp_client.list_tools()
        if not tools:
            print("❌ No tools available")
            return
            
        print("\n📋 Available Wazuh Tools:")
        print("-" * 40)
        for tool in tools:
            print(f"🔧 {tool.name}")
            print(f"   📝 {tool.description}")
            if tool.category:
                print(f"   🏷️  Category: {tool.category}")
            if tool.http_method:
                print(f"   🌐 HTTP Method: {tool.http_method}")
            print()
            
    async def run(self):
        """Run the interactive chat"""
        self.print_welcome()
        
        while self.running:
            try:
                user_input = input("\n🤖 Ask me anything about Wazuh: ").strip()
                
                if not user_input:
                    continue
                    
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    self.running = False
                    break
                    
                elif user_input.lower() == 'help':
                    self.print_help()
                    continue
                    
                elif user_input.lower() == 'tools':
                    await self.list_tools()
                    continue
                    
                # Process the query through the agent
                print("🤔 Processing your question...")
                response = await self.agent.query(user_input)
                print(f"\n🎯 Answer: {response}")
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Error in chat loop: {e}")
                print(f"❌ An error occurred: {e}")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Wazuh MCP Client with LangChain and OpenAI")
    parser.add_argument("--config", 
                       help="Path to clusters configuration file (optional if using .env)")
    parser.add_argument("--env-file", 
                       help="Path to .env file (default: .env)")
    parser.add_argument("--openai-key", 
                       help="OpenAI API key (or set OPENAI_API_KEY env var)")
    parser.add_argument("--model", default="gpt-4", 
                       help="OpenAI model to use (default: gpt-4)")
    parser.add_argument("--host", 
                       help="Host for MCP server (default from env or 0.0.0.0)")
    parser.add_argument("--port", type=int,
                       help="Port for MCP server (default from env or 8080)")
    parser.add_argument("--no-interactive", action="store_true", 
                       help="Don't start interactive chat")
    parser.add_argument("--validate-only", action="store_true",
                       help="Only validate configuration and exit")
    
    args = parser.parse_args()
    
    # Load configuration from environment
    try:
        env_config = get_mcp_config(args.env_file)
        
        # Override with command line arguments if provided
        if args.openai_key:
            env_config.openai_api_key = args.openai_key
        if args.host:
            env_config.server_host = args.host
        if args.port:
            env_config.server_port = args.port
            
        # Validate configuration
        issues = validate_config(env_config)
        if issues:
            logger.warning("Configuration issues found:")
            for issue in issues:
                logger.warning(f"  - {issue}")
        
        if args.validate_only:
            if issues:
                print("❌ Configuration validation failed")
                for issue in issues:
                    print(f"  - {issue}")
                return 1
            else:
                print("✅ Configuration validation passed")
                print(f"Clusters: {[c.name for c in env_config.clusters]}")
                return 0
        
        # Create clusters.yml from environment if needed
        config_file = args.config
        if not config_file:
            config_file = create_clusters_yaml(env_config, "generated_clusters.yml")
            
    except Exception as e:
        if args.config and Path(args.config).exists():
            # Fallback to file-based configuration
            logger.info("Using file-based configuration")
            config_file = args.config
            openai_key = args.openai_key or os.getenv("OPENAI_API_KEY")
            if not openai_key:
                logger.error("OpenAI API key is required. Use --openai-key or set OPENAI_API_KEY env var")
                return 1
            
            # Use defaults for server settings
            server_host = args.host or "0.0.0.0"
            server_port = args.port or 8080
        else:
            logger.error(f"Configuration error: {e}")
            logger.error("Either provide --config with a valid file or set up .env file")
            return 1
    
    # Check if config file exists
    if config_file and not Path(config_file).exists():
        logger.error(f"Config file not found: {config_file}")
        return 1
    
    server_manager = None
    
    try:
        # Start the MCP server
        server_manager = WazuhMCPServerManager(
            config_path=config_file,
            host=env_config.server_host if 'env_config' in locals() else server_host,
            port=env_config.server_port if 'env_config' in locals() else server_port
        )
        
        if not await server_manager.start():
            logger.error("Failed to start MCP server")
            return 1
            
        # Create and initialize the client
        server_url = f"http://{env_config.server_host if 'env_config' in locals() else server_host}:{env_config.server_port if 'env_config' in locals() else server_port}"
        async with WazuhMCPClient(server_url) as client:
            # Wait for server to be ready
            if not await client.wait_for_server():
                logger.error("MCP server is not responding")
                return 1
                
            # Initialize the LangChain agent
            openai_api_key = env_config.openai_api_key if 'env_config' in locals() else openai_key
            agent = WazuhLangChainAgent(
                mcp_client=client,
                openai_api_key=openai_api_key,
                model=args.model
            )
            
            await agent.initialize_tools()
            
            if not args.no_interactive:
                # Start interactive chat
                chat = InteractiveChat(agent)
                await chat.run()
            else:
                # Just show available tools and exit
                tools = await client.list_tools()
                print(f"✅ MCP server is running with {len(tools)} tools available")
                for tool in tools:
                    print(f"  • {tool.name}: {tool.description}")
                    
    except Exception as e:
        logger.error(f"Error in main: {e}")
        return 1
    finally:
        # Clean up
        if server_manager:
            server_manager.stop()
            
    return 0


if __name__ == "__main__":
    # Handle graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received interrupt signal, shutting down...")
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the main function
    sys.exit(asyncio.run(main()))

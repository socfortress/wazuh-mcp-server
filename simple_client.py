#!/usr/bin/env python3
"""
Simple client for Wazuh MCP Server

This client:
1. Runs the Wazuh MCP server in the background
2. Provides a simple interface to interact with the server directly
3. Can be extended to work with any LLM that supports tool calling

Usage:
    python simple_client.py --config clusters.yml

Example clusters.yml:
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
"""

import asyncio
import logging
import signal
import subprocess
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WazuhMCPClient:
    """Client for interacting with the Wazuh MCP Server"""
    
    def __init__(self, server_url: str = "http://localhost:8080"):
        self.server_url = server_url
        self.client = httpx.AsyncClient(timeout=30.0)
        self.available_tools: List[Dict[str, Any]] = []
        
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
        
    async def list_tools(self) -> List[Dict[str, Any]]:
        """Get available tools from the MCP server"""
        try:
            # Make a request to get tools via the streaming endpoint
            response = await self.client.post(
                f"{self.server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "system",
                            "content": "Please list all available tools."
                        }
                    ],
                    "stream": False,
                    "tools": "list"  # Special request to list tools
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                # Extract tools from the response
                if "tools" in data:
                    self.available_tools = data["tools"]
                    return self.available_tools
                    
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            
        # Fallback: return known tools
        self.available_tools = [
            {
                "name": "AuthenticateTool",
                "description": "Authenticate with a Wazuh cluster to refresh JWT tokens",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cluster": {
                            "type": "string",
                            "description": "Cluster name from clusters.yml"
                        }
                    },
                    "required": ["cluster"]
                }
            },
            {
                "name": "GetAgentsTool", 
                "description": "Get list of Wazuh agents from a cluster with optional filtering",
                "parameters": {
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
                }
            }
        ]
        return self.available_tools
            
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a specific tool with arguments"""
        try:
            # Use the OpenAI-compatible endpoint for tool calling
            response = await self.client.post(
                f"{self.server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "user",
                            "content": f"Use the {tool_name} tool with these arguments: {json.dumps(arguments)}"
                        }
                    ],
                    "tools": [
                        {
                            "type": "function",
                            "function": {
                                "name": tool_name,
                                "arguments": json.dumps(arguments)
                            }
                        }
                    ],
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"✅ Tool {tool_name} called successfully")
                return data
            else:
                logger.error(f"❌ Tool call failed with status {response.status_code}: {response.text}")
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            logger.error(f"❌ Failed to call tool {tool_name}: {e}")
            return {"error": str(e)}


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
            # Check if config file exists
            if not Path(self.config_path).exists():
                logger.error(f"❌ Config file not found: {self.config_path}")
                return False
                
            # Start the server
            cmd = [
                sys.executable, "-m", "wazuh_mcp_server",
                "--config", self.config_path,
                "--host", self.host,
                "--port", str(self.port)
            ]
            
            logger.info(f"🚀 Starting MCP server with command: {' '.join(cmd)}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give the server time to start
            await asyncio.sleep(3)
            
            # Check if process is still running
            if self.process.poll() is None:
                logger.info("✅ MCP server started successfully")
                return True
            else:
                stdout, stderr = self.process.communicate()
                logger.error(f"❌ MCP server failed to start.")
                logger.error(f"Stdout: {stdout}")
                logger.error(f"Stderr: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to start MCP server: {e}")
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


class InteractiveShell:
    """Interactive shell for the Wazuh MCP client"""
    
    def __init__(self, client: WazuhMCPClient):
        self.client = client
        self.tools = []
        
    async def initialize(self):
        """Initialize the shell"""
        self.tools = await self.client.list_tools()
        
    def print_welcome(self):
        """Print welcome message"""
        print("=" * 60)
        print("🎉 Welcome to the Wazuh MCP Interactive Client!")
        print("=" * 60)
        print("This client allows you to interact with your Wazuh clusters using")
        print("the Model Context Protocol (MCP) server.")
        print()
        print("Available commands:")
        print("  help         - Show this help message")
        print("  tools        - List available tools")
        print("  auth <cluster> - Authenticate with a Wazuh cluster")
        print("  agents <cluster> [status] [limit] [offset] - Get agents from cluster")
        print("  raw <tool> <args> - Call a tool with raw JSON arguments")
        print("  quit         - Exit the client")
        print()
        print("Examples:")
        print("  auth prod")
        print("  agents prod active 10 0")
        print("  raw GetAgentsTool '{\"cluster\": \"prod\", \"status\": [\"active\"], \"limit\": 5}'")
        print()
        
    def print_tools(self):
        """Print available tools"""
        if not self.tools:
            print("❌ No tools available")
            return
            
        print("📋 Available Tools:")
        print("-" * 40)
        for tool in self.tools:
            print(f"🔧 {tool['name']}")
            print(f"   Description: {tool['description']}")
            if 'parameters' in tool:
                params = tool['parameters'].get('properties', {})
                required = tool['parameters'].get('required', [])
                print(f"   Parameters:")
                for param, details in params.items():
                    req_str = " (required)" if param in required else ""
                    print(f"     • {param}{req_str}: {details.get('description', 'No description')}")
            print()
            
    async def handle_command(self, command: str) -> bool:
        """Handle a user command. Returns True to continue, False to quit."""
        command = command.strip()
        if not command:
            return True
            
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == "quit" or cmd == "q":
            return False
            
        elif cmd == "help" or cmd == "h":
            self.print_welcome()
            
        elif cmd == "tools":
            self.print_tools()
            
        elif cmd == "auth":
            if len(parts) < 2:
                print("❌ Usage: auth <cluster>")
                return True
                
            cluster = parts[1]
            print(f"🔐 Authenticating with cluster '{cluster}'...")
            result = await self.client.call_tool("AuthenticateTool", {"cluster": cluster})
            self.print_result(result)
            
        elif cmd == "agents":
            if len(parts) < 2:
                print("❌ Usage: agents <cluster> [status] [limit] [offset]")
                return True
                
            cluster = parts[1]
            args = {"cluster": cluster}
            
            if len(parts) > 2:
                args["status"] = [parts[2]]
            if len(parts) > 3:
                try:
                    args["limit"] = int(parts[3])
                except ValueError:
                    print("❌ Invalid limit value")
                    return True
            if len(parts) > 4:
                try:
                    args["offset"] = int(parts[4])
                except ValueError:
                    print("❌ Invalid offset value")
                    return True
                    
            print(f"👥 Getting agents from cluster '{cluster}'...")
            result = await self.client.call_tool("GetAgentsTool", args)
            self.print_result(result)
            
        elif cmd == "raw":
            if len(parts) < 3:
                print("❌ Usage: raw <tool> <json_args>")
                return True
                
            tool_name = parts[1]
            json_args = " ".join(parts[2:])
            
            try:
                args = json.loads(json_args)
                print(f"🔧 Calling tool '{tool_name}'...")
                result = await self.client.call_tool(tool_name, args)
                self.print_result(result)
            except json.JSONDecodeError:
                print("❌ Invalid JSON arguments")
                
        else:
            print(f"❌ Unknown command: {cmd}")
            print("Type 'help' for available commands")
            
        return True
        
    def print_result(self, result: Dict[str, Any]):
        """Print the result of a tool call"""
        if "error" in result:
            print(f"❌ Error: {result['error']}")
        else:
            print("✅ Result:")
            print(json.dumps(result, indent=2))
            
    async def run(self):
        """Run the interactive shell"""
        await self.initialize()
        self.print_welcome()
        
        while True:
            try:
                command = input("🔍 wazuh-mcp> ").strip()
                if not await self.handle_command(command):
                    break
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except EOFError:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                logger.error(f"Error handling command: {e}")
                print(f"❌ An error occurred: {e}")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Wazuh MCP Interactive Client")
    parser.add_argument("--config", required=True, help="Path to clusters.yml file")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Server port (default: 8080)")
    parser.add_argument("--log-level", default="INFO", help="Log level (default: INFO)")
    
    args = parser.parse_args()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Start the MCP server
    server_manager = WazuhMCPServerManager(
        config_path=args.config,
        host=args.host,
        port=args.port
    )
    
    try:
        if not await server_manager.start():
            logger.error("❌ Failed to start MCP server")
            return 1
            
        # Initialize the MCP client
        server_url = f"http://{args.host}:{args.port}"
        async with WazuhMCPClient(server_url) as mcp_client:
            
            # Wait for server to be ready
            if not await mcp_client.wait_for_server():
                logger.error("❌ MCP server is not responding")
                return 1
                
            # Run the interactive shell
            shell = InteractiveShell(mcp_client)
            await shell.run()
            
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        return 1
        
    finally:
        # Clean up
        server_manager.stop()
        
    return 0


if __name__ == "__main__":
    # Handle graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received signal, shutting down...")
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the main function
    sys.exit(asyncio.run(main()))

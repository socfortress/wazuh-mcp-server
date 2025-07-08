#!/usr/bin/env python3
"""
Interactive client for Wazuh MCP Server

This client:
1. Runs the Wazuh MCP server in the background
2. Uses OpenAI + LangChain to interact with the server's tools
3. Provides a conversational interface for Wazuh operations

Usage:
    python interactive_client.py --config clusters.yml --openai-key YOUR_API_KEY
"""

import asyncio
import logging
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import json
import httpx
from dataclasses import dataclass

# Third-party imports
import openai
from langchain.schema import HumanMessage, AIMessage, SystemMessage
from langchain.chat_models import ChatOpenAI
from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationBufferWindowMemory
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class WazuhTool:
    """Represents a Wazuh MCP tool"""
    name: str
    description: str
    schema: Dict[str, Any]


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
                    logger.info("MCP server is ready")
                    return True
            except Exception as e:
                logger.debug(f"Attempt {attempt + 1}: Server not ready - {e}")
                await asyncio.sleep(delay)
        return False
        
    async def list_tools(self) -> List[WazuhTool]:
        """Get available tools from the MCP server"""
        try:
            # Use the OpenAI-compatible endpoint to list tools
            response = await self.client.post(
                f"{self.server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "system", "content": "list_tools"}],
                    "stream": False
                }
            )
            response.raise_for_status()
            
            # Parse the response to extract tools
            data = response.json()
            tools = []
            
            # If the response contains tool definitions, parse them
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0].get("message", {}).get("content", "")
                try:
                    tool_data = json.loads(content)
                    if isinstance(tool_data, list):
                        for tool_info in tool_data:
                            tools.append(WazuhTool(
                                name=tool_info.get("name", ""),
                                description=tool_info.get("description", ""),
                                schema=tool_info.get("schema", {})
                            ))
                except json.JSONDecodeError:
                    logger.warning("Could not parse tool list response")
            
            self.available_tools = tools
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
                            "content": f"call_tool:{tool_name}",
                            "tool_call": {
                                "name": tool_name,
                                "arguments": arguments
                            }
                        }
                    ],
                    "stream": False
                }
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to call tool {tool_name}: {e}")
            return {"error": str(e)}


class WazuhLangChainAgent:
    """LangChain agent that can interact with Wazuh via MCP"""
    
    def __init__(self, openai_api_key: str, mcp_client: WazuhMCPClient):
        self.openai_api_key = openai_api_key
        self.mcp_client = mcp_client
        
        # Initialize OpenAI
        self.llm = ChatOpenAI(
            model="gpt-4",
            openai_api_key=openai_api_key,
            temperature=0.1,
            streaming=True,
            callbacks=[StreamingStdOutCallbackHandler()]
        )
        
        # Initialize memory
        self.memory = ConversationBufferWindowMemory(
            k=10,
            return_messages=True,
            memory_key="chat_history"
        )
        
        # Will be populated with tools from MCP server
        self.tools: List[Tool] = []
        self.agent = None
        
    async def initialize_tools(self):
        """Initialize tools from the MCP server"""
        await self.mcp_client.list_tools()
        
        # Create LangChain tools from MCP tools
        self.tools = []
        
        # Add a generic tool for authentication
        auth_tool = Tool(
            name="authenticate_wazuh_cluster",
            description="Authenticate with a Wazuh cluster to refresh JWT tokens",
            func=self._create_tool_wrapper("AuthenticateTool")
        )
        self.tools.append(auth_tool)
        
        # Add agent listing tool
        agents_tool = Tool(
            name="get_wazuh_agents",
            description="Get list of Wazuh agents from a cluster with optional filtering by status, limit, and offset",
            func=self._create_tool_wrapper("GetAgentsTool")
        )
        self.tools.append(agents_tool)
        
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
        
    def _create_tool_wrapper(self, tool_name: str):
        """Create a wrapper function for calling MCP tools"""
        async def tool_wrapper(input_str: str) -> str:
            try:
                # Parse the input as JSON if possible, otherwise use as cluster name
                try:
                    args = json.loads(input_str)
                except json.JSONDecodeError:
                    # If it's not JSON, assume it's a cluster name
                    args = {"cluster": input_str}
                
                result = await self.mcp_client.call_tool(tool_name, args)
                return json.dumps(result, indent=2)
                
            except Exception as e:
                return f"Error calling {tool_name}: {str(e)}"
                
        # Convert async function to sync for LangChain
        def sync_wrapper(input_str: str) -> str:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an event loop, we need to handle this differently
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, tool_wrapper(input_str))
                    return future.result()
            else:
                return asyncio.run(tool_wrapper(input_str))
                
        return sync_wrapper
        
    async def chat(self, message: str) -> str:
        """Chat with the agent"""
        try:
            # Add context about available clusters and tools
            context = f"""
You are a helpful assistant that can interact with Wazuh security platforms through available tools.

Available tools:
- authenticate_wazuh_cluster: Refresh JWT tokens for a cluster
- get_wazuh_agents: Get list of agents from a cluster

When calling tools, use JSON format for arguments. For example:
- To authenticate: {{"cluster": "prod"}}
- To get agents: {{"cluster": "prod", "status": ["active"], "limit": 10, "offset": 0}}

Remember to authenticate with a cluster before trying to get agents or perform other operations.
"""
            
            # Run the agent
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                self.agent.run,
                f"{context}\n\nUser: {message}"
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error in chat: {e}")
            return f"I encountered an error: {str(e)}"


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
                logger.error(f"Config file not found: {self.config_path}")
                return False
                
            # Start the server
            cmd = [
                sys.executable, "-m", "wazuh_mcp_server",
                "--config", self.config_path,
                "--host", self.host,
                "--port", str(self.port)
            ]
            
            logger.info(f"Starting MCP server with command: {' '.join(cmd)}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give the server time to start
            await asyncio.sleep(2)
            
            # Check if process is still running
            if self.process.poll() is None:
                logger.info("MCP server started successfully")
                return True
            else:
                stdout, stderr = self.process.communicate()
                logger.error(f"MCP server failed to start. Stdout: {stdout}, Stderr: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start MCP server: {e}")
            return False
            
    def stop(self):
        """Stop the MCP server"""
        if self.process:
            logger.info("Stopping MCP server...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("MCP server did not stop gracefully, killing...")
                self.process.kill()
                self.process.wait()
            self.process = None
            logger.info("MCP server stopped")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Interactive Wazuh MCP Client")
    parser.add_argument("--config", required=True, help="Path to clusters.yml file")
    parser.add_argument("--openai-key", required=True, help="OpenAI API key")
    parser.add_argument("--host", default="0.0.0.0", help="Server host")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    
    args = parser.parse_args()
    
    # Start the MCP server
    server_manager = WazuhMCPServerManager(
        config_path=args.config,
        host=args.host,
        port=args.port
    )
    
    try:
        logger.info("Starting Wazuh MCP Server...")
        if not await server_manager.start():
            logger.error("Failed to start MCP server")
            return 1
            
        # Initialize the MCP client
        server_url = f"http://{args.host}:{args.port}"
        async with WazuhMCPClient(server_url) as mcp_client:
            
            # Wait for server to be ready
            if not await mcp_client.wait_for_server():
                logger.error("MCP server is not responding")
                return 1
                
            # Initialize the LangChain agent
            agent = WazuhLangChainAgent(args.openai_key, mcp_client)
            await agent.initialize_tools()
            
            logger.info("🎉 Wazuh MCP Client is ready! Type 'quit' to exit.")
            logger.info("You can ask questions about your Wazuh clusters, agents, and security data.")
            logger.info("Examples:")
            logger.info("  - 'Show me all active agents in the prod cluster'")
            logger.info("  - 'Authenticate with the lab cluster'")
            logger.info("  - 'What agents are pending approval?'")
            print("\n" + "="*50)
            
            # Interactive chat loop
            while True:
                try:
                    user_input = input("\n🔍 You: ").strip()
                    
                    if user_input.lower() in ['quit', 'exit', 'q']:
                        logger.info("Goodbye!")
                        break
                        
                    if not user_input:
                        continue
                        
                    print("\n🤖 Assistant: ", end="")
                    response = await agent.chat(user_input)
                    print(f"\n{response}")
                    
                except KeyboardInterrupt:
                    logger.info("\nReceived interrupt signal, shutting down...")
                    break
                except EOFError:
                    logger.info("\nReceived EOF, shutting down...")
                    break
                except Exception as e:
                    logger.error(f"Error in chat loop: {e}")
                    continue
                    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
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

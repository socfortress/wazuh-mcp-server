#!/usr/bin/env python3
"""
LangChain integration example for Wazuh MCP Server

This example shows how to use the Wazuh MCP server with LangChain agents.
It demonstrates creating custom tools, setting up agents, and handling conversations.

Requirements:
    pip install langchain openai httpx

Usage:
    python langchain_example.py --config clusters.yml --openai-key YOUR_API_KEY
"""

import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    from langchain.tools import BaseTool
    from langchain.agents import initialize_agent, AgentType
    from langchain.chat_models import ChatOpenAI
    from langchain.memory import ConversationBufferWindowMemory
    from langchain.schema import AgentAction, AgentFinish
    from langchain.callbacks.base import BaseCallbackHandler
    from pydantic import BaseModel, Field
except ImportError as e:
    logger.error(f"Required dependencies not installed: {e}")
    logger.error("Install with: pip install langchain openai")
    sys.exit(1)


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
            
            logger.info(f"Starting MCP server: {' '.join(cmd)}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            await asyncio.sleep(3)
            
            if self.process.poll() is None:
                logger.info("✅ MCP server started successfully")
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


class WazuhMCPClient:
    """Client for interacting with the Wazuh MCP Server"""
    
    def __init__(self, server_url: str = "http://localhost:8080"):
        self.server_url = server_url
        self.client = httpx.AsyncClient(timeout=30.0)
        
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
        return False
        
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
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            logger.error(f"Failed to call tool {tool_name}: {e}")
            return {"success": False, "error": str(e)}


# LangChain Tool Definitions
class WazuhAuthenticateInput(BaseModel):
    """Input for Wazuh authentication tool"""
    cluster: str = Field(description="Cluster name from clusters.yml")


class WazuhGetAgentsInput(BaseModel):
    """Input for Wazuh get agents tool"""
    cluster: str = Field(description="Cluster name from clusters.yml")
    status: Optional[List[str]] = Field(default=None, description="Filter by agent status (e.g., ['active', 'pending'])")
    limit: Optional[int] = Field(default=500, description="Maximum number of agents to return")
    offset: Optional[int] = Field(default=0, description="Number of agents to skip")


class WazuhAuthenticateTool(BaseTool):
    """LangChain tool for authenticating with Wazuh clusters"""
    
    name = "authenticate_wazuh_cluster"
    description = "Authenticate with a Wazuh cluster to refresh JWT tokens. Use this before calling other Wazuh tools."
    args_schema = WazuhAuthenticateInput
    
    def __init__(self, mcp_client: WazuhMCPClient):
        super().__init__()
        self.mcp_client = mcp_client
        
    def _run(self, cluster: str) -> str:
        """Run the authentication tool"""
        return asyncio.run(self._arun(cluster))
        
    async def _arun(self, cluster: str) -> str:
        """Async run the authentication tool"""
        try:
            result = await self.mcp_client.call_tool("AuthenticateTool", {"cluster": cluster})
            
            if result.get("success"):
                return f"✅ Successfully authenticated with cluster '{cluster}'"
            else:
                return f"❌ Authentication failed for cluster '{cluster}': {result.get('error', 'Unknown error')}"
                
        except Exception as e:
            logger.error(f"Error in authentication tool: {e}")
            return f"❌ Authentication error: {str(e)}"


class WazuhGetAgentsTool(BaseTool):
    """LangChain tool for getting Wazuh agents"""
    
    name = "get_wazuh_agents"
    description = "Get list of Wazuh agents from a cluster. You can filter by status, limit results, and paginate with offset."
    args_schema = WazuhGetAgentsInput
    
    def __init__(self, mcp_client: WazuhMCPClient):
        super().__init__()
        self.mcp_client = mcp_client
        
    def _run(self, cluster: str, status: Optional[List[str]] = None, limit: Optional[int] = 500, offset: Optional[int] = 0) -> str:
        """Run the get agents tool"""
        return asyncio.run(self._arun(cluster, status, limit, offset))
        
    async def _arun(self, cluster: str, status: Optional[List[str]] = None, limit: Optional[int] = 500, offset: Optional[int] = 0) -> str:
        """Async run the get agents tool"""
        try:
            args = {"cluster": cluster}
            if status:
                args["status"] = status
            if limit:
                args["limit"] = limit
            if offset:
                args["offset"] = offset
                
            result = await self.mcp_client.call_tool("GetAgentsTool", args)
            
            if result.get("success"):
                data = result.get("data", {})
                # Format the response nicely
                if isinstance(data, dict) and "choices" in data:
                    # Extract the actual content from the MCP response
                    choices = data.get("choices", [])
                    if choices:
                        content = choices[0].get("message", {}).get("content", "")
                        return f"✅ Agents from cluster '{cluster}':\n{content}"
                
                return f"✅ Agents from cluster '{cluster}':\n{json.dumps(data, indent=2)}"
            else:
                return f"❌ Failed to get agents from cluster '{cluster}': {result.get('error', 'Unknown error')}"
                
        except Exception as e:
            logger.error(f"Error in get agents tool: {e}")
            return f"❌ Get agents error: {str(e)}"


class WazuhCallbackHandler(BaseCallbackHandler):
    """Custom callback handler for Wazuh operations"""
    
    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs) -> None:
        """Called when a tool starts running"""
        tool_name = serialized.get("name", "Unknown")
        logger.info(f"🔧 Starting tool: {tool_name}")
        
    def on_tool_end(self, output: str, **kwargs) -> None:
        """Called when a tool finishes running"""
        logger.info(f"✅ Tool completed successfully")
        
    def on_tool_error(self, error: BaseException, **kwargs) -> None:
        """Called when a tool encounters an error"""
        logger.error(f"❌ Tool error: {error}")
        
    def on_agent_action(self, action: AgentAction, **kwargs) -> None:
        """Called when an agent takes an action"""
        logger.info(f"🤖 Agent action: {action.tool} with input: {action.tool_input}")
        
    def on_agent_finish(self, finish: AgentFinish, **kwargs) -> None:
        """Called when an agent finishes"""
        logger.info(f"🎯 Agent finished: {finish.return_values}")


class WazuhLangChainAgent:
    """LangChain agent for Wazuh operations"""
    
    def __init__(self, openai_api_key: str, mcp_client: WazuhMCPClient):
        self.openai_api_key = openai_api_key
        self.mcp_client = mcp_client
        
        # Initialize OpenAI LLM
        self.llm = ChatOpenAI(
            model="gpt-4",
            openai_api_key=openai_api_key,
            temperature=0.1
        )
        
        # Initialize memory
        self.memory = ConversationBufferWindowMemory(
            k=10,
            return_messages=True,
            memory_key="chat_history"
        )
        
        # Initialize tools
        self.tools = [
            WazuhAuthenticateTool(mcp_client),
            WazuhGetAgentsTool(mcp_client)
        ]
        
        # Initialize callback handler
        self.callback_handler = WazuhCallbackHandler()
        
        # Initialize agent
        self.agent = initialize_agent(
            self.tools,
            self.llm,
            agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            callbacks=[self.callback_handler],
            max_iterations=3,
            early_stopping_method="generate"
        )
        
    async def chat(self, message: str) -> str:
        """Chat with the agent"""
        try:
            # Add context about available clusters and operations
            context = """
You are a helpful assistant for Wazuh security operations. You have access to tools that can:

1. Authenticate with Wazuh clusters
2. Get agent information from clusters

Important notes:
- Always authenticate with a cluster before trying to get agents or perform operations
- When asked about agents, you can filter by status (active, pending, disconnected, etc.)
- You can limit results and use pagination with offset
- Be helpful and explain what you're doing

Available clusters may include: prod, lab, staging, dev (check the user's clusters.yml file)
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
            return f"❌ I encountered an error: {str(e)}"


class InteractiveChat:
    """Interactive chat interface"""
    
    def __init__(self, agent: WazuhLangChainAgent):
        self.agent = agent
        
    def print_welcome(self):
        """Print welcome message"""
        print("=" * 70)
        print("🎉 Welcome to the Wazuh MCP LangChain Agent!")
        print("=" * 70)
        print("This is an intelligent agent that can help you manage your Wazuh security infrastructure.")
        print("The agent has access to your Wazuh clusters and can perform various operations.")
        print()
        print("What the agent can do:")
        print("• Authenticate with your Wazuh clusters")
        print("• Get information about agents")
        print("• Filter agents by status")
        print("• Provide security insights")
        print()
        print("Example questions:")
        print("• 'Authenticate with the prod cluster'")
        print("• 'Show me all active agents in the lab cluster'")
        print("• 'How many pending agents are there in prod?'")
        print("• 'Get the first 10 agents from the staging cluster'")
        print()
        print("The agent will think through problems step by step and use the appropriate tools.")
        print("Type 'quit' to exit.")
        print("=" * 70)
        
    async def run(self):
        """Run the interactive chat"""
        self.print_welcome()
        
        while True:
            try:
                user_input = input("\n💬 You: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break
                    
                if not user_input:
                    continue
                    
                print(f"\n🤖 Agent: Thinking...")
                response = await self.agent.chat(user_input)
                print(f"\n🤖 Agent: {response}")
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except EOFError:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                logger.error(f"Error in chat loop: {e}")
                print(f"❌ An error occurred: {e}")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Wazuh MCP LangChain Example")
    parser.add_argument("--config", required=True, help="Path to clusters.yml file")
    parser.add_argument("--openai-key", required=True, help="OpenAI API key")
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
            logger.info("✅ LangChain agent initialized")
            
            # Run interactive chat
            chat = InteractiveChat(agent)
            await chat.run()
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1
        
    finally:
        # Clean up
        server_manager.stop()
        
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

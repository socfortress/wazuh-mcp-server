#!/usr/bin/env python3
"""
OpenAI-compatible client for Wazuh MCP Server

This client provides an OpenAI-compatible interface to interact with the Wazuh MCP server.
It can be used with LangChain, OpenAI SDK, or any tool that supports OpenAI's API format.

Usage:
    python openai_client.py --config clusters.yml --openai-key YOUR_API_KEY

Features:
- Automatic server management
- OpenAI-compatible tool calling
- LangChain integration examples
- Interactive chat interface
- Tool discovery and usage
"""

import asyncio
import json
import logging
import signal
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import argparse
import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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


class WazuhOpenAIClient:
    """OpenAI-compatible client for Wazuh MCP Server"""
    
    def __init__(self, server_url: str = "http://localhost:8080", openai_api_key: str = None):
        self.server_url = server_url
        self.openai_api_key = openai_api_key
        self.client = httpx.AsyncClient(timeout=60.0)
        self.tools = []
        
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
        
    async def initialize_tools(self):
        """Initialize available tools"""
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": "authenticate_wazuh_cluster",
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
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_wazuh_agents",
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
            }
        ]
        
    async def call_wazuh_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a Wazuh MCP tool"""
        try:
            # Map friendly names to actual tool names
            tool_mapping = {
                "authenticate_wazuh_cluster": "AuthenticateTool",
                "get_wazuh_agents": "GetAgentsTool"
            }
            
            actual_tool_name = tool_mapping.get(tool_name, tool_name)
            
            # Call the tool via the MCP server
            response = await self.client.post(
                f"{self.server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "system",
                            "content": f"Call tool {actual_tool_name} with arguments: {json.dumps(arguments)}"
                        }
                    ],
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "data": data
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
            
    async def chat_completions(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4",
        stream: bool = False,
        tools: Optional[List[Dict]] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        OpenAI-compatible chat completions endpoint
        
        This method provides an OpenAI-compatible interface while internally
        routing tool calls to the Wazuh MCP server.
        """
        try:
            # Use OpenAI API if we have a key and no Wazuh tools are being called
            if self.openai_api_key and not self._contains_wazuh_tools(tools):
                return await self._call_openai_api(messages, model, stream, tools, temperature, max_tokens, **kwargs)
            
            # Handle Wazuh tool calls
            if tools and self._contains_wazuh_tools(tools):
                return await self._handle_wazuh_tools(messages, tools)
                
            # Default response for non-tool calls
            return {
                "id": "chatcmpl-wazuh-mcp",
                "object": "chat.completion",
                "created": 1699000000,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "I'm a Wazuh MCP assistant. I can help you with:\n\n1. Authenticating with Wazuh clusters\n2. Getting agent information\n3. Querying Wazuh security data\n\nWhat would you like to do?"
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": 50,
                    "completion_tokens": 50,
                    "total_tokens": 100
                }
            }
            
        except Exception as e:
            logger.error(f"Error in chat_completions: {e}")
            return {
                "error": {
                    "message": str(e),
                    "type": "internal_error",
                    "code": "internal_error"
                }
            }
            
    def _contains_wazuh_tools(self, tools: Optional[List[Dict]]) -> bool:
        """Check if tools contain Wazuh-specific tools"""
        if not tools:
            return False
            
        wazuh_tools = {"authenticate_wazuh_cluster", "get_wazuh_agents"}
        for tool in tools:
            if tool.get("type") == "function":
                func_name = tool.get("function", {}).get("name", "")
                if func_name in wazuh_tools:
                    return True
        return False
        
    async def _handle_wazuh_tools(self, messages: List[Dict[str, str]], tools: List[Dict]) -> Dict[str, Any]:
        """Handle Wazuh tool calls"""
        last_message = messages[-1] if messages else {}
        
        # Check if this is a tool call request
        if last_message.get("role") == "user":
            content = last_message.get("content", "")
            
            # Simple tool calling logic - in a real implementation, this would be more sophisticated
            if "authenticate" in content.lower():
                # Extract cluster name from the message
                words = content.split()
                cluster = None
                for i, word in enumerate(words):
                    if word.lower() in ["cluster", "with"] and i + 1 < len(words):
                        cluster = words[i + 1]
                        break
                
                if cluster:
                    result = await self.call_wazuh_tool("authenticate_wazuh_cluster", {"cluster": cluster})
                    return self._create_tool_response(result, "authenticate_wazuh_cluster")
                    
            elif "agents" in content.lower():
                # Extract cluster and other parameters
                words = content.split()
                cluster = None
                status = None
                
                for i, word in enumerate(words):
                    if word.lower() in ["cluster", "from"] and i + 1 < len(words):
                        cluster = words[i + 1]
                    elif word.lower() == "status" and i + 1 < len(words):
                        status = [words[i + 1]]
                
                if cluster:
                    args = {"cluster": cluster}
                    if status:
                        args["status"] = status
                    
                    result = await self.call_wazuh_tool("get_wazuh_agents", args)
                    return self._create_tool_response(result, "get_wazuh_agents")
        
        # Default response if no tool call was detected
        return {
            "id": "chatcmpl-wazuh-mcp",
            "object": "chat.completion", 
            "created": 1699000000,
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "I didn't understand that request. Please specify a cluster name and what you'd like to do. For example:\n\n- 'authenticate with prod cluster'\n- 'get agents from lab cluster'\n- 'show active agents from prod cluster'"
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": 50,
                "total_tokens": 100
            }
        }
        
    def _create_tool_response(self, result: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Create a properly formatted tool response"""
        if result.get("success"):
            content = f"✅ Tool '{tool_name}' executed successfully:\n\n{json.dumps(result['data'], indent=2)}"
        else:
            content = f"❌ Tool '{tool_name}' failed: {result.get('error', 'Unknown error')}"
            
        return {
            "id": "chatcmpl-wazuh-mcp",
            "object": "chat.completion",
            "created": 1699000000,
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 100,
                "total_tokens": 200
            }
        }
        
    async def _call_openai_api(self, messages, model, stream, tools, temperature, max_tokens, **kwargs):
        """Call the actual OpenAI API"""
        try:
            import openai
            
            openai.api_key = self.openai_api_key
            
            response = await openai.ChatCompletion.acreate(
                model=model,
                messages=messages,
                stream=stream,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            )
            
            return response
            
        except ImportError:
            logger.error("OpenAI package not installed. Install with: pip install openai")
            return {"error": {"message": "OpenAI package not installed", "type": "missing_dependency"}}
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            return {"error": {"message": str(e), "type": "openai_error"}}


class InteractiveChat:
    """Interactive chat interface"""
    
    def __init__(self, client: WazuhOpenAIClient):
        self.client = client
        self.conversation_history = []
        
    def print_welcome(self):
        """Print welcome message"""
        print("=" * 70)
        print("🎉 Welcome to the Wazuh MCP OpenAI-Compatible Client!")
        print("=" * 70)
        print("This client provides an OpenAI-compatible interface to your Wazuh clusters.")
        print("You can ask questions in natural language and I'll help you interact with Wazuh.")
        print()
        print("Available operations:")
        print("• Authenticate with clusters")
        print("• Get agent information")
        print("• Query security data")
        print()
        print("Example questions:")
        print("• 'authenticate with prod cluster'")
        print("• 'show me all agents from lab cluster'")
        print("• 'get active agents from prod cluster'")
        print()
        print("Type 'quit' to exit, 'help' for commands, or 'tools' to see available tools.")
        print("=" * 70)
        
    def print_tools(self):
        """Print available tools"""
        print("🔧 Available Wazuh Tools:")
        print("-" * 40)
        for tool in self.client.tools:
            func = tool.get("function", {})
            print(f"• {func.get('name', 'Unknown')}")
            print(f"  Description: {func.get('description', 'No description')}")
            
            params = func.get("parameters", {}).get("properties", {})
            required = func.get("parameters", {}).get("required", [])
            
            if params:
                print("  Parameters:")
                for param, details in params.items():
                    req_str = " (required)" if param in required else ""
                    print(f"    - {param}{req_str}: {details.get('description', 'No description')}")
            print()
            
    async def handle_message(self, message: str) -> str:
        """Handle a user message"""
        if message.lower() in ['quit', 'exit', 'q']:
            return "quit"
        elif message.lower() in ['help', 'h']:
            self.print_welcome()
            return "help"
        elif message.lower() == 'tools':
            self.print_tools()
            return "tools"
        elif message.lower() == 'clear':
            self.conversation_history.clear()
            print("🧹 Conversation history cleared.")
            return "clear"
            
        # Add user message to history
        self.conversation_history.append({"role": "user", "content": message})
        
        # Get response from client
        response = await self.client.chat_completions(
            messages=self.conversation_history,
            model="gpt-4",
            tools=self.client.tools
        )
        
        # Extract assistant response
        if "choices" in response and len(response["choices"]) > 0:
            assistant_message = response["choices"][0]["message"]["content"]
            self.conversation_history.append({"role": "assistant", "content": assistant_message})
            return assistant_message
        elif "error" in response:
            error_msg = f"❌ Error: {response['error'].get('message', 'Unknown error')}"
            return error_msg
        else:
            return "❌ Unexpected response format"
            
    async def run(self):
        """Run the interactive chat"""
        self.print_welcome()
        
        while True:
            try:
                user_input = input("\n💬 You: ").strip()
                if not user_input:
                    continue
                    
                response = await self.handle_message(user_input)
                
                if response == "quit":
                    print("👋 Goodbye!")
                    break
                elif response not in ["help", "tools", "clear"]:
                    print(f"\n🤖 Assistant: {response}")
                    
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
    parser = argparse.ArgumentParser(description="Wazuh MCP OpenAI-Compatible Client")
    parser.add_argument("--config", required=True, help="Path to clusters.yml file")
    parser.add_argument("--openai-key", help="OpenAI API key (optional)")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Server port (default: 8080)")
    parser.add_argument("--log-level", default="INFO", help="Log level (default: INFO)")
    parser.add_argument("--no-interactive", action="store_true", help="Don't start interactive mode")
    
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
            
        # Initialize the OpenAI-compatible client
        server_url = f"http://{args.host}:{args.port}"
        async with WazuhOpenAIClient(server_url, args.openai_key) as client:
            
            # Wait for server to be ready
            if not await client.wait_for_server():
                logger.error("MCP server is not responding")
                return 1
                
            # Initialize tools
            await client.initialize_tools()
            logger.info(f"✅ Client initialized with {len(client.tools)} tools")
            
            if not args.no_interactive:
                # Run interactive chat
                chat = InteractiveChat(client)
                await chat.run()
            else:
                print("🎉 Wazuh MCP server is running!")
                print(f"📍 Server URL: {server_url}")
                print("🔧 OpenAI-compatible client is ready for programmatic use")
                print("Press Ctrl+C to stop...")
                
                # Keep running until interrupted
                try:
                    while True:
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    print("\n👋 Shutting down...")
                    
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

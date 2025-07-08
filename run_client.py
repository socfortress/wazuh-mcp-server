#!/usr/bin/env python3
"""
Client runner for Wazuh MCP Server

This script connects to a running MCP server and provides an interactive
interface using LangChain and OpenAI for natural language queries.

Usage:
    python run_client.py
"""

import os
import sys
import asyncio
import logging

# Load environment configuration
from env_config import load_env_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import our client components
try:
    from client import WazuhMCPClient, WazuhLangChainAgent, InteractiveChat
except ImportError as e:
    logger.error(f"Failed to import client components: {e}")
    logger.error("Make sure all dependencies are installed: pip install -r client_requirements.txt")
    sys.exit(1)

async def test_server_connection(host: str = "localhost", port: int = 8080) -> bool:
    """Test if the MCP server is running"""
    import httpx
    
    url = f"http://{host}:{port}/health"
    print(f"🔍 Testing server connection to {url}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5.0)
            if response.status_code == 200:
                print("✅ MCP server is reachable")
                return True
            else:
                print(f"❌ Server returned status {response.status_code}")
                return False
    except Exception as e:
        print(f"❌ Cannot reach server: {e}")
        print("Make sure the server is running with: python start_mcp.py")
        return False

async def test_basic_functionality(host: str = "localhost", port: int = 8080):
    """Test basic MCP server functionality"""
    print("\n🔧 Testing tool discovery...")
    
    import httpx
    server_url = f"http://{host}:{port}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "system", "content": "list_tools"}],
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                print("✅ Tool discovery successful")
                data = response.json()
                print(f"Server response preview: {str(data)[:200]}...")
                return True
            else:
                print(f"❌ Tool discovery failed: {response.status_code}")
                print(f"Response: {response.text}")
                return False
    except Exception as e:
        print(f"❌ Tool discovery error: {e}")
        return False

async def run_interactive_client():
    """Run the interactive client"""
    
    # Load environment configuration
    load_env_file()
    
    # Get configuration
    host = os.getenv("MCP_SERVER_HOST", "localhost")
    port = int(os.getenv("MCP_SERVER_PORT", "8080"))
    openai_key = os.getenv("OPENAI_API_KEY")
    
    if not openai_key:
        print("❌ OPENAI_API_KEY not found in environment")
        print("Make sure your .env file contains: OPENAI_API_KEY=your-key-here")
        return 1
    
    # Test server connection
    print(f"🔍 Checking MCP server at http://{host}:{port}...")
    if not await test_server_connection(host, port):
        print(f"❌ MCP server is not running at http://{host}:{port}")
        print("Start the server first with: python start_mcp.py")
        return 1
    
    print("✅ MCP server is running!")
    
    # Connect to the MCP server
    server_url = f"http://{host}:{port}"
    
    try:
        async with WazuhMCPClient(server_url) as client:
            # Wait for server to be ready
            if not await client.wait_for_server(max_attempts=5):
                print("❌ MCP server is not responding")
                return 1
            
            # Create and initialize the LangChain agent
            agent = WazuhLangChainAgent(
                mcp_client=client,
                openai_api_key=openai_key,
                model="gpt-4"
            )
            
            print("🤖 Initializing LangChain agent with Wazuh tools...")
            await agent.initialize_tools()
            
            # Start interactive chat
            chat = InteractiveChat(agent)
            await chat.run()
            
    except Exception as e:
        logger.error(f"Error running client: {e}")
        return 1
    
    return 0

async def run_example_queries():
    """Run some example queries"""
    
    # Load environment configuration
    load_env_file()
    
    # Get configuration
    host = os.getenv("MCP_SERVER_HOST", "localhost")
    port = int(os.getenv("MCP_SERVER_PORT", "8080"))
    openai_key = os.getenv("OPENAI_API_KEY")
    
    if not openai_key:
        print("❌ OPENAI_API_KEY not found in environment")
        return 1
    
    server_url = f"http://{host}:{port}"
    
    try:
        async with WazuhMCPClient(server_url) as client:
            if not await client.wait_for_server(max_attempts=5):
                print("❌ MCP server is not responding")
                return 1
            
            # Create agent
            agent = WazuhLangChainAgent(
                mcp_client=client,
                openai_api_key=openai_key,
                model="gpt-4"
            )
            
            await agent.initialize_tools()
            
            # Example queries
            queries = [
                "What tools are available?",
                "Authenticate with the prod cluster",
                "Show me agents from the prod cluster",
                "How many active agents are there in prod?"
            ]
            
            print("🚀 Running example queries:")
            print("=" * 50)
            
            for query in queries:
                print(f"\n🤔 Query: {query}")
                response = await agent.query(query)
                print(f"🎯 Response: {response}")
                print("-" * 30)
            
    except Exception as e:
        logger.error(f"Error running examples: {e}")
        return 1
    
    return 0

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Wazuh MCP Client Runner")
    parser.add_argument("--examples", action="store_true", 
                       help="Run example queries instead of interactive mode")
    parser.add_argument("--test-connection", action="store_true",
                       help="Test server connection and exit")
    
    args = parser.parse_args()
    
    print("🤖 Wazuh MCP Client")
    print("=" * 30)
    
    # Load environment
    load_env_file()
    
    if args.test_connection:
        host = os.getenv("MCP_SERVER_HOST", "localhost")
        port = int(os.getenv("MCP_SERVER_PORT", "8080"))
        
        async def test():
            if await test_server_connection(host, port):
                print(f"✅ Server is running at http://{host}:{port}")
                return 0
            else:
                print(f"❌ Server is not running at http://{host}:{port}")
                return 1
        
        sys.exit(asyncio.run(test()))
    
    elif args.examples:
        print("Running example queries...")
        sys.exit(asyncio.run(run_example_queries()))
    
    else:
        print("Starting interactive client...")
        sys.exit(asyncio.run(run_interactive_client()))

if __name__ == "__main__":
    main()

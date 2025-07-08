#!/usr/bin/env python3
"""
Simple client runner for testing the Wazuh MCP server

This script connects to the MCP server and demonstrates basic functionality.
"""

import asyncio
import sys
import os
from pathlib import Path

# Load environment variables
if Path(".env").exists():
    from dotenv import load_dotenv
    load_dotenv()

async def test_mcp_connection():
    """Test basic connection to MCP server"""
    import httpx
    
    server_url = "http://localhost:8080"
    
    print("🔌 Testing MCP server connection...")
    
    try:
        async with httpx.AsyncClient() as client:
            # Test health endpoint
            response = await client.get(f"{server_url}/health")
            if response.status_code == 200:
                print("✅ Server health check passed")
                print(f"Response: {response.json()}")
            else:
                print(f"❌ Health check failed: {response.status_code}")
                return False
                
            # Test tool listing (via messages endpoint)
            print("\n🔧 Testing tool discovery...")
            response = await client.post(
                f"{server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {"role": "system", "content": "list_tools"}
                    ],
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Tool discovery successful")
                print(f"Response: {data}")
            else:
                print(f"❌ Tool discovery failed: {response.status_code}")
                print(f"Response: {response.text}")
                
            # Test authentication tool
            print("\n🔑 Testing authentication...")
            response = await client.post(
                f"{server_url}/messages",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "system", 
                            "content": "Call tool AuthenticateTool with arguments: {\"cluster\": \"prod\"}"
                        }
                    ],
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Authentication test completed")
                print(f"Response: {data}")
            else:
                print(f"❌ Authentication test failed: {response.status_code}")
                print(f"Response: {response.text}")
                
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False
        
    return True

async def test_langchain_client():
    """Test the LangChain client if OpenAI key is available"""
    print("\n🤖 Testing LangChain integration...")
    
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        print("⚠️ No OpenAI API key found, skipping LangChain test")
        return
    
    try:
        # Import our client
        from client import WazuhMCPClient, WazuhLangChainAgent
        
        async with WazuhMCPClient("http://localhost:8080") as mcp_client:
            # Test basic client functionality
            if not await mcp_client.wait_for_server(max_attempts=3):
                print("❌ MCP server not ready")
                return
                
            print("✅ MCP client connected")
            
            # Discover tools
            tools = await mcp_client.list_tools()
            print(f"📋 Discovered {len(tools)} tools:")
            for tool in tools:
                print(f"  • {tool.name}: {tool.description}")
            
            # Initialize LangChain agent
            agent = WazuhLangChainAgent(mcp_client, openai_key)
            await agent.initialize_tools()
            print("✅ LangChain agent initialized")
            
            # Test a simple query
            print("\n💬 Testing natural language query...")
            response = await agent.query("List the available tools and what they do")
            print(f"🎯 Response: {response}")
            
    except ImportError as e:
        print(f"⚠️ LangChain dependencies not available: {e}")
    except Exception as e:
        print(f"❌ LangChain test failed: {e}")

async def main():
    """Main test function"""
    print("🧪 Wazuh MCP Client Test")
    print("=" * 40)
    
    # Test basic connection
    if await test_mcp_connection():
        print("\n✅ Basic MCP connection tests passed")
    else:
        print("\n❌ Basic MCP connection tests failed")
        return 1
    
    # Test LangChain integration
    await test_langchain_client()
    
    print("\n🎉 All tests completed!")
    return 0

if __name__ == "__main__":
    print("Make sure the MCP server is running first!")
    print("Run: python start_mcp.py")
    print()
    
    try:
        result = asyncio.run(main())
        sys.exit(result)
    except KeyboardInterrupt:
        print("\n👋 Test interrupted")
        sys.exit(0)

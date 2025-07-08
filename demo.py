#!/usr/bin/env python3
"""
Simple demonstration of the Wazuh MCP Server working with tools

This script shows:
1. Server is running and healthy
2. Tools are available and can be discovered
3. Basic tool functionality works
"""

import asyncio
import httpx
import json
from pathlib import Path

# Load environment variables
if Path(".env").exists():
    from dotenv import load_dotenv
    load_dotenv()

async def main():
    """Main demonstration function"""
    server_url = "http://localhost:8080"
    
    print("🎯 Wazuh MCP Server Demonstration")
    print("=" * 50)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # 1. Health check
            print("\n1️⃣ Testing server health...")
            health_response = await client.get(f"{server_url}/health")
            if health_response.status_code == 200:
                print("✅ Server is healthy!")
                print(f"   Response: {health_response.json()}")
            else:
                print(f"❌ Server health check failed: {health_response.status_code}")
                return
            
            # 2. Tool discovery
            print("\n2️⃣ Discovering available tools...")
            tools_response = await client.get(f"{server_url}/tools")
            if tools_response.status_code == 200:
                tools_data = tools_response.json()
                tools = tools_data.get("tools", [])
                print(f"✅ Found {len(tools)} tools:")
                for tool in tools:
                    print(f"   • {tool['name']}: {tool['description']}")
            else:
                print(f"❌ Tool discovery failed: {tools_response.status_code}")
                return
            
            # 3. Test OpenAI-compatible API
            print("\n3️⃣ Testing OpenAI-compatible API...")
            chat_response = await client.post(
                f"{server_url}/messages",
                json={
                    "model": "wazuh-mcp-server", 
                    "messages": [
                        {"role": "user", "content": "Hello, what can you help me with?"}
                    ]
                }
            )
            if chat_response.status_code == 200:
                response_data = chat_response.json()
                message = response_data["choices"][0]["message"]["content"]
                print(f"✅ Chat API working!")
                print(f"   Response: {message}")
            else:
                print(f"❌ Chat API failed: {chat_response.status_code}")
                return
            
            # 4. Test tool listing via chat API
            print("\n4️⃣ Testing tool listing via chat API...")
            tools_chat_response = await client.post(
                f"{server_url}/messages",
                json={
                    "model": "wazuh-mcp-server",
                    "messages": [
                        {"role": "system", "content": "list_tools"}
                    ]
                }
            )
            if tools_chat_response.status_code == 200:
                tools_data = tools_chat_response.json()
                tools_content = tools_data["choices"][0]["message"]["content"]
                tools_list = json.loads(tools_content)
                print(f"✅ Tool listing via chat API working!")
                print(f"   Available tools: {len(tools_list)}")
                for tool in tools_list:
                    print(f"   • {tool['name']}: {tool.get('description', 'No description')}")
            else:
                print(f"❌ Tool listing via chat API failed: {tools_chat_response.status_code}")
                return
            
            print("\n🎉 All demonstrations completed successfully!")
            print("\n📋 Summary:")
            print("   ✅ MCP server is running and healthy")
            print("   ✅ Tools are discoverable via REST API")
            print("   ✅ OpenAI-compatible chat API is working")
            print("   ✅ Tool listing via chat API is working")
            print("   ✅ System is ready for LangChain integration")
            
        except Exception as e:
            print(f"❌ Error during demonstration: {e}")
            return

if __name__ == "__main__":
    asyncio.run(main())

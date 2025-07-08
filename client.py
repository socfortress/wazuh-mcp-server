#!/usr/bin/env python3
"""
Simple MCP client to test the Wazuh MCP server.

This client connects to the MCP server and lists available tools.
"""
import asyncio
import json
import httpx
from typing import Dict, Any

class MCPClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check if the server is running."""
        response = await self.client.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()
    
    async def list_tools(self) -> Dict[str, Any]:
        """List available tools from the MCP server."""
        response = await self.client.get(f"{self.base_url}/tools")
        response.raise_for_status()
        return response.json()
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any] = None) -> Dict[str, Any]:
        """Call a specific tool."""
        if arguments is None:
            arguments = {}
            
        # Create a message to simulate tool calling
        message = {
            "messages": [
                {
                    "role": "user",
                    "content": f"Call tool {tool_name} with arguments: {json.dumps(arguments)}"
                }
            ]
        }
        
        response = await self.client.post(f"{self.base_url}/messages", json=message)
        response.raise_for_status()
        return response.json()
    
    async def close(self):
        """Close the client."""
        await self.client.aclose()

async def main():
    print("🔧 Wazuh MCP Client")
    print("=" * 50)
    
    client = MCPClient()
    
    try:
        # Health check
        print("1. Health Check...")
        health = await client.health_check()
        print(f"   Status: {health.get('status', 'unknown')}")
        
        # List tools
        print("\n2. Available Tools:")
        tools_response = await client.list_tools()
        tools = tools_response.get('tools', [])
        
        if not tools:
            print("   No tools available")
        else:
            for i, tool in enumerate(tools, 1):
                name = tool.get('name', 'Unknown')
                description = tool.get('description', 'No description')
                print(f"   {i}. {name}")
                print(f"      Description: {description}")
        
        # Test AuthenticateTool
        print("\n3. Testing AuthenticateTool...")
        try:
            auth_response = await client.call_tool("AuthenticateTool")
            print("   ✅ Authentication test completed")
            print(f"   Response: {json.dumps(auth_response, indent=2)}")
        except Exception as e:
            print(f"   ❌ Authentication test failed: {e}")
        
        # Test GetAgentsTool
        print("\n4. Testing GetAgentsTool...")
        try:
            agents_response = await client.call_tool("GetAgentsTool", {"limit": 5})
            print("   ✅ Agents query test completed")
            print(f"   Response: {json.dumps(agents_response, indent=2)}")
        except Exception as e:
            print(f"   ❌ Agents query test failed: {e}")
            
    except Exception as e:
        print(f"❌ Client error: {e}")
    
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())

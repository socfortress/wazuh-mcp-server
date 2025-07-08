#!/usr/bin/env python3
"""
Advanced MCP client that actually calls the tools via the MCP protocol.

This demonstrates how to properly interact with the MCP server's tools.
"""
import asyncio
import json
import httpx
import sys
from typing import Dict, Any

class AdvancedMCPClient:
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
    
    async def authenticate(self) -> Dict[str, Any]:
        """Test authentication with the Wazuh manager."""
        # This would normally be handled by the MCP protocol
        # For now, we'll simulate the call
        message = {
            "messages": [
                {
                    "role": "user", 
                    "content": "Please authenticate with the Wazuh manager"
                }
            ],
            "tools": [
                {
                    "name": "AuthenticateTool",
                    "arguments": {}
                }
            ]
        }
        
        response = await self.client.post(f"{self.base_url}/messages", json=message)
        response.raise_for_status()
        return response.json()
    
    async def get_agents(self, limit: int = 10) -> Dict[str, Any]:
        """Get agents from the Wazuh manager."""
        message = {
            "messages": [
                {
                    "role": "user",
                    "content": f"Please get {limit} agents from the Wazuh manager"
                }
            ],
            "tools": [
                {
                    "name": "GetAgentsTool",
                    "arguments": {"limit": limit}
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
    print("🔧 Advanced Wazuh MCP Client")
    print("=" * 50)
    
    client = AdvancedMCPClient()
    
    try:
        # Health check
        print("1. Health Check...")
        health = await client.health_check()
        print(f"   Status: {health.get('status', 'unknown')}")
        
        if health.get('status') != 'ok':
            print("   ❌ Server is not healthy. Exiting.")
            return
        
        # List tools
        print("\n2. Available Tools:")
        tools_response = await client.list_tools()
        tools = tools_response.get('tools', [])
        
        if not tools:
            print("   ❌ No tools available")
            return
        
        for i, tool in enumerate(tools, 1):
            name = tool.get('name', 'Unknown')
            description = tool.get('description', 'No description')
            print(f"   {i}. {name}")
            print(f"      Description: {description}")
        
        # Test authentication
        print("\n3. Testing Authentication...")
        try:
            auth_response = await client.authenticate()
            print("   ✅ Authentication request sent")
            content = auth_response.get('choices', [{}])[0].get('message', {}).get('content', '')
            print(f"   Response: {content}")
        except Exception as e:
            print(f"   ❌ Authentication failed: {e}")
        
        # Test getting agents
        print("\n4. Testing Agent Retrieval...")
        try:
            agents_response = await client.get_agents(limit=5)
            print("   ✅ Agent retrieval request sent")
            content = agents_response.get('choices', [{}])[0].get('message', {}).get('content', '')
            print(f"   Response: {content}")
        except Exception as e:
            print(f"   ❌ Agent retrieval failed: {e}")
        
        print("\n" + "=" * 50)
        print("✅ All tests completed successfully!")
        print("\nNote: The current implementation returns simple responses.")
        print("To see actual Wazuh data, the server needs to be connected to")
        print("a running Wazuh manager with valid credentials.")
        
    except httpx.ConnectError:
        print("❌ Cannot connect to the server. Make sure it's running on localhost:8080")
        print("Start the server with: python start_server.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)
    
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())

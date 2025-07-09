#!/usr/bin/env python3
"""
Minimal SSE Client for Wazuh MCP Server
Connects to the server, lists tools, and demonstrates tool calls.

Usage:
  python client-sse.py

Make sure the server is running:
  python server.py
"""

import asyncio
import httpx
from typing import Dict, Any, List

class WazuhMCPClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools from the MCP server."""
        response = await self.client.get(f"{self.base_url}/tools")
        response.raise_for_status()
        return response.json()
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Call a specific tool with arguments."""
        if arguments is None:
            arguments = {}
            
        payload = {
            "name": tool_name,
            "arguments": arguments
        }
        
        response = await self.client.post(f"{self.base_url}/tools/call", json=payload)
        response.raise_for_status()
        return response.json()

async def main():
    """Demonstrate the Wazuh MCP Server functionality."""
    print("=== Wazuh MCP Server Client Demo ===\n")
    
    async with WazuhMCPClient() as client:
        try:
            # List available tools
            print("1. Listing available tools...")
            tools = await client.list_tools()
            print(f"Available tools: {len(tools)}")
            for tool in tools:
                print(f"  - {tool['name']}: {tool.get('description', 'No description')}")
            print()
            
            # Test AuthenticateTool
            print("2. Testing AuthenticateTool...")
            try:
                auth_result = await client.call_tool("AuthenticateTool")
                print(f"Authentication result: {auth_result}")
            except Exception as e:
                print(f"Authentication error: {e}")
            print()
            
            # Test GetAgentsTool with default parameters
            print("3. Testing GetAgentsTool (default parameters)...")
            try:
                agents_result = await client.call_tool("GetAgentsTool")
                print("Agents result (first 500 chars):")
                result_text = agents_result[0]["text"] if agents_result else "No result"
                print(result_text[:500] + "..." if len(result_text) > 500 else result_text)
            except Exception as e:
                print(f"GetAgents error: {e}")
            print()
            
            # Test GetAgentsTool with filters
            print("4. Testing GetAgentsTool with filters...")
            try:
                filtered_agents = await client.call_tool("GetAgentsTool", {
                    "status": ["active"],
                    "limit": 10,
                    "offset": 0
                })
                print("Filtered agents result (first 500 chars):")
                result_text = filtered_agents[0]["text"] if filtered_agents else "No result"
                print(result_text[:500] + "..." if len(result_text) > 500 else result_text)
            except Exception as e:
                print(f"Filtered GetAgents error: {e}")
            print()
            
        except httpx.ConnectError:
            print("Error: Could not connect to the server.")
            print("Make sure the server is running: python server.py")
        except Exception as e:
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    asyncio.run(main())

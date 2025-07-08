#!/usr/bin/env python3
"""
Example usage of the Wazuh MCP Client

This script demonstrates various ways to use the comprehensive Wazuh MCP client,
including programmatic usage, different query patterns, and integration examples.
"""

import asyncio
import logging
import os
from pathlib import Path
import sys

# Import our client components
from client import WazuhMCPServerManager, WazuhMCPClient, WazuhLangChainAgent

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def example_basic_usage():
    """Basic example of using the client programmatically"""
    print("🚀 Basic Usage Example")
    print("=" * 50)
    
    # Start the MCP server
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            logger.error("Failed to start MCP server")
            return
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            # Wait for server to be ready
            if not await client.wait_for_server():
                logger.error("Server not ready")
                return
            
            # List available tools
            tools = await client.list_tools()
            print(f"📋 Available tools: {len(tools)}")
            for tool in tools:
                print(f"  • {tool.name}: {tool.description}")
            
            # Example direct tool call
            print("\n🔧 Direct tool call example:")
            result = await client.call_tool("AuthenticateTool", {"cluster": "prod"})
            print(f"Authentication result: {result}")
            
    finally:
        server_manager.stop()


async def example_langchain_integration():
    """Example of using LangChain integration"""
    print("\n🤖 LangChain Integration Example")
    print("=" * 50)
    
    # Check for OpenAI key
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        print("❌ OpenAI API key required for this example")
        return
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            logger.error("Failed to start MCP server")
            return
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if not await client.wait_for_server():
                logger.error("Server not ready")
                return
            
            # Create and initialize the agent
            agent = WazuhLangChainAgent(client, openai_key)
            await agent.initialize_tools()
            
            # Example queries
            queries = [
                "List all available tools",
                "Authenticate with the prod cluster",
                "Show me information about agents in the lab cluster",
                "How many clusters are configured?"
            ]
            
            for query in queries:
                print(f"\n🤔 Query: {query}")
                response = await agent.query(query)
                print(f"🎯 Response: {response}")
                
    finally:
        server_manager.stop()


async def example_custom_queries():
    """Example of various custom queries"""
    print("\n📊 Custom Query Examples")
    print("=" * 50)
    
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        print("❌ OpenAI API key required for this example")
        return
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            logger.error("Failed to start MCP server")
            return
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if not await client.wait_for_server():
                logger.error("Server not ready")
                return
            
            agent = WazuhLangChainAgent(client, openai_key)
            await agent.initialize_tools()
            
            # Advanced queries
            advanced_queries = [
                "Get active agents from prod cluster with a limit of 10",
                "Show me agents with pending status from the lab environment",
                "Compare agent counts between prod and lab clusters",
                "What's the difference between active and disconnected agents?"
            ]
            
            for query in advanced_queries:
                print(f"\n🔍 Advanced Query: {query}")
                response = await agent.query(query)
                print(f"🎯 Response: {response[:200]}..." if len(response) > 200 else response)
                
    finally:
        server_manager.stop()


async def example_tool_discovery():
    """Example of discovering and using tools dynamically"""
    print("\n🔧 Tool Discovery Example")
    print("=" * 50)
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            logger.error("Failed to start MCP server")
            return
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if not await client.wait_for_server():
                logger.error("Server not ready")
                return
            
            # Discover tools
            tools = await client.list_tools()
            print(f"📋 Discovered {len(tools)} tools:")
            
            for tool in tools:
                print(f"\n🔧 Tool: {tool.name}")
                print(f"   📝 Description: {tool.description}")
                print(f"   🏷️ Category: {tool.category}")
                print(f"   🌐 HTTP Method: {tool.http_method}")
                print(f"   📋 Schema: {tool.schema}")
                
                # Example of calling each tool
                if tool.name == "AuthenticateTool":
                    print("   🔑 Testing authentication...")
                    result = await client.call_tool(tool.name, {"cluster": "prod"})
                    print(f"   ✅ Result: {result.get('success', False)}")
                
                elif tool.name == "GetAgentsTool":
                    print("   👥 Testing agent listing...")
                    result = await client.call_tool(tool.name, {
                        "cluster": "prod", 
                        "limit": 5
                    })
                    print(f"   ✅ Result: {result.get('success', False)}")
                    
    finally:
        server_manager.stop()


async def example_error_handling():
    """Example of error handling"""
    print("\n⚠️ Error Handling Example")
    print("=" * 50)
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            logger.error("Failed to start MCP server")
            return
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if not await client.wait_for_server():
                logger.error("Server not ready")
                return
            
            # Test various error scenarios
            print("🔍 Testing invalid cluster name...")
            result = await client.call_tool("AuthenticateTool", {"cluster": "invalid"})
            print(f"Expected error: {result}")
            
            print("\n🔍 Testing invalid tool name...")
            result = await client.call_tool("NonExistentTool", {"param": "value"})
            print(f"Expected error: {result}")
            
            print("\n🔍 Testing invalid parameters...")
            result = await client.call_tool("GetAgentsTool", {"invalid_param": "value"})
            print(f"Expected error: {result}")
            
    finally:
        server_manager.stop()


async def main():
    """Main function to run all examples"""
    print("🎯 Wazuh MCP Client Examples")
    print("=" * 70)
    
    # Check if config file exists
    if not Path("example_clusters.yml").exists():
        print("❌ example_clusters.yml not found. Please create it first.")
        return
    
    # Run all examples
    await example_basic_usage()
    await example_langchain_integration()
    await example_custom_queries()
    await example_tool_discovery()
    await example_error_handling()
    
    print("\n✅ All examples completed!")


if __name__ == "__main__":
    print("""
🚀 Wazuh MCP Client Examples
============================

This script demonstrates various ways to use the Wazuh MCP client:

1. Basic programmatic usage
2. LangChain integration
3. Custom queries
4. Tool discovery
5. Error handling

Make sure you have:
- example_clusters.yml configured
- OpenAI API key set (export OPENAI_API_KEY="your-key")
- All dependencies installed (pip install -r client_requirements.txt)

Press Enter to continue or Ctrl+C to exit...
""")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    
    asyncio.run(main())

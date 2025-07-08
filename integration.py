#!/usr/bin/env python3
"""
Integration script for Wazuh MCP Server with LangChain.

This script demonstrates how to connect to the Wazuh MCP server
and use it with LangChain to query for online agents.
"""

import asyncio
import os
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent

# Load environment variables from .env file
load_dotenv()

# Initialize LLM - using GPT-4o as requested
model = ChatOpenAI(model="gpt-4o", temperature=0)

async def main():
    """Main function to demonstrate Wazuh MCP server integration."""
    print("🔗 Connecting to Wazuh MCP Server...")
    
    # Connect to the Wazuh MCP server
    client = MultiServerMCPClient({
        "wazuh-mcp-server": {
            "transport": "sse",
            "url": "http://localhost:9001/sse",  # Updated to use port 9001
            "headers": {}  # No special headers needed for local server
        }
    })
    
    try:
        # Get available tools from the server
        tools = await client.get_tools()
        print(f"✅ Connected! Available tools: {[tool.name for tool in tools]}")
        
        # Initialize the agent with the MCP tools
        agent = initialize_agent(
            tools=tools,
            llm=model,
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=True,  # Show the agent's reasoning process
        )
        
        print("\n🤖 Agent initialized! Querying for online agents...")
        print("=" * 60)
        
        # Query for online agents
        try:
            result = await agent.ainvoke({"input": "give me the online agents"})
            print("\n" + "=" * 60)
            print("🎯 Final Result:")
            print(result.get("output", "No output returned"))
            
        except Exception as e:
            print(f"❌ Error during query: {e}")
            
            # Let's try a simpler approach - list all agents first
            print("\n🔄 Trying to list all agents instead...")
            try:
                result = await agent.ainvoke({"input": "list all agents from the Wazuh manager"})
                print("\n" + "=" * 60)
                print("🎯 Final Result:")
                print(result.get("output", "No output returned"))
            except Exception as e2:
                print(f"❌ Error during fallback query: {e2}")
                
                # Manual tool inspection
                print("\n🔍 Let's inspect the available tools:")
                for tool in tools:
                    print(f"  - {tool.name}: {tool.description}")
                    
    finally:
        # Clean up the client
        await client.close()

def check_requirements():
    """Check if all requirements are met."""
    print("🔍 Checking requirements...")
    
    # Check if OpenAI API key is set
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️  Warning: OPENAI_API_KEY environment variable not set!")
        print("   Please set it with: export OPENAI_API_KEY='your-api-key-here'")
        print("   Or create a .env file with OPENAI_API_KEY=your-api-key-here")
        return False
    
    # Check if server is running
    try:
        import httpx
        with httpx.Client() as client:
            response = client.get("http://localhost:9001/health", timeout=5)
            if response.status_code == 200:
                print("✅ Wazuh MCP server is running")
                return True
            else:
                print("❌ Wazuh MCP server health check failed")
                return False
    except Exception as e:
        print(f"❌ Cannot connect to Wazuh MCP server: {e}")
        print("   Make sure the server is running with: python -m wazuh_mcp_server --transport stream --host localhost --port 9001")
        return False

if __name__ == "__main__":
    print("🚀 Wazuh MCP Server Integration with LangChain")
    print("=" * 60)
    
    if check_requirements():
        asyncio.run(main())
    else:
        print("\n❌ Requirements not met. Please fix the issues above and try again.")

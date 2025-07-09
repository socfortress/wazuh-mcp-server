#!/usr/bin/env python3
"""
Example integration script showing how to connect to the Wazuh MCP Server
from a LangChain application.
"""

import asyncio
import os
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent

# Set your OpenAI API key
# os.environ["OPENAI_API_KEY"] = "your-openai-api-key-here"

# Initialize LLM
model = ChatOpenAI(model="gpt-4o")

async def main():
    """Connect to Wazuh MCP Server and create an agent."""
    
    print("🔌 Connecting to Wazuh MCP Server...")
    
    # Connect to your Wazuh MCP server
    async with MultiServerMCPClient({
        "wazuh-mcp-server": {
            "transport": "sse",
            "url": "http://127.0.0.1:9900/sse",  # Your Wazuh server SSE endpoint
            "headers": {
                # Add any authentication headers if needed
                # "Authorization": "Bearer your-token-here",
            }
        }
    }) as client:
        
        print("📋 Getting available tools...")
        tools = client.get_tools()
        
        print(f"✅ Found {len(tools)} tools:")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")
        
        print("\n🤖 Creating LangChain agent...")
        agent = initialize_agent(
            tools=tools,
            llm=model,
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=True,  # Shows the agent's thought process
        )

        print("\n🚀 Running example queries...")
        
        # Example 1: Authenticate with Wazuh
        print("\n" + "="*50)
        print("Example 1: Authenticate with Wazuh")
        print("="*50)
        try:
            response = await agent.ainvoke({
                "input": "Authenticate with the Wazuh server to get a new JWT token"
            })
            print("Response:", response)
        except Exception as e:
            print(f"Error: {e}")

        # Example 2: Get agents
        print("\n" + "="*50)
        print("Example 2: List Wazuh agents")
        print("="*50)
        try:
            response = await agent.ainvoke({
                "input": "Get a list of all Wazuh agents"
            })
            print("Response:", response)
        except Exception as e:
            print(f"Error: {e}")

        # Example 3: Custom query
        print("\n" + "="*50)
        print("Example 3: Custom query")
        print("="*50)
        try:
            response = await agent.ainvoke({
                "input": "What tools are available for managing Wazuh?"
            })
            print("Response:", response)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    print("🌟 Wazuh MCP Server Integration Example")
    print("=" * 50)
    print("Make sure your Wazuh MCP Server is running on http://127.0.0.1:9900")
    print("Start it with: python -m wazuh_mcp_server --host 127.0.0.1 --port 9900")
    print()
    
    # Check if OpenAI API key is set
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️  Warning: OPENAI_API_KEY environment variable not set.")
        print("   Set it with: export OPENAI_API_KEY='your-api-key-here'")
        print()
    
    asyncio.run(main())

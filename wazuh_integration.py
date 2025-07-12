#!/usr/bin/env python3
"""
Integration script to connect to Wazuh MCP Server from LangChain.
"""

import asyncio

from langchain.agents import AgentType, initialize_agent
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI

# Initialize LLM (can use any LangChain-compatible LLM)
model = ChatOpenAI(model="gpt-4o")


async def main():
    # Connect to Wazuh MCP server and create agent
    client = MultiServerMCPClient(
        {
            "wazuh-mcp-server": {
                "transport": "sse",
                "url": "http://127.0.0.1:8000/sse/",  # Your Wazuh MCP server SSE endpoint
                "headers": {
                    # Add any authentication headers your Wazuh server needs
                    # "Authorization": "Bearer secret-token",
                },
            },
        },
    )

    print("Getting tools from MCP server...")
    tools = await client.get_tools()
    print(f"Found {len(tools)} tools: {[tool.name for tool in tools]}")

    agent = initialize_agent(
        tools=tools,
        llm=model,
        agent=AgentType.OPENAI_FUNCTIONS,
        verbose=True,  # Enables detailed output of the agent's thought process
    )

    # Example queries for Wazuh
    print("\n=== Testing Authentication ===")
    await agent.ainvoke({"input": "Authenticate with Wazuh to get a new JWT token"})

    print("\n=== Testing Get Agents ===")
    await agent.ainvoke(
        {
            "input": "Show me all agents and their IP addresses.",
        },
    )


if __name__ == "__main__":
    asyncio.run(main())

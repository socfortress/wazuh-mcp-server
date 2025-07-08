#!/usr/bin/env python3
"""
Test script for the Wazuh MCP Client

This script tests the basic functionality of the client to ensure it works correctly
with the MCP server.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from client import WazuhMCPServerManager, WazuhMCPClient

async def test_server_startup():
    """Test that the MCP server starts correctly"""
    print("🧪 Testing MCP server startup...")
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        success = await server_manager.start()
        if success:
            print("✅ MCP server started successfully")
            return True
        else:
            print("❌ MCP server failed to start")
            return False
    finally:
        server_manager.stop()


async def test_server_health():
    """Test that the server health endpoint works"""
    print("\n🧪 Testing server health endpoint...")
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            print("❌ Failed to start server for health test")
            return False
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if await client.wait_for_server(max_attempts=10):
                print("✅ Server health check passed")
                return True
            else:
                print("❌ Server health check failed")
                return False
    finally:
        server_manager.stop()


async def test_tool_discovery():
    """Test tool discovery functionality"""
    print("\n🧪 Testing tool discovery...")
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            print("❌ Failed to start server for tool discovery test")
            return False
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if not await client.wait_for_server(max_attempts=10):
                print("❌ Server not ready for tool discovery test")
                return False
            
            tools = await client.list_tools()
            if len(tools) > 0:
                print(f"✅ Discovered {len(tools)} tools:")
                for tool in tools:
                    print(f"  • {tool.name}: {tool.description}")
                return True
            else:
                print("❌ No tools discovered")
                return False
    finally:
        server_manager.stop()


async def test_basic_tool_call():
    """Test basic tool calling functionality"""
    print("\n🧪 Testing basic tool call...")
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            print("❌ Failed to start server for tool call test")
            return False
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if not await client.wait_for_server(max_attempts=10):
                print("❌ Server not ready for tool call test")
                return False
            
            # Try calling a tool (this may fail due to invalid credentials, but that's ok)
            result = await client.call_tool("AuthenticateTool", {"cluster": "prod"})
            
            if "success" in result:
                print("✅ Tool call format is correct")
                if result["success"]:
                    print("  ✅ Authentication successful")
                else:
                    print(f"  ℹ️ Authentication failed (expected with example config): {result.get('error', 'No error message')}")
                return True
            else:
                print("❌ Tool call format is incorrect")
                return False
    finally:
        server_manager.stop()


async def test_langchain_integration():
    """Test LangChain integration if OpenAI key is available"""
    print("\n🧪 Testing LangChain integration...")
    
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        print("⚠️ Skipping LangChain test (no OpenAI API key)")
        return True
    
    try:
        from client import WazuhLangChainAgent
    except ImportError as e:
        print(f"⚠️ Skipping LangChain test (missing dependencies): {e}")
        return True
    
    server_manager = WazuhMCPServerManager("example_clusters.yml")
    
    try:
        if not await server_manager.start():
            print("❌ Failed to start server for LangChain test")
            return False
        
        async with WazuhMCPClient("http://localhost:8080") as client:
            if not await client.wait_for_server(max_attempts=10):
                print("❌ Server not ready for LangChain test")
                return False
            
            try:
                agent = WazuhLangChainAgent(client, openai_key)
                await agent.initialize_tools()
                print("✅ LangChain agent initialized successfully")
                return True
            except Exception as e:
                print(f"❌ LangChain agent initialization failed: {e}")
                return False
    finally:
        server_manager.stop()


async def run_all_tests():
    """Run all tests"""
    print("🧪 Running Wazuh MCP Client Tests")
    print("=" * 50)
    
    # Check prerequisites
    if not Path("example_clusters.yml").exists():
        print("❌ example_clusters.yml not found. Please create it first.")
        return False
    
    tests = [
        ("Server Startup", test_server_startup),
        ("Server Health", test_server_health),
        ("Tool Discovery", test_tool_discovery),
        ("Basic Tool Call", test_basic_tool_call),
        ("LangChain Integration", test_langchain_integration),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            result = await test_func()
            if result:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test '{test_name}' failed with exception: {e}")
            failed += 1
    
    print("\n📊 Test Results:")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"🎯 Total: {passed + failed}")
    
    if failed == 0:
        print("\n🎉 All tests passed!")
        return True
    else:
        print(f"\n⚠️ {failed} test(s) failed")
        return False


if __name__ == "__main__":
    print("🧪 Wazuh MCP Client Test Suite")
    print("=" * 40)
    print("This will test the basic functionality of the client.")
    print("Make sure you have example_clusters.yml configured.")
    print()
    
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)

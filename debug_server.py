#!/usr/bin/env python3
"""
Debug script to help troubleshoot MCP server startup issues
"""

import sys
import os
import subprocess
from pathlib import Path

def check_python_path():
    """Check if the src directory is in Python path"""
    print("🔍 Checking Python path...")
    
    src_path = Path(__file__).parent / "src"
    if str(src_path) not in sys.path:
        print(f"⚠️ Adding {src_path} to Python path")
        sys.path.insert(0, str(src_path))
    else:
        print(f"✅ {src_path} is in Python path")

def test_imports():
    """Test if we can import required modules"""
    print("\n🔍 Testing imports...")
    
    try:
        print("Testing wazuh_mcp_server import...")
        import wazuh_mcp_server
        print("✅ wazuh_mcp_server imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import wazuh_mcp_server: {e}")
        return False
    
    try:
        print("Testing wazuh_mcp_server.__main__ import...")
        import wazuh_mcp_server.__main__
        print("✅ wazuh_mcp_server.__main__ imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import wazuh_mcp_server.__main__: {e}")
        return False
    
    try:
        print("Testing tools import...")
        import tools
        print("✅ tools imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import tools: {e}")
        return False
    
    try:
        print("Testing mcp_server_core import...")
        import mcp_server_core
        print("✅ mcp_server_core imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import mcp_server_core: {e}")
        return False
    
    return True

def test_config_file():
    """Test if we can load the config file"""
    print("\n🔍 Testing config file loading...")
    
    if not Path("temp_clusters.yml").exists():
        print("❌ temp_clusters.yml not found")
        return False
    
    try:
        from wazuh_mcp_server.clusters_information import load_clusters_from_yaml
        registry = load_clusters_from_yaml("temp_clusters.yml")
        print(f"✅ Loaded {len(registry)} clusters from config")
        for name, cluster in registry.items():
            print(f"  • {name}: {cluster.api_url}")
        return True
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        return False

def test_tools():
    """Test if tools can be loaded"""
    print("\n🔍 Testing tools loading...")
    
    try:
        from tools import TOOL_REGISTRY
        from tools.tool_filter import get_enabled_tools
        
        print(f"✅ Found {len(TOOL_REGISTRY)} tools in registry")
        for name in TOOL_REGISTRY.keys():
            print(f"  • {name}")
        
        enabled_tools = get_enabled_tools(TOOL_REGISTRY, None)
        print(f"✅ {len(enabled_tools)} tools enabled after filtering")
        
        return True
    except Exception as e:
        print(f"❌ Failed to load tools: {e}")
        return False

def test_direct_server_start():
    """Test starting the server directly"""
    print("\n🔍 Testing direct server start...")
    
    try:
        # Try to start the server directly
        from wazuh_mcp_server.streaming_server import serve_streaming
        
        print("✅ Can import serve_streaming function")
        
        # Don't actually start it, just test the import
        return True
    except Exception as e:
        print(f"❌ Failed to import serve_streaming: {e}")
        return False

def main():
    """Main debug function"""
    print("🐛 MCP Server Debug Tool")
    print("=" * 40)
    
    # Add src to Python path
    check_python_path()
    
    # Run tests
    tests = [
        ("Import Test", test_imports),
        ("Config Test", test_config_file),
        ("Tools Test", test_tools),
        ("Server Test", test_direct_server_start),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test_name} failed with exception: {e}")
            failed += 1
    
    print(f"\n📊 Debug Results:")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed > 0:
        print("\n🔧 Suggested fixes:")
        print("1. Make sure you're in the project root directory")
        print("2. Check if all dependencies are installed: pip install -r requirements.in")
        print("3. Verify the src directory structure is correct")
        print("4. Make sure temp_clusters.yml exists and is valid")
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

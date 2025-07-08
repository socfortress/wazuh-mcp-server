#!/usr/bin/env python3
"""
Simple script to start the Wazuh MCP server without PYTHONPATH issues.
Usage: python run_server.py [--host HOST] [--port PORT]
"""
import sys
from pathlib import Path

def main():
    # Add src directory to Python path
    src_path = Path(__file__).parent / "src"
    sys.path.insert(0, str(src_path))
    
    # Import and run the server
    from wazuh_mcp_server.__main__ import main as server_main
    
    # Run with default arguments if none provided
    if len(sys.argv) == 1:
        sys.argv.extend(["--host", "0.0.0.0", "--port", "8082"])
    
    server_main()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Simple wrapper to start the Wazuh MCP server without path issues.
"""
import sys
from pathlib import Path

def main():
    # Add src directory to Python path
    src_path = Path(__file__).parent / "src"
    sys.path.insert(0, str(src_path))
    
    # Now import and run the main function
    from wazuh_mcp_server.__main__ import main as server_main
    server_main()

if __name__ == "__main__":
    main()

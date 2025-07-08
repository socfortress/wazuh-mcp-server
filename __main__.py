#!/usr/bin/env python3
"""
Entry point for running wazuh_mcp_server as a module from the project root.
Usage: python -m wazuh_mcp_server --transport stream --host 0.0.0.0 --port 8080
"""
import sys
from pathlib import Path

# Add src directory to Python path so we can import wazuh_mcp_server
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Import and run the main function
from wazuh_mcp_server.__main__ import main

if __name__ == "__main__":
    main()

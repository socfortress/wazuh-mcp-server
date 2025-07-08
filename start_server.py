#!/usr/bin/env python3
"""
Simple startup script for the Wazuh MCP server using environment variables.
"""
import logging
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set up logging
logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    from wazuh_mcp_server.streaming_server import serve_streaming
    
    # Start the server
    serve_streaming(host="0.0.0.0", port=8080)

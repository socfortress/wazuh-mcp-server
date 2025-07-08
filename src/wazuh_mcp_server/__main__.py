import argparse
import os
from wazuh_mcp_server.streaming_server import build_app

def main():
    # Set default log level for FastMCP
    os.environ.setdefault("LOG_LEVEL", "INFO")
    
    p = argparse.ArgumentParser("wazuh-mcp-server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    
    # Use FastMCP's built-in server
    app = build_app()
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

if __name__ == "__main__":
    main()
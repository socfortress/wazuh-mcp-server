import argparse
from wazuh_mcp_server.streaming_server import serve_streaming

def main() -> None:
    parser = argparse.ArgumentParser("wazuh-mcp-server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--transport", default="stream", choices=["stream"], 
                        help="Transport type (currently only 'stream' is supported)")
    args = parser.parse_args()
    
    if args.transport == "stream":
        serve_streaming(host=args.host, port=args.port)
    else:
        raise ValueError(f"Unsupported transport: {args.transport}")

if __name__ == "__main__":
    main()
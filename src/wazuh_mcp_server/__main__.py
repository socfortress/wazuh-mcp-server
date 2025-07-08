import argparse
from wazuh_mcp_server.streaming_server import serve_streaming

def main() -> None:
    parser = argparse.ArgumentParser("wazuh-mcp-server")
    parser.add_argument("--config", default=None,
                        help="YAML file describing one or more Wazuh managers")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    serve_streaming(host=args.host, port=args.port, config_path=args.config)

if __name__ == "__main__":
    main()
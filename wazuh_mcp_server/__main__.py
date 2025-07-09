"""
Main CLI entry point for the Wazuh MCP Server.
"""

import argparse
import logging
import sys

from dotenv import load_dotenv

from .config import Config
from .server import create_server

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CLI."""
    parser = argparse.ArgumentParser(
        description="Wazuh MCP Server - Model Context Protocol server for Wazuh Manager",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind server to (default: 8000)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument("--wazuh-url", help="Wazuh Manager URL (overrides WAZUH_PROD_URL env var)")
    parser.add_argument(
        "--wazuh-username",
        help="Wazuh username (overrides WAZUH_PROD_USERNAME env var)",
    )
    parser.add_argument(
        "--wazuh-password",
        help="Wazuh password (overrides WAZUH_PROD_PASSWORD env var)",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    return parser


def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Create config from environment
    config = Config.from_env()

    # Override with CLI arguments
    if args.wazuh_url:
        config.wazuh.url = args.wazuh_url
    if args.wazuh_username:
        config.wazuh.username = args.wazuh_username
    if args.wazuh_password:
        config.wazuh.password = args.wazuh_password
    if args.no_ssl_verify:
        config.wazuh.ssl_verify = False

    config.server.host = args.host
    config.server.port = args.port
    config.server.log_level = args.log_level

    try:
        # Validate configuration
        config.validate()
        config.setup_logging()

        # Create and start server
        server = create_server(config)
        server.start()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Failed to start server: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

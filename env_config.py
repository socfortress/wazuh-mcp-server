#!/usr/bin/env python3
"""
Environment configuration module for Wazuh MCP Client

This module handles loading configuration from environment variables and .env files.
"""

import os
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

# Try to load python-dotenv for .env file support
try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    logger.warning("python-dotenv not available. Install with: pip install python-dotenv")


@dataclass
class ClusterConfig:
    """Configuration for a single Wazuh cluster"""
    name: str
    api_url: str
    username: str
    password: str
    ssl_verify: bool = True


@dataclass
class MCPConfig:
    """Configuration for the MCP client"""
    openai_api_key: str
    clusters: List[ClusterConfig]
    server_host: str = "0.0.0.0"
    server_port: int = 8080
    log_level: str = "info"
    disabled_tools: Optional[List[str]] = None
    disabled_categories: Optional[List[str]] = None
    read_only: bool = False


def load_env_file(env_file: Optional[str] = None) -> bool:
    """Load environment variables from .env file"""
    if not DOTENV_AVAILABLE:
        return False
    
    if env_file is None:
        # Look for .env file in current directory
        env_file = Path(".env")
    else:
        env_file = Path(env_file)
    
    if env_file.exists():
        load_dotenv(env_file)
        logger.info(f"Loaded environment from {env_file}")
        return True
    else:
        logger.debug(f"No .env file found at {env_file}")
        return False


def get_cluster_config(cluster_name: str) -> Optional[ClusterConfig]:
    """Get configuration for a specific cluster from environment variables"""
    prefix = f"WAZUH_{cluster_name.upper()}_"
    
    url = os.getenv(f"{prefix}URL")
    username = os.getenv(f"{prefix}USERNAME")
    password = os.getenv(f"{prefix}PASSWORD")
    ssl_verify = os.getenv(f"{prefix}SSL_VERIFY", "true").lower() == "true"
    
    if not all([url, username, password]):
        return None
    
    return ClusterConfig(
        name=cluster_name,
        api_url=url,
        username=username,
        password=password,
        ssl_verify=ssl_verify
    )


def get_all_clusters() -> List[ClusterConfig]:
    """Get all configured clusters from environment variables"""
    clusters = []
    
    # Check for common cluster names
    cluster_names = ["prod", "lab", "staging", "dev", "test"]
    
    # Also check for any WAZUH_*_URL patterns
    for key in os.environ:
        if key.startswith("WAZUH_") and key.endswith("_URL"):
            cluster_name = key[6:-4].lower()  # Remove WAZUH_ prefix and _URL suffix
            if cluster_name not in cluster_names:
                cluster_names.append(cluster_name)
    
    for cluster_name in cluster_names:
        config = get_cluster_config(cluster_name)
        if config:
            clusters.append(config)
            logger.info(f"Found cluster configuration: {cluster_name}")
    
    return clusters


def get_mcp_config(env_file: Optional[str] = None) -> MCPConfig:
    """Load complete MCP configuration from environment"""
    # Load .env file if available
    load_env_file(env_file)
    
    # Get OpenAI API key
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        raise ValueError("OPENAI_API_KEY environment variable is required")
    
    # Get all cluster configurations
    clusters = get_all_clusters()
    if not clusters:
        raise ValueError("No cluster configurations found. Set WAZUH_*_URL, WAZUH_*_USERNAME, and WAZUH_*_PASSWORD")
    
    # Get server configuration
    server_host = os.getenv("MCP_SERVER_HOST", "0.0.0.0")
    server_port = int(os.getenv("MCP_SERVER_PORT", "8080"))
    log_level = os.getenv("LOG_LEVEL", "info")
    
    # Get tool filtering configuration
    disabled_tools = None
    if os.getenv("WAZUH_DISABLED_TOOLS"):
        disabled_tools = [tool.strip() for tool in os.getenv("WAZUH_DISABLED_TOOLS").split(",")]
    
    disabled_categories = None
    if os.getenv("WAZUH_DISABLED_CATEGORIES"):
        disabled_categories = [cat.strip() for cat in os.getenv("WAZUH_DISABLED_CATEGORIES").split(",")]
    
    read_only = os.getenv("WAZUH_READ_ONLY", "false").lower() == "true"
    
    return MCPConfig(
        openai_api_key=openai_api_key,
        clusters=clusters,
        server_host=server_host,
        server_port=server_port,
        log_level=log_level,
        disabled_tools=disabled_tools,
        disabled_categories=disabled_categories,
        read_only=read_only
    )


def create_clusters_yaml(config: MCPConfig, output_file: str = "clusters.yml") -> str:
    """Create a clusters.yml file from the environment configuration"""
    import yaml
    
    clusters_data = {
        "clusters": {}
    }
    
    for cluster in config.clusters:
        clusters_data["clusters"][cluster.name] = {
            "name": cluster.name,
            "api_url": cluster.api_url,
            "username": cluster.username,
            "password": cluster.password,
            "ssl_verify": cluster.ssl_verify
        }
    
    with open(output_file, "w") as f:
        yaml.dump(clusters_data, f, default_flow_style=False)
    
    logger.info(f"Created {output_file} from environment configuration")
    return output_file


def validate_config(config: MCPConfig) -> List[str]:
    """Validate the configuration and return a list of issues"""
    issues = []
    
    if not config.openai_api_key or config.openai_api_key == "your-openai-api-key-here":
        issues.append("OpenAI API key is not set or is using placeholder value")
    
    if not config.clusters:
        issues.append("No Wazuh clusters configured")
    
    for cluster in config.clusters:
        if not cluster.api_url or cluster.api_url.startswith("https://wazuh.company.tld"):
            issues.append(f"Cluster '{cluster.name}' has placeholder URL")
        
        if not cluster.username or cluster.username in ["api-user", "wazuh", "wazuh-user"]:
            issues.append(f"Cluster '{cluster.name}' may be using placeholder username")
        
        if not cluster.password or cluster.password in ["S3cr3t!", "lab123", "wazuh-pass"]:
            issues.append(f"Cluster '{cluster.name}' may be using placeholder password")
    
    return issues


if __name__ == "__main__":
    """Test the configuration loading"""
    try:
        config = get_mcp_config()
        print("✅ Configuration loaded successfully:")
        print(f"  OpenAI API Key: {'*' * 20}...{config.openai_api_key[-4:]}")
        print(f"  Clusters: {[c.name for c in config.clusters]}")
        print(f"  Server: {config.server_host}:{config.server_port}")
        
        issues = validate_config(config)
        if issues:
            print("\n⚠️ Configuration issues:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("\n✅ Configuration validation passed")
            
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        print("\nMake sure you have:")
        print("1. Created a .env file with your configuration")
        print("2. Set OPENAI_API_KEY")
        print("3. Set WAZUH_*_URL, WAZUH_*_USERNAME, WAZUH_*_PASSWORD for at least one cluster")

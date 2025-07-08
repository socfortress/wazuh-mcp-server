#!/usr/bin/env python3
"""
Quick start script for the Wazuh MCP Client

This script helps you get started with the Wazuh MCP client quickly.
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🚀 Wazuh MCP Client Quick Start")
    print("=" * 40)
    
    # Step 1: Check if we're in the right directory
    if not Path("client.py").exists():
        print("❌ client.py not found in current directory")
        print("Please run this script from the wazuh-mcp-server directory")
        return 1
    
    # Step 2: Check Python version
    if sys.version_info < (3, 11):
        print("❌ Python 3.11+ is required")
        return 1
    
    # Step 3: Install dependencies
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "client_requirements.txt"
        ])
        print("✅ Dependencies installed")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return 1
    
    # Step 4: Check for config file or .env
    if not Path(".env").exists() and not Path("example_clusters.yml").exists():
        print("⚠️ Creating example .env file...")
        env_content = """# Wazuh MCP Server Environment Configuration
# Fill in your actual values

# OpenAI Configuration
OPENAI_API_KEY=your-openai-api-key-here

# Wazuh Manager Configuration
# Production Cluster
WAZUH_PROD_URL=https://wazuh.company.tld:55000
WAZUH_PROD_USERNAME=api-user
WAZUH_PROD_PASSWORD=S3cr3t!
WAZUH_PROD_SSL_VERIFY=true

# Lab/Testing Cluster (optional)
# WAZUH_LAB_URL=https://wazuh-lab:55000
# WAZUH_LAB_USERNAME=wazuh
# WAZUH_LAB_PASSWORD=lab123
# WAZUH_LAB_SSL_VERIFY=false

# MCP Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8080
LOG_LEVEL=info
"""
        with open(".env", "w") as f:
            f.write(env_content)
        print("✅ Created .env file")
        print("⚠️ Please edit .env file with your actual credentials")
    
    # Step 5: Check OpenAI key
    if not os.getenv("OPENAI_API_KEY") and not Path(".env").exists():
        print("⚠️ OpenAI API key not found")
        key = input("Enter your OpenAI API key (or press Enter to skip): ")
        if key:
            print(f"Add this to your .env file: OPENAI_API_KEY={key}")
    
    # Step 6: Show usage
    print("\n🎯 Ready to use!")
    print("Usage examples:")
    if Path(".env").exists():
        print("  python client.py                                    # Use .env configuration")
        print("  python client.py --validate-only                    # Validate .env config")
        print("  python env_config.py                                # Test .env loading")
    else:
        print("  python client.py --config example_clusters.yml      # Use YAML config")
    
    print("  python setup_client.py                              # For detailed setup")
    print("  python test_client.py                               # To test functionality")
    print("  python examples.py                                  # For usage examples")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

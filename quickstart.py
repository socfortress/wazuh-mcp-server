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
    
    # Step 4: Check for config file
    if not Path("example_clusters.yml").exists():
        print("⚠️ Creating example configuration...")
        config_content = """clusters:
  prod:
    name: prod
    api_url: https://wazuh.company.tld:55000
    username: api-user
    password: S3cr3t!
    ssl_verify: true
  lab:
    name: lab
    api_url: https://wazuh-lab:55000
    username: wazuh
    password: lab123
    ssl_verify: false
"""
        with open("example_clusters.yml", "w") as f:
            f.write(config_content)
        print("✅ Created example_clusters.yml")
        print("⚠️ Please edit this file with your actual cluster details")
    
    # Step 5: Check OpenAI key
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️ OpenAI API key not found")
        key = input("Enter your OpenAI API key (or press Enter to skip): ")
        if key:
            print(f"Add this to your environment: export OPENAI_API_KEY='{key}'")
    
    # Step 6: Show usage
    print("\n🎯 Ready to use!")
    print("Usage examples:")
    print("  python client.py --config example_clusters.yml")
    print("  python client.py --config example_clusters.yml --openai-key YOUR_KEY")
    print("  python setup_client.py  # For detailed setup")
    print("  python test_client.py   # To test functionality")
    print("  python examples.py      # For usage examples")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

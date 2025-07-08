#!/usr/bin/env python3
"""
Setup script for the Wazuh MCP Client

This script helps users set up the client environment and verify everything is working.
"""

import subprocess
import sys
import os
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 11):
        print("❌ Python 3.11+ is required")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} is compatible")
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    print("\n📦 Checking dependencies...")
    
    required_packages = [
        "httpx",
        "pydantic",
        "openai",
        "langchain"
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} is installed")
        except ImportError:
            print(f"❌ {package} is missing")
            missing.append(package)
    
    if missing:
        print(f"\n⚠️ Missing packages: {', '.join(missing)}")
        print("Install with: pip install -r client_requirements.txt")
        return False
    
    return True

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "client_requirements.txt"
        ])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def check_config_file():
    """Check if configuration file exists"""
    print("\n⚙️ Checking configuration...")
    
    if Path("example_clusters.yml").exists():
        print("✅ example_clusters.yml found")
        return True
    else:
        print("❌ example_clusters.yml not found")
        print("Please create this file with your Wazuh cluster configuration")
        return False

def check_openai_key():
    """Check if OpenAI API key is configured"""
    print("\n🔑 Checking OpenAI API key...")
    
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        print("✅ OpenAI API key is configured")
        return True
    else:
        print("⚠️ OpenAI API key not found")
        print("Set it with: export OPENAI_API_KEY='your-key-here'")
        return False

def check_wazuh_server():
    """Check if wazuh-mcp-server is available"""
    print("\n🖥️ Checking Wazuh MCP server...")
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "wazuh_mcp_server", "--help"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ wazuh-mcp-server is available")
            return True
        else:
            print("❌ wazuh-mcp-server is not available")
            print("Make sure it's installed and in your Python path")
            return False
    except FileNotFoundError:
        print("❌ wazuh-mcp-server not found")
        return False

def create_example_config():
    """Create an example configuration file"""
    print("\n📝 Creating example configuration...")
    
    config_content = """# Example Wazuh Clusters Configuration
# Copy this file and modify with your actual cluster details

clusters:
  # Production cluster
  prod:
    name: prod
    api_url: https://wazuh.company.tld:55000
    username: api-user
    password: S3cr3t!
    ssl_verify: true

  # Lab/testing cluster
  lab:
    name: lab
    api_url: https://wazuh-lab.company.tld:55000
    username: wazuh
    password: lab123
    ssl_verify: false  # For self-signed certificates in testing

  # Development cluster
  dev:
    name: dev
    api_url: https://localhost:55000
    username: wazuh-user
    password: wazuh-pass
    ssl_verify: false  # For local development
"""
    
    try:
        with open("example_clusters.yml", "w") as f:
            f.write(config_content)
        print("✅ Created example_clusters.yml")
        print("⚠️ Please edit this file with your actual Wazuh cluster details")
        return True
    except Exception as e:
        print(f"❌ Failed to create config file: {e}")
        return False

def run_quick_test():
    """Run a quick test to verify setup"""
    print("\n🧪 Running quick test...")
    
    try:
        result = subprocess.run([
            sys.executable, "test_client.py"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Quick test passed")
            return True
        else:
            print("❌ Quick test failed")
            print(result.stdout)
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def main():
    """Main setup function"""
    print("🚀 Wazuh MCP Client Setup")
    print("=" * 40)
    
    steps = [
        ("Check Python version", check_python_version),
        ("Check dependencies", check_dependencies),
        ("Check config file", check_config_file),
        ("Check OpenAI key", check_openai_key),
        ("Check Wazuh server", check_wazuh_server),
    ]
    
    issues = []
    
    for step_name, step_func in steps:
        if not step_func():
            issues.append(step_name)
    
    if issues:
        print(f"\n⚠️ Issues found in: {', '.join(issues)}")
        
        # Offer to fix some issues
        if "Check dependencies" in issues:
            response = input("\n❓ Would you like to install missing dependencies? (y/n): ")
            if response.lower() == 'y':
                install_dependencies()
        
        if "Check config file" in issues:
            response = input("\n❓ Would you like to create example config file? (y/n): ")
            if response.lower() == 'y':
                create_example_config()
        
        if "Check OpenAI key" in issues:
            key = input("\n❓ Enter your OpenAI API key (or press Enter to skip): ")
            if key:
                print(f'Add this to your shell profile: export OPENAI_API_KEY="{key}"')
    
    print("\n📋 Setup Summary:")
    print("=" * 20)
    
    if not issues:
        print("✅ All checks passed! You're ready to use the client.")
        
        response = input("\n❓ Run quick test? (y/n): ")
        if response.lower() == 'y':
            run_quick_test()
    else:
        print("⚠️ Some issues need to be resolved before using the client.")
        print("\nNext steps:")
        print("1. Fix the issues listed above")
        print("2. Run this setup script again")
        print("3. Test with: python test_client.py")
    
    print("\n🎉 Setup complete!")
    print("To use the client, run: python client.py --config example_clusters.yml")

if __name__ == "__main__":
    main()

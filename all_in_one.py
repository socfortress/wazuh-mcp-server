#!/usr/bin/env python3
"""
All-in-one startup script for Wazuh MCP

This script installs dependencies, starts the server, and runs the client.
"""

import subprocess
import sys
import time
from pathlib import Path

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "client_requirements.txt"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Dependencies installed")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False
    return True

def start_server():
    """Start the MCP server"""
    print("🚀 Starting MCP server...")
    
    server_process = subprocess.Popen([
        sys.executable, "start_mcp.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Wait for server to be ready
    print("⏳ Waiting for server to start...")
    time.sleep(5)
    
    return server_process

def run_client():
    """Run the client"""
    print("🤖 Starting client...")
    
    # Run client examples first
    print("\n📋 Running example queries...")
    subprocess.run([sys.executable, "run_client.py", "--examples"])
    
    print("\n🎯 Starting interactive mode...")
    subprocess.run([sys.executable, "run_client.py"])

def main():
    """Main function"""
    print("🎉 Wazuh MCP All-in-One Startup")
    print("=" * 40)
    
    # Check .env file
    if not Path(".env").exists():
        print("❌ .env file not found")
        print("Please create a .env file with your configuration")
        return 1
    
    # Install dependencies
    if not install_dependencies():
        return 1
    
    # Start server
    server_process = start_server()
    
    try:
        # Run client
        run_client()
        
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
    
    finally:
        # Clean up server
        if server_process:
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
        
        print("👋 Goodbye!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

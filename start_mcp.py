#!/usr/bin/env python3
"""
Simple startup script for Wazuh MCP Server with .env configuration

This script:
1. Loads configuration from .env file
2. Creates a temporary clusters.yml file
3. Starts the MCP server
4. Runs the client with natural language queries

Usage:
    python start_mcp.py
"""

import os
import sys
import asyncio
import subprocess
import yaml
import httpx
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from env_config import load_env_file, get_all_clusters

def create_clusters_yaml_from_env() -> str:
    """Create a temporary clusters.yml file from environment variables"""
    
    # Load .env file
    load_env_file()
    
    # Get all clusters
    clusters = get_all_clusters()
    
    if not clusters:
        print("❌ No clusters found in .env file")
        print("Make sure you have variables like:")
        print("  WAZUH_PROD_URL=https://your-wazuh:55000")
        print("  WAZUH_PROD_USERNAME=your-username")
        print("  WAZUH_PROD_PASSWORD=your-password")
        sys.exit(1)
    
    # Create clusters.yml content
    clusters_data = {
        "clusters": {}
    }
    
    for cluster in clusters:
        clusters_data["clusters"][cluster.name] = {
            "name": cluster.name,
            "api_url": cluster.api_url,
            "username": cluster.username,
            "password": cluster.password,
            "ssl_verify": cluster.ssl_verify
        }
    
    # Write to temporary file
    temp_file = "temp_clusters.yml"
    with open(temp_file, 'w') as f:
        yaml.dump(clusters_data, f, default_flow_style=False)
    
    print(f"✅ Created {temp_file} with {len(clusters)} clusters:")
    for cluster in clusters:
        print(f"  • {cluster.name}: {cluster.api_url}")
    
    return temp_file

def start_mcp_server(config_file: str, host: str = "0.0.0.0", port: int = 8080):
    """Start the MCP server"""
    # Use direct Python execution with proper PYTHONPATH
    env = os.environ.copy()
    env['PYTHONPATH'] = 'src'
    
    cmd = [
        sys.executable, "-c",
        f"""
import sys
sys.path.insert(0, 'src')
from wazuh_mcp_server.streaming_server import serve_streaming
serve_streaming('{host}', {port}, '{config_file}')
"""
    ]
    
    print(f"🚀 Starting MCP server on {host}:{port} with config {config_file}")
    
    # Start server in background
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Combine stderr into stdout
        text=True,
        env=env
    )
    
    # Give it a moment to start and check if it's still running
    import time
    time.sleep(3)
    
    if process.poll() is not None:
        # Process has already terminated
        stdout, stderr = process.communicate()
        print("❌ Server process terminated immediately!")
        print(f"Exit code: {process.returncode}")
        if stdout:
            print(f"OUTPUT:\n{stdout}")
        return None
    
    return process

async def wait_for_server(host: str = "localhost", port: int = 8080, timeout: int = 30):
    """Wait for the MCP server to be ready"""
    
    url = f"http://{host}:{port}/health"
    
    for i in range(timeout):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=1.0)
                if response.status_code == 200:
                    print("✅ MCP server is ready!")
                    return True
        except Exception:
            pass
        
        print(f"⏳ Waiting for server... ({i+1}/{timeout})")
        await asyncio.sleep(1)
    
    print("❌ Server failed to start within timeout")
    return False

def main():
    """Main function"""
    print("🎯 Wazuh MCP Server Startup")
    print("=" * 40)
    
    # Check if .env file exists
    if not Path(".env").exists():
        print("❌ .env file not found")
        print("Please create a .env file with your configuration")
        sys.exit(1)
    
    # Create clusters.yml from .env
    config_file = create_clusters_yaml_from_env()
    
    # Get server configuration
    load_env_file()
    host = os.getenv("MCP_SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_SERVER_PORT", "8080"))
    
    # Start the server
    server_process = start_mcp_server(config_file, host, port)
    
    if server_process is None:
        print("❌ Failed to start server")
        sys.exit(1)
    
    try:
        # Wait for server to be ready
        if asyncio.run(wait_for_server(host, port)):
            print(f"\n🎉 MCP server is running at http://{host}:{port}")
            print(f"📋 Health check: http://{host}:{port}/health")
            print(f"📊 Config file: {config_file}")
            
            print("\n🤖 Now you can run the client:")
            print(f"python client.py --host {host} --port {port}")
            print("or")
            print("python run_client.py")
            
            # Keep server running
            print("\n⏸️  Press Ctrl+C to stop the server...")
            server_process.wait()
        else:
            print("❌ Failed to start server")
            # Get server output for debugging
            if server_process.poll() is not None:
                stdout, stderr = server_process.communicate()
                print("Server output:")
                if stdout:
                    print(f"STDOUT:\n{stdout}")
            else:
                # Server is still running but not responding
                print("Server is running but not responding to health checks")
                # Kill it and get output
                server_process.terminate()
                try:
                    stdout, stderr = server_process.communicate(timeout=5)
                    if stdout:
                        print(f"Server output:\n{stdout}")
                except subprocess.TimeoutExpired:
                    server_process.kill()
                    print("Server was forcefully killed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping server...")
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_process.kill()
        
        # Clean up temp file
        if Path(config_file).exists():
            Path(config_file).unlink()
        
        print("👋 Server stopped")

if __name__ == "__main__":
    main()

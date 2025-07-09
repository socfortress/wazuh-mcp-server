#!/bin/bash
# Build script for wazuh-mcp-server

set -e

echo "🚀 Building wazuh-mcp-server package..."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build/
rm -rf dist/
rm -rf *.egg-info/

# Install build dependencies
echo "📦 Installing build dependencies..."
pip install --upgrade pip
pip install build twine wheel

# Build the package
echo "🔨 Building the package..."
python -m build

# Check the package
echo "🔍 Checking package integrity..."
twine check dist/*

# List built files
echo "📄 Built files:"
ls -la dist/

echo "✅ Package built successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Test the package: pip install dist/wazuh_mcp_server-*.whl"
echo "2. Upload to PyPI: twine upload dist/*"
echo "3. Or upload to test PyPI: twine upload --repository testpypi dist/*"

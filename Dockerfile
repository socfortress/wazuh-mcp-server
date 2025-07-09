FROM python:3.11-slim

LABEL maintainer="your.email@example.com"
LABEL description="Wazuh MCP Server - Model Context Protocol server for Wazuh Manager"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd -r wazuh && useradd -r -g wazuh wazuh

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Create directory for logs
RUN mkdir -p /app/logs && chown -R wazuh:wazuh /app

# Switch to non-root user
USER wazuh

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Command to run the application
CMD ["wazuh-mcp-server", "--host", "0.0.0.0", "--port", "8000"]

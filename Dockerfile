# Wazuh MCP Server container: streamable HTTP on :8000, non-root, health check on /healthz.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY wazuh_mcp_server ./wazuh_mcp_server
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10004 mcp
COPY --from=build /install /usr/local
ENV MCP_TRANSPORT=http \
    MCP_SERVER_HOST=0.0.0.0 \
    MCP_SERVER_PORT=8000 \
    PYTHONUNBUFFERED=1
USER mcp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1
CMD ["wazuh-mcp-server"]

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Container images are published to
`ghcr.io/socfortress/wazuh-mcp-server` with matching tags.

## [0.2.0] - Unreleased

### Added
- Streamable HTTP transport (`--transport http` / `MCP_TRANSPORT`) at `/mcp`, with bearer-token
  auth (`MCP_AUTH_TOKEN`) and an unauthenticated `GET /healthz`.
- Every tool is classified in `TOOL_META`. `WAZUH_READ_ONLY` and `WAZUH_DISABLED_CATEGORIES` are enforced.
- `MCP_MAX_OUTPUT_CHARS` (default 32000) bounds tool output.
- Dockerfile (non-root, health check) and a workflow that publishes images to GHCR
  (`main`, `sha-…`, and semver tags from `v*` git tags).

### Changed
- Tool output is compact JSON. Oversized responses drop whole `affected_items` and add a
  `truncated` object with returned, original and total item counts and the original size.
  Plain-text truncation states "showing N of M characters".
- The default `limit` for list tools is 50 (was 500).
- Backend failures are returned as MCP tool errors (`isError`) instead of success text. This includes
  Wazuh's HTTP 200 responses with `"error": 1` (total failure, e.g. "Agent does not exist");
  partial failures (`"error": 2`) keep their data.
- Tools return their text directly. Before, the `[{"type": "text", ...}]` wrapper was JSON-encoded a
  second time, which doubled the escaping in every response.
- `fastmcp` is pinned to `>=2.10,<3`, and Python 3.10+ is required.
- `--host`/`--port` override `MCP_SERVER_HOST`/`MCP_SERVER_PORT` only when given.

### Fixed
- The truncation marker no longer contains a literal `\n`.

## [0.1.0]

- Initial stdio MCP server with read-only Wazuh Manager tools.

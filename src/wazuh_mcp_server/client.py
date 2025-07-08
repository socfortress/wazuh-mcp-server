import httpx, time, asyncio, logging
from typing import Optional
from .env_config import ClusterConfig

_LOG = logging.getLogger(__name__)

class WazuhClient:
    """Lightweight, token-caching client for one Wazuh manager."""
    _token: Optional[str] = None
    _expiry: float        = 0.0

    def __init__(self, cluster: ClusterConfig):
        self.cluster = cluster
        self._client = httpx.AsyncClient(
            base_url=str(cluster.api_url),
            verify=cluster.ssl_verify,
            timeout=30,
            http2=True,
        )

    async def _refresh_token(self) -> None:
        if self._token and self._expiry - time.time() > 60:
            return
        auth = (self.cluster.username, self.cluster.password)
        r = await self._client.post("/security/user/authenticate", auth=auth)
        r.raise_for_status()
        data = r.json()["data"]
        self._token  = data["token"]
        self._expiry = time.time() + 900  # default 15 min
        _LOG.debug("Refreshed JWT for %s (expires %d)", self.cluster.name, self._expiry)

    async def request(self, method: str, url: str, **kw):
        await self._refresh_token()
        headers = kw.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        return await self._client.request(method, url, headers=headers, **kw)

# Simple registry shared across tools
_client: Optional[WazuhClient] = None

def get_client(cluster_name: str = "default", registry=None) -> WazuhClient:
    global _client
    if _client is None:
        if registry and "default" in registry:
            _client = WazuhClient(registry["default"])
        else:
            # Fallback to environment config
            from .env_config import get_mcp_config
            config = get_mcp_config()
            _client = WazuhClient(config.clusters[0])
    return _client
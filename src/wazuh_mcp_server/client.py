import httpx, time, asyncio, logging
from typing import Dict, Optional
from .clusters_information import ClusterInfo

_LOG = logging.getLogger(__name__)

class WazuhClient:
    """Lightweight, token-caching client for one Wazuh manager."""
    _token: Optional[str] = None
    _expiry: float        = 0.0

    def __init__(self, cluster: ClusterInfo):
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
_clients: Dict[str, WazuhClient] = {}

def get_client(cluster_name: str, registry) -> WazuhClient:
    if cluster_name not in _clients:
        _clients[cluster_name] = WazuhClient(registry[cluster_name])
    return _clients[cluster_name]
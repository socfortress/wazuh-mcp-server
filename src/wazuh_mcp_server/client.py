"""
Token-caching HTTP client for *one* Wazuh Manager.
Configuration comes from env-vars:

  WAZUH_API_URL
  WAZUH_USERNAME
  WAZUH_PASSWORD
  WAZUH_SSL_VERIFY (true|false, default true)
"""

from __future__ import annotations
import os, time, logging
import httpx

_log = logging.getLogger(__name__)


class WazuhClient:
    _token: str | None = None
    _expiry: float = 0.0

    def __init__(self) -> None:
        url = os.getenv("WAZUH_API_URL")
        user = os.getenv("WAZUH_USERNAME")
        pwd  = os.getenv("WAZUH_PASSWORD")
        if not all((url, user, pwd)):
            raise RuntimeError("WAZUH_API_URL/USERNAME/PASSWORD must be set")

        verify = os.getenv("WAZUH_SSL_VERIFY", "true").lower() not in {"0", "false", "no"}
        self._basic = (user, pwd)
        self._cli   = httpx.AsyncClient(base_url=url, verify=verify, timeout=30, http2=True)

    # ------------------------------------------------------------------ #
    async def _refresh_token(self) -> None:
        if self._token and self._expiry - time.time() > 60:
            return
        r = await self._cli.post("/security/user/authenticate", auth=self._basic)
        r.raise_for_status()
        self._token  = r.json()["data"]["token"]
        self._expiry = time.time() + 900
        _log.debug("New JWT obtained (exp %d)", self._expiry)

    async def request(self, method: str, url: str, **kw):
        await self._refresh_token()
        headers = kw.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        return await self._cli.request(method, url, headers=headers, **kw)


# singleton
_client: WazuhClient | None = None
def get_client() -> WazuhClient:
    global _client
    if _client is None:
        _client = WazuhClient()
    return _client
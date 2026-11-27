"""
Wazuh Indexer (OpenSearch) client for querying alerts.

Alerts are not exposed by the Wazuh Manager API; the manager ships them to the indexer,
where they are stored in the `wazuh-alerts-*` indices.
"""

import logging
from typing import Any, Dict, List, Optional

import httpx

from .config import IndexerConfig

logger = logging.getLogger(__name__)

# Fields alerts can be grouped by in summaries. Keeping this a fixed list stops aggregations
# on analyzed text fields, which OpenSearch rejects.
SUMMARY_FIELDS = {
    "agent.id",
    "agent.name",
    "rule.id",
    "rule.level",
    "rule.groups",
    "rule.description",
    "rule.mitre.id",
    "rule.mitre.tactic",
    "data.srcip",
    "data.dstuser",
    "decoder.name",
    "location",
    "manager.name",
}


class IndexerError(Exception):
    """The indexer rejected a query or could not be reached."""


class IndexerClient:
    """Async HTTP client for alert queries against the Wazuh Indexer."""

    def __init__(self, config: IndexerConfig) -> None:
        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.url,
            auth=(config.username, config.password),
            verify=config.ssl_verify,
            timeout=config.timeout,
        )

    @staticmethod
    def build_filters(
        start: Optional[str] = "now-24h",
        end: Optional[str] = "now",
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        rule_ids: Optional[List[str]] = None,
        min_level: Optional[int] = None,
        max_level: Optional[int] = None,
        rule_groups: Optional[List[str]] = None,
        mitre_ids: Optional[List[str]] = None,
        srcip: Optional[str] = None,
        query: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build an OpenSearch bool query from alert filters."""
        filters: List[Dict[str, Any]] = []

        time_range: Dict[str, Any] = {}
        if start:
            time_range["gte"] = start
        if end:
            time_range["lte"] = end
        if time_range:
            filters.append({"range": {"timestamp": time_range}})

        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})
        if agent_name:
            filters.append({"term": {"agent.name": agent_name}})
        if rule_ids:
            filters.append({"terms": {"rule.id": [str(r) for r in rule_ids]}})

        level_range: Dict[str, int] = {}
        if min_level is not None:
            level_range["gte"] = min_level
        if max_level is not None:
            level_range["lte"] = max_level
        if level_range:
            filters.append({"range": {"rule.level": level_range}})

        if rule_groups:
            filters.append({"terms": {"rule.groups": rule_groups}})
        if mitre_ids:
            filters.append({"terms": {"rule.mitre.id": mitre_ids}})
        if srcip:
            filters.append({"term": {"data.srcip": srcip}})

        bool_query: Dict[str, Any] = {"filter": filters}
        if query:
            bool_query["must"] = [{"query_string": {"query": query, "default_operator": "AND"}}]
        return {"bool": bool_query}

    async def _search(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST a search body to the alerts index and return the raw response."""
        url = f"/{self.config.alerts_index}/_search"
        try:
            response = await self._client.post(url, json=body)
            response.raise_for_status()
            raw = response.json()
        except httpx.HTTPStatusError as e:
            reason = e.response.text[:500]
            try:
                err = e.response.json().get("error", {})
                root = (err.get("root_cause") or [{}])[0]
                reason = root.get("reason") or err.get("reason") or reason
            except Exception:
                pass
            logger.error("Indexer search failed: %s - %s", e.response.status_code, reason)
            raise IndexerError(f"Indexer returned {e.response.status_code}: {reason}") from e
        except httpx.HTTPError as e:
            logger.error("Indexer request failed: %s", e)
            raise IndexerError(f"Indexer request failed: {e}") from e

        # Query errors such as an unparsable query_string come back as HTTP 200 with every
        # shard failed and no hits; without this check they read as "no matching alerts".
        # Shards skipped by the pre-filter (e.g. daily indices outside the time range) count as
        # successful without having searched, so they don't count as a shard that answered.
        shards = raw.get("_shards") or {}
        if shards.get("failed"):
            reason = self._shard_failure_reason(shards)
            searched = shards.get("successful", 0) - shards.get("skipped", 0)
            if searched <= 0:
                logger.error("Indexer search failed on all shards: %s", reason)
                raise IndexerError(f"Indexer search failed: {reason}")
            logger.warning("Indexer search failed on %s shard(s): %s", shards["failed"], reason)
            raw["_partial"] = {
                "failed_shards": shards["failed"],
                "total_shards": shards.get("total"),
                "reason": reason,
            }
        return raw

    @staticmethod
    def _shard_failure_reason(shards: Dict[str, Any]) -> str:
        """Most specific reason from the first shard failure."""
        failures = shards.get("failures") or [{}]
        reason = failures[0].get("reason") or {}
        if not isinstance(reason, str):
            caused_by = reason.get("caused_by") or {}
            reason = caused_by.get("reason") or reason.get("reason") or "unknown shard failure"
        # Lucene parse errors append a long "Was expecting one of:" token list; keep line one.
        return reason.strip().splitlines()[0]

    async def search_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
        sort_order: str = "desc",
        select: Optional[List[str]] = None,
        **filters: Any,
    ) -> Dict[str, Any]:
        """Search alerts, newest first by default.

        Returns the Wazuh API shape (`data.affected_items`, `data.total_affected_items`) so
        output truncation works the same as for the manager tools.
        """
        body: Dict[str, Any] = {
            "query": self.build_filters(**filters),
            "size": limit,
            "from": offset,
            "sort": [{"timestamp": {"order": sort_order}}],
            "track_total_hits": True,
        }
        if select:
            body["_source"] = select

        raw = await self._search(body)
        hits = raw.get("hits", {})
        total = hits.get("total", {})
        total_count = total.get("value", 0) if isinstance(total, dict) else total
        items = [{"_id": h.get("_id"), **(h.get("_source") or {})} for h in hits.get("hits", [])]
        result = {
            "data": {
                "affected_items": items,
                "total_affected_items": total_count,
                "total_failed_items": 0,
                "failed_items": [],
            },
            "message": f"{len(items)} of {total_count} matching alerts returned",
            "error": 0,
        }
        if "_partial" in raw:
            result["partial"] = raw["_partial"]
        return result

    async def summarize_alerts(
        self,
        group_by: str = "rule.id",
        top: int = 10,
        **filters: Any,
    ) -> Dict[str, Any]:
        """Count matching alerts grouped by a field, plus counts per rule level."""
        if group_by not in SUMMARY_FIELDS:
            raise IndexerError(
                f"group_by must be one of: {', '.join(sorted(SUMMARY_FIELDS))} (got {group_by!r})"
            )
        aggs: Dict[str, Any] = {
            "by_field": {"terms": {"field": group_by, "size": top}},
            "by_level": {"terms": {"field": "rule.level", "size": 16, "order": {"_key": "desc"}}},
        }
        if group_by == "rule.id":
            aggs["by_field"]["aggs"] = {
                "description": {"terms": {"field": "rule.description", "size": 1}},
                "level": {"max": {"field": "rule.level"}},
            }
        body = {
            "query": self.build_filters(**filters),
            "size": 0,
            "track_total_hits": True,
            "aggs": aggs,
        }

        raw = await self._search(body)
        total = raw.get("hits", {}).get("total", {})
        total_count = total.get("value", 0) if isinstance(total, dict) else total
        groups = []
        for bucket in raw.get("aggregations", {}).get("by_field", {}).get("buckets", []):
            item = {group_by: bucket.get("key"), "count": bucket.get("doc_count")}
            desc = bucket.get("description", {}).get("buckets")
            if desc:
                item["rule.description"] = desc[0].get("key")
            if bucket.get("level", {}).get("value") is not None:
                item["rule.level"] = int(bucket["level"]["value"])
            groups.append(item)
        levels = {
            str(b.get("key")): b.get("doc_count")
            for b in raw.get("aggregations", {}).get("by_level", {}).get("buckets", [])
        }
        result = {
            "data": {
                "total_alerts": total_count,
                "group_by": group_by,
                "groups": groups,
                "by_level": levels,
            },
            "error": 0,
        }
        if "_partial" in raw:
            result["partial"] = raw["_partial"]
        return result

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

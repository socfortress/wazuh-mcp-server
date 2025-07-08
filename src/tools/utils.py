"""
utils.py – small shared helpers for wazuh-mcp-server tools.
"""

from __future__ import annotations
import textwrap, logging
from typing import Any

_LOG = logging.getLogger(__name__)


def safe_truncate(s: str, limit: int = 16_000, placeholder: str = " …[truncated]") -> str:
    """
    Ensure ``s`` is no longer than *limit* bytes (UTF-8 safe) by
    trimming from the end and appending *placeholder*.
    """
    if len(s.encode()) <= limit:
        return s
    truncated = s.encode()[: limit - len(placeholder.encode())].decode(errors="ignore")
    return f"{truncated}{placeholder}"


def human_join(items: list[str], sep: str = ", ", final: str = " and ") -> str:
    """
    >>> human_join(["a"])           -> 'a'
    >>> human_join(["a","b"])       -> 'a and b'
    >>> human_join(["a","b","c"])   -> 'a, b and c'
    """
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return sep.join(items[:-1]) + final + items[-1]


def log_json(label: str, obj: Any, truncate: int | None = 2_048) -> None:
    """
    Debug helper – pretty-print JSON (if ``truncate`` is set) without blowing up logs.
    """
    import json, pprint

    try:
        pretty = json.dumps(obj, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        pretty = pprint.pformat(obj, width=100)

    if truncate and len(pretty) > truncate:
        pretty = pretty[: truncate] + " …"

    _LOG.debug("%s:\n%s", label, pretty)


def dedent_strip(s: str) -> str:
    """textwrap.dedent + strip."""
    return textwrap.dedent(s).strip()
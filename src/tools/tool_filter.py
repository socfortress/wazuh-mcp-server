"""
tool_filter.py – centralised allow/deny logic for wazuh-mcp-server.

A tool *function* may expose an (optional) ``_meta`` attribute:

    @register("GetAgentsTool")
    async def get_agents(args: GetAgentsArgs, registry, **_):
        ...
    get_agents._meta = {
        "category": "agents",
        "http_method": "GET",   # <- used for read-only enforcement
    }

If no metadata is present, sensible defaults are assumed.
"""

from __future__ import annotations
import os, re, yaml
from pathlib import Path
from typing import Dict, Callable, Pattern, Iterable

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

_SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}


def _split_env(name: str) -> set[str]:
    """Return a *lower-cased* set of comma-separated items from an env-var."""
    raw = os.getenv(name, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _compile_regexes(patterns: Iterable[str]) -> list[Pattern[str]]:
    return [re.compile(pat, flags=re.I) for pat in patterns if pat.strip()]


def _load_yaml(path: str | None) -> dict:
    if not path:
        return {}
    fp = Path(path)
    if not fp.exists():
        raise FileNotFoundError(f"Filter YAML not found: {fp}")
    return yaml.safe_load(fp.read_text()) or {}


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #

def get_enabled_tools(
    registry: Dict[str, Callable],
    filter_yaml: str | None = None,
) -> Dict[str, Callable]:
    """
    Return a *new* dict with tools that survive all allow/deny checks.

    1. Disabled by name/category/regex → dropped.
    2. ``WAZUH_READ_ONLY=true`` will automatically drop anything that
       is not a safe HTTP verb (POST/PUT/PATCH/DELETE).
    3. YAML file (if provided) may contain::

           filter:
             disabled_tools:
               - AuthenticateTool
             disabled_categories:
               - dangerous
             disabled_regex:
               - '^Delete.*'

    Environment variables always win over YAML.
    """

    cfg = _load_yaml(filter_yaml).get("filter", {})

    disabled_names: set[str] = (
        _split_env("WAZUH_DISABLED_TOOLS")
        | {n.lower() for n in cfg.get("disabled_tools", [])}
    )
    disabled_cats: set[str] = (
        _split_env("WAZUH_DISABLED_CATEGORIES")
        | {c.lower() for c in cfg.get("disabled_categories", [])}
    )
    disabled_regex: list[Pattern[str]] = (
        _compile_regexes(os.getenv("WAZUH_DISABLED_TOOLS_REGEX", "").split(","))
        + _compile_regexes(cfg.get("disabled_regex", []))
    )
    read_only = os.getenv("WAZUH_READ_ONLY", "false").lower() in ("1", "true", "yes")

    enabled: Dict[str, Callable] = {}
    for name, fn in registry.items():
        lname = name.lower()

        # --- 1. disabled by explicit name ---------------------------------- #
        if lname in disabled_names:
            continue

        # --- 2. disabled by category --------------------------------------- #
        cat = getattr(fn, "_meta", {}).get("category", "")
        if cat.lower() in disabled_cats:
            continue

        # --- 3. disabled by regex ------------------------------------------ #
        if any(r.search(name) for r in disabled_regex):
            continue

        # --- 4. read-only enforcement -------------------------------------- #
        if read_only:
            method = getattr(fn, "_meta", {}).get("http_method", "GET").upper()
            if method not in _SAFE_HTTP_METHODS:
                continue

        enabled[name] = fn

    return enabled
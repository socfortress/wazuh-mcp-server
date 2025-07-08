"""
Cluster-free allow/deny logic.
"""
from __future__ import annotations
import os, re, yaml
from pathlib import Path
from typing import Dict, Callable, Pattern

_SAFE = {"GET", "HEAD", "OPTIONS"}

def _split(name: str) -> set[str]:
    return {x.strip().lower() for x in os.getenv(name, "").split(",") if x.strip()}

def _regex(lst): return [re.compile(p, re.I) for p in lst if p]

def _load_yaml(path: str | None):
    return yaml.safe_load(Path(path).read_text()) if (path and Path(path).exists()) else {}

def get_enabled_tools(reg: Dict[str, Callable], yaml_path: str | None):
    cfg = _load_yaml(yaml_path).get("filter", {})
    deny_name = _split("WAZUH_DISABLED_TOOLS") | {n.lower() for n in cfg.get("disabled_tools", [])}
    deny_cat  = _split("WAZUH_DISABLED_CATEGORIES") | {c.lower() for c in cfg.get("disabled_categories", [])}
    deny_re   = _regex(os.getenv("WAZUH_DISABLED_TOOLS_REGEX", "").split(",")) + \
                _regex(cfg.get("disabled_regex", []))

    read_only = os.getenv("WAZUH_READ_ONLY", "false").lower() in {"1", "true", "yes"}

    out: Dict[str, Callable] = {}
    for name, fn in reg.items():
        meta = getattr(fn, "_meta", {})
        if name.lower() in deny_name: continue
        if meta.get("category", "").lower() in deny_cat: continue
        if any(r.search(name) for r in deny_re): continue
        if read_only and meta.get("http_method", "GET").upper() not in _SAFE: continue
        out[name] = fn
    return out
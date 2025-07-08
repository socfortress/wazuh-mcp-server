from __future__ import annotations
import yaml
from pathlib import Path
from typing import Dict, Optional
from pydantic import BaseModel, HttpUrl, Field

class ClusterInfo(BaseModel):
    name: str
    api_url: HttpUrl = Field(..., description="https://wazuh.example:55000")
    username: str
    password: str
    ssl_verify: bool = True

def load_clusters_from_yaml(path: Optional[str]) -> Dict[str, ClusterInfo]:
    if path is None:
        raise RuntimeError("Must supply --config when running in multi-cluster mode")
    data = yaml.safe_load(Path(path).read_text()) or {}
    items = {}
    for item in data.get("clusters", {}).values():
        ci = ClusterInfo(**item)
        items[ci.name] = ci
    if not items:
        raise ValueError("No clusters defined in YAML")
    return items
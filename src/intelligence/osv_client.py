import json
import time
from pathlib import Path
from typing import Dict, List, Any

import requests


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_osv_package(name: str, ecosystem: str, version: str | None = None, timeout: int = 20) -> Dict[str, Any]:
    payload = {
        "package": {
            "name": name,
            "ecosystem": ecosystem
        }
    }

    if version:
        payload["version"] = version

    response = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout)
    response.raise_for_status()
    return response.json()


def load_or_query_osv(component: Dict[str, Any], cache_dir: str = "data/cache/osv") -> Dict[str, Any]:
    Path(cache_dir).mkdir(parents=True, exist_ok=True)

    name = component["component_name"]
    ecosystem = component["ecosystem"]
    version = component.get("version") or "unknown"

    cache_file = Path(cache_dir) / f"{ecosystem}_{name}_{version}.json"

    if cache_file.exists():
        return json.loads(cache_file.read_text(encoding="utf-8"))

    data = query_osv_package(name=name, ecosystem=ecosystem, version=component.get("version"))
    cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    time.sleep(0.2)
    return data


def flatten_osv_results(component: Dict[str, Any], osv_response: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    for vuln in osv_response.get("vulns", []):
        aliases = vuln.get("aliases", [])
        cve_aliases = [alias for alias in aliases if alias.startswith("CVE-")]

        findings.append({
            "asset_id": component["asset_id"],
            "component_name": component["component_name"],
            "version": component.get("version"),
            "ecosystem": component["ecosystem"],
            "source": "OSV",
            "vulnerability_id": vuln.get("id"),
            "cve_ids": cve_aliases,
            "summary": vuln.get("summary"),
            "details": vuln.get("details"),
            "modified": vuln.get("modified"),
            "published": vuln.get("published"),
            "aliases": aliases
        })

    return findings

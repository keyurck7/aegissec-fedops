"""Live vulnerability-intelligence ingestion for the presentation surface.

The module queries OSV using governed component identities from the controlled
presentation inventory. It never fabricates intelligence when the remote source
fails or returns an invalid contract.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns/{vulnerability_id}"

DEFAULT_INVENTORY_PATH = Path(
    "data/demo/aegissec_demo_component_inventory.json"
)
DEFAULT_OUTPUT_PATH = Path(
    "data/processed/presentation_demo/latest_live_intelligence.json"
)

ALLOWED_ECOSYSTEMS = {
    "Go",
    "Maven",
    "NuGet",
    "PyPI",
    "RubyGems",
    "npm",
}


class LiveIntelligenceError(RuntimeError):
    """Raised when live intelligence cannot be safely accepted."""


def utc_now() -> str:
    """Return an RFC 3339 UTC timestamp."""

    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic JSON bytes for hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    """Return a deterministic SHA-256 digest."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def read_json(path: Path | str) -> Any:
    """Read a JSON document from disk."""

    resolved = Path(path)

    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LiveIntelligenceError(
            f"Required JSON file does not exist: {resolved}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise LiveIntelligenceError(
            f"Invalid JSON document: {resolved}"
        ) from exc


def _nested(
    value: Mapping[str, Any],
    *path: str,
) -> Any:
    current: Any = value

    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)

    return current


def _first_nonempty(*values: Any) -> Any:
    for value in values:
        if value is not None and str(value).strip():
            return value
    return None


def normalize_component(
    component: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize one controlled component into an OSV query contract."""

    package = component.get("package")
    package_mapping = (
        package
        if isinstance(package, Mapping)
        else {}
    )

    component_id = _first_nonempty(
        component.get("component_id"),
        component.get("id"),
        component.get("asset_component_id"),
    )

    ecosystem = _first_nonempty(
        package_mapping.get("ecosystem"),
        component.get("ecosystem"),
    )

    package_name = _first_nonempty(
        package_mapping.get("name"),
        component.get("package_name"),
        component.get("component_name"),
        component.get("name"),
    )

    version = _first_nonempty(
        package_mapping.get("version"),
        component.get("version"),
        component.get("installed_version"),
    )

    sector = _first_nonempty(
        component.get("sector"),
        _nested(component, "asset_context", "sector"),
        "UNSPECIFIED",
    )

    criticality = _first_nonempty(
        component.get("criticality"),
        component.get("asset_criticality"),
        _nested(component, "asset_context", "criticality"),
        "UNKNOWN",
    )

    mission_essential = bool(
        _first_nonempty(
            component.get("mission_essential"),
            _nested(
                component,
                "asset_context",
                "mission_essential",
            ),
            False,
        )
    )

    internet_exposed = bool(
        _first_nonempty(
            component.get("internet_exposed"),
            _nested(
                component,
                "asset_context",
                "internet_exposed",
            ),
            False,
        )
    )

    missing = [
        name
        for name, value in {
            "component_id": component_id,
            "ecosystem": ecosystem,
            "package_name": package_name,
            "version": version,
        }.items()
        if value is None
    ]

    if missing:
        raise LiveIntelligenceError(
            "Component is missing required fields "
            f"{missing}: {component}"
        )

    ecosystem = str(ecosystem).strip()

    if ecosystem not in ALLOWED_ECOSYSTEMS:
        raise LiveIntelligenceError(
            f"Unsupported OSV ecosystem: {ecosystem}"
        )

    return {
        "component_id": str(component_id).strip(),
        "sector": str(sector).strip(),
        "criticality": str(criticality).strip().upper(),
        "mission_essential": mission_essential,
        "internet_exposed": internet_exposed,
        "package": {
            "ecosystem": ecosystem,
            "name": str(package_name).strip(),
            "version": str(version).strip(),
        },
    }


def load_inventory(
    path: Path | str = DEFAULT_INVENTORY_PATH,
) -> dict[str, Any]:
    """Load and validate the controlled presentation inventory."""

    inventory = read_json(path)

    if not isinstance(inventory, Mapping):
        raise LiveIntelligenceError(
            "Inventory root must be a JSON object."
        )

    raw_components = inventory.get("components")

    if not isinstance(raw_components, list):
        raise LiveIntelligenceError(
            "Inventory must contain a components array."
        )

    if not raw_components:
        raise LiveIntelligenceError(
            "Inventory contains no components."
        )

    normalized = [
        normalize_component(component)
        for component in raw_components
    ]

    ids = [
        component["component_id"]
        for component in normalized
    ]

    if len(ids) != len(set(ids)):
        raise LiveIntelligenceError(
            "Duplicate component identifiers detected."
        )

    return {
        "inventory_id": inventory.get(
            "inventory_id",
            "UNKNOWN-INVENTORY",
        ),
        "authorized_demo": bool(
            inventory.get("authorized_demo", False)
        ),
        "production_eligible": bool(
            inventory.get("production_eligible", False)
        ),
        "components": normalized,
        "source_sha256": sha256_value(inventory),
    }


def build_batch_payload(
    components: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Create the OSV querybatch request."""

    queries = []

    for component in components:
        package = component["package"]

        queries.append({
            "version": package["version"],
            "package": {
                "name": package["name"],
                "ecosystem": package["ecosystem"],
            },
        })

    return {"queries": queries}


def request_json(
    url: str,
    *,
    payload: Mapping[str, Any] | None = None,
    timeout: float = 25.0,
    attempts: int = 3,
) -> Any:
    """Request JSON with bounded retry behavior."""

    if attempts < 1:
        raise ValueError("attempts must be at least one")

    body = (
        canonical_json_bytes(payload)
        if payload is not None
        else None
    )

    headers = {
        "Accept": "application/json",
        "User-Agent": (
            "AegisSec-FedOps-Presentation/1.0 "
            "(controlled-academic-demonstration)"
        ),
    }

    if body is not None:
        headers["Content-Type"] = "application/json"

    last_error: Exception | None = None

    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method="POST" if body is not None else "GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:
                raw = response.read()

            return json.loads(raw.decode("utf-8"))

        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:
            last_error = exc

            if attempt < attempts:
                time.sleep(float(attempt))

    raise LiveIntelligenceError(
        f"Live intelligence request failed for {url}: "
        f"{last_error}"
    )


def extract_cve_aliases(
    vulnerability: Mapping[str, Any],
) -> list[str]:
    """Return normalized CVE aliases from one OSV record."""

    aliases = vulnerability.get("aliases", [])

    if not isinstance(aliases, list):
        return []

    return sorted({
        str(alias).upper()
        for alias in aliases
        if str(alias).upper().startswith("CVE-")
    })


def summarize_vulnerability(
    vulnerability: Mapping[str, Any],
) -> dict[str, Any]:
    """Create a compact presentation-safe advisory record."""

    severity = vulnerability.get("severity", [])

    if not isinstance(severity, list):
        severity = []

    database_specific = vulnerability.get(
        "database_specific",
        {},
    )

    if not isinstance(database_specific, Mapping):
        database_specific = {}

    return {
        "osv_id": vulnerability.get("id"),
        "cve_aliases": extract_cve_aliases(vulnerability),
        "summary": vulnerability.get(
            "summary",
            "No summary supplied by source.",
        ),
        "published": vulnerability.get("published"),
        "modified": vulnerability.get("modified"),
        "withdrawn": vulnerability.get("withdrawn"),
        "severity": severity,
        "database_severity": database_specific.get(
            "severity"
        ),
        "source_record_sha256": sha256_value(
            vulnerability
        ),
    }


def ingest_osv(
    inventory_path: Path | str = DEFAULT_INVENTORY_PATH,
    output_path: Path | str = DEFAULT_OUTPUT_PATH,
    *,
    timeout: float = 25.0,
    max_details: int = 100,
) -> dict[str, Any]:
    """Query OSV and create a governed component intelligence report."""

    inventory = load_inventory(inventory_path)
    components = inventory["components"]

    if not inventory["authorized_demo"]:
        raise LiveIntelligenceError(
            "Inventory is not authorized for demonstration."
        )

    payload = build_batch_payload(components)

    batch_response = request_json(
        OSV_BATCH_URL,
        payload=payload,
        timeout=timeout,
    )

    if not isinstance(batch_response, Mapping):
        raise LiveIntelligenceError(
            "OSV batch response must be an object."
        )

    results = batch_response.get("results")

    if not isinstance(results, list):
        raise LiveIntelligenceError(
            "OSV batch response is missing results."
        )

    if len(results) != len(components):
        raise LiveIntelligenceError(
            "OSV response count does not match component "
            f"count: {len(results)} != {len(components)}"
        )

    vulnerability_ids = []

    for result in results:
        vulns = (
            result.get("vulns", [])
            if isinstance(result, Mapping)
            else []
        )

        if not isinstance(vulns, list):
            raise LiveIntelligenceError(
                "OSV result vulns field must be an array."
            )

        vulnerability_ids.extend(
            str(vulnerability["id"])
            for vulnerability in vulns
            if isinstance(vulnerability, Mapping)
            and vulnerability.get("id")
        )

    unique_ids = sorted(set(vulnerability_ids))

    detail_cache: dict[str, dict[str, Any]] = {}

    for vulnerability_id in unique_ids[:max_details]:
        encoded_id = urllib.parse.quote(
            vulnerability_id,
            safe="",
        )

        detail = request_json(
            OSV_DETAIL_URL.format(
                vulnerability_id=encoded_id
            ),
            timeout=timeout,
        )

        if not isinstance(detail, Mapping):
            raise LiveIntelligenceError(
                f"Invalid OSV detail record: {vulnerability_id}"
            )

        detail_cache[vulnerability_id] = (
            summarize_vulnerability(detail)
        )

    component_results = []

    for component, result in zip(
        components,
        results,
        strict=True,
    ):
        vulns = result.get("vulns", [])
        ids = sorted({
            str(vulnerability["id"])
            for vulnerability in vulns
            if isinstance(vulnerability, Mapping)
            and vulnerability.get("id")
        })

        advisories = [
            detail_cache[vulnerability_id]
            for vulnerability_id in ids
            if vulnerability_id in detail_cache
        ]

        cve_aliases = sorted({
            alias
            for advisory in advisories
            for alias in advisory["cve_aliases"]
        })

        component_results.append({
            **component,
            "vulnerability_status": (
                "VULNERABILITIES_IDENTIFIED"
                if ids
                else "NO_MATCHES_IDENTIFIED"
            ),
            "matched_vulnerability_count": len(ids),
            "osv_ids": ids,
            "cve_aliases": cve_aliases,
            "advisories": advisories,
            "details_truncated": any(
                vulnerability_id
                not in detail_cache
                for vulnerability_id in ids
            ),
        })

    vulnerable_components = [
        component
        for component in component_results
        if component["matched_vulnerability_count"] > 0
    ]

    total_matches = sum(
        component["matched_vulnerability_count"]
        for component in component_results
    )

    report = {
        "report_id": (
            "AEG-LIVE-OSV-"
            + sha256_value({
                "inventory": inventory["inventory_id"],
                "components": component_results,
            })[:24].upper()
        ),
        "generated_at": utc_now(),
        "source": {
            "name": "OSV",
            "mode": "LIVE_API",
            "endpoint": "/v1/querybatch",
            "detail_endpoint": "/v1/vulns/{id}",
            "response_sha256": sha256_value(
                batch_response
            ),
        },
        "inventory": {
            "inventory_id": inventory["inventory_id"],
            "inventory_sha256": inventory[
                "source_sha256"
            ],
            "authorized_demo": inventory[
                "authorized_demo"
            ],
            "production_eligible": inventory[
                "production_eligible"
            ],
        },
        "summary": {
            "components_assessed": len(
                component_results
            ),
            "vulnerable_components": len(
                vulnerable_components
            ),
            "components_without_matches": (
                len(component_results)
                - len(vulnerable_components)
            ),
            "total_component_vulnerability_matches": (
                total_matches
            ),
            "unique_osv_records": len(unique_ids),
            "detailed_records_retrieved": len(
                detail_cache
            ),
        },
        "components": component_results,
        "governance": {
            "real_customer_data": "ABSENT",
            "personal_data": "ABSENT",
            "live_source_claim": "VERIFIED",
            "production_readiness": "BLOCKED",
            "human_review_required": True,
            "next_stage": (
                "MILESTONE_12P_2B_KEV_EPSS_ENRICHMENT"
            ),
        },
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    integrity_path = output.with_suffix(
        output.suffix + ".sha256"
    )

    digest = hashlib.sha256(
        output.read_bytes()
    ).hexdigest()

    integrity_path.write_text(
        f"{digest}  {output.name}\n",
        encoding="utf-8",
    )

    return report

"""CISA KEV and FIRST EPSS enrichment for presentation intelligence.

The module enriches OSV-derived CVE aliases with:

* CISA Known Exploited Vulnerabilities evidence
* FIRST EPSS exploitation-probability evidence
* deterministic, non-authoritative attention signals

The resulting attention signal cannot override SSVC or authorize remediation.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.presentation_demo.live_intelligence import (
    LiveIntelligenceError,
    request_json,
    sha256_value,
    utc_now,
)


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"

DEFAULT_INPUT_PATH = Path(
    "data/processed/presentation_demo/"
    "latest_live_intelligence.json"
)

DEFAULT_OUTPUT_PATH = Path(
    "data/processed/presentation_demo/"
    "latest_enriched_intelligence.json"
)


class ThreatEnrichmentError(RuntimeError):
    """Raised when external enrichment cannot be accepted safely."""


def read_json(path: Path | str) -> Any:
    """Load a JSON document using fail-closed validation."""

    resolved = Path(path)

    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ThreatEnrichmentError(
            f"Required JSON file does not exist: {resolved}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ThreatEnrichmentError(
            f"Invalid JSON document: {resolved}"
        ) from exc


def normalize_cve(value: Any) -> str | None:
    """Return an uppercase CVE identifier when valid."""

    candidate = str(value).strip().upper()

    if not candidate.startswith("CVE-"):
        return None

    parts = candidate.split("-")

    if len(parts) != 3:
        return None

    if not parts[1].isdigit() or not parts[2].isdigit():
        return None

    return candidate


def extract_cves(report: Mapping[str, Any]) -> list[str]:
    """Extract unique CVE aliases from all component records."""

    components = report.get("components")

    if not isinstance(components, list):
        raise ThreatEnrichmentError(
            "Live intelligence report is missing components."
        )

    cves: set[str] = set()

    for component in components:
        if not isinstance(component, Mapping):
            raise ThreatEnrichmentError(
                "Component record must be a JSON object."
            )

        aliases = component.get("cve_aliases", [])

        if not isinstance(aliases, list):
            raise ThreatEnrichmentError(
                "Component cve_aliases must be an array."
            )

        for alias in aliases:
            normalized = normalize_cve(alias)

            if normalized:
                cves.add(normalized)

    return sorted(cves)


def chunk_cves(
    cves: Sequence[str],
    *,
    maximum_query_characters: int = 1900,
) -> list[list[str]]:
    """Split CVEs into bounded FIRST API query groups."""

    if maximum_query_characters < 20:
        raise ValueError(
            "maximum_query_characters is too small"
        )

    chunks: list[list[str]] = []
    current: list[str] = []
    current_length = 0

    for cve in cves:
        additional = len(cve) + (1 if current else 0)

        if (
            current
            and current_length + additional
            > maximum_query_characters
        ):
            chunks.append(current)
            current = []
            current_length = 0
            additional = len(cve)

        if len(cve) > maximum_query_characters:
            raise ThreatEnrichmentError(
                f"CVE identifier exceeds query limit: {cve}"
            )

        current.append(cve)
        current_length += additional

    if current:
        chunks.append(current)

    return chunks


def fetch_kev_catalog(
    *,
    timeout: float = 30.0,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Fetch and index the official CISA KEV catalog."""

    response = request_json(
        CISA_KEV_URL,
        timeout=timeout,
    )

    if not isinstance(response, Mapping):
        raise ThreatEnrichmentError(
            "CISA KEV response must be a JSON object."
        )

    vulnerabilities = response.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise ThreatEnrichmentError(
            "CISA KEV response is missing vulnerabilities."
        )

    index: dict[str, dict[str, Any]] = {}

    for record in vulnerabilities:
        if not isinstance(record, Mapping):
            continue

        cve = normalize_cve(record.get("cveID"))

        if cve is None:
            continue

        if cve in index:
            raise ThreatEnrichmentError(
                f"Duplicate CISA KEV entry detected: {cve}"
            )

        index[cve] = {
            "cve": cve,
            "vendor_project": record.get("vendorProject"),
            "product": record.get("product"),
            "vulnerability_name": record.get(
                "vulnerabilityName"
            ),
            "date_added": record.get("dateAdded"),
            "due_date": record.get("dueDate"),
            "known_ransomware_campaign_use": record.get(
                "knownRansomwareCampaignUse"
            ),
            "required_action": record.get(
                "requiredAction"
            ),
            "short_description": record.get(
                "shortDescription"
            ),
            "notes": record.get("notes"),
            "cwes": record.get("cwes", []),
        }

    metadata = {
        "catalog_version": response.get(
            "catalogVersion"
        ),
        "date_released": response.get("dateReleased"),
        "declared_count": response.get("count"),
        "indexed_count": len(index),
        "response_sha256": sha256_value(response),
    }

    return index, metadata


def fetch_epss_scores(
    cves: Sequence[str],
    *,
    timeout: float = 30.0,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Fetch current FIRST EPSS scores in bounded batches."""

    index: dict[str, dict[str, Any]] = {}
    response_digests: list[str] = []
    response_versions: set[str] = set()
    response_dates: set[str] = set()

    chunks = chunk_cves(cves)

    for chunk in chunks:
        joined = ",".join(chunk)
        encoded = urllib.parse.quote(joined, safe=",")

        url = f"{FIRST_EPSS_URL}?cve={encoded}"

        response = request_json(
            url,
            timeout=timeout,
        )

        if not isinstance(response, Mapping):
            raise ThreatEnrichmentError(
                "FIRST EPSS response must be an object."
            )

        if response.get("status") != "OK":
            raise ThreatEnrichmentError(
                "FIRST EPSS response status was not OK."
            )

        data = response.get("data")

        if not isinstance(data, list):
            raise ThreatEnrichmentError(
                "FIRST EPSS response is missing data."
            )

        response_digests.append(sha256_value(response))

        if response.get("version"):
            response_versions.add(
                str(response["version"])
            )

        for record in data:
            if not isinstance(record, Mapping):
                continue

            cve = normalize_cve(record.get("cve"))

            if cve is None:
                continue

            try:
                epss = float(record["epss"])
                percentile = float(record["percentile"])
            except (
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                raise ThreatEnrichmentError(
                    f"Invalid EPSS score record for {cve}"
                ) from exc

            if not 0.0 <= epss <= 1.0:
                raise ThreatEnrichmentError(
                    f"EPSS score outside [0, 1]: {cve}"
                )

            if not 0.0 <= percentile <= 1.0:
                raise ThreatEnrichmentError(
                    f"EPSS percentile outside [0, 1]: {cve}"
                )

            date_value = (
                record.get("date")
                or record.get("created")
            )

            if date_value:
                response_dates.add(str(date_value))

            index[cve] = {
                "cve": cve,
                "epss": epss,
                "percentile": percentile,
                "score_date": date_value,
            }

    metadata = {
        "requested_cves": len(cves),
        "returned_scores": len(index),
        "missing_scores": sorted(
            set(cves) - set(index)
        ),
        "request_batches": len(chunks),
        "api_versions": sorted(response_versions),
        "score_dates": sorted(response_dates),
        "aggregate_response_sha256": sha256_value(
            response_digests
        ),
    }

    return index, metadata


def attention_signal(
    *,
    kev_count: int,
    maximum_epss: float | None,
    criticality: str,
    mission_essential: bool,
    internet_exposed: bool,
) -> tuple[str, list[str]]:
    """Create a deterministic advisory-only attention signal."""

    reasons: list[str] = []

    if kev_count:
        reasons.append("CISA_KEV_CONFIRMED")

        if (
            mission_essential
            or internet_exposed
            or criticality == "CRITICAL"
        ):
            reasons.append(
                "HIGH_CONSEQUENCE_ASSET_CONTEXT"
            )
            return "IMMEDIATE_REVIEW", reasons

        return "PRIORITY_REVIEW", reasons

    if maximum_epss is None:
        reasons.append("NO_EPSS_SCORE_AVAILABLE")
        return "MONITOR", reasons

    if maximum_epss >= 0.50:
        reasons.append("EPSS_AT_LEAST_0_50")

        if mission_essential or internet_exposed:
            reasons.append(
                "ELEVATED_EXPOSURE_OR_MISSION_CONTEXT"
            )
            return "PRIORITY_REVIEW", reasons

        return "SCHEDULED_REVIEW", reasons

    if maximum_epss >= 0.10:
        reasons.append("EPSS_AT_LEAST_0_10")
        return "SCHEDULED_REVIEW", reasons

    reasons.append("EPSS_BELOW_0_10")
    return "MONITOR", reasons


def enrich_component(
    component: Mapping[str, Any],
    *,
    kev_index: Mapping[str, Mapping[str, Any]],
    epss_index: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Enrich one component with CVE-level threat evidence."""

    aliases = component.get("cve_aliases", [])

    cves = sorted({
        normalized
        for alias in aliases
        if (normalized := normalize_cve(alias))
    })

    records: list[dict[str, Any]] = []

    for cve in cves:
        kev_record = kev_index.get(cve)
        epss_record = epss_index.get(cve)

        records.append({
            "cve": cve,
            "known_exploited": kev_record is not None,
            "kev": (
                dict(kev_record)
                if kev_record is not None
                else None
            ),
            "epss": (
                dict(epss_record)
                if epss_record is not None
                else None
            ),
        })

    kev_count = sum(
        int(record["known_exploited"])
        for record in records
    )

    epss_values = [
        float(record["epss"]["epss"])
        for record in records
        if record["epss"] is not None
    ]

    percentile_values = [
        float(record["epss"]["percentile"])
        for record in records
        if record["epss"] is not None
    ]

    maximum_epss = max(epss_values, default=None)
    maximum_percentile = max(
        percentile_values,
        default=None,
    )

    criticality = str(
        component.get("criticality", "UNKNOWN")
    ).upper()

    signal, reasons = attention_signal(
        kev_count=kev_count,
        maximum_epss=maximum_epss,
        criticality=criticality,
        mission_essential=bool(
            component.get("mission_essential", False)
        ),
        internet_exposed=bool(
            component.get("internet_exposed", False)
        ),
    )

    enriched = dict(component)

    enriched["threat_enrichment"] = {
        "cve_count": len(cves),
        "epss_scored_cves": len(epss_values),
        "kev_confirmed_cves": kev_count,
        "maximum_epss": maximum_epss,
        "maximum_epss_percent": (
            round(maximum_epss * 100, 4)
            if maximum_epss is not None
            else None
        ),
        "maximum_percentile": maximum_percentile,
        "attention_signal": signal,
        "reason_codes": reasons,
        "cve_records": records,
        "authority": "ADVISORY_ONLY",
    }

    return enriched


def build_enriched_report(
    input_path: Path | str = DEFAULT_INPUT_PATH,
    output_path: Path | str = DEFAULT_OUTPUT_PATH,
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Create a governed KEV and EPSS enrichment report."""

    source_report = read_json(input_path)

    if not isinstance(source_report, Mapping):
        raise ThreatEnrichmentError(
            "Live intelligence root must be an object."
        )

    source_governance = source_report.get(
        "governance",
        {},
    )

    if not isinstance(source_governance, Mapping):
        raise ThreatEnrichmentError(
            "Live report governance must be an object."
        )

    if (
        source_governance.get("live_source_claim")
        != "VERIFIED"
    ):
        raise ThreatEnrichmentError(
            "Input OSV source claim is not verified."
        )

    cves = extract_cves(source_report)

    if not cves:
        raise ThreatEnrichmentError(
            "No CVE aliases are available for enrichment."
        )

    kev_index, kev_metadata = fetch_kev_catalog(
        timeout=timeout
    )

    epss_index, epss_metadata = fetch_epss_scores(
        cves,
        timeout=timeout,
    )

    source_components = source_report.get(
        "components",
        [],
    )

    enriched_components = [
        enrich_component(
            component,
            kev_index=kev_index,
            epss_index=epss_index,
        )
        for component in source_components
    ]

    components_with_kev = sum(
        int(
            component["threat_enrichment"][
                "kev_confirmed_cves"
            ]
            > 0
        )
        for component in enriched_components
    )

    unique_kev_cves = sorted({
        record["cve"]
        for component in enriched_components
        for record in component[
            "threat_enrichment"
        ]["cve_records"]
        if record["known_exploited"]
    })

    maximum_epss = max(
        (
            component["threat_enrichment"][
                "maximum_epss"
            ]
            for component in enriched_components
            if component["threat_enrichment"][
                "maximum_epss"
            ]
            is not None
        ),
        default=None,
    )

    signal_distribution: dict[str, int] = {}

    for component in enriched_components:
        signal = component["threat_enrichment"][
            "attention_signal"
        ]

        signal_distribution[signal] = (
            signal_distribution.get(signal, 0) + 1
        )

    report_identity = {
        "osv_report_id": source_report.get("report_id"),
        "kev_sha256": kev_metadata["response_sha256"],
        "epss_sha256": epss_metadata[
            "aggregate_response_sha256"
        ],
        "components": enriched_components,
    }

    report = {
        "report_id": (
            "AEG-THREAT-"
            + sha256_value(report_identity)[
                :24
            ].upper()
        ),
        "generated_at": utc_now(),
        "source_report": {
            "report_id": source_report.get(
                "report_id"
            ),
            "sha256": sha256_value(source_report),
            "path": str(input_path),
        },
        "sources": {
            "osv": source_report.get("source"),
            "cisa_kev": {
                "authority": (
                    "KNOWN_EXPLOITED_VULNERABILITIES"
                ),
                **kev_metadata,
            },
            "first_epss": {
                "meaning": (
                    "PROBABILITY_OF_EXPLOITATION_"
                    "ACTIVITY_IN_NEXT_30_DAYS"
                ),
                **epss_metadata,
            },
        },
        "summary": {
            "components_assessed": len(
                enriched_components
            ),
            "unique_cves": len(cves),
            "epss_scored_cves": len(epss_index),
            "kev_confirmed_cves": len(
                unique_kev_cves
            ),
            "components_with_kev": components_with_kev,
            "maximum_epss": maximum_epss,
            "signal_distribution": (
                signal_distribution
            ),
        },
        "components": enriched_components,
        "governance": {
            "enrichment_authority": "ADVISORY_ONLY",
            "authoritative_policy_engine": "SSVC",
            "ml_override_permitted": False,
            "automated_disposition_permitted": False,
            "human_review_required": True,
            "real_customer_data": "ABSENT",
            "personal_data": "ABSENT",
            "production_readiness": "BLOCKED",
            "next_stage": (
                "MILESTONE_12P_3_SQLITE_AND_"
                "PRESENTATION_ANALYTICS"
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

    digest = hashlib.sha256(
        output.read_bytes()
    ).hexdigest()

    integrity_path = output.with_suffix(
        output.suffix + ".sha256"
    )

    integrity_path.write_text(
        f"{digest}  {output.name}\n",
        encoding="utf-8",
    )

    return report

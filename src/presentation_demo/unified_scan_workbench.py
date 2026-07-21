"""Unified command-center workbench for governed software evidence intake."""

from __future__ import annotations

import json
import re

from pathlib import Path
from typing import Any
from urllib.parse import quote

import pandas as pd

from src.intake.unified_gateway import (
    ingest_bytes,
    serialize_envelope,
)
from src.intelligence.janvi_snapshot_provider import (
    lookup_cve,
    provider_summary,
)
from src.presentation_demo.sbom_ingestion import (
    SBOMIngestionError,
    scan_cyclonedx_bytes,
)


ROOT = Path(__file__).resolve().parents[2]

DEFAULT_JANVI_DATABASE = (
    ROOT
    / "data"
    / "external"
    / "janvi_snapshot_20260714"
    / "janvi_intelligence.sqlite"
)

CVE_PATTERN = re.compile(
    r"CVE-\d{4}-\d{4,}",
    re.IGNORECASE,
)


def generated_purl(
    component: dict[str, Any],
) -> str | None:
    existing = component.get("purl")

    if isinstance(existing, str) and existing.strip():
        return existing.strip()

    name = str(
        component.get("name") or ""
    ).strip()

    version = str(
        component.get("version") or ""
    ).strip()

    ecosystem = str(
        component.get("ecosystem") or ""
    ).strip()

    if not name or not version or not ecosystem:
        return None

    normalized = ecosystem.lower()

    if normalized == "pypi":
        return (
            "pkg:pypi/"
            + quote(name, safe="._-")
            + "@"
            + quote(version, safe="._+-")
        )

    if normalized == "npm":
        return (
            "pkg:npm/"
            + quote(name, safe="@/._-")
            + "@"
            + quote(version, safe="._+-")
        )

    if normalized == "maven":
        if ":" in name:
            group, artifact = name.split(
                ":",
                1,
            )

            return (
                "pkg:maven/"
                + quote(group, safe="._-")
                + "/"
                + quote(artifact, safe="._-")
                + "@"
                + quote(version, safe="._+-")
            )

        return None

    mappings = {
        "go": "golang",
        "crates.io": "cargo",
        "rubygems": "gem",
        "nuget": "nuget",
        "packagist": "composer",
        "debian": "deb",
        "alpine": "apk",
        "rpm": "rpm",
    }

    purl_type = mappings.get(
        normalized
    )

    if purl_type is None:
        return None

    return (
        f"pkg:{purl_type}/"
        + quote(name, safe="/._-")
        + "@"
        + quote(version, safe="._+-")
    )


def build_synthetic_cyclonedx(
    envelope: dict[str, Any],
) -> dict[str, Any]:
    """Convert canonical exact-version components into scan-compatible CDX."""

    components: list[dict[str, Any]] = []

    for component in envelope.get(
        "components",
        [],
    ):
        version = component.get(
            "version"
        )

        if not version:
            continue

        item: dict[str, Any] = {
            "type": "library",
            "name": component["name"],
            "version": version,
            "bom-ref": component[
                "component_id"
            ],
            "properties": [
                {
                    "name": (
                        "aegissec:"
                        "source_component_id"
                    ),
                    "value": component[
                        "component_id"
                    ],
                },
                {
                    "name": (
                        "aegissec:"
                        "source_identity_status"
                    ),
                    "value": component[
                        "identity_status"
                    ],
                },
            ],
        }

        purl = generated_purl(
            component
        )

        if purl:
            item["purl"] = purl

        supplier = component.get(
            "supplier"
        )

        if supplier:
            item["supplier"] = {
                "name": supplier
            }

        scope = component.get(
            "scope"
        )

        if scope in {
            "required",
            "optional",
            "excluded",
        }:
            item["scope"] = scope

        components.append(item)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": (
                    "AegisSec Unified Intake"
                ),
                "version": "1.0.0",
            },
            "properties": [
                {
                    "name": (
                        "aegissec:"
                        "source_input_id"
                    ),
                    "value": envelope[
                        "input_id"
                    ],
                },
                {
                    "name": (
                        "aegissec:"
                        "source_format"
                    ),
                    "value": envelope[
                        "detection"
                    ]["format"],
                },
            ],
        },
        "components": components,
    }


def dataframe_components(
    envelope: dict[str, Any],
) -> pd.DataFrame:
    columns = [
        "component_id",
        "name",
        "version",
        "raw_version",
        "ecosystem",
        "purl",
        "supplier",
        "scope",
        "identity_status",
        "source_location",
    ]

    frame = pd.DataFrame(
        envelope.get(
            "components",
            [],
        )
    )

    if frame.empty:
        return pd.DataFrame(
            columns=columns
        )

    available = [
        column
        for column in columns
        if column in frame.columns
    ]

    return frame[available]


def collect_cve_ids(
    envelope: dict[str, Any],
    scan: dict[str, Any] | None,
) -> list[str]:
    observed: set[str] = set()

    for hint in envelope.get(
        "vulnerability_hints",
        [],
    ):
        value = str(
            hint.get(
                "vulnerability_id"
            )
            or ""
        )

        for match in CVE_PATTERN.findall(
            value
        ):
            observed.add(
                match.upper()
            )

    if scan is not None:
        findings = scan.get(
            "vulnerability_findings"
        )

        if isinstance(
            findings,
            pd.DataFrame,
        ):
            for value in findings.astype(
                str
            ).to_numpy().ravel():
                for match in CVE_PATTERN.findall(
                    value
                ):
                    observed.add(
                        match.upper()
                    )

    return sorted(observed)


def snapshot_evidence(
    cve_ids: list[str],
    database_path: Path = (
        DEFAULT_JANVI_DATABASE
    ),
) -> pd.DataFrame:
    columns = [
        "cve_id",
        "snapshot_kev",
        "snapshot_epss",
        "snapshot_percentile",
        "snapshot_cvss",
        "snapshot_severity",
        "vendor",
        "product",
        "required_action",
        "snapshot_id",
    ]

    if not database_path.is_file():
        return pd.DataFrame(
            columns=columns
        )

    records: list[dict[str, Any]] = []

    for cve_id in cve_ids:
        record = lookup_cve(
            database_path,
            cve_id,
        )

        if record is None:
            continue

        records.append(
            {
                "cve_id": record[
                    "cve_id"
                ],
                "snapshot_kev": bool(
                    record[
                        "kev_flag"
                    ]
                ),
                "snapshot_epss": record[
                    "epss_score"
                ],
                "snapshot_percentile": (
                    record[
                        "epss_percentile"
                    ]
                ),
                "snapshot_cvss": record[
                    "cvss_score"
                ],
                "snapshot_severity": (
                    record["severity"]
                ),
                "vendor": record[
                    "cisa_vendor_project"
                ],
                "product": record[
                    "cisa_product"
                ],
                "required_action": record[
                    "cisa_required_action"
                ],
                "snapshot_id": record[
                    "source_snapshot_id"
                ],
            }
        )

    return pd.DataFrame(
        records,
        columns=columns,
    )


def load_snapshot_summary(
    database_path: Path = (
        DEFAULT_JANVI_DATABASE
    ),
) -> dict[str, Any] | None:
    if not database_path.is_file():
        return None

    return provider_summary(
        database_path
    )


def run_unified_scan(
    payload: bytes,
    *,
    filename: str,
    authorized: bool,
    declared_media_type: str | None = None,
    database_path: Path = (
        DEFAULT_JANVI_DATABASE
    ),
) -> dict[str, Any]:
    envelope = ingest_bytes(
        payload,
        filename=filename,
        authorized=authorized,
        declared_media_type=(
            declared_media_type
        ),
    )

    synthetic_document = (
        build_synthetic_cyclonedx(
            envelope
        )
    )

    exact_scan_components = len(
        synthetic_document[
            "components"
        ]
    )

    scan: dict[str, Any] | None = None
    scan_error: str | None = None

    if exact_scan_components:
        scan_payload = json.dumps(
            synthetic_document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        try:
            scan = scan_cyclonedx_bytes(
                scan_payload,
                filename=(
                    filename
                    + ".normalized.cdx.json"
                ),
            )
        except SBOMIngestionError as exc:
            scan_error = str(exc)
    else:
        scan_error = (
            "No exact-version components were "
            "eligible for governed vulnerability matching."
        )

    cve_ids = collect_cve_ids(
        envelope,
        scan,
    )

    historical_snapshot = (
        snapshot_evidence(
            cve_ids,
            database_path=database_path,
        )
    )

    return {
        "envelope": envelope,
        "envelope_bytes": (
            serialize_envelope(
                envelope
            )
        ),
        "component_frame": (
            dataframe_components(
                envelope
            )
        ),
        "synthetic_cyclonedx": (
            synthetic_document
        ),
        "exact_scan_components": (
            exact_scan_components
        ),
        "scan": scan,
        "scan_error": scan_error,
        "cve_ids": cve_ids,
        "snapshot_evidence": (
            historical_snapshot
        ),
        "snapshot_summary": (
            load_snapshot_summary(
                database_path
            )
        ),
        "governance": {
            "live_source_precedence": (
                True
            ),
            "snapshot_authority": (
                "HISTORICAL_READ_ONLY"
            ),
            "scanner_authority": (
                "ADVISORY_ONLY"
            ),
            "ssvc_authority": (
                "PRESERVED"
            ),
            "final_disposition": (
                "HUMAN"
            ),
            "production_readiness": (
                "BLOCKED"
            ),
        },
    }

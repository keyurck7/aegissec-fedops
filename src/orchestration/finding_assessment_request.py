"""Per-finding assessment request boundary for AegisSec-FedOps."""

from __future__ import annotations

import hashlib
import json
import os
import re

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import pandas as pd

from src.intake.unified_gateway import (
    verify_envelope_integrity,
)


SCHEMA_VERSION = "1.0.0"

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)

RUNTIME_SEMANTICS = (
    "Runtime reachability and mitigation influence exploitability "
    "and remediation handling, but do not rewrite whether the "
    "observed software version falls in an affected range."
)


class FindingAssessmentRequestError(
    RuntimeError
):
    """Raised when a per-finding request cannot be constructed safely."""


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def canonical_json_bytes(
    document: Any,
) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(
    payload: bytes,
) -> str:
    return hashlib.sha256(
        payload
    ).hexdigest()


def json_safe(
    value: Any,
) -> Any:
    if value is None:
        return None

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            json_safe(item)
            for item in value
        ]

    if isinstance(
        value,
        Path,
    ):
        return str(value)

    if isinstance(
        value,
        float,
    ) and pd.isna(value):
        return None

    if hasattr(
        value,
        "item",
    ):
        try:
            return json_safe(
                value.item()
            )
        except Exception:
            pass

    return value


def normalized_key(
    value: str,
) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        value.strip().lower(),
    ).strip("_")


def normalized_row(
    row: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        normalized_key(str(key)): (
            json_safe(value)
        )
        for key, value in row.items()
    }


def first_value(
    row: Mapping[str, Any],
    *aliases: str,
) -> Any:
    normalized = normalized_row(
        row
    )

    for alias in aliases:
        value = normalized.get(
            normalized_key(alias)
        )

        if value is None:
            continue

        if isinstance(value, str):
            value = value.strip()

            if not value:
                continue

        return value

    return None


def optional_float(
    value: Any,
) -> float | None:
    if value is None:
        return None

    try:
        parsed = float(value)
    except (
        TypeError,
        ValueError,
    ):
        return None

    if pd.isna(parsed):
        return None

    return parsed


def optional_bool(
    value: Any,
) -> bool | None:
    if value is None:
        return None

    if isinstance(
        value,
        bool,
    ):
        return value

    if isinstance(
        value,
        (
            int,
            float,
        ),
    ):
        return bool(value)

    normalized = str(
        value
    ).strip().lower()

    if normalized in {
        "true",
        "1",
        "yes",
        "y",
        "listed",
        "known",
    }:
        return True

    if normalized in {
        "false",
        "0",
        "no",
        "n",
        "not_listed",
        "not listed",
        "",
    }:
        return False

    return None


def extract_cve_id(
    row: Mapping[str, Any],
) -> str | None:
    candidate = first_value(
        row,
        "cve_id",
        "cve",
        "vulnerability_id",
        "vulnerability",
        "vuln_id",
        "finding_id",
    )

    if candidate is not None:
        match = CVE_PATTERN.search(
            str(candidate)
        )

        if match:
            return match.group(
                0
            ).upper()

    for value in row.values():
        if value is None:
            continue

        match = CVE_PATTERN.search(
            str(value)
        )

        if match:
            return match.group(
                0
            ).upper()

    return None


def component_index(
    envelope: Mapping[str, Any],
) -> dict[str, Any]:
    components = envelope.get(
        "components",
        [],
    )

    by_id: dict[str, dict[str, Any]] = {}
    by_purl: dict[str, dict[str, Any]] = {}
    by_name_version: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}
    by_name: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for raw_component in components:
        component = dict(
            raw_component
        )

        component_id = component.get(
            "component_id"
        )

        purl = component.get("purl")
        name = component.get("name")
        version = component.get(
            "version"
        )

        if component_id:
            by_id[
                str(component_id)
            ] = component

        if purl:
            by_purl[
                str(purl).lower()
            ] = component

        if name and version:
            by_name_version[
                (
                    str(name).lower(),
                    str(version),
                )
            ] = component

        if name:
            by_name.setdefault(
                str(name).lower(),
                [],
            ).append(component)

    return {
        "by_id": by_id,
        "by_purl": by_purl,
        "by_name_version": (
            by_name_version
        ),
        "by_name": by_name,
    }


def resolve_component(
    envelope: Mapping[str, Any],
    finding_row: Mapping[str, Any],
    matched_components: pd.DataFrame | None = None,
) -> dict[str, Any]:
    """Resolve a finding identity into the canonical intake component.

    Finding rows use the risk-mart component identifier. The matched-components
    table binds that identifier to the canonical input component through
    ``bom_ref``. Direct identity resolution remains available as a fallback.
    """

    index = component_index(
        envelope
    )

    component_id = first_value(
        finding_row,
        "component_id",
        "risk_component_id",
        "matched_component_id",
        "source_component_id",
        "input_component_id",
        "uploaded_component_id",
        "bom_ref",
        "bom-ref",
    )

    purl = first_value(
        finding_row,
        "purl",
        "component_purl",
        "package_purl",
        "package_url",
    )

    name = first_value(
        finding_row,
        "component_name",
        "package_name",
        "dependency_name",
        "artifact_name",
        "name",
        "package",
    )

    version = first_value(
        finding_row,
        "component_version",
        "package_version",
        "installed_version",
        "resolved_version",
        "version",
    )

    ecosystem = first_value(
        finding_row,
        "ecosystem",
        "package_ecosystem",
        "package_type",
        "component_type",
        "type",
    )

    # Direct canonical component ID.
    if (
        component_id
        and str(component_id)
        in index["by_id"]
    ):
        return dict(
            index["by_id"][
                str(component_id)
            ]
        )

    # Direct canonical PURL.
    if (
        purl
        and str(purl).lower()
        in index["by_purl"]
    ):
        return dict(
            index["by_purl"][
                str(purl).lower()
            ]
        )

    # Explicit bridge:
    # risk-mart component_id -> matched row -> bom_ref -> intake component_id.
    bridge_rows: list[
        dict[str, Any]
    ] = []

    if (
        component_id
        and isinstance(
            matched_components,
            pd.DataFrame,
        )
        and not matched_components.empty
    ):
        for raw_row in matched_components.to_dict(
            orient="records"
        ):
            row = normalized_row(
                raw_row
            )

            risk_component_id = first_value(
                row,
                "component_id",
                "risk_component_id",
                "matched_component_id",
            )

            if (
                risk_component_id is not None
                and str(risk_component_id)
                == str(component_id)
            ):
                bridge_rows.append(
                    row
                )

    bridge_rows.sort(
        key=lambda row: (
            str(
                first_value(
                    row,
                    "bom_ref",
                    "input_component_id",
                )
                or ""
            ),
            str(
                first_value(
                    row,
                    "purl",
                    "component_purl",
                )
                or ""
            ),
            str(
                first_value(
                    row,
                    "package_name",
                    "component_name",
                    "name",
                )
                or ""
            ),
            str(
                first_value(
                    row,
                    "version",
                    "component_version",
                )
                or ""
            ),
        )
    )

    for bridge in bridge_rows:
        canonical_id = first_value(
            bridge,
            "bom_ref",
            "bom-ref",
            "input_component_id",
            "uploaded_component_id",
            "source_component_id",
        )

        if (
            canonical_id
            and str(canonical_id)
            in index["by_id"]
        ):
            return dict(
                index["by_id"][
                    str(canonical_id)
                ]
            )

        bridge_purl = first_value(
            bridge,
            "purl",
            "component_purl",
            "package_purl",
            "package_url",
        )

        if (
            bridge_purl
            and str(bridge_purl).lower()
            in index["by_purl"]
        ):
            return dict(
                index["by_purl"][
                    str(bridge_purl).lower()
                ]
            )

        bridge_name = first_value(
            bridge,
            "component_name",
            "package_name",
            "dependency_name",
            "artifact_name",
            "name",
        )

        bridge_version = first_value(
            bridge,
            "component_version",
            "package_version",
            "installed_version",
            "resolved_version",
            "version",
        )

        if (
            bridge_name
            and bridge_version
        ):
            key = (
                str(
                    bridge_name
                ).lower(),
                str(
                    bridge_version
                ),
            )

            if (
                key
                in index[
                    "by_name_version"
                ]
            ):
                return dict(
                    index[
                        "by_name_version"
                    ][key]
                )

    # Direct name and version fallback.
    if name and version:
        key = (
            str(name).lower(),
            str(version),
        )

        if (
            key
            in index[
                "by_name_version"
            ]
        ):
            return dict(
                index[
                    "by_name_version"
                ][key]
            )

    # A unique component name may be used only when unambiguous.
    if name:
        candidates = index[
            "by_name"
        ].get(
            str(name).lower(),
            [],
        )

        if len(candidates) == 1:
            return dict(
                candidates[0]
            )

    # Preserve the unresolved source identity. Never manufacture certainty.
    return {
        "component_id": (
            str(component_id)
            if component_id
            else None
        ),
        "name": (
            str(name)
            if name
            else None
        ),
        "version": (
            str(version)
            if version
            else None
        ),
        "ecosystem": (
            str(ecosystem)
            if ecosystem
            else None
        ),
        "purl": (
            str(purl)
            if purl
            else None
        ),
        "identity_status": (
            "UNRESOLVED_FINDING_IDENTITY"
        ),
    }


def runtime_defaults(
    runtime_context: Mapping[
        str,
        Any,
    ] | None,
) -> dict[str, Any]:
    supplied = dict(
        runtime_context
        or {}
    )

    return {
        "presence": str(
            supplied.get(
                "presence",
                "PRESENT",
            )
        ).upper(),
        "reachability": str(
            supplied.get(
                "reachability",
                "UNKNOWN",
            )
        ).upper(),
        "configuration": str(
            supplied.get(
                "configuration",
                "UNKNOWN",
            )
        ).upper(),
        "affectedness_semantics": (
            supplied.get(
                "affectedness_semantics"
            )
            or RUNTIME_SEMANTICS
        ),
        **{
            str(key): json_safe(value)
            for key, value
            in supplied.items()
            if key
            not in {
                "presence",
                "reachability",
                "configuration",
                "affectedness_semantics",
            }
        },
    }


def selected_finding_evidence(
    finding_row: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "technical": {
            "cvss_score": optional_float(
                first_value(
                    finding_row,
                    "cvss_score",
                    "cvss",
                    "base_score",
                )
            ),
            "severity": first_value(
                finding_row,
                "severity",
                "base_severity",
                "cvss_severity",
            ),
            "cvss_vector": first_value(
                finding_row,
                "cvss_vector",
                "vector",
                "vector_string",
            ),
            "source_name": first_value(
                finding_row,
                "source_name",
                "vulnerability_source",
                "source",
            ),
        },
        "exploitation": {
            "epss_score": optional_float(
                first_value(
                    finding_row,
                    "epss_score",
                    "epss",
                    "probability",
                )
            ),
            "epss_percentile": (
                optional_float(
                    first_value(
                        finding_row,
                        "epss_percentile",
                        "percentile",
                    )
                )
            ),
            "kev_flag": optional_bool(
                first_value(
                    finding_row,
                    "kev_flag",
                    "kev",
                    "is_kev",
                    "known_exploited",
                    "cisa_kev",
                )
            ),
            "known_ransomware_use": (
                first_value(
                    finding_row,
                    "known_ransomware_use",
                    "cisa_known_ransomware_use",
                    "ransomware_use",
                )
            ),
        },
    }


def historical_snapshot_for_cve(
    snapshot_frame: pd.DataFrame,
    cve_id: str | None,
) -> dict[str, Any] | None:
    if (
        cve_id is None
        or snapshot_frame.empty
    ):
        return None

    candidate_columns = [
        column
        for column
        in snapshot_frame.columns
        if normalized_key(
            str(column)
        )
        in {
            "cve_id",
            "cve",
            "vulnerability_id",
        }
    ]

    if not candidate_columns:
        return None

    column = candidate_columns[0]

    matches = snapshot_frame[
        snapshot_frame[column]
        .astype(str)
        .str.upper()
        == cve_id.upper()
    ]

    if matches.empty:
        return None

    return json_safe(
        matches.iloc[0].to_dict()
    )


def build_finding_assessment_request(
    *,
    input_envelope: Mapping[
        str,
        Any,
    ],
    asset_context: Mapping[
        str,
        Any,
    ],
    component: Mapping[
        str,
        Any,
    ],
    finding_row: Mapping[
        str,
        Any,
    ],
    historical_snapshot: Mapping[
        str,
        Any,
    ] | None = None,
    runtime_context: Mapping[
        str,
        Any,
    ] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    safe_finding = json_safe(
        dict(finding_row)
    )

    cve_id = extract_cve_id(
        safe_finding
    )

    safe_component = {
        "component_id": (
            component.get(
                "component_id"
            )
        ),
        "name": component.get(
            "name"
        ),
        "version": component.get(
            "version"
        ),
        "ecosystem": component.get(
            "ecosystem"
        ),
        "purl": component.get(
            "purl"
        ),
        "identity_status": (
            component.get(
                "identity_status"
            )
        ),
    }

    asset_id = (
        asset_context.get(
            "asset_id"
        )
        or asset_context.get(
            "record_id"
        )
    )

    asset_document = json_safe(
        dict(asset_context)
    )

    asset_sha256 = sha256_bytes(
        canonical_json_bytes(
            asset_document
        )
    )

    finding_sha256 = sha256_bytes(
        canonical_json_bytes(
            safe_finding
        )
    )

    input_valid = (
        verify_envelope_integrity(
            dict(input_envelope)
        )
    )

    blocking: list[str] = []
    warnings: list[str] = []

    if not input_valid:
        blocking.append(
            "INPUT_ENVELOPE_INTEGRITY_FAILED"
        )

    if not asset_id:
        blocking.append(
            "ASSET_IDENTIFIER_MISSING"
        )

    if not safe_component["name"]:
        blocking.append(
            "COMPONENT_NAME_MISSING"
        )

    if not safe_component[
        "version"
    ]:
        blocking.append(
            "EXACT_COMPONENT_VERSION_MISSING"
        )

    if not (
        safe_component["ecosystem"]
        or safe_component["purl"]
    ):
        blocking.append(
            "COMPONENT_ECOSYSTEM_AND_PURL_MISSING"
        )

    if cve_id is None:
        blocking.append(
            "CVE_IDENTIFIER_MISSING_OR_INVALID"
        )

    runtime = runtime_defaults(
        runtime_context
    )

    if (
        runtime["reachability"]
        == "UNKNOWN"
    ):
        warnings.append(
            "RUNTIME_REACHABILITY_UNKNOWN"
        )

    if (
        runtime["configuration"]
        == "UNKNOWN"
    ):
        warnings.append(
            "RUNTIME_CONFIGURATION_UNKNOWN"
        )

    selected = (
        selected_finding_evidence(
            safe_finding
        )
    )

    if (
        selected["exploitation"][
            "epss_score"
        ]
        is None
    ):
        warnings.append(
            "EPSS_UNKNOWN"
        )

    if (
        selected["exploitation"][
            "kev_flag"
        ]
        is None
    ):
        warnings.append(
            "KEV_CONFIRMATION_UNKNOWN"
        )

    status = (
        "BLOCKED"
        if blocking
        else "READY_FOR_AFFECTEDNESS"
    )

    created = (
        created_at
        or utc_now()
    )

    request_seed = {
        "asset_id": asset_id,
        "component": (
            safe_component
        ),
        "cve_id": cve_id,
        "input_envelope_sha256": (
            input_envelope[
                "integrity"
            ]["envelope_sha256"]
        ),
        "correlation_row_sha256": (
            finding_sha256
        ),
        "asset_context_sha256": (
            asset_sha256
        ),
        "historical_snapshot": (
            json_safe(
                historical_snapshot
            )
        ),
    }

    request_id = (
        "AEG-FAR-"
        + sha256_bytes(
            canonical_json_bytes(
                request_seed
            )
        )[:24].upper()
    )

    unsigned = {
        "schema_version": (
            SCHEMA_VERSION
        ),
        "request_id": request_id,
        "created_at": created,
        "status": status,
        "unit_of_assessment": {
            "asset_id": asset_id,
            "component": (
                safe_component
            ),
            "cve_id": cve_id,
        },
        "input_reference": {
            "input_id": (
                input_envelope[
                    "input_id"
                ]
            ),
            "input_envelope_sha256": (
                input_envelope[
                    "integrity"
                ]["envelope_sha256"]
            ),
        },
        "asset_context": {
            "record_id": asset_id,
            "sha256": asset_sha256,
            "criticality": json_safe(
                asset_context.get(
                    "criticality",
                    {},
                )
            ),
            "exposure": json_safe(
                asset_context.get(
                    "exposure",
                    {},
                )
            ),
            "impact_assessment": (
                json_safe(
                    asset_context.get(
                        "impact_assessment",
                        {},
                    )
                )
            ),
        },
        "runtime_context": runtime,
        "evidence_snapshot": {
            "correlation_source": (
                "GOVERNED_PRESENTATION_RISK_MART"
            ),
            "correlation_authority": (
                "CORRELATION_EVIDENCE_ONLY"
            ),
            "correlation_row_sha256": (
                finding_sha256
            ),
            "technical": (
                selected["technical"]
            ),
            "exploitation": (
                selected[
                    "exploitation"
                ]
            ),
            "historical_intelligence": (
                json_safe(
                    historical_snapshot
                )
            ),
        },
        "readiness": {
            "status": status,
            "blocking_reason_codes": (
                sorted(
                    set(blocking)
                )
            ),
            "warnings": sorted(
                set(warnings)
            ),
        },
        "governance": {
            "request_authority": (
                "ASSESSMENT_INPUT_ONLY"
            ),
            "affectedness_authority": (
                "DETERMINISTIC_ENGINE"
            ),
            "policy_authority": (
                "SSVC"
            ),
            "model_authority": (
                "ADVISORY_ONLY"
            ),
            "may_override_ssvc": (
                False
            ),
            "automated_disposition_permitted": (
                False
            ),
            "final_disposition_authority": (
                "HUMAN"
            ),
            "production_readiness": (
                "BLOCKED"
            ),
        },
    }

    return {
        **unsigned,
        "integrity": {
            "request_sha256": (
                sha256_bytes(
                    canonical_json_bytes(
                        unsigned
                    )
                )
            ),
        },
    }


def verify_finding_assessment_request(
    request: Mapping[str, Any],
) -> bool:
    integrity = request.get(
        "integrity"
    )

    if not isinstance(
        integrity,
        Mapping,
    ):
        return False

    expected = integrity.get(
        "request_sha256"
    )

    if not isinstance(
        expected,
        str,
    ):
        return False

    unsigned = {
        key: value
        for key, value
        in request.items()
        if key != "integrity"
    }

    observed = sha256_bytes(
        canonical_json_bytes(
            unsigned
        )
    )

    return observed == expected


def build_requests_from_workbench(
    *,
    workbench_result: Mapping[
        str,
        Any,
    ],
    asset_context: Mapping[
        str,
        Any,
    ],
    runtime_context: Mapping[
        str,
        Any,
    ] | None = None,
    maximum_requests: int = 10_000,
) -> dict[str, Any]:
    envelope = workbench_result[
        "envelope"
    ]

    scan = workbench_result.get(
        "scan"
    )

    if not isinstance(
        scan,
        Mapping,
    ):
        raise FindingAssessmentRequestError(
            "Workbench result has no governed scan."
        )

    findings = scan.get(
        "vulnerability_findings"
    )

    if not isinstance(
        findings,
        pd.DataFrame,
    ):
        raise FindingAssessmentRequestError(
            "Vulnerability findings must be a DataFrame."
        )

    matched_components = scan.get(
        "matched_components"
    )

    if not isinstance(
        matched_components,
        pd.DataFrame,
    ):
        matched_components = pd.DataFrame()

    if len(findings) > maximum_requests:
        raise FindingAssessmentRequestError(
            "Finding count exceeds the governed request limit."
        )

    snapshot_frame = (
        workbench_result.get(
            "snapshot_evidence"
        )
    )

    if not isinstance(
        snapshot_frame,
        pd.DataFrame,
    ):
        snapshot_frame = pd.DataFrame()

    observed: dict[
        str,
        dict[str, Any],
    ] = {}

    duplicate_count = 0

    for _, series in findings.iterrows():
        finding_row = json_safe(
            series.to_dict()
        )

        component = resolve_component(
            envelope,
            finding_row,
            matched_components=(
                matched_components
            ),
        )

        cve_id = extract_cve_id(
            finding_row
        )

        historical = (
            historical_snapshot_for_cve(
                snapshot_frame,
                cve_id,
            )
        )

        request = (
            build_finding_assessment_request(
                input_envelope=(
                    envelope
                ),
                asset_context=(
                    asset_context
                ),
                component=component,
                finding_row=(
                    finding_row
                ),
                historical_snapshot=(
                    historical
                ),
                runtime_context=(
                    runtime_context
                ),
            )
        )

        request_id = request[
            "request_id"
        ]

        if request_id in observed:
            duplicate_count += 1
            continue

        observed[
            request_id
        ] = request

    requests = sorted(
        observed.values(),
        key=lambda item: (
            str(
                item[
                    "unit_of_assessment"
                ]["cve_id"]
                or ""
            ),
            str(
                item[
                    "unit_of_assessment"
                ]["component"].get(
                    "name"
                )
                or ""
            ),
            item["request_id"],
        ),
    )

    ready_count = sum(
        request["status"]
        == "READY_FOR_AFFECTEDNESS"
        for request in requests
    )

    blocked_count = (
        len(requests)
        - ready_count
    )

    unique_components = {
        request[
            "unit_of_assessment"
        ]["component"].get(
            "component_id"
        )
        or (
            request[
                "unit_of_assessment"
            ]["component"].get(
                "name"
            ),
            request[
                "unit_of_assessment"
            ]["component"].get(
                "version"
            ),
        )
        for request in requests
    }

    unique_cves = {
        request[
            "unit_of_assessment"
        ]["cve_id"]
        for request in requests
        if request[
            "unit_of_assessment"
        ]["cve_id"]
    }

    unsigned_manifest = {
        "schema_version": "1.0.0",
        "generated_at": utc_now(),
        "input_id": envelope[
            "input_id"
        ],
        "asset_id": (
            asset_context.get(
                "asset_id"
            )
            or asset_context.get(
                "record_id"
            )
        ),
        "statistics": {
            "source_finding_rows": (
                len(findings)
            ),
            "request_count": (
                len(requests)
            ),
            "ready_count": ready_count,
            "blocked_count": (
                blocked_count
            ),
            "duplicate_request_count": (
                duplicate_count
            ),
            "unique_component_count": (
                len(unique_components)
            ),
            "unique_cve_count": (
                len(unique_cves)
            ),
        },
        "requests": requests,
        "governance": {
            "unit_of_assessment": (
                "ASSET_X_COMPONENT_VERSION_X_CVE_X_EVIDENCE_SNAPSHOT"
            ),
            "affectedness_authority": (
                "DETERMINISTIC_ENGINE"
            ),
            "policy_authority": (
                "SSVC"
            ),
            "model_authority": (
                "ADVISORY_ONLY"
            ),
            "final_disposition_authority": (
                "HUMAN"
            ),
            "production_readiness": (
                "BLOCKED"
            ),
        },
    }

    return {
        **unsigned_manifest,
        "integrity": {
            "manifest_sha256": (
                sha256_bytes(
                    canonical_json_bytes(
                        unsigned_manifest
                    )
                )
            ),
        },
    }


def write_manifest_atomic(
    manifest: Mapping[str, Any],
    path: Path,
) -> tuple[Path, Path]:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = canonical_json_bytes(
        manifest
    )

    temporary = path.with_name(
        "." + path.name + ".partial"
    )

    with temporary.open(
        "wb"
    ) as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(
            handle.fileno()
        )

    os.replace(
        temporary,
        path,
    )

    digest = sha256_bytes(
        payload
    )

    sidecar = Path(
        str(path) + ".sha256"
    )

    sidecar.write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
    )

    return path, sidecar

"""Governed CycloneDX SBOM ingestion and risk-mart correlation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DEFAULT_DATABASE = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "aegissec_presentation_risk_mart.sqlite"
)

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_COMPONENTS = 10_000

PURL_ECOSYSTEMS = {
    "maven": "Maven",
    "pypi": "PyPI",
    "npm": "npm",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "golang": "Go",
}


class SBOMIngestionError(RuntimeError):
    """Raised when an SBOM cannot be processed safely."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def normalize_text(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip().casefold()


def parse_purl(
    purl: str,
) -> dict[str, str | None]:
    empty = {
        "purl_type": None,
        "ecosystem": None,
        "package_name": None,
        "version": None,
    }

    if not isinstance(purl, str):
        return empty

    if not purl.startswith("pkg:"):
        return empty

    body = (
        purl[4:]
        .split("#", 1)[0]
        .split("?", 1)[0]
    )

    if "/" not in body:
        return empty

    purl_type, remainder = body.split(
        "/",
        1,
    )

    if "@" in remainder:
        package_path, version = remainder.rsplit(
            "@",
            1,
        )
    else:
        package_path = remainder
        version = None

    purl_type = unquote(
        purl_type
    ).casefold()

    package_path = unquote(
        package_path
    )

    version = (
        unquote(version)
        if version
        else None
    )

    ecosystem = PURL_ECOSYSTEMS.get(
        purl_type
    )

    if purl_type == "maven":
        parts = package_path.split("/")

        if len(parts) >= 2:
            package_name = (
                ".".join(parts[:-1])
                + ":"
                + parts[-1]
            )
        else:
            package_name = package_path
    else:
        package_name = package_path

    return {
        "purl_type": purl_type,
        "ecosystem": ecosystem,
        "package_name": package_name,
        "version": version,
    }


def property_map(
    component: dict[str, Any],
) -> dict[str, str]:
    properties = component.get(
        "properties",
        [],
    )

    if not isinstance(
        properties,
        list,
    ):
        return {}

    output: dict[str, str] = {}

    for item in properties:
        if not isinstance(
            item,
            dict,
        ):
            continue

        name = item.get("name")
        value = item.get("value")

        if isinstance(
            name,
            str,
        ):
            output[name] = str(
                value
                if value is not None
                else ""
            )

    return output


def parse_boolean(
    value: str | None,
) -> bool | None:
    if value is None:
        return None

    normalized = value.strip().casefold()

    if normalized in {
        "true",
        "yes",
        "1",
    }:
        return True

    if normalized in {
        "false",
        "no",
        "0",
    }:
        return False

    return None


def extract_component_identity(
    component: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    purl = component.get(
        "purl"
    )

    if not isinstance(
        purl,
        str,
    ):
        purl = ""

    parsed_purl = parse_purl(
        purl
    )

    properties = property_map(
        component
    )

    group = component.get(
        "group"
    )

    if not isinstance(
        group,
        str,
    ):
        group = ""

    name = component.get(
        "name"
    )

    if not isinstance(
        name,
        str,
    ):
        name = ""

    ecosystem = (
        parsed_purl["ecosystem"]
        or properties.get(
            "aegissec:ecosystem"
        )
        or ""
    )

    package_name = (
        parsed_purl["package_name"]
        or properties.get(
            "aegissec:component_name"
        )
        or ""
    )

    if not package_name:
        if (
            ecosystem == "Maven"
            and group
            and name
        ):
            package_name = (
                f"{group}:{name}"
            )
        else:
            package_name = name

    version = component.get(
        "version"
    )

    if not isinstance(
        version,
        str,
    ):
        version = ""

    version = (
        version
        or parsed_purl["version"]
        or ""
    )

    identity_complete = bool(
        ecosystem
        and package_name
        and version
    )

    return {
        "sbom_index": index,
        "bom_ref": component.get(
            "bom-ref"
        ),
        "component_type": component.get(
            "type"
        ),
        "ecosystem": ecosystem,
        "package_name": package_name,
        "version": version,
        "purl": purl,
        "identity_status": (
            "COMPLETE"
            if identity_complete
            else "UNKNOWN"
        ),
        "asset_id": properties.get(
            "aegissec:asset_id"
        ),
        "asset_name": properties.get(
            "aegissec:asset_name"
        ),
        "sector": properties.get(
            "aegissec:sector"
        ),
        "criticality": properties.get(
            "aegissec:criticality"
        ),
        "internet_exposed":
            parse_boolean(
                properties.get(
                    "aegissec:"
                    "internet_exposed"
                )
            ),
        "mission_essential":
            parse_boolean(
                properties.get(
                    "aegissec:"
                    "mission_essential"
                )
            ),
    }


def parse_cyclonedx_bytes(
    payload: bytes,
    filename: str = (
        "uploaded.cdx.json"
    ),
) -> dict[str, Any]:
    if not isinstance(
        payload,
        bytes,
    ):
        raise SBOMIngestionError(
            "SBOM payload must be bytes."
        )

    if not payload:
        raise SBOMIngestionError(
            "The uploaded SBOM is empty."
        )

    if len(payload) > MAX_UPLOAD_BYTES:
        raise SBOMIngestionError(
            "The uploaded SBOM exceeds "
            "the 5 MB limit."
        )

    try:
        text = payload.decode(
            "utf-8"
        )
    except UnicodeDecodeError as exc:
        raise SBOMIngestionError(
            "The SBOM must be UTF-8."
        ) from exc

    try:
        document = json.loads(
            text
        )
    except json.JSONDecodeError as exc:
        raise SBOMIngestionError(
            "Invalid JSON at "
            f"line {exc.lineno}, "
            f"column {exc.colno}."
        ) from exc

    if not isinstance(
        document,
        dict,
    ):
        raise SBOMIngestionError(
            "CycloneDX JSON must be "
            "a top-level object."
        )

    if (
        document.get("bomFormat")
        != "CycloneDX"
    ):
        raise SBOMIngestionError(
            "Only CycloneDX JSON "
            "SBOMs are accepted."
        )

    spec_version = document.get(
        "specVersion"
    )

    if not isinstance(
        spec_version,
        str,
    ):
        raise SBOMIngestionError(
            "CycloneDX specVersion "
            "is required."
        )

    components = document.get(
        "components"
    )

    if not isinstance(
        components,
        list,
    ):
        raise SBOMIngestionError(
            "CycloneDX components "
            "must be an array."
        )

    if not components:
        raise SBOMIngestionError(
            "The CycloneDX SBOM "
            "contains no components."
        )

    if (
        len(components)
        > MAX_COMPONENTS
    ):
        raise SBOMIngestionError(
            "The SBOM exceeds the "
            "10,000-component limit."
        )

    parsed_components = []

    for index, component in enumerate(
        components
    ):
        if not isinstance(
            component,
            dict,
        ):
            raise SBOMIngestionError(
                "Component at index "
                f"{index} is not an object."
            )

        parsed_components.append(
            extract_component_identity(
                component,
                index,
            )
        )

    return {
        "filename": filename,
        "sha256": sha256_bytes(
            payload
        ),
        "size_bytes": len(payload),
        "bom_format": "CycloneDX",
        "spec_version": spec_version,
        "serial_number": document.get(
            "serialNumber"
        ),
        "sbom_version": document.get(
            "version"
        ),
        "component_count": len(
            parsed_components
        ),
        "identity_complete_count": sum(
            component[
                "identity_status"
            ]
            == "COMPLETE"
            for component
            in parsed_components
        ),
        "identity_unknown_count": sum(
            component[
                "identity_status"
            ]
            != "COMPLETE"
            for component
            in parsed_components
        ),
        "components":
            parsed_components,
        "validation_status":
            "PASS",
    }


def load_risk_mart(
    database_path: Path,
) -> tuple[
    pd.DataFrame,
    pd.DataFrame,
]:
    if not database_path.is_file():
        raise SBOMIngestionError(
            "Risk mart is missing: "
            f"{database_path}"
        )

    connection = sqlite3.connect(
        database_path
    )

    try:
        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if integrity != "ok":
            raise SBOMIngestionError(
                "SQLite integrity "
                f"failed: {integrity}"
            )

        components = pd.read_sql_query(
            """
            SELECT
                component_id,
                sector,
                ecosystem,
                package_name,
                version,
                target,
                purl,
                criticality,
                internet_exposed,
                mission_essential,
                vulnerability_count,
                kev_count,
                max_epss,
                source_signal,
                analytics_signal,
                attention_score
            FROM components
            """,
            connection,
        )

        findings = pd.read_sql_query(
            """
            SELECT
                cv.component_id,
                v.vulnerability_id,
                v.primary_cve,
                v.severity,
                v.cvss_score,
                v.epss_score,
                v.kev
            FROM component_vulnerabilities AS cv
            JOIN vulnerabilities AS v
              ON v.vulnerability_id =
                 cv.vulnerability_id
            ORDER BY
                cv.component_id,
                v.kev DESC,
                v.epss_score DESC,
                v.vulnerability_id
            """,
            connection,
        )

    finally:
        connection.close()

    return components, findings


def match_component(
    uploaded: dict[str, Any],
    risk_components: pd.DataFrame,
) -> tuple[
    pd.Series | None,
    str,
    str,
]:
    if (
        uploaded["identity_status"]
        != "COMPLETE"
    ):
        return (
            None,
            "NO_MATCH",
            "INCOMPLETE_IDENTITY",
        )

    uploaded_purl = normalize_text(
        uploaded.get("purl")
    )

    if uploaded_purl:
        purl_matches = risk_components[
            risk_components["purl"]
            .fillna("")
            .map(normalize_text)
            == uploaded_purl
        ]

        if len(purl_matches) == 1:
            return (
                purl_matches.iloc[0],
                "EXACT_PURL",
                "",
            )

        if len(purl_matches) > 1:
            return (
                None,
                "AMBIGUOUS",
                "MULTIPLE_PURL_MATCHES",
            )

    ecosystem = normalize_text(
        uploaded.get("ecosystem")
    )

    package_name = normalize_text(
        uploaded.get("package_name")
    )

    version = str(
        uploaded.get("version")
        or ""
    ).strip()

    identity_matches = risk_components[
        (
            risk_components[
                "ecosystem"
            ]
            .fillna("")
            .map(normalize_text)
            == ecosystem
        )
        & (
            risk_components[
                "package_name"
            ]
            .fillna("")
            .map(normalize_text)
            == package_name
        )
        & (
            risk_components[
                "version"
            ]
            .fillna("")
            .astype(str)
            .str.strip()
            == version
        )
    ]

    if len(identity_matches) == 1:
        return (
            identity_matches.iloc[0],
            (
                "EXACT_ECOSYSTEM_"
                "NAME_VERSION"
            ),
            "",
        )

    if len(identity_matches) > 1:
        return (
            None,
            "AMBIGUOUS",
            "MULTIPLE_IDENTITY_MATCHES",
        )

    target = (
        str(
            uploaded.get(
                "package_name"
            )
            or ""
        )
        + "@"
        + version
    )

    target_matches = risk_components[
        risk_components[
            "target"
        ]
        .fillna("")
        .map(normalize_text)
        == normalize_text(target)
    ]

    if len(target_matches) == 1:
        return (
            target_matches.iloc[0],
            "EXACT_TARGET",
            "",
        )

    return (
        None,
        "NO_MATCH",
        "NOT_IN_GOVERNED_RISK_MART",
    )


def scan_cyclonedx_bytes(
    payload: bytes,
    filename: str = (
        "uploaded.cdx.json"
    ),
    database_path: Path = (
        DEFAULT_DATABASE
    ),
) -> dict[str, Any]:
    parsed = parse_cyclonedx_bytes(
        payload,
        filename=filename,
    )

    (
        risk_components,
        risk_findings,
    ) = load_risk_mart(
        database_path
    )

    matched_rows = []
    unmatched_rows = []

    for uploaded in parsed[
        "components"
    ]:
        (
            matched,
            method,
            reason,
        ) = match_component(
            uploaded,
            risk_components,
        )

        base = {
            "sbom_index":
                uploaded["sbom_index"],
            "bom_ref":
                uploaded["bom_ref"],
            "ecosystem":
                uploaded["ecosystem"],
            "package_name":
                uploaded["package_name"],
            "version":
                uploaded["version"],
            "purl":
                uploaded["purl"],
            "identity_status":
                uploaded[
                    "identity_status"
                ],
            "match_method":
                method,
        }

        if matched is None:
            unmatched_rows.append(
                {
                    **base,
                    "reason": reason,
                }
            )

            continue

        max_epss = matched[
            "max_epss"
        ]

        matched_rows.append(
            {
                **base,
                "component_id":
                    matched[
                        "component_id"
                    ],
                "sector":
                    matched["sector"],
                "criticality":
                    matched[
                        "criticality"
                    ],
                "internet_exposed":
                    bool(
                        matched[
                            "internet_exposed"
                        ]
                    ),
                "mission_essential":
                    bool(
                        matched[
                            "mission_essential"
                        ]
                    ),
                "vulnerability_count":
                    int(
                        matched[
                            "vulnerability_count"
                        ]
                    ),
                "kev_count":
                    int(
                        matched[
                            "kev_count"
                        ]
                    ),
                "max_epss": (
                    float(max_epss)
                    if pd.notna(
                        max_epss
                    )
                    else None
                ),
                "source_signal":
                    matched[
                        "source_signal"
                    ],
                "analytics_signal":
                    matched[
                        "analytics_signal"
                    ],
                "attention_score":
                    float(
                        matched[
                            "attention_score"
                        ]
                    ),
            }
        )

    matched_frame = pd.DataFrame(
        matched_rows
    )

    unmatched_frame = pd.DataFrame(
        unmatched_rows
    )

    if matched_frame.empty:
        findings_frame = (
            risk_findings.iloc[
                0:0
            ].copy()
        )
    else:
        findings_frame = (
            risk_findings[
                risk_findings[
                    "component_id"
                ].isin(
                    matched_frame[
                        "component_id"
                    ]
                )
            ].copy()
        )

    vulnerable_components = (
        int(
            (
                matched_frame[
                    "vulnerability_count"
                ]
                > 0
            ).sum()
        )
        if not matched_frame.empty
        else 0
    )

    kev_components = (
        int(
            (
                matched_frame[
                    "kev_count"
                ]
                > 0
            ).sum()
        )
        if not matched_frame.empty
        else 0
    )

    maximum_epss = None

    if (
        not matched_frame.empty
        and matched_frame[
            "max_epss"
        ].notna().any()
    ):
        maximum_epss = float(
            matched_frame[
                "max_epss"
            ].dropna().max()
        )

    if matched_frame.empty:
        operational_status = (
            "NO_GOVERNED_MATCHES"
        )
    elif kev_components > 0:
        operational_status = (
            "IMMEDIATE_HUMAN_REVIEW"
        )
    elif (
        maximum_epss is not None
        and maximum_epss >= 0.50
    ):
        operational_status = (
            "PREDICTIVE_REVIEW"
        )
    elif vulnerable_components > 0:
        operational_status = (
            "VULNERABILITIES_IDENTIFIED"
        )
    else:
        operational_status = (
            "NO_KNOWN_MATCHES_"
            "IN_CURRENT_SNAPSHOT"
        )

    return {
        "document": parsed,
        "summary": {
            "uploaded_components":
                parsed[
                    "component_count"
                ],
            "identity_complete":
                parsed[
                    "identity_complete_count"
                ],
            "identity_unknown":
                parsed[
                    "identity_unknown_count"
                ],
            "matched_components":
                len(matched_frame),
            "unmatched_components":
                len(unmatched_frame),
            "vulnerable_matched_components":
                vulnerable_components,
            "components_with_kev":
                kev_components,
            "vulnerability_evidence_rows":
                len(findings_frame),
            "maximum_epss":
                maximum_epss,
            "operational_status":
                operational_status,
            "clean_bill_of_health":
                False,
            "stage_gate":
                "PASS",
            "production_readiness":
                "BLOCKED",
        },
        "matched_components":
            matched_frame,
        "unmatched_components":
            unmatched_frame,
        "vulnerability_findings":
            findings_frame,
        "governance": {
            "input_authority":
                "UPLOADED_EVIDENCE",
            "analytics_authority":
                "PRESENTATION_ANALYTICS_ONLY",
            "authoritative_policy_engine":
                "SSVC",
            "automated_disposition_permitted":
                False,
            "human_review_required":
                True,
            "clean_bill_of_health_permitted":
                False,
            "production_readiness":
                "BLOCKED",
        },
    }


def dataframe_records(
    frame: pd.DataFrame,
) -> list[dict[str, Any]]:
    if frame.empty:
        return []

    return json.loads(
        frame.to_json(
            orient="records",
            date_format="iso",
        )
    )


def serializable_scan(
    result: dict[str, Any],
) -> dict[str, Any]:
    return {
        "document":
            result["document"],
        "summary":
            result["summary"],
        "matched_components":
            dataframe_records(
                result[
                    "matched_components"
                ]
            ),
        "unmatched_components":
            dataframe_records(
                result[
                    "unmatched_components"
                ]
            ),
        "vulnerability_findings":
            dataframe_records(
                result[
                    "vulnerability_findings"
                ]
            ),
        "governance":
            result["governance"],
    }

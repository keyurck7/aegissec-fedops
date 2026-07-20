from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from src.presentation_demo.sqlite_analytics import (
    PresentationAnalyticsError,
    build_risk_mart,
    sha256_file,
)


def example_report() -> dict:
    return {
        "governance": {
            "authoritative_policy_engine":
                "SSVC",
            "production_readiness":
                "BLOCKED",
        },
        "components": [
            {
                "component_id":
                    "AEG-CMP-TEST-001",
                "sector":
                    "HEALTHCARE",
                "ecosystem":
                    "Maven",
                "target":
                    "demo-critical@1.0.0",
                "criticality":
                    "CRITICAL",
                "internet_exposed":
                    True,
                "mission_essential":
                    True,
                "contains_health_data":
                    True,
                "vulnerability_count":
                    2,
                "kev_count":
                    1,
                "max_epss":
                    0.99,
                "attention_signal":
                    "IMMEDIATE_REVIEW",
                "vulnerabilities": [
                    {
                        "id":
                            "CVE-2024-10001",
                        "epss_score":
                            0.99,
                        "kev":
                            True,
                        "severity":
                            "CRITICAL",
                        "cvss_score":
                            9.8,
                    },
                    {
                        "id":
                            "GHSA-AAAA-BBBB-CCCC",
                        "epss_score":
                            0.25,
                        "kev":
                            False,
                        "severity":
                            "HIGH",
                        "cvss_score":
                            8.1,
                    },
                ],
            },
            {
                "component_id":
                    "AEG-CMP-TEST-002",
                "sector":
                    "EDUCATION",
                "ecosystem":
                    "PyPI",
                "target":
                    "demo-monitor@2.0.0",
                "criticality":
                    "MEDIUM",
                "internet_exposed":
                    False,
                "mission_essential":
                    False,
                "contains_health_data":
                    False,
                "vulnerability_count":
                    0,
                "kev_count":
                    0,
                "max_epss":
                    None,
                "attention_signal":
                    "MONITOR",
                "vulnerabilities":
                    [],
            },
        ],
    }


def write_input(
    tmp_path: Path,
) -> Path:
    path = tmp_path / "enriched.json"

    path.write_text(
        json.dumps(
            example_report(),
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    Path(f"{path}.sha256").write_text(
        f"{sha256_file(path)}  "
        f"{path.name}\n",
        encoding="utf-8",
    )

    return path


def test_builds_governed_risk_mart(
    tmp_path: Path,
) -> None:
    source = write_input(tmp_path)
    database = tmp_path / "risk.sqlite"
    summary = tmp_path / "summary.json"

    result = build_risk_mart(
        source,
        database,
        summary,
    )

    assert result["stage_gate"] == "PASS"

    assert (
        result["counts"]["components"]
        == 2
    )

    assert (
        result["counts"][
            "components_with_kev"
        ]
        == 1
    )

    assert (
        result["governance"][
            "authoritative_policy_engine"
        ]
        == "SSVC"
    )

    assert (
        result["governance"][
            "production_readiness"
        ]
        == "BLOCKED"
    )

    assert database.exists()
    assert Path(
        f"{database}.sha256"
    ).exists()

    assert summary.exists()
    assert Path(
        f"{summary}.sha256"
    ).exists()


def test_priority_queue_is_deterministic(
    tmp_path: Path,
) -> None:
    source = write_input(tmp_path)
    database = tmp_path / "risk.sqlite"
    summary = tmp_path / "summary.json"

    build_risk_mart(
        source,
        database,
        summary,
    )

    with sqlite3.connect(
        database
    ) as connection:
        first = connection.execute(
            """
            SELECT
                component_id,
                analytics_signal
            FROM v_top_priority_queue
            LIMIT 1
            """
        ).fetchone()

    assert first == (
        "AEG-CMP-TEST-001",
        "IMMEDIATE_REVIEW",
    )


def test_sector_view_is_created(
    tmp_path: Path,
) -> None:
    source = write_input(tmp_path)
    database = tmp_path / "risk.sqlite"
    summary = tmp_path / "summary.json"

    build_risk_mart(
        source,
        database,
        summary,
    )

    with sqlite3.connect(
        database
    ) as connection:
        sectors = connection.execute(
            """
            SELECT sector
            FROM v_sector_summary
            ORDER BY sector
            """
        ).fetchall()

    assert sectors == [
        ("EDUCATION",),
        ("HEALTHCARE",),
    ]


def test_tampering_is_rejected(
    tmp_path: Path,
) -> None:
    source = write_input(tmp_path)

    source.write_text(
        "{}",
        encoding="utf-8",
    )

    with pytest.raises(
        PresentationAnalyticsError,
        match="Integrity mismatch",
    ):
        build_risk_mart(
            source,
            tmp_path / "risk.sqlite",
            tmp_path / "summary.json",
        )


def test_production_ready_input_is_rejected(
    tmp_path: Path,
) -> None:
    report = example_report()

    report["governance"][
        "production_readiness"
    ] = "READY"

    source = tmp_path / "enriched.json"

    source.write_text(
        json.dumps(
            report,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    Path(f"{source}.sha256").write_text(
        f"{sha256_file(source)}  "
        f"{source.name}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        PresentationAnalyticsError,
        match="blocked from production",
    ):
        build_risk_mart(
            source,
            tmp_path / "risk.sqlite",
            tmp_path / "summary.json",
        )

def test_real_enrichment_shape_maps_kev_and_package(
    tmp_path: Path,
) -> None:
    report = {
        "summary": {
            "components_assessed": 1,
            "components_with_kev": 1,
        },
        "governance": {
            "authoritative_policy_engine": "SSVC",
            "production_readiness": "BLOCKED",
        },
        "components": [
            {
                "component_id": "AEG-CMP-REAL-SHAPE",
                "sector": "HEALTHCARE",
                "criticality": "CRITICAL",
                "internet_exposed": True,
                "mission_essential": True,
                "contains_health_data": True,
                "package": {
                    "ecosystem": "Maven",
                    "name": (
                        "org.apache.logging.log4j:"
                        "log4j-core"
                    ),
                    "version": "2.14.1",
                },
                "matched_vulnerability_count": 7,
                "threat_enrichment": {
                    "kev_confirmed_cves": 2,
                    "maximum_epss": 0.99999,
                    "attention_signal": (
                        "IMMEDIATE_REVIEW"
                    ),
                    "cve_records": [
                        {
                            "cve": "CVE-2021-44228",
                            "known_exploited": True,
                            "epss": {
                                "epss": 0.99999,
                                "percentile": 1.0,
                            },
                        }
                    ],
                },
            }
        ],
    }

    source = tmp_path / "enriched.json"

    source.write_text(
        json.dumps(
            report,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    Path(f"{source}.sha256").write_text(
        f"{sha256_file(source)}  "
        f"{source.name}\n",
        encoding="utf-8",
    )

    database = tmp_path / "risk.sqlite"
    summary = tmp_path / "summary.json"

    result = build_risk_mart(
        source,
        database,
        summary,
    )

    assert (
        result["counts"]["components_with_kev"]
        == 1
    )

    with sqlite3.connect(
        database
    ) as connection:
        row = connection.execute(
            """
            SELECT
                target,
                kev_count,
                max_epss,
                source_signal,
                analytics_signal
            FROM components
            """
        ).fetchone()

    assert row[0] == (
        "org.apache.logging.log4j:"
        "log4j-core@2.14.1"
    )
    assert row[1] == 2
    assert row[2] == pytest.approx(
        0.99999
    )
    assert row[3] == "IMMEDIATE_REVIEW"
    assert row[4] == "IMMEDIATE_REVIEW"

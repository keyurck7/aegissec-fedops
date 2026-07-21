from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from src.presentation_demo.sbom_ingestion import (
    SBOMIngestionError,
    parse_cyclonedx_bytes,
    parse_purl,
    scan_cyclonedx_bytes,
)


def sample_sbom(
    purl: str = (
        "pkg:maven/"
        "org.apache.logging.log4j/"
        "log4j-core@2.14.1"
    ),
) -> bytes:
    return json.dumps(
        {
            "bomFormat":
                "CycloneDX",
            "specVersion":
                "1.6",
            "version":
                1,
            "components": [
                {
                    "type":
                        "library",
                    "bom-ref":
                        "component-1",
                    "name":
                        "log4j-core",
                    "version":
                        "2.14.1",
                    "purl":
                        purl,
                }
            ],
        }
    ).encode("utf-8")


def create_test_database(
    path: Path,
) -> None:
    connection = sqlite3.connect(
        path
    )

    try:
        connection.executescript(
            """
            CREATE TABLE components (
                component_id TEXT,
                sector TEXT,
                ecosystem TEXT,
                package_name TEXT,
                version TEXT,
                target TEXT,
                purl TEXT,
                criticality TEXT,
                internet_exposed INTEGER,
                mission_essential INTEGER,
                vulnerability_count INTEGER,
                kev_count INTEGER,
                max_epss REAL,
                source_signal TEXT,
                analytics_signal TEXT,
                attention_score REAL
            );

            CREATE TABLE vulnerabilities (
                vulnerability_id TEXT,
                primary_cve TEXT,
                severity TEXT,
                cvss_score REAL,
                epss_score REAL,
                kev INTEGER,
                raw_json TEXT
            );

            CREATE TABLE component_vulnerabilities (
                component_id TEXT,
                vulnerability_id TEXT
            );
            """
        )

        connection.execute(
            """
            INSERT INTO components VALUES (
                'AEG-CMP-0001',
                'HEALTHCARE',
                'Maven',
                'org.apache.logging.log4j:log4j-core',
                '2.14.1',
                'org.apache.logging.log4j:log4j-core@2.14.1',
                '',
                'CRITICAL',
                1,
                1,
                7,
                2,
                0.99999,
                'IMMEDIATE_REVIEW',
                'IMMEDIATE_REVIEW',
                100.0
            )
            """
        )

        connection.execute(
            """
            INSERT INTO vulnerabilities VALUES (
                'CVE-2021-44228',
                'CVE-2021-44228',
                'CRITICAL',
                10.0,
                0.99999,
                1,
                '{}'
            )
            """
        )

        connection.execute(
            """
            INSERT INTO component_vulnerabilities
            VALUES (
                'AEG-CMP-0001',
                'CVE-2021-44228'
            )
            """
        )

        connection.commit()

    finally:
        connection.close()


def test_parse_maven_purl() -> None:
    parsed = parse_purl(
        "pkg:maven/"
        "org.apache.logging.log4j/"
        "log4j-core@2.14.1"
    )

    assert (
        parsed["ecosystem"]
        == "Maven"
    )

    assert (
        parsed["package_name"]
        == (
            "org.apache.logging.log4j:"
            "log4j-core"
        )
    )

    assert (
        parsed["version"]
        == "2.14.1"
    )


def test_parse_valid_cyclonedx() -> None:
    result = parse_cyclonedx_bytes(
        sample_sbom()
    )

    assert (
        result[
            "validation_status"
        ]
        == "PASS"
    )

    assert (
        result[
            "component_count"
        ]
        == 1
    )

    assert (
        result[
            "identity_complete_count"
        ]
        == 1
    )


def test_reject_wrong_format() -> None:
    payload = json.dumps(
        {
            "bomFormat":
                "SPDX",
            "components":
                [],
        }
    ).encode("utf-8")

    with pytest.raises(
        SBOMIngestionError,
        match="Only CycloneDX",
    ):
        parse_cyclonedx_bytes(
            payload
        )


def test_reject_empty_components() -> None:
    payload = json.dumps(
        {
            "bomFormat":
                "CycloneDX",
            "specVersion":
                "1.6",
            "components":
                [],
        }
    ).encode("utf-8")

    with pytest.raises(
        SBOMIngestionError,
        match="contains no components",
    ):
        parse_cyclonedx_bytes(
            payload
        )


def test_match_and_escalate(
    tmp_path: Path,
) -> None:
    database_path = (
        tmp_path
        / "risk.sqlite"
    )

    create_test_database(
        database_path
    )

    result = scan_cyclonedx_bytes(
        sample_sbom(),
        database_path=database_path,
    )

    assert (
        result["summary"][
            "matched_components"
        ]
        == 1
    )

    assert (
        result["summary"][
            "components_with_kev"
        ]
        == 1
    )

    assert (
        result["summary"][
            "operational_status"
        ]
        == "IMMEDIATE_HUMAN_REVIEW"
    )

    assert (
        result["summary"][
            "clean_bill_of_health"
        ]
        is False
    )


def test_unmatched_fails_closed(
    tmp_path: Path,
) -> None:
    database_path = (
        tmp_path
        / "risk.sqlite"
    )

    create_test_database(
        database_path
    )

    result = scan_cyclonedx_bytes(
        sample_sbom(
            "pkg:pypi/"
            "unknown-package@9.9.9"
        ),
        database_path=database_path,
    )

    assert (
        result["summary"][
            "matched_components"
        ]
        == 0
    )

    assert (
        result["summary"][
            "unmatched_components"
        ]
        == 1
    )

    assert (
        result["summary"][
            "operational_status"
        ]
        == "NO_GOVERNED_MATCHES"
    )

    assert (
        result["governance"][
            "clean_bill_of_health_permitted"
        ]
        is False
    )

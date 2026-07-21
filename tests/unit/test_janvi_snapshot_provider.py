from __future__ import annotations

import csv
import sqlite3
from pathlib import Path

import pytest

from src.intelligence.janvi_snapshot_provider import (
    SnapshotProviderError,
    build_provider,
    lookup_cve,
    open_read_only,
    provider_summary,
    query_priority_candidates,
    sha256_path,
)


FIELDNAMES = [
    "cve_id",
    "source_identifier",
    "published",
    "last_modified",
    "vuln_status",
    "description",
    "cvss_version",
    "cvss_score",
    "severity",
    "cvss_vector",
    "exploitability_score",
    "impact_score",
    "cwe_ids",
    "reference_urls",
    "cpe_criteria",
    "epss_score",
    "epss_percentile",
    "epss_date",
    "epss_source",
    "kev_flag",
    "cisa_vendor_project",
    "cisa_product",
    "cisa_vulnerability_name",
    "cisa_date_added",
    "cisa_short_description",
    "cisa_required_action",
    "cisa_due_date",
    "cisa_known_ransomware_use",
    "cisa_notes",
    "cisa_source_url",
]


def write_sample_csv(path: Path) -> None:
    rows = [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell",
            "cvss_score": "10.0",
            "severity": "CRITICAL",
            "epss_score": "0.99999",
            "epss_percentile": "1.0",
            "kev_flag": "true",
            "cisa_vendor_project": "Apache",
            "cisa_product": "Log4j",
        },
        {
            "cve_id": "CVE-2024-10000",
            "description": "High EPSS example",
            "cvss_score": "8.1",
            "severity": "HIGH",
            "epss_score": "0.70",
            "epss_percentile": "0.98",
            "kev_flag": "false",
        },
        {
            "cve_id": "CVE-2024-10001",
            "description": "Missing EPSS example",
            "cvss_score": "6.0",
            "severity": "MEDIUM",
            "epss_score": "",
            "epss_percentile": "",
            "kev_flag": "false",
        },
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=FIELDNAMES,
        )

        writer.writeheader()

        for row in rows:
            complete = {
                field: row.get(field, "")
                for field in FIELDNAMES
            }
            writer.writerow(complete)


def build_sample(
    tmp_path: Path,
):
    source = tmp_path / "source.csv"
    database = tmp_path / "provider.sqlite"
    report = tmp_path / "provider_report.json"
    policy = tmp_path / "policy.yaml"

    write_sample_csv(source)

    policy.write_text(
        "production_readiness: BLOCKED\n",
        encoding="utf-8",
    )

    result = build_provider(
        source_csv=source,
        database_path=database,
        report_path=report,
        snapshot_id="AEG-TEST-SNAPSHOT",
        snapshot_date="2026-07-14",
        policy_path=policy,
        expected_source_sha256=sha256_path(
            source
        ),
        batch_size=2,
    )

    return source, database, report, result


def test_build_and_lookup(
    tmp_path: Path,
) -> None:
    _, database, _, result = build_sample(
        tmp_path
    )

    assert result["quality_gate"][
        "stage_gate"
    ] == "PASS"

    record = lookup_cve(
        database,
        "cve-2021-44228",
    )

    assert record is not None
    assert record["kev_flag"] == 1
    assert record["epss_score"] == pytest.approx(
        0.99999
    )


def test_missing_epss_remains_null(
    tmp_path: Path,
) -> None:
    _, database, _, _ = build_sample(
        tmp_path
    )

    record = lookup_cve(
        database,
        "CVE-2024-10001",
    )

    assert record is not None
    assert record["epss_score"] is None


def test_summary_and_priority_view(
    tmp_path: Path,
) -> None:
    _, database, _, _ = build_sample(
        tmp_path
    )

    summary = provider_summary(
        database
    )

    assert summary["total_cves"] == 3
    assert summary["kev_cves"] == 1
    assert summary["missing_epss"] == 1

    candidates = query_priority_candidates(
        database,
        limit=3,
    )

    assert candidates[0][
        "advisory_signal"
    ] == "CONFIRMED_KEV"


def test_provider_is_read_only(
    tmp_path: Path,
) -> None:
    _, database, _, _ = build_sample(
        tmp_path
    )

    with open_read_only(
        database
    ) as connection:
        with pytest.raises(
            sqlite3.OperationalError
        ):
            connection.execute(
                """
                DELETE FROM vulnerabilities
                """
            )


def test_source_hash_mismatch_is_blocked(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.csv"
    database = tmp_path / "provider.sqlite"
    report = tmp_path / "report.json"
    policy = tmp_path / "policy.yaml"

    write_sample_csv(source)

    policy.write_text(
        "production_readiness: BLOCKED\n",
        encoding="utf-8",
    )

    with pytest.raises(
        SnapshotProviderError,
        match="SHA-256",
    ):
        build_provider(
            source_csv=source,
            database_path=database,
            report_path=report,
            snapshot_id="AEG-TEST",
            snapshot_date="2026-07-14",
            policy_path=policy,
            expected_source_sha256="0" * 64,
        )

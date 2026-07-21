#!/usr/bin/env python3
"""Build the governed read-only Janvi intelligence provider."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )

from src.intelligence.janvi_snapshot_provider import (  # noqa: E402
    build_provider,
    lookup_cve,
    provider_summary,
    query_priority_candidates,
)


PREFLIGHT_REPORT = (
    ROOT
    / "reports"
    / "intelligence"
    / "janvi_snapshot_preflight.json"
)

DATABASE_PATH = (
    ROOT
    / "data"
    / "external"
    / "janvi_snapshot_20260714"
    / "janvi_intelligence.sqlite"
)

BUILD_REPORT = (
    ROOT
    / "reports"
    / "intelligence"
    / "janvi_sqlite_provider_report.json"
)

POLICY_PATH = (
    ROOT
    / "policies"
    / "intelligence"
    / "external_snapshot_precedence_v1.yaml"
)


def main() -> int:
    print("=" * 76)
    print(
        "AEGISSEC-FEDOPS JANVI READ-ONLY SQLITE PROVIDER"
    )
    print("=" * 76)

    if not PREFLIGHT_REPORT.is_file():
        raise RuntimeError(
            "Janvi preflight report is missing."
        )

    preflight = json.loads(
        PREFLIGHT_REPORT.read_text(
            encoding="utf-8"
        )
    )

    if (
        preflight["quality_gate"]["stage_gate"]
        != "PASS"
    ):
        raise RuntimeError(
            "The Janvi preflight stage gate "
            "did not pass."
        )

    source_record = preflight[
        "extracted_sources"
    ]["enriched_intelligence"]

    source_csv = (
        ROOT
        / source_record["output_path"]
    )

    print("Snapshot ID :", preflight["snapshot_id"])
    print("Source CSV  :", source_csv)
    print("Source rows :", preflight[
        "enriched_statistics"
    ]["rows"])

    print()
    print("===== SQLITE MATERIALIZATION =====")

    report = build_provider(
        source_csv=source_csv,
        database_path=DATABASE_PATH,
        report_path=BUILD_REPORT,
        snapshot_id=preflight[
            "snapshot_id"
        ],
        snapshot_date=preflight[
            "snapshot_date"
        ],
        policy_path=POLICY_PATH,
        expected_source_sha256=source_record[
            "sha256"
        ],
    )

    print()
    print("===== READ-ONLY PROVIDER VERIFICATION =====")

    summary = provider_summary(
        DATABASE_PATH
    )

    log4shell = lookup_cve(
        DATABASE_PATH,
        "CVE-2021-44228",
    )

    candidates = query_priority_candidates(
        DATABASE_PATH,
        limit=5,
    )

    print("Database          :", DATABASE_PATH)
    print("Database bytes    :", report[
        "database"
    ]["size_bytes"])
    print("Database SHA-256  :", report[
        "database"
    ]["sha256"])
    print("Total CVEs        :", summary["total_cves"])
    print("KEV CVEs          :", summary["kev_cves"])
    print("Missing EPSS      :", summary["missing_epss"])
    print("Maximum EPSS      :", summary["maximum_epss"])
    print(
        "Log4Shell present :",
        log4shell is not None,
    )

    if log4shell is not None:
        print(
            "Log4Shell KEV     :",
            log4shell["kev_flag"],
        )
        print(
            "Log4Shell EPSS    :",
            log4shell["epss_score"],
        )
        print(
            "Log4Shell CVSS    :",
            log4shell["cvss_score"],
        )

    print()
    print("Top advisory candidates:")

    for item in candidates:
        print(
            f"  {item['cve_id']:18} "
            f"| {item['advisory_signal']:20} "
            f"| KEV={item['kev_flag']} "
            f"| EPSS={item['epss_score']}"
        )

    assert summary["total_cves"] == 364_478
    assert summary["kev_cves"] == 1_638
    assert summary["missing_epss"] == 73_554
    assert log4shell is not None
    assert log4shell["kev_flag"] == 1

    assert (
        summary["metadata"][
            "may_override_ssvc"
        ]
        == "false"
    )

    assert (
        summary["metadata"][
            "production_readiness"
        ]
        == "BLOCKED"
    )

    print()
    print("=" * 76)
    print(
        "MILESTONE 13A.1B READ-ONLY SQLITE PROVIDER: PASS"
    )
    print("LIVE SOURCE PRECEDENCE: PRESERVED")
    print("SSVC AUTHORITY: PRESERVED")
    print("PRODUCTION READINESS: BLOCKED")
    print("NEXT: UNIFIED MULTI-FORMAT INTAKE GATEWAY")
    print("=" * 76)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

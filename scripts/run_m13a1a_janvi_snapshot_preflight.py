#!/usr/bin/env python3
"""Governed registration and validation of Janvi's intelligence snapshot."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
import sys
import zipfile

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

ARCHIVE_PATH = ROOT / "janvi_data_ethics_20260714.zip"

EXPECTED_ARCHIVE_SHA256 = (
    "dcc3af7e0c81bc84a973ad8f2f31ab7c86578322180e7aea8ce07ea7f49bf566"
)

SOURCE_DIRECTORY = (
    ROOT
    / "data"
    / "external"
    / "janvi_snapshot_20260714"
    / "source"
)

REPORT_DIRECTORY = (
    ROOT
    / "reports"
    / "intelligence"
)

REPORT_PATH = (
    REPORT_DIRECTORY
    / "janvi_snapshot_preflight.json"
)

REPORT_SHA256_PATH = (
    REPORT_DIRECTORY
    / "janvi_snapshot_preflight.json.sha256"
)

SNAPSHOT_DATE = "2026-07-14"

REQUIRED_FILES = {
    "enriched_intelligence": (
        "nvd_epss_cisa_enriched_2026-07-14.csv"
    ),
    "cisa_kev": (
        "cisa_kev_catalog_2026-07-14.csv"
    ),
    "epss": (
        "epss_scores_2026-07-14.csv"
    ),
    "provenance": (
        "data_provenance_log.csv"
    ),
}

COLUMN_ALIASES = {
    "cve": [
        "cve_id",
        "cve",
        "cveid",
    ],
    "epss": [
        "epss_score",
        "epss",
        "score",
    ],
    "percentile": [
        "epss_percentile",
        "percentile",
        "epss_percentile_score",
    ],
    "kev": [
        "kev_flag",
        "is_kev",
        "cisa_kev_status",
        "known_exploited",
    ],
}

CVE_PREFIX = "CVE-"


def configure_csv_limit() -> None:
    limit = sys.maxsize

    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def canonical_json_bytes(document: dict[str, Any]) -> bytes:
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


def find_unique_member(
    archive: zipfile.ZipFile,
    basename: str,
) -> str:
    matches = [
        name
        for name in archive.namelist()
        if Path(name).name == basename
    ]

    if not matches:
        raise RuntimeError(
            f"Required archive member was not found: {basename}"
        )

    if len(matches) > 1:
        raise RuntimeError(
            f"Multiple archive members share the name {basename}: "
            + ", ".join(matches)
        )

    return matches[0]


def extract_sources() -> dict[str, Any]:
    SOURCE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    extracted: dict[str, Any] = {}

    with zipfile.ZipFile(
        ARCHIVE_PATH,
        "r",
    ) as archive:
        bad_member = archive.testzip()

        if bad_member is not None:
            raise RuntimeError(
                f"ZIP integrity failure at member: {bad_member}"
            )

        for logical_name, basename in REQUIRED_FILES.items():
            member_name = find_unique_member(
                archive,
                basename,
            )

            member_info = archive.getinfo(
                member_name
            )

            output_path = (
                SOURCE_DIRECTORY
                / basename
            )

            temporary_path = (
                SOURCE_DIRECTORY
                / f".{basename}.partial"
            )

            if temporary_path.exists():
                temporary_path.unlink()

            with archive.open(
                member_name,
                "r",
            ) as source:
                with temporary_path.open(
                    "wb",
                ) as destination:
                    shutil.copyfileobj(
                        source,
                        destination,
                        length=1024 * 1024,
                    )

            temporary_path.replace(
                output_path
            )

            extracted[logical_name] = {
                "archive_member": member_name,
                "output_path": str(
                    output_path.relative_to(ROOT)
                ),
                "size_bytes": output_path.stat().st_size,
                "compressed_size_bytes": (
                    member_info.compress_size
                ),
                "crc32": f"{member_info.CRC:08x}",
                "sha256": sha256_path(output_path),
            }

            print(
                f"EXTRACTED  {logical_name:24} "
                f"{output_path.stat().st_size:12,d} bytes"
            )

    return extracted


def normalized_header(path: Path) -> tuple[list[str], dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        reader = csv.reader(handle)

        try:
            original = next(reader)
        except StopIteration as exc:
            raise RuntimeError(
                f"CSV file is empty: {path}"
            ) from exc

    lookup = {
        name.strip().lower(): name
        for name in original
    }

    return original, lookup


def resolve_column(
    lookup: dict[str, str],
    semantic_name: str,
    required: bool = True,
) -> str | None:
    for alias in COLUMN_ALIASES[semantic_name]:
        if alias.lower() in lookup:
            return lookup[alias.lower()]

    if required:
        raise RuntimeError(
            f"Required semantic column is missing: {semantic_name}"
        )

    return None


def parse_probability(
    raw_value: str | None,
) -> tuple[float | None, bool]:
    if raw_value is None:
        return None, True

    value = raw_value.strip()

    if value == "":
        return None, True

    try:
        parsed = float(value)
    except ValueError:
        return None, False

    if not math.isfinite(parsed):
        return None, False

    if not 0.0 <= parsed <= 1.0:
        return None, False

    return parsed, True


def parse_kev(
    raw_value: str | None,
) -> tuple[bool, bool]:
    if raw_value is None:
        return False, False

    value = raw_value.strip().lower()

    positive_values = {
        "true",
        "1",
        "yes",
        "y",
        "listed",
        "known_exploited",
        "in_kev",
    }

    negative_values = {
        "false",
        "0",
        "no",
        "n",
        "not_listed",
        "not in kev",
        "",
    }

    if value in positive_values:
        return True, True

    if value in negative_values:
        return False, True

    # Some exports use descriptive KEV text rather than Boolean values.
    if "listed" in value and "not" not in value:
        return True, True

    return False, False


def valid_cve_identifier(value: str) -> bool:
    normalized = value.strip().upper()

    if not normalized.startswith(CVE_PREFIX):
        return False

    parts = normalized.split("-")

    if len(parts) != 3:
        return False

    if not parts[1].isdigit():
        return False

    if len(parts[1]) != 4:
        return False

    if not parts[2].isdigit():
        return False

    return len(parts[2]) >= 4


def inspect_enriched_dataset(
    path: Path,
) -> dict[str, Any]:
    header, lookup = normalized_header(path)

    columns = {
        "cve": resolve_column(
            lookup,
            "cve",
        ),
        "epss": resolve_column(
            lookup,
            "epss",
        ),
        "percentile": resolve_column(
            lookup,
            "percentile",
        ),
        "kev": resolve_column(
            lookup,
            "kev",
        ),
    }

    rows = 0
    valid_cves = 0
    invalid_cves = 0
    duplicate_cves = 0
    missing_epss = 0
    invalid_epss = 0
    invalid_percentiles = 0
    invalid_kev_values = 0
    kev_rows = 0

    maximum_epss: float | None = None
    maximum_percentile: float | None = None

    seen_cves: set[str] = set()

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)

        for row in reader:
            rows += 1

            cve = (
                row.get(columns["cve"])
                or ""
            ).strip().upper()

            if valid_cve_identifier(cve):
                valid_cves += 1

                if cve in seen_cves:
                    duplicate_cves += 1
                else:
                    seen_cves.add(cve)
            else:
                invalid_cves += 1

            epss, epss_valid = parse_probability(
                row.get(columns["epss"])
            )

            if not epss_valid:
                invalid_epss += 1
            elif epss is None:
                missing_epss += 1
            else:
                maximum_epss = (
                    epss
                    if maximum_epss is None
                    else max(maximum_epss, epss)
                )

            percentile, percentile_valid = parse_probability(
                row.get(columns["percentile"])
            )

            if not percentile_valid:
                invalid_percentiles += 1
            elif percentile is not None:
                maximum_percentile = (
                    percentile
                    if maximum_percentile is None
                    else max(
                        maximum_percentile,
                        percentile,
                    )
                )

            is_kev, kev_valid = parse_kev(
                row.get(columns["kev"])
            )

            if not kev_valid:
                invalid_kev_values += 1
            elif is_kev:
                kev_rows += 1

            if rows % 50_000 == 0:
                print(
                    f"INSPECTED  {rows:12,d} enriched rows"
                )

    return {
        "header_column_count": len(header),
        "resolved_columns": columns,
        "rows": rows,
        "unique_cves": len(seen_cves),
        "valid_cve_rows": valid_cves,
        "invalid_cve_rows": invalid_cves,
        "duplicate_cve_rows": duplicate_cves,
        "missing_epss_rows": missing_epss,
        "invalid_epss_rows": invalid_epss,
        "invalid_percentile_rows": invalid_percentiles,
        "invalid_kev_rows": invalid_kev_values,
        "kev_rows": kev_rows,
        "positive_prevalence": (
            kev_rows / rows
            if rows
            else None
        ),
        "maximum_epss": maximum_epss,
        "maximum_percentile": maximum_percentile,
    }


def inspect_csv_shape(path: Path) -> dict[str, Any]:
    header, _ = normalized_header(path)

    rows = 0

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        reader = csv.reader(handle)

        next(reader, None)

        for _ in reader:
            rows += 1

    return {
        "rows": rows,
        "columns": len(header),
        "header": header,
    }


def main() -> int:
    configure_csv_limit()

    print("=" * 76)
    print("AEGISSEC-FEDOPS JANVI SNAPSHOT GOVERNED PREFLIGHT")
    print("=" * 76)

    if not ARCHIVE_PATH.is_file():
        raise RuntimeError(
            f"Archive is missing: {ARCHIVE_PATH}"
        )

    archive_sha256 = sha256_path(
        ARCHIVE_PATH
    )

    print("Archive        :", ARCHIVE_PATH.name)
    print("Archive bytes  :", ARCHIVE_PATH.stat().st_size)
    print("Archive SHA-256:", archive_sha256)

    if archive_sha256 != EXPECTED_ARCHIVE_SHA256:
        raise RuntimeError(
            "Archive SHA-256 does not match the registered archive."
        )

    print("Archive identity: PASS")

    print()
    print("===== CONTROLLED EXTRACTION =====")

    extracted = extract_sources()

    print()
    print("===== ENRICHED DATA INSPECTION =====")

    enriched_path = (
        ROOT
        / extracted["enriched_intelligence"]["output_path"]
    )

    statistics = inspect_enriched_dataset(
        enriched_path
    )

    print()
    print("===== SUPPORTING FILE INSPECTION =====")

    supporting_statistics = {}

    for logical_name in [
        "cisa_kev",
        "epss",
        "provenance",
    ]:
        source_path = (
            ROOT
            / extracted[logical_name]["output_path"]
        )

        result = inspect_csv_shape(
            source_path
        )

        supporting_statistics[logical_name] = result

        print(
            f"{logical_name:24} "
            f"rows={result['rows']:,} "
            f"columns={result['columns']}"
        )

    row_count = statistics["rows"]

    invalid_cve_ratio = (
        statistics["invalid_cve_rows"] / row_count
        if row_count
        else 1.0
    )

    invalid_epss_ratio = (
        statistics["invalid_epss_rows"] / row_count
        if row_count
        else 1.0
    )

    checks = {
        "archive_identity_verified": True,
        "zip_crc_validation_passed": True,
        "required_sources_extracted": (
            len(extracted) == len(REQUIRED_FILES)
        ),
        "minimum_enriched_rows_300000": (
            statistics["rows"] >= 300_000
        ),
        "minimum_unique_cves_300000": (
            statistics["unique_cves"] >= 300_000
        ),
        "minimum_kev_examples_1000": (
            statistics["kev_rows"] >= 1_000
        ),
        "invalid_cve_ratio_below_0_1_percent": (
            invalid_cve_ratio <= 0.001
        ),
        "invalid_epss_ratio_below_0_1_percent": (
            invalid_epss_ratio <= 0.001
        ),
        "provenance_records_present": (
            supporting_statistics["provenance"]["rows"] > 0
        ),
        "epss_snapshot_present": (
            supporting_statistics["epss"]["rows"] > 100_000
        ),
        "kev_snapshot_present": (
            supporting_statistics["cisa_kev"]["rows"] > 1_000
        ),
    }

    warnings: list[str] = []

    if statistics["duplicate_cve_rows"] > 0:
        warnings.append(
            "Duplicate CVE identifiers were detected. "
            "They will be deduplicated in the read-only provider."
        )

    if statistics["missing_epss_rows"] > 0:
        warnings.append(
            "Some CVE records have no EPSS value. "
            "Missing values will remain unknown."
        )

    if statistics["invalid_percentile_rows"] > 0:
        warnings.append(
            "Invalid EPSS percentile values were detected."
        )

    if statistics["invalid_kev_rows"] > 0:
        warnings.append(
            "Unrecognized KEV values were detected."
        )

    stage_gate = (
        "PASS"
        if all(checks.values())
        else "FAIL"
    )

    snapshot_id = (
        "AEG-JANVI-"
        + archive_sha256[:24].upper()
    )

    report = {
        "schema_version": "1.0.0",
        "snapshot_id": snapshot_id,
        "snapshot_date": SNAPSHOT_DATE,
        "generated_at": (
            datetime.now(timezone.utc).isoformat()
        ),
        "source": {
            "archive": ARCHIVE_PATH.name,
            "archive_sha256": archive_sha256,
            "archive_size_bytes": ARCHIVE_PATH.stat().st_size,
            "scope": "NVD + FIRST EPSS + CISA KEV",
            "submitted_dataset": "JANVI_TEAM_DATASET",
        },
        "extracted_sources": extracted,
        "enriched_statistics": statistics,
        "supporting_statistics": supporting_statistics,
        "quality_gate": {
            "checks": checks,
            "warnings": warnings,
            "stage_gate": stage_gate,
        },
        "governance": {
            "authority": (
                "READ_ONLY_EXTERNAL_INTELLIGENCE_SNAPSHOT"
            ),
            "newer_live_sources_take_precedence": True,
            "may_override_live_kev": False,
            "may_override_live_epss": False,
            "may_determine_affectedness_alone": False,
            "may_override_ssvc": False,
            "automated_disposition_permitted": False,
            "human_review_required_for_high_consequence_use": True,
            "production_readiness": "BLOCKED",
        },
        "next_stage": (
            "MILESTONE_13A_1B_READ_ONLY_SQLITE_PROVIDER"
        ),
    }

    REPORT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_bytes = canonical_json_bytes(
        report
    )

    REPORT_PATH.write_bytes(
        report_bytes
    )

    report_sha256 = hashlib.sha256(
        report_bytes
    ).hexdigest()

    REPORT_SHA256_PATH.write_text(
        f"{report_sha256}  {REPORT_PATH.name}\n",
        encoding="utf-8",
    )

    print()
    print("===== SNAPSHOT SUMMARY =====")
    print("Snapshot ID       :", snapshot_id)
    print("Rows              :", statistics["rows"])
    print("Unique CVEs       :", statistics["unique_cves"])
    print("KEV rows          :", statistics["kev_rows"])
    print("Missing EPSS      :", statistics["missing_epss_rows"])
    print("Maximum EPSS      :", statistics["maximum_epss"])
    print("Duplicate CVEs    :", statistics["duplicate_cve_rows"])
    print("Invalid CVEs      :", statistics["invalid_cve_rows"])
    print("Invalid EPSS      :", statistics["invalid_epss_rows"])
    print("Warnings          :", len(warnings))
    print("Report            :", REPORT_PATH.relative_to(ROOT))
    print("Report SHA-256    :", report_sha256)
    print("Stage gate        :", stage_gate)
    print("Production        : BLOCKED")

    if warnings:
        print()
        print("Warnings:")

        for warning in warnings:
            print(" -", warning)

    if stage_gate != "PASS":
        print()
        print("Failed checks:")

        for check_name, passed in checks.items():
            if not passed:
                print(" -", check_name)

        return 1

    print()
    print("=" * 76)
    print("MILESTONE 13A.1A JANVI SNAPSHOT PREFLIGHT: PASS")
    print("NEXT: READ-ONLY SQLITE INTELLIGENCE PROVIDER")
    print("=" * 76)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only SQLite provider for the governed Janvi intelligence snapshot."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import sqlite3
import sys

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SnapshotProviderError(RuntimeError):
    """Raised when an intelligence snapshot cannot be governed safely."""


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


def valid_cve_identifier(value: str) -> bool:
    normalized = value.strip().upper()
    parts = normalized.split("-")

    return (
        len(parts) == 3
        and parts[0] == "CVE"
        and len(parts[1]) == 4
        and parts[1].isdigit()
        and len(parts[2]) >= 4
        and parts[2].isdigit()
    )


def optional_float(value: str | None) -> float | None:
    if value is None:
        return None

    normalized = value.strip()

    if normalized == "":
        return None

    try:
        parsed = float(normalized)
    except ValueError:
        return None

    if not math.isfinite(parsed):
        return None

    return parsed


def probability(value: str | None) -> float | None:
    parsed = optional_float(value)

    if parsed is None:
        return None

    if not 0.0 <= parsed <= 1.0:
        return None

    return parsed


def kev_boolean(value: str | None) -> int:
    if value is None:
        return 0

    normalized = value.strip().lower()

    positive = {
        "true",
        "1",
        "yes",
        "y",
        "listed",
        "known_exploited",
        "in_kev",
    }

    negative = {
        "",
        "false",
        "0",
        "no",
        "n",
        "not_listed",
        "not in kev",
    }

    if normalized in positive:
        return 1

    if normalized in negative:
        return 0

    if (
        "listed" in normalized
        and "not" not in normalized
    ):
        return 1

    return 0


def resolve_columns(
    fieldnames: list[str] | None,
) -> dict[str, str | None]:
    if not fieldnames:
        raise SnapshotProviderError(
            "The source CSV has no header."
        )

    lookup = {
        name.strip().lower(): name
        for name in fieldnames
    }

    def find(
        *candidate_names: str,
        required: bool = False,
    ) -> str | None:
        for candidate in candidate_names:
            match = lookup.get(
                candidate.lower()
            )

            if match is not None:
                return match

        if required:
            raise SnapshotProviderError(
                "Required source column missing: "
                + " / ".join(candidate_names)
            )

        return None

    return {
        "cve_id": find(
            "cve_id",
            "cve",
            "cveid",
            required=True,
        ),
        "source_identifier": find(
            "source_identifier"
        ),
        "published": find("published"),
        "last_modified": find("last_modified"),
        "vuln_status": find("vuln_status"),
        "description": find("description"),
        "cvss_version": find("cvss_version"),
        "cvss_score": find("cvss_score"),
        "severity": find("severity"),
        "cvss_vector": find("cvss_vector"),
        "exploitability_score": find(
            "exploitability_score"
        ),
        "impact_score": find("impact_score"),
        "cwe_ids": find("cwe_ids"),
        "reference_urls": find(
            "reference_urls"
        ),
        "cpe_criteria": find("cpe_criteria"),
        "epss_score": find(
            "epss_score",
            "epss",
            "score",
            required=True,
        ),
        "epss_percentile": find(
            "epss_percentile",
            "percentile",
            required=True,
        ),
        "epss_date": find("epss_date"),
        "epss_source": find("epss_source"),
        "kev_flag": find(
            "kev_flag",
            "is_kev",
            "cisa_kev_status",
            "known_exploited",
            required=True,
        ),
        "cisa_vendor_project": find(
            "cisa_vendor_project"
        ),
        "cisa_product": find(
            "cisa_product"
        ),
        "cisa_vulnerability_name": find(
            "cisa_vulnerability_name"
        ),
        "cisa_date_added": find(
            "cisa_date_added"
        ),
        "cisa_short_description": find(
            "cisa_short_description"
        ),
        "cisa_required_action": find(
            "cisa_required_action"
        ),
        "cisa_due_date": find(
            "cisa_due_date"
        ),
        "cisa_known_ransomware_use": find(
            "cisa_known_ransomware_use"
        ),
        "cisa_notes": find("cisa_notes"),
        "cisa_source_url": find(
            "cisa_source_url"
        ),
    }


def row_text(
    row: dict[str, str],
    column: str | None,
) -> str | None:
    if column is None:
        return None

    value = row.get(column)

    if value is None:
        return None

    normalized = value.strip()

    return normalized or None


def create_schema(
    connection: sqlite3.Connection,
) -> None:
    connection.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE vulnerabilities (
            cve_id TEXT PRIMARY KEY,
            source_identifier TEXT,
            published TEXT,
            last_modified TEXT,
            vuln_status TEXT,
            description TEXT,
            cvss_version TEXT,
            cvss_score REAL,
            severity TEXT,
            cvss_vector TEXT,
            exploitability_score REAL,
            impact_score REAL,
            cwe_ids TEXT,
            reference_urls TEXT,
            cpe_criteria TEXT,
            epss_score REAL,
            epss_percentile REAL,
            epss_date TEXT,
            epss_source TEXT,
            kev_flag INTEGER NOT NULL
                CHECK (kev_flag IN (0, 1)),
            cisa_vendor_project TEXT,
            cisa_product TEXT,
            cisa_vulnerability_name TEXT,
            cisa_date_added TEXT,
            cisa_short_description TEXT,
            cisa_required_action TEXT,
            cisa_due_date TEXT,
            cisa_known_ransomware_use TEXT,
            cisa_notes TEXT,
            cisa_source_url TEXT,
            source_snapshot_id TEXT NOT NULL,
            source_row_number INTEGER NOT NULL
        );

        CREATE INDEX idx_vulnerabilities_kev
            ON vulnerabilities (
                kev_flag,
                epss_score DESC
            );

        CREATE INDEX idx_vulnerabilities_epss
            ON vulnerabilities (
                epss_score DESC
            );

        CREATE INDEX idx_vulnerabilities_percentile
            ON vulnerabilities (
                epss_percentile DESC
            );

        CREATE INDEX idx_vulnerabilities_cvss
            ON vulnerabilities (
                cvss_score DESC
            );

        CREATE INDEX idx_vulnerabilities_severity
            ON vulnerabilities (
                severity
            );

        CREATE INDEX idx_vulnerabilities_vendor_product
            ON vulnerabilities (
                cisa_vendor_project,
                cisa_product
            );

        CREATE VIEW v_kev_catalog AS
        SELECT
            cve_id,
            cisa_vendor_project,
            cisa_product,
            cisa_vulnerability_name,
            cisa_date_added,
            cisa_required_action,
            cisa_due_date,
            cisa_known_ransomware_use,
            epss_score,
            epss_percentile
        FROM vulnerabilities
        WHERE kev_flag = 1;

        CREATE VIEW v_priority_candidates AS
        SELECT
            cve_id,
            kev_flag,
            epss_score,
            epss_percentile,
            cvss_score,
            severity,
            cisa_vendor_project,
            cisa_product,
            CASE
                WHEN kev_flag = 1
                    THEN 'CONFIRMED_KEV'
                WHEN epss_score IS NULL
                    THEN 'UNKNOWN_EPSS_REVIEW'
                WHEN epss_score >= 0.50
                    THEN 'HIGH_EPSS_REVIEW'
                WHEN epss_score >= 0.10
                    THEN 'ELEVATED_EPSS_REVIEW'
                ELSE 'MONITOR'
            END AS advisory_signal
        FROM vulnerabilities;

        CREATE VIEW v_provider_summary AS
        SELECT
            COUNT(*) AS total_cves,
            SUM(kev_flag) AS kev_cves,
            SUM(
                CASE
                    WHEN epss_score IS NULL THEN 1
                    ELSE 0
                END
            ) AS missing_epss,
            MAX(epss_score) AS maximum_epss,
            MAX(cvss_score) AS maximum_cvss
        FROM vulnerabilities;
        """
    )


def open_read_only(
    database_path: Path,
) -> sqlite3.Connection:
    resolved = database_path.resolve()

    connection = sqlite3.connect(
        f"file:{resolved.as_posix()}?mode=ro&immutable=1",
        uri=True,
    )

    connection.row_factory = sqlite3.Row
    connection.execute(
        "PRAGMA query_only = ON"
    )

    return connection


def lookup_cve(
    database_path: Path,
    cve_id: str,
) -> dict[str, Any] | None:
    normalized = cve_id.strip().upper()

    with open_read_only(
        database_path
    ) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM vulnerabilities
            WHERE cve_id = ?
            """,
            (normalized,),
        ).fetchone()

    return (
        dict(row)
        if row is not None
        else None
    )


def provider_summary(
    database_path: Path,
) -> dict[str, Any]:
    with open_read_only(
        database_path
    ) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM v_provider_summary
            """
        ).fetchone()

        metadata_rows = connection.execute(
            """
            SELECT key, value
            FROM metadata
            """
        ).fetchall()

    summary = dict(row)
    summary["metadata"] = {
        item["key"]: item["value"]
        for item in metadata_rows
    }

    return summary


def query_priority_candidates(
    database_path: Path,
    limit: int = 20,
) -> list[dict[str, Any]]:
    safe_limit = max(
        1,
        min(int(limit), 500),
    )

    with open_read_only(
        database_path
    ) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM v_priority_candidates
            ORDER BY
                kev_flag DESC,
                COALESCE(epss_score, -1) DESC,
                COALESCE(cvss_score, -1) DESC,
                cve_id ASC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def build_provider(
    *,
    source_csv: Path,
    database_path: Path,
    report_path: Path,
    snapshot_id: str,
    snapshot_date: str,
    policy_path: Path,
    expected_source_sha256: str,
    batch_size: int = 2_000,
) -> dict[str, Any]:
    configure_csv_limit()

    if not source_csv.is_file():
        raise SnapshotProviderError(
            f"Source CSV is missing: {source_csv}"
        )

    if not policy_path.is_file():
        raise SnapshotProviderError(
            f"Policy is missing: {policy_path}"
        )

    observed_source_sha256 = sha256_path(
        source_csv
    )

    if (
        observed_source_sha256
        != expected_source_sha256
    ):
        raise SnapshotProviderError(
            "Source SHA-256 does not match "
            "the governed preflight report."
        )

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_database = Path(
        str(database_path) + ".building"
    )

    if temporary_database.exists():
        temporary_database.unlink()

    connection = sqlite3.connect(
        temporary_database
    )

    connection.execute(
        "PRAGMA journal_mode = DELETE"
    )
    connection.execute(
        "PRAGMA synchronous = NORMAL"
    )
    connection.execute(
        "PRAGMA temp_store = MEMORY"
    )

    rows_inserted = 0
    kev_rows = 0
    missing_epss_rows = 0
    maximum_epss: float | None = None

    try:
        create_schema(connection)

        with source_csv.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as handle:
            reader = csv.DictReader(handle)
            columns = resolve_columns(
                reader.fieldnames
            )

            batch: list[tuple[Any, ...]] = []

            insert_sql = """
                INSERT INTO vulnerabilities (
                    cve_id,
                    source_identifier,
                    published,
                    last_modified,
                    vuln_status,
                    description,
                    cvss_version,
                    cvss_score,
                    severity,
                    cvss_vector,
                    exploitability_score,
                    impact_score,
                    cwe_ids,
                    reference_urls,
                    cpe_criteria,
                    epss_score,
                    epss_percentile,
                    epss_date,
                    epss_source,
                    kev_flag,
                    cisa_vendor_project,
                    cisa_product,
                    cisa_vulnerability_name,
                    cisa_date_added,
                    cisa_short_description,
                    cisa_required_action,
                    cisa_due_date,
                    cisa_known_ransomware_use,
                    cisa_notes,
                    cisa_source_url,
                    source_snapshot_id,
                    source_row_number
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?
                )
            """

            for source_row_number, row in enumerate(
                reader,
                start=2,
            ):
                cve_id = (
                    row_text(
                        row,
                        columns["cve_id"],
                    )
                    or ""
                ).upper()

                if not valid_cve_identifier(
                    cve_id
                ):
                    raise SnapshotProviderError(
                        "Malformed CVE at source row "
                        f"{source_row_number}: {cve_id!r}"
                    )

                epss_score = probability(
                    row_text(
                        row,
                        columns["epss_score"],
                    )
                )

                epss_percentile = probability(
                    row_text(
                        row,
                        columns[
                            "epss_percentile"
                        ],
                    )
                )

                kev_flag = kev_boolean(
                    row_text(
                        row,
                        columns["kev_flag"],
                    )
                )

                if epss_score is None:
                    missing_epss_rows += 1
                else:
                    maximum_epss = (
                        epss_score
                        if maximum_epss is None
                        else max(
                            maximum_epss,
                            epss_score,
                        )
                    )

                kev_rows += kev_flag

                batch.append(
                    (
                        cve_id,
                        row_text(
                            row,
                            columns[
                                "source_identifier"
                            ],
                        ),
                        row_text(
                            row,
                            columns["published"],
                        ),
                        row_text(
                            row,
                            columns[
                                "last_modified"
                            ],
                        ),
                        row_text(
                            row,
                            columns["vuln_status"],
                        ),
                        row_text(
                            row,
                            columns["description"],
                        ),
                        row_text(
                            row,
                            columns["cvss_version"],
                        ),
                        optional_float(
                            row_text(
                                row,
                                columns["cvss_score"],
                            )
                        ),
                        row_text(
                            row,
                            columns["severity"],
                        ),
                        row_text(
                            row,
                            columns["cvss_vector"],
                        ),
                        optional_float(
                            row_text(
                                row,
                                columns[
                                    "exploitability_score"
                                ],
                            )
                        ),
                        optional_float(
                            row_text(
                                row,
                                columns[
                                    "impact_score"
                                ],
                            )
                        ),
                        row_text(
                            row,
                            columns["cwe_ids"],
                        ),
                        row_text(
                            row,
                            columns["reference_urls"],
                        ),
                        row_text(
                            row,
                            columns["cpe_criteria"],
                        ),
                        epss_score,
                        epss_percentile,
                        row_text(
                            row,
                            columns["epss_date"],
                        ),
                        row_text(
                            row,
                            columns["epss_source"],
                        ),
                        kev_flag,
                        row_text(
                            row,
                            columns[
                                "cisa_vendor_project"
                            ],
                        ),
                        row_text(
                            row,
                            columns["cisa_product"],
                        ),
                        row_text(
                            row,
                            columns[
                                "cisa_vulnerability_name"
                            ],
                        ),
                        row_text(
                            row,
                            columns[
                                "cisa_date_added"
                            ],
                        ),
                        row_text(
                            row,
                            columns[
                                "cisa_short_description"
                            ],
                        ),
                        row_text(
                            row,
                            columns[
                                "cisa_required_action"
                            ],
                        ),
                        row_text(
                            row,
                            columns[
                                "cisa_due_date"
                            ],
                        ),
                        row_text(
                            row,
                            columns[
                                "cisa_known_ransomware_use"
                            ],
                        ),
                        row_text(
                            row,
                            columns["cisa_notes"],
                        ),
                        row_text(
                            row,
                            columns[
                                "cisa_source_url"
                            ],
                        ),
                        snapshot_id,
                        source_row_number,
                    )
                )

                if len(batch) >= batch_size:
                    connection.executemany(
                        insert_sql,
                        batch,
                    )

                    rows_inserted += len(batch)
                    batch.clear()

                    if (
                        rows_inserted
                        % 50_000
                        < batch_size
                    ):
                        print(
                            "MATERIALIZED "
                            f"{rows_inserted:12,d} CVEs"
                        )

            if batch:
                connection.executemany(
                    insert_sql,
                    batch,
                )
                rows_inserted += len(batch)

        metadata = {
            "provider_schema_version": "1.0.0",
            "snapshot_id": snapshot_id,
            "snapshot_date": snapshot_date,
            "source_csv": str(source_csv),
            "source_csv_sha256": (
                observed_source_sha256
            ),
            "policy_path": str(policy_path),
            "policy_sha256": sha256_path(
                policy_path
            ),
            "authority": (
                "READ_ONLY_EXTERNAL_INTELLIGENCE"
            ),
            "newer_live_sources_take_precedence": (
                "true"
            ),
            "may_override_ssvc": "false",
            "automated_disposition_permitted": (
                "false"
            ),
            "production_readiness": "BLOCKED",
            "rows_inserted": str(
                rows_inserted
            ),
            "missing_epss_rows": str(
                missing_epss_rows
            ),
            "kev_rows": str(kev_rows),
        }

        connection.executemany(
            """
            INSERT INTO metadata (
                key,
                value
            )
            VALUES (?, ?)
            """,
            metadata.items(),
        )

        connection.commit()

        integrity_result = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if integrity_result != "ok":
            raise SnapshotProviderError(
                "SQLite integrity check failed: "
                f"{integrity_result}"
            )

        observed_rows = connection.execute(
            """
            SELECT COUNT(*)
            FROM vulnerabilities
            """
        ).fetchone()[0]

        if observed_rows != rows_inserted:
            raise SnapshotProviderError(
                "Materialized row-count mismatch."
            )

    except Exception:
        connection.close()

        if temporary_database.exists():
            temporary_database.unlink()

        raise

    connection.close()

    os.replace(
        temporary_database,
        database_path,
    )

    database_sha256 = sha256_path(
        database_path
    )

    database_sha256_path = Path(
        str(database_path) + ".sha256"
    )

    database_sha256_path.write_text(
        f"{database_sha256}  "
        f"{database_path.name}\n",
        encoding="utf-8",
    )

    report = {
        "schema_version": "1.0.0",
        "provider_id": (
            "AEG-JANVI-SQLITE-"
            + database_sha256[:24].upper()
        ),
        "snapshot_id": snapshot_id,
        "snapshot_date": snapshot_date,
        "generated_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "source": {
            "path": str(source_csv),
            "sha256": (
                observed_source_sha256
            ),
        },
        "database": {
            "path": str(database_path),
            "sha256": database_sha256,
            "size_bytes": (
                database_path.stat().st_size
            ),
            "integrity_check": "ok",
            "mode": "READ_ONLY",
        },
        "statistics": {
            "rows": rows_inserted,
            "kev_rows": kev_rows,
            "missing_epss_rows": (
                missing_epss_rows
            ),
            "maximum_epss": maximum_epss,
        },
        "governance": {
            "authority": (
                "READ_ONLY_EXTERNAL_INTELLIGENCE"
            ),
            "newer_live_sources_take_precedence": (
                True
            ),
            "may_determine_affectedness_alone": (
                False
            ),
            "may_override_ssvc": False,
            "automated_disposition_permitted": (
                False
            ),
            "human_review_required": True,
            "production_readiness": (
                "BLOCKED"
            ),
        },
        "quality_gate": {
            "source_hash_verified": True,
            "sqlite_integrity_verified": True,
            "row_count_verified": True,
            "read_only_provider_created": True,
            "stage_gate": "PASS",
        },
        "next_stage": (
            "MILESTONE_13A_2_UNIFIED_INTAKE_GATEWAY"
        ),
    }

    report_bytes = canonical_json_bytes(
        report
    )

    report_path.write_bytes(
        report_bytes
    )

    report_sha256 = hashlib.sha256(
        report_bytes
    ).hexdigest()

    report_sha256_path = Path(
        str(report_path) + ".sha256"
    )

    report_sha256_path.write_text(
        f"{report_sha256}  "
        f"{report_path.name}\n",
        encoding="utf-8",
    )

    return report

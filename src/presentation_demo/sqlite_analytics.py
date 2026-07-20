from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


class PresentationAnalyticsError(RuntimeError):
    """Raised when the presentation risk mart cannot be built safely."""


VULNERABILITY_ID_PATTERN = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA-[A-Z0-9-]+|PYSEC-[A-Z0-9-]+|"
    r"GO-[A-Z0-9-]+|RUSTSEC-[A-Z0-9-]+|OSV-[A-Z0-9-]+)$",
    re.IGNORECASE,
)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def verify_sidecar(path: Path) -> None:
    sidecar = Path(f"{path}.sha256")

    if not sidecar.exists():
        raise PresentationAnalyticsError(
            f"Missing integrity sidecar: {sidecar}"
        )

    expected = sidecar.read_text(
        encoding="utf-8"
    ).split()[0]

    observed = sha256_file(path)

    if expected != observed:
        raise PresentationAnalyticsError(
            f"Integrity mismatch for {path}: "
            f"expected {expected}, observed {observed}"
        )


def find_scalar(
    value: Any,
    keys: tuple[str, ...],
    default: Any = None,
) -> Any:
    if isinstance(value, Mapping):
        for key in keys:
            candidate = value.get(key)

            if candidate is not None and not isinstance(
                candidate,
                (dict, list),
            ):
                return candidate

        for candidate in value.values():
            found = find_scalar(
                candidate,
                keys,
                None,
            )

            if found is not None:
                return found

    elif isinstance(value, list):
        for candidate in value:
            found = find_scalar(
                candidate,
                keys,
                None,
            )

            if found is not None:
                return found

    return default


def iter_mappings(
    value: Any,
) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value

        for child in value.values():
            yield from iter_mappings(child)

    elif isinstance(value, list):
        for child in value:
            yield from iter_mappings(child)


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return bool(value)

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "active",
        "confirmed",
    }


def as_probability(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None

    try:
        number = float(value)
    except (TypeError, ValueError):
        return None

    if 1.0 < number <= 100.0:
        number /= 100.0

    if 0.0 <= number <= 1.0:
        return number

    return None


def get_component_id(
    record: Mapping[str, Any],
) -> str | None:
    value = find_scalar(
        record,
        (
            "component_id",
            "asset_component_id",
        ),
    )

    if isinstance(value, str) and value.strip():
        return value.strip()

    return None


def locate_components(
    report: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    preferred_keys = (
        "components",
        "component_findings",
        "component_results",
        "component_enrichments",
        "findings",
        "results",
    )

    for key in preferred_keys:
        candidate = report.get(key)

        if not isinstance(candidate, list):
            continue

        rows = [
            row
            for row in candidate
            if isinstance(row, Mapping)
        ]

        if any(
            get_component_id(row)
            for row in rows
        ):
            return rows

    candidates: list[
        list[Mapping[str, Any]]
    ] = []

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for child in value.values():
                visit(child)

        elif isinstance(value, list):
            rows = [
                row
                for row in value
                if isinstance(row, Mapping)
            ]

            if any(
                get_component_id(row)
                for row in rows
            ):
                candidates.append(rows)

            for child in value:
                visit(child)

    visit(report)

    if not candidates:
        raise PresentationAnalyticsError(
            "No component records were found "
            "inside the enriched report."
        )

    return max(
        candidates,
        key=lambda rows: sum(
            bool(get_component_id(row))
            for row in rows
        ),
    )


def vulnerability_id(
    record: Mapping[str, Any],
) -> str | None:
    keys = (
        "cve_id",
        "cve",
        "vulnerability_id",
        "vuln_id",
        "osv_id",
        "advisory_id",
        "id",
    )

    for key in keys:
        value = record.get(key)

        if (
            isinstance(value, str)
            and VULNERABILITY_ID_PATTERN.match(
                value.strip()
            )
        ):
            return value.strip().upper()

    aliases = record.get("aliases")

    if isinstance(aliases, list):
        for alias in aliases:
            if (
                isinstance(alias, str)
                and VULNERABILITY_ID_PATTERN.match(
                    alias.strip()
                )
            ):
                return alias.strip().upper()

    return None


def extract_vulnerabilities(
    component: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    discovered: dict[
        str,
        Mapping[str, Any],
    ] = {}

    for record in iter_mappings(component):
        identifier = vulnerability_id(record)

        if identifier:
            discovered.setdefault(
                identifier,
                record,
            )

    return list(discovered.values())


def package_identity(
    record: Mapping[str, Any],
) -> tuple[str, str, str, str]:
    target = str(
        find_scalar(
            record,
            (
                "target",
                "package_coordinate",
                "coordinate",
                "display_name",
                "purl",
            ),
            "",
        )
        or ""
    )

    package_name = str(
        find_scalar(
            record,
            (
                "package_name",
                "component_name",
                "artifact_name",
                "name",
            ),
            "",
        )
        or ""
    )

    version = str(
        find_scalar(
            record,
            (
                "package_version",
                "component_version",
                "version",
            ),
            "",
        )
        or ""
    )

    purl = str(
        find_scalar(
            record,
            (
                "purl",
                "package_url",
            ),
            "",
        )
        or ""
    )

    if not package_name and target:
        package_name = target.split(
            "@",
            1,
        )[0]

    if not version and "@" in target:
        version = target.rsplit(
            "@",
            1,
        )[-1]

    if not target and package_name:
        target = (
            f"{package_name}@{version}"
            if version
            else package_name
        )

    return (
        package_name,
        version,
        target,
        purl,
    )


def calculate_attention_score(
    *,
    criticality: str,
    max_epss: float | None,
    kev_count: int,
    internet_exposed: bool,
    mission_essential: bool,
    contains_health_data: bool,
) -> float:
    score = (max_epss or 0.0) * 55.0

    if kev_count > 0:
        score += 25.0

    score += {
        "CRITICAL": 15.0,
        "HIGH": 10.0,
        "MEDIUM": 5.0,
        "LOW": 2.0,
    }.get(
        criticality.upper(),
        0.0,
    )

    if internet_exposed:
        score += 5.0

    if mission_essential:
        score += 5.0

    if contains_health_data:
        score += 3.0

    return round(
        min(score, 100.0),
        2,
    )


def analytics_signal(
    score: float,
) -> str:
    if score >= 85.0:
        return "IMMEDIATE_REVIEW"

    if score >= 65.0:
        return "PRIORITY_REVIEW"

    if score >= 40.0:
        return "SCHEDULED_REVIEW"

    return "MONITOR"


def write_integrity_sidecar(
    path: Path,
) -> Path:
    sidecar = Path(f"{path}.sha256")

    sidecar.write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="utf-8",
    )

    return sidecar


def build_risk_mart(
    enriched_path: Path | str,
    database_path: Path | str,
    summary_path: Path | str,
) -> dict[str, Any]:
    enriched_path = Path(enriched_path)
    database_path = Path(database_path)
    summary_path = Path(summary_path)

    verify_sidecar(enriched_path)

    report = json.loads(
        enriched_path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(report, dict):
        raise PresentationAnalyticsError(
            "Enriched report must be "
            "a JSON object."
        )

    governance = report.get(
        "governance",
        {},
    )

    if not isinstance(
        governance,
        Mapping,
    ):
        governance = {}

    authority = str(
        governance.get(
            "authoritative_policy_engine"
        )
        or governance.get(
            "ssvc_authority"
        )
        or "SSVC"
    ).upper()

    production_readiness = str(
        governance.get(
            "production_readiness"
        )
        or report.get(
            "production_readiness"
        )
        or "BLOCKED"
    ).upper()

    if authority != "SSVC":
        raise PresentationAnalyticsError(
            f"Unexpected policy authority: "
            f"{authority}"
        )

    if production_readiness != "BLOCKED":
        raise PresentationAnalyticsError(
            "Presentation analytics must "
            "remain blocked from production."
        )

    component_rows = locate_components(
        report
    )

    source_sha256 = sha256_file(
        enriched_path
    )

    generated_at = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    mart_id = (
        "AEG-RISK-MART-"
        + hashlib.sha256(
            source_sha256.encode("utf-8")
        ).hexdigest()[:24].upper()
    )

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = Path(
        f"{database_path}.tmp"
    )

    temporary_path.unlink(
        missing_ok=True
    )

    connection = sqlite3.connect(
        temporary_path
    )

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    try:
        connection.executescript(
            """
            CREATE TABLE metadata(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE components(
                component_id TEXT PRIMARY KEY,
                sector TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                target TEXT NOT NULL,
                purl TEXT NOT NULL,
                criticality TEXT NOT NULL,
                internet_exposed INTEGER NOT NULL,
                mission_essential INTEGER NOT NULL,
                contains_health_data INTEGER NOT NULL,
                vulnerability_count INTEGER NOT NULL,
                kev_count INTEGER NOT NULL,
                max_epss REAL,
                source_signal TEXT NOT NULL,
                analytics_signal TEXT NOT NULL,
                attention_score REAL NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE vulnerabilities(
                vulnerability_id TEXT PRIMARY KEY,
                primary_cve TEXT,
                severity TEXT NOT NULL,
                cvss_score REAL,
                epss_score REAL,
                kev INTEGER NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE component_vulnerabilities(
                component_id TEXT NOT NULL,
                vulnerability_id TEXT NOT NULL,
                PRIMARY KEY(
                    component_id,
                    vulnerability_id
                ),
                FOREIGN KEY(component_id)
                    REFERENCES components(
                        component_id
                    ),
                FOREIGN KEY(vulnerability_id)
                    REFERENCES vulnerabilities(
                        vulnerability_id
                    )
            );
            """
        )

        metadata = {
            "mart_id": mart_id,
            "generated_at": generated_at,
            "source_path": str(
                enriched_path
            ),
            "source_sha256":
                source_sha256,
            "authoritative_policy_engine":
                authority,
            "analytics_authority":
                "PRESENTATION_ANALYTICS_ONLY",
            "production_readiness":
                production_readiness,
            "automated_disposition_permitted":
                "false",
        }

        connection.executemany(
            """
            INSERT INTO metadata(
                key,
                value
            ) VALUES (?, ?)
            """,
            sorted(metadata.items()),
        )

        for component in component_rows:
            identifier = get_component_id(
                component
            )

            if not identifier:
                continue

            vulnerability_rows = (
                extract_vulnerabilities(
                    component
                )
            )

            derived_epss: list[float] = []
            derived_kev_count = 0

            for vulnerability in (
                vulnerability_rows
            ):
                epss = as_probability(
                    find_scalar(
                        vulnerability,
                        (
                            "epss",
                            "epss_score",
                            "epss_probability",
                        ),
                    )
                )

                if epss is not None:
                    derived_epss.append(
                        epss
                    )

                derived_kev_count += int(
                    as_bool(
                        find_scalar(
                            vulnerability,
                            (
                                "kev",
                                "in_kev",
                                "cisa_kev",
                                "kev_confirmed",
                            ),
                            False,
                        )
                    )
                )

            criticality = str(
                find_scalar(
                    component,
                    (
                        "criticality",
                        "asset_criticality",
                        "criticality_level",
                    ),
                    "UNKNOWN",
                )
                or "UNKNOWN"
            ).upper()

            sector = str(
                find_scalar(
                    component,
                    (
                        "sector",
                        "sector_name",
                    ),
                    "UNKNOWN",
                )
                or "UNKNOWN"
            ).upper()

            ecosystem = str(
                find_scalar(
                    component,
                    (
                        "ecosystem",
                        "package_ecosystem",
                    ),
                    "UNKNOWN",
                )
                or "UNKNOWN"
            )

            internet_exposed = as_bool(
                find_scalar(
                    component,
                    (
                        "internet_exposed",
                        "externally_accessible",
                        "publicly_exposed",
                    ),
                    False,
                )
            )

            mission_essential = as_bool(
                find_scalar(
                    component,
                    (
                        "mission_essential",
                        "mission_critical",
                        "essential",
                    ),
                    False,
                )
            )

            contains_health_data = as_bool(
                find_scalar(
                    component,
                    (
                        "contains_health_data",
                        "health_data",
                        "phi_present",
                    ),
                    False,
                )
            )

            max_epss = as_probability(
                find_scalar(
                    component,
                    (
                        "max_epss",
                        "maximum_epss",
                        "max_epss_score",
                    ),
                )
            )

            if (
                max_epss is None
                and derived_epss
            ):
                max_epss = max(
                    derived_epss
                )

            try:
                kev_count = int(
                    find_scalar(
                        component,
                        (
                            "kev_count",
                            "cisa_kev_count",
                            "known_exploited_count",
                            "kev_confirmed_cves",
                        ),
                    )
                )
            except (TypeError, ValueError):
                kev_count = (
                    derived_kev_count
                )

            try:
                vulnerability_count = int(
                    find_scalar(
                        component,
                        (
                            "vulnerability_count",
                            "matches",
                            "match_count",
                            "osv_match_count",
                            "matched_vulnerability_count",
                        ),
                    )
                )
            except (TypeError, ValueError):
                vulnerability_count = len(
                    vulnerability_rows
                )

            source_signal = str(
                find_scalar(
                    component,
                    (
                        "attention_signal",
                        "signal",
                        "priority_signal",
                        "review_signal",
                    ),
                    "",
                )
                or ""
            )

            (
                package_name,
                version,
                target,
                purl,
            ) = package_identity(
                component
            )

            score = (
                calculate_attention_score(
                    criticality=criticality,
                    max_epss=max_epss,
                    kev_count=kev_count,
                    internet_exposed=
                        internet_exposed,
                    mission_essential=
                        mission_essential,
                    contains_health_data=
                        contains_health_data,
                )
            )

            connection.execute(
                """
                INSERT INTO components
                VALUES(
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?
                )
                """,
                (
                    identifier,
                    sector,
                    ecosystem,
                    package_name,
                    version,
                    target,
                    purl,
                    criticality,
                    int(internet_exposed),
                    int(mission_essential),
                    int(
                        contains_health_data
                    ),
                    vulnerability_count,
                    kev_count,
                    max_epss,
                    source_signal,
                    analytics_signal(score),
                    score,
                    canonical_json(
                        component
                    ),
                ),
            )

            for vulnerability in (
                vulnerability_rows
            ):
                vulnerability_identifier = (
                    vulnerability_id(
                        vulnerability
                    )
                )

                if not (
                    vulnerability_identifier
                ):
                    continue

                epss_score = as_probability(
                    find_scalar(
                        vulnerability,
                        (
                            "epss",
                            "epss_score",
                            "epss_probability",
                        ),
                    )
                )

                kev = as_bool(
                    find_scalar(
                        vulnerability,
                        (
                            "kev",
                            "in_kev",
                            "cisa_kev",
                            "kev_confirmed",
                            "known_exploited",
                        ),
                        False,
                    )
                )

                severity = str(
                    find_scalar(
                        vulnerability,
                        (
                            "severity",
                            "cvss_severity",
                        ),
                        "UNKNOWN",
                    )
                    or "UNKNOWN"
                ).upper()

                try:
                    cvss_score = float(
                        find_scalar(
                            vulnerability,
                            (
                                "cvss_score",
                                "cvss",
                                "base_score",
                            ),
                        )
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    cvss_score = None

                primary_cve = (
                    vulnerability_identifier
                    if vulnerability_identifier
                    .startswith("CVE-")
                    else None
                )

                connection.execute(
                    """
                    INSERT INTO vulnerabilities
                    VALUES(
                        ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(
                        vulnerability_id
                    ) DO UPDATE SET
                        epss_score = CASE
                            WHEN excluded.epss_score
                                IS NULL
                            THEN vulnerabilities
                                .epss_score
                            WHEN vulnerabilities
                                .epss_score
                                IS NULL
                            THEN excluded.epss_score
                            ELSE MAX(
                                excluded.epss_score,
                                vulnerabilities
                                    .epss_score
                            )
                        END,
                        kev = MAX(
                            excluded.kev,
                            vulnerabilities.kev
                        ),
                        cvss_score = COALESCE(
                            excluded.cvss_score,
                            vulnerabilities
                                .cvss_score
                        )
                    """,
                    (
                        vulnerability_identifier,
                        primary_cve,
                        severity,
                        cvss_score,
                        epss_score,
                        int(kev),
                        canonical_json(
                            vulnerability
                        ),
                    ),
                )

                connection.execute(
                    """
                    INSERT OR IGNORE INTO
                    component_vulnerabilities(
                        component_id,
                        vulnerability_id
                    ) VALUES (?, ?)
                    """,
                    (
                        identifier,
                        vulnerability_identifier,
                    ),
                )

        connection.executescript(
            """
            CREATE VIEW v_top_priority_queue AS
            SELECT
                component_id,
                sector,
                ecosystem,
                target,
                criticality,
                vulnerability_count,
                kev_count,
                max_epss,
                source_signal,
                analytics_signal,
                attention_score
            FROM components
            ORDER BY
                kev_count DESC,
                COALESCE(
                    max_epss,
                    -1
                ) DESC,
                attention_score DESC,
                vulnerability_count DESC,
                component_id ASC;

            CREATE VIEW v_sector_summary AS
            SELECT
                sector,
                COUNT(*) AS components,
                SUM(
                    CASE
                        WHEN vulnerability_count
                            > 0
                        THEN 1
                        ELSE 0
                    END
                ) AS vulnerable_components,
                SUM(
                    CASE
                        WHEN kev_count > 0
                        THEN 1
                        ELSE 0
                    END
                ) AS components_with_kev,
                SUM(
                    vulnerability_count
                ) AS vulnerability_matches,
                ROUND(
                    MAX(
                        COALESCE(
                            max_epss,
                            0
                        )
                    ),
                    5
                ) AS maximum_epss,
                ROUND(
                    AVG(attention_score),
                    2
                ) AS average_attention_score
            FROM components
            GROUP BY sector
            ORDER BY
                average_attention_score
                    DESC,
                sector ASC;

            CREATE VIEW
            v_vulnerability_catalog AS
            SELECT
                vulnerabilities
                    .vulnerability_id,
                vulnerabilities.primary_cve,
                vulnerabilities.severity,
                vulnerabilities.cvss_score,
                vulnerabilities.epss_score,
                vulnerabilities.kev,
                COUNT(
                    component_vulnerabilities
                        .component_id
                ) AS affected_components
            FROM vulnerabilities
            LEFT JOIN
                component_vulnerabilities
                ON component_vulnerabilities
                    .vulnerability_id
                = vulnerabilities
                    .vulnerability_id
            GROUP BY
                vulnerabilities
                    .vulnerability_id,
                vulnerabilities.primary_cve,
                vulnerabilities.severity,
                vulnerabilities.cvss_score,
                vulnerabilities.epss_score,
                vulnerabilities.kev
            ORDER BY
                vulnerabilities.kev DESC,
                COALESCE(
                    vulnerabilities.epss_score,
                    -1
                ) DESC,
                affected_components DESC,
                vulnerabilities
                    .vulnerability_id ASC;
            """
        )

        connection.commit()

        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if integrity != "ok":
            raise (
                PresentationAnalyticsError(
                    "SQLite integrity check "
                    "failed."
                )
            )

        counts = {
            "components":
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM components
                    """
                ).fetchone()[0],
            "vulnerable_components":
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM components
                    WHERE vulnerability_count
                        > 0
                    """
                ).fetchone()[0],
            "components_with_kev":
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM components
                    WHERE kev_count > 0
                    """
                ).fetchone()[0],
            "vulnerabilities_materialized":
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM vulnerabilities
                    """
                ).fetchone()[0],
            "component_vulnerability_links":
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM component_vulnerabilities
                    """
                ).fetchone()[0],
            "sectors":
                connection.execute(
                    """
                    SELECT COUNT(
                        DISTINCT sector
                    )
                    FROM components
                    """
                ).fetchone()[0],
        }

        source_summary = report.get(
            "summary",
            {},
        )

        if isinstance(
            source_summary,
            Mapping,
        ):
            expected_components = (
                source_summary.get(
                    "components_assessed"
                )
            )

            expected_kev_components = (
                source_summary.get(
                    "components_with_kev"
                )
            )

            if (
                expected_components is not None
                and int(expected_components)
                != counts["components"]
            ):
                raise PresentationAnalyticsError(
                    "Source-to-mart component count "
                    "mismatch."
                )

            if (
                expected_kev_components
                is not None
                and int(
                    expected_kev_components
                )
                != counts[
                    "components_with_kev"
                ]
            ):
                raise PresentationAnalyticsError(
                    "Source-to-mart KEV component "
                    "count mismatch."
                )

        top_priority_queue = [
            {
                "component_id": row[0],
                "sector": row[1],
                "target": row[3],
                "kev_count": row[6],
                "max_epss": row[7],
                "analytics_signal":
                    row[9],
                "attention_score":
                    row[10],
            }
            for row in connection.execute(
                """
                SELECT *
                FROM v_top_priority_queue
                LIMIT 10
                """
            ).fetchall()
        ]

    except Exception:
        connection.rollback()
        connection.close()

        temporary_path.unlink(
            missing_ok=True
        )

        raise

    else:
        connection.close()

    temporary_path.replace(
        database_path
    )

    summary = {
        "mart_id": mart_id,
        "generated_at": generated_at,
        "source_path": str(
            enriched_path
        ),
        "source_sha256":
            source_sha256,
        "database_path": str(
            database_path
        ),
        "database_sha256":
            sha256_file(database_path),
        "counts": counts,
        "top_priority_queue":
            top_priority_queue,
        "governance": {
            "authoritative_policy_engine":
                authority,
            "analytics_authority":
                "PRESENTATION_ANALYTICS_ONLY",
            "automated_disposition_permitted":
                False,
            "production_readiness":
                production_readiness,
        },
        "stage_gate": "PASS",
        "next_stage":
            "MILESTONE_12P_4_NOTEBOOK_AND_STREAMLIT",
    }

    summary_path.write_text(
        canonical_json(summary) + "\n",
        encoding="utf-8",
    )

    write_integrity_sidecar(
        database_path
    )

    write_integrity_sidecar(
        summary_path
    )

    return summary

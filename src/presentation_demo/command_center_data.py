"""Validated data access for the notebook and Streamlit command center."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
)

MODEL_DIR = DATA_DIR / "model_benchmark"

DATABASE_PATH = (
    DATA_DIR
    / "aegissec_presentation_risk_mart.sqlite"
)

RISK_SUMMARY_PATH = (
    DATA_DIR
    / "latest_risk_mart_summary.json"
)

ENRICHED_PATH = (
    DATA_DIR
    / "latest_enriched_intelligence.json"
)

MODEL_REPORT_PATH = (
    MODEL_DIR
    / "real_model_benchmark_report.json"
)

CANDIDATES_PATH = (
    MODEL_DIR
    / "real_model_candidates.json"
)

IMPORTANCE_PATH = (
    MODEL_DIR
    / "real_model_feature_importance.json"
)


class CommandCenterDataError(RuntimeError):
    """Raised when presentation evidence is invalid or incomplete."""


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

    if not sidecar.is_file():
        raise CommandCenterDataError(
            f"Missing integrity sidecar: {sidecar}"
        )

    expected = sidecar.read_text(
        encoding="utf-8"
    ).split()[0]

    observed = sha256_file(path)

    if expected != observed:
        raise CommandCenterDataError(
            f"Integrity verification failed: {path}"
        )


def load_verified_json(path: Path) -> Any:
    verify_sidecar(path)

    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise CommandCenterDataError(
            f"Invalid JSON artifact: {path}"
        ) from exc


def recursive_first(
    value: Any,
    key: str,
) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]

        for child in value.values():
            found = recursive_first(child, key)

            if found is not None:
                return found

    elif isinstance(value, list):
        for child in value:
            found = recursive_first(child, key)

            if found is not None:
                return found

    return None


def load_synthetic_baseline() -> dict[str, Any] | None:
    reports = sorted(
        (
            ROOT
            / "data"
            / "processed"
            / "ml_advisory"
        ).glob(
            "**/milestone12f_training_report.json"
        )
    )

    if not reports:
        return None

    latest = reports[-1]

    return {
        "path": str(latest),
        "document": json.loads(
            latest.read_text(encoding="utf-8")
        ),
    }


def load_command_center_bundle() -> dict[str, Any]:
    required = [
        DATABASE_PATH,
        RISK_SUMMARY_PATH,
        ENRICHED_PATH,
        MODEL_REPORT_PATH,
        CANDIDATES_PATH,
        IMPORTANCE_PATH,
    ]

    for path in required:
        if not path.is_file():
            raise CommandCenterDataError(
                f"Missing presentation artifact: {path}"
            )

        verify_sidecar(path)

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        integrity = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if integrity != "ok":
            raise CommandCenterDataError(
                "SQLite integrity verification failed."
            )

        components = pd.read_sql_query(
            """
            SELECT *
            FROM v_top_priority_queue
            """,
            connection,
        )

        sectors = pd.read_sql_query(
            """
            SELECT *
            FROM v_sector_summary
            """,
            connection,
        )

        vulnerabilities = pd.read_sql_query(
            """
            SELECT *
            FROM v_vulnerability_catalog
            """,
            connection,
        )

        component_vulnerabilities = pd.read_sql_query(
            """
            SELECT
                links.component_id,
                vulnerabilities.vulnerability_id,
                vulnerabilities.primary_cve,
                vulnerabilities.severity,
                vulnerabilities.cvss_score,
                vulnerabilities.epss_score,
                vulnerabilities.kev
            FROM component_vulnerabilities AS links
            JOIN vulnerabilities
                ON vulnerabilities.vulnerability_id
                = links.vulnerability_id
            ORDER BY
                links.component_id,
                vulnerabilities.kev DESC,
                COALESCE(
                    vulnerabilities.epss_score,
                    -1
                ) DESC
            """,
            connection,
        )

        metadata_rows = connection.execute(
            """
            SELECT key, value
            FROM metadata
            ORDER BY key
            """
        ).fetchall()

    risk_summary = load_verified_json(
        RISK_SUMMARY_PATH
    )

    enriched = load_verified_json(
        ENRICHED_PATH
    )

    model_report = load_verified_json(
        MODEL_REPORT_PATH
    )

    candidates = load_verified_json(
        CANDIDATES_PATH
    )

    importance = load_verified_json(
        IMPORTANCE_PATH
    )

    if (
        risk_summary["governance"][
            "authoritative_policy_engine"
        ]
        != "SSVC"
    ):
        raise CommandCenterDataError(
            "SSVC authority is not preserved."
        )

    if (
        model_report["governance"][
            "model_authority"
        ]
        != "ADVISORY_ONLY"
    ):
        raise CommandCenterDataError(
            "Unexpected model authority."
        )

    return {
        "components": components,
        "sectors": sectors,
        "vulnerabilities": vulnerabilities,
        "component_vulnerabilities":
            component_vulnerabilities,
        "metadata": dict(metadata_rows),
        "risk_summary": risk_summary,
        "enriched": enriched,
        "model_report": model_report,
        "candidates": candidates,
        "importance": importance,
        "synthetic_baseline":
            load_synthetic_baseline(),
    }

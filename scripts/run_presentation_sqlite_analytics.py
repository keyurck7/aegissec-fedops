from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.sqlite_analytics import (  # noqa: E402
    build_risk_mart,
)


INPUT_PATH = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "latest_enriched_intelligence.json"
)

DATABASE_PATH = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "aegissec_presentation_risk_mart.sqlite"
)

SUMMARY_PATH = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "latest_risk_mart_summary.json"
)


def main() -> int:
    summary = build_risk_mart(
        INPUT_PATH,
        DATABASE_PATH,
        SUMMARY_PATH,
    )

    print("=" * 76)
    print(
        "AEGISSEC-FEDOPS SQLITE "
        "RISK DATA MART"
    )
    print("=" * 76)

    print(
        json.dumps(
            {
                "mart_id":
                    summary["mart_id"],
                "counts":
                    summary["counts"],
                "governance":
                    summary["governance"],
                "stage_gate":
                    summary["stage_gate"],
                "next_stage":
                    summary["next_stage"],
            },
            indent=2,
            sort_keys=True,
        )
    )

    print()
    print(
        "Top component attention queue:"
    )

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        rows = connection.execute(
            """
            SELECT
                component_id,
                sector,
                target,
                kev_count,
                max_epss,
                source_signal,
                analytics_signal,
                attention_score
            FROM v_top_priority_queue
            LIMIT 16
            """
        ).fetchall()

    for row in rows:
        epss_display = (
            "N/A"
            if row[4] is None
            else f"{row[4] * 100:.2f}%"
        )

        print(
            f"  {row[0]} | "
            f"{row[1]:24} | "
            f"Source={row[5]:18} | "
            f"Analytics={row[6]:18} | "
            f"Score={row[7]:6.2f} | "
            f"KEV={row[3]:2d} | "
            f"EPSS={epss_display:8} | "
            f"{row[2]}"
        )

    print()
    print(f"Database : {DATABASE_PATH}")
    print(f"Summary  : {SUMMARY_PATH}")
    print("SSVC authority: PRESERVED")
    print("Production readiness: BLOCKED")
    print(
        "Next stage: notebook and "
        "Streamlit dashboard"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

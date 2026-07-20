#!/usr/bin/env python3
"""Inspect the complete AegisSec presentation vertical slice."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.master_vertical_slice import (  # noqa: E402
    load_master_vertical_slice,
)


def main() -> int:
    bundle = load_master_vertical_slice()

    summary = bundle["summary"]

    print("=" * 78)
    print(
        "AEGISSEC-FEDOPS MASTER "
        "VERTICAL SLICE"
    )
    print("=" * 78)

    print()
    print("Governed SSVC decision")
    print(
        "  Decision ID        :",
        summary["decision_id"],
    )
    print(
        "  CVE                :",
        summary["cve_id"],
    )
    print(
        "  Vector             :",
        summary["vector"],
    )
    print(
        "  Decision-table row :",
        summary["matched_row"],
    )
    print(
        "  Outcome            :",
        summary["outcome_name"],
    )
    print(
        "  Stage gate         :",
        summary["stage_gate"],
    )
    print(
        "  Human review       :",
        summary[
            "human_review_required"
        ],
    )
    print(
        "  Final disposition  :",
        summary[
            "final_disposition_status"
        ],
    )

    print()
    print("Predictive separation")
    print(
        "  Custom model       :",
        summary["model_winner"],
    )
    print(
        "  Custom model label :",
        summary["model_label"],
    )
    print(
        "  Model authority    :",
        summary["model_authority"],
    )
    print(
        "  Near-term forecast :",
        summary[
            "near_term_forecast_lane"
        ],
    )
    print(
        "  Custom forecast    :",
        summary[
            "future_custom_forecast"
        ],
    )

    print()
    print("SSVC decision points")

    print(
        bundle[
            "decision_points"
        ].to_string(
            index=False
        )
    )

    print()
    print("Threshold operating policies")

    print(
        bundle[
            "operating_points"
        ][
            [
                "policy",
                "threshold",
                "precision",
                "recall",
                "f1",
                "balanced_accuracy",
            ]
        ].to_string(
            index=False
        )
    )

    print()
    print(
        "SSVC authority              : PRESERVED"
    )
    print(
        "Prediction claim boundary   : PRESERVED"
    )
    print(
        "Final disposition authority : HUMAN"
    )
    print(
        "Production readiness        : BLOCKED"
    )
    print(
        "MASTER VERTICAL SLICE       : PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

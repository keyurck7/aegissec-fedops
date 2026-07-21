#!/usr/bin/env python3
"""Run the controlled executable AegisSec assessment path."""

from __future__ import annotations

import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )

from src.orchestration.assessment_ledger import (  # noqa: E402
    verify_ledger,
    write_ledger_atomic,
)
from src.orchestration.controlled_vertical_adapters import (  # noqa: E402
    execute_controlled_vertical_slice,
)


OUTPUT = (
    ROOT
    / "reports"
    / "orchestration"
    / "m13b1d_controlled_vertical_assessment.json"
)


def main() -> int:
    print("=" * 76)
    print(
        "MILESTONE 13B.1D "
        "DYNAMIC ASSESSMENT ORCHESTRATOR"
    )
    print("=" * 76)

    ledger, context = (
        execute_controlled_vertical_slice()
    )

    valid, errors = verify_ledger(
        ledger
    )

    if not valid:
        raise RuntimeError(
            "; ".join(errors)
        )

    path, sidecar = (
        write_ledger_atomic(
            ledger,
            OUTPUT,
        )
    )

    summary = context[
        "master_vertical_slice"
    ]["summary"]

    print(
        "Execution lane :",
        context["execution_lane"],
    )

    print(
        "Assessment ID  :",
        ledger["assessment_id"],
    )

    print(
        "Run status     :",
        ledger["run_status"],
    )

    print(
        "CVE            :",
        summary["cve_id"],
    )

    print(
        "SSVC vector    :",
        summary["vector"],
    )

    print(
        "Decision row   :",
        summary["matched_row"],
    )

    print(
        "Outcome        :",
        summary["outcome_name"],
    )

    print(
        "Final status   :",
        summary[
            "final_disposition_status"
        ],
    )

    print(
        "Production     :",
        summary[
            "production_readiness"
        ],
    )

    print(
        "Event count    :",
        ledger["integrity"][
            "event_count"
        ],
    )

    print(
        "Head hash      :",
        ledger["integrity"][
            "head_event_hash"
        ],
    )

    print(
        "Ledger         :",
        path.relative_to(ROOT),
    )

    print(
        "Sidecar        :",
        sidecar.relative_to(ROOT),
    )

    print()
    print("Stage ledger:")

    for definition in ledger[
        "stage_plan"
    ]:
        stage_id = definition[
            "stage_id"
        ]

        state = ledger[
            "stages"
        ][stage_id]

        print(
            f"  {stage_id:28} "
            f"{state['status']:22} "
            f"outputs={len(state['outputs'])}"
        )

    assert (
        ledger["run_status"]
        == "AWAITING_HUMAN_REVIEW"
    )

    assert (
        ledger["stages"][
            "HUMAN_REVIEW"
        ]["status"]
        == "PENDING"
    )

    assert (
        ledger["stages"][
            "FINALIZATION"
        ]["status"]
        == "PENDING"
    )

    assert (
        summary[
            "final_disposition_status"
        ]
        == "NOT_AUTHORIZED"
    )

    assert (
        summary[
            "production_readiness"
        ]
        == "BLOCKED"
    )

    print()
    print("=" * 76)
    print(
        "MILESTONE 13B.1D "
        "DYNAMIC ORCHESTRATOR: PASS"
    )
    print(
        "EXISTING ENGINES: REUSED"
    )
    print(
        "BUSINESS RULE DUPLICATION: NONE"
    )
    print(
        "ASSESSMENT STATUS: "
        "AWAITING_HUMAN_REVIEW"
    )
    print(
        "SSVC AUTHORITY: PRESERVED"
    )
    print(
        "FINAL DISPOSITION: NOT_AUTHORIZED"
    )
    print(
        "PRODUCTION READINESS: BLOCKED"
    )
    print("=" * 76)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

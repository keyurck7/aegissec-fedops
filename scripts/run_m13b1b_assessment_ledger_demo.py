#!/usr/bin/env python3
"""Demonstrate the governed assessment stage ledger."""

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

from src.orchestration.assessment_ledger import (  # noqa: E402
    PASSED,
    RUNNING,
    create_assessment_ledger,
    transition_stage,
    verify_ledger,
    write_ledger_atomic,
)


OUTPUT = (
    ROOT
    / "reports"
    / "orchestration"
    / "m13b1b_assessment_ledger_demo.json"
)


def complete_stage(
    ledger,
    stage_id,
):
    ledger = transition_stage(
        ledger,
        stage_id=stage_id,
        to_status=RUNNING,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-orchestrator"
        ),
        message=(
            f"{stage_id} started."
        ),
    )

    return transition_stage(
        ledger,
        stage_id=stage_id,
        to_status=PASSED,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-orchestrator"
        ),
        message=(
            f"{stage_id} passed."
        ),
        outputs=[
            {
                "artifact_type": (
                    f"{stage_id}_RESULT"
                ),
                "authority": (
                    "GOVERNED_STAGE_OUTPUT"
                ),
            }
        ],
    )


def main() -> int:
    print("=" * 76)
    print(
        "MILESTONE 13B.1B "
        "ASSESSMENT LEDGER DEMONSTRATION"
    )
    print("=" * 76)

    ledger = create_assessment_ledger(
        input_id=(
            "AEG-INP-DEMO-DYNAMIC-ASSESSMENT"
        ),
        input_envelope_sha256=(
            "d" * 64
        ),
        created_by=(
            "aegissec-orchestrator"
        ),
        asset_context_id=(
            "AEG-ASSET-DEMO-HEALTHCARE"
        ),
    )

    for stage_id in (
        "INTAKE_VALIDATION",
        "ASSET_CONTEXT",
        "COMPONENT_CORRELATION",
        "EVIDENCE_ARBITRATION",
    ):
        ledger = complete_stage(
            ledger,
            stage_id,
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

    print(
        "Assessment ID :",
        ledger["assessment_id"],
    )

    print(
        "Run status    :",
        ledger["run_status"],
    )

    print(
        "Events        :",
        len(ledger["events"]),
    )

    print(
        "Head hash     :",
        ledger["integrity"][
            "head_event_hash"
        ],
    )

    print(
        "Ledger SHA-256:",
        ledger["integrity"][
            "ledger_sha256"
        ],
    )

    print(
        "Document      :",
        path.relative_to(ROOT),
    )

    print(
        "Sidecar       :",
        sidecar.relative_to(ROOT),
    )

    print()
    print("Stage states:")

    for definition in ledger[
        "stage_plan"
    ]:
        stage_id = definition[
            "stage_id"
        ]

        print(
            f"  {stage_id:28} "
            f"{ledger['stages'][stage_id]['status']}"
        )

    print()
    print("=" * 76)
    print(
        "MILESTONE 13B.1B "
        "ASSESSMENT LEDGER DEMO: PASS"
    )
    print(
        "EVENT CHAIN: VERIFIED"
    )
    print(
        "DOWNSTREAM GATING: ENFORCED"
    )
    print(
        "FINAL AUTHORITY: HUMAN"
    )
    print(
        "PRODUCTION READINESS: BLOCKED"
    )
    print("=" * 76)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

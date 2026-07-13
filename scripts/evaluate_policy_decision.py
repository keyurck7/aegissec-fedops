from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.affectedness.affectedness_engine import (
    AffectednessEngine,
)
from src.governance.evidence_trust_engine import (
    EvidenceTrustEngine,
)
from src.policy.policy_floor_engine import (
    PolicyFloorEngine,
)


DEFAULT_DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_affectedness.json"
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(
            f"Expected JSON object: {path}"
        )

    return payload


def resolve_reference(
    reference: dict,
) -> Path:
    path = (
        PROJECT_ROOT
        / reference["relative_path"]
    ).resolve()

    if (
        path != PROJECT_ROOT
        and PROJECT_ROOT not in path.parents
    ):
        raise ValueError(
            "Referenced path escapes project root."
        )

    return path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the AegisSec policy floor "
            "for a Decision Record."
        )
    )

    parser.add_argument(
        "decision_record",
        type=Path,
        nargs="?",
        default=DEFAULT_DECISION_PATH,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    decision = load_json(
        args.decision_record
    )

    asset = load_json(
        resolve_reference(
            decision["input_records"][
                "asset_context"
            ]
        )
    )

    intelligence = load_json(
        resolve_reference(
            decision["input_records"][
                "vulnerability_intelligence"
            ]
        )
    )

    evidence = load_json(
        resolve_reference(
            decision["input_records"][
                "evidence_records"
            ][0]
        )
    )

    trust = EvidenceTrustEngine().assess(
        evidence
    )

    affectedness = (
        AffectednessEngine().assess(
            component_instance=(
                decision["component_instance"]
            ),
            intelligence_record=intelligence,
            evidence_trust=trust,
        )
    )

    policy = PolicyFloorEngine().evaluate(
        asset_context=asset,
        intelligence_record=intelligence,
        component_instance=(
            decision["component_instance"]
        ),
        affectedness_assessment=affectedness,
        evidence_trust=trust,
    )

    output_text = json.dumps(
        policy.to_dict(),
        indent=2,
        ensure_ascii=False,
    )

    print(output_text)

    if args.output is not None:
        args.output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        args.output.write_text(
            output_text + "\n",
            encoding="utf-8",
        )

        print()
        print(
            f"Assessment written to: "
            f"{args.output}"
        )

    return (
        0
        if policy.invariants_passed
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())

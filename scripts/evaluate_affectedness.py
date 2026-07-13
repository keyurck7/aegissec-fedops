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


DEFAULT_DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record.json"
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return payload


def resolve_reference(reference: dict) -> Path:
    relative_path = reference["relative_path"]
    resolved = (PROJECT_ROOT / relative_path).resolve()

    if (
        resolved != PROJECT_ROOT
        and PROJECT_ROOT not in resolved.parents
    ):
        raise ValueError(
            "Referenced path escapes the project root."
        )

    return resolved


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate component affectedness from a "
            "Decision Record and its referenced evidence."
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

    decision = load_json(args.decision_record)

    intelligence_reference = decision[
        "input_records"
    ]["vulnerability_intelligence"]

    evidence_reference = decision[
        "input_records"
    ]["evidence_records"][0]

    intelligence = load_json(
        resolve_reference(intelligence_reference)
    )

    evidence = load_json(
        resolve_reference(evidence_reference)
    )

    trust_engine = EvidenceTrustEngine()
    trust_assessment = trust_engine.assess(evidence)

    affectedness_engine = AffectednessEngine()

    assessment = affectedness_engine.assess(
        component_instance=decision["component_instance"],
        intelligence_record=intelligence,
        evidence_trust=trust_assessment,
    )

    payload = assessment.to_dict()

    output_text = json.dumps(
        payload,
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
        print(f"Assessment written to: {args.output}")

    return 0 if assessment.status != "unknown" else 1


if __name__ == "__main__":
    raise SystemExit(main())

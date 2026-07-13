from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.governance.evidence_trust_engine import (
    DEFAULT_POLICY_PATH,
    EvidenceTrustEngine,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Calculate policy-controlled trust for an "
            "AegisSec Evidence Record."
        )
    )

    parser.add_argument(
        "record",
        type=Path,
        help="Path to the Evidence Record JSON file.",
    )

    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY_PATH,
        help="Optional trust-policy path.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path for the Trust Assessment JSON.",
    )

    return parser.parse_args()


def load_record(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"Evidence Record not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        record = json.load(file)

    if not isinstance(record, dict):
        raise ValueError(
            "Evidence Record must be a JSON object."
        )

    return record


def main() -> int:
    args = parse_arguments()

    try:
        record = load_record(args.record)

        engine = EvidenceTrustEngine(
            policy_path=args.policy
        )

        assessment = engine.assess(record)
        payload = assessment.to_dict()

    except (
        FileNotFoundError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "success": False,
                    "error": str(exc),
                },
                indent=2,
            )
        )
        return 2

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

    return 0 if assessment.accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

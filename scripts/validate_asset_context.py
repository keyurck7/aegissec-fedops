from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.validation.asset_context_validator import AssetContextValidator


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate an AegisSec Asset Context Record."
    )

    parser.add_argument(
        "record",
        type=Path,
        help="Path to the Asset Context JSON file.",
    )

    parser.add_argument(
        "--schema",
        type=Path,
        default=(
            PROJECT_ROOT
            / "schemas"
            / "aegis_asset_context.schema.json"
        ),
        help="Optional custom schema path.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    try:
        validator = AssetContextValidator(args.schema)
        result = validator.validate_file(args.record)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "status": "rejected",
                    "fatal_error": str(exc),
                },
                indent=2,
            )
        )
        return 2

    output = {
        "record": str(args.record),
        "valid": result.valid,
        **result.to_dict(),
    }

    print(json.dumps(output, indent=2))

    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())

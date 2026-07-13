from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingestion.vulnerability_feature_parser import (
    parse_vulnerability_feature_row,
)


DEFAULT_INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "parsing"
    / "strict_parsing_cases.csv"
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Demonstrate strict parsing and missing-value semantics."
        )
    )

    parser.add_argument(
        "input_file",
        type=Path,
        nargs="?",
        default=DEFAULT_INPUT_PATH,
        help="CSV containing raw vulnerability feature rows.",
    )

    parser.add_argument(
        "--show-outcomes",
        action="store_true",
        help="Print every field-level parsing outcome.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    accepted_count = 0
    rejected_count = 0
    results: list[dict] = []

    with args.input_file.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            report = parse_vulnerability_feature_row(row)

            if report.accepted:
                accepted_count += 1
            else:
                rejected_count += 1

            result = {
                "finding_id": row.get("finding_id"),
                "accepted": report.accepted,
                "parsed_kev_flag": report.values["kev_flag"],
                "parsed_epss_probability": (
                    report.values["epss_probability"]
                ),
                "epss_status": (
                    report.outcomes["epss_probability"]
                    .status.value
                ),
                "error_codes": [
                    error.code
                    for error in report.errors
                ],
                "warning_codes": [
                    warning.code
                    for warning in report.warnings
                ],
            }

            if args.show_outcomes:
                result["outcomes"] = {
                    field_name: outcome.to_dict()
                    for field_name, outcome in report.outcomes.items()
                }

            results.append(result)

    print(
        json.dumps(
            {
                "input_file": str(args.input_file),
                "accepted_rows": accepted_count,
                "rejected_rows": rejected_count,
                "results": results,
            },
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

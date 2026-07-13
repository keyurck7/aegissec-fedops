from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.assurance.policy_assurance import (
    PolicyAssuranceRunner,
    write_json,
)


DEFAULT_CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_corpus.jsonl"
)

DEFAULT_MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_manifest.json"
)

DEFAULT_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "assurance"
    / "step9_policy_assurance_report.json"
)


FIXED_EVALUATION_TIME = datetime(
    2026,
    7,
    13,
    19,
    45,
    tzinfo=timezone.utc,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the AegisSec 120-case policy "
            "assurance corpus."
        )
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS_PATH,
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_REPORT_PATH,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    runner = PolicyAssuranceRunner(
        project_root=PROJECT_ROOT
    )

    report = runner.run(
        corpus_path=args.corpus,
        manifest_path=args.manifest,
        evaluated_at=FIXED_EVALUATION_TIME,
    )

    write_json(
        args.output,
        report,
    )

    summary = report["summary"]

    print("AegisSec Step 9 Assurance Report")
    print(
        "Cases:",
        f"{summary['passed_cases']}/"
        f"{summary['case_count']} passed",
    )
    print(
        "Counterfactual pairs:",
        f"{summary['passed_pairs']}/"
        f"{summary['pair_count']} passed",
    )
    print(
        "Policy invariant cases:",
        f"{summary['invariant_pass_cases']}/"
        f"{summary['case_count']} passed",
    )
    print(
        "Sector disparities:",
        summary["sector_disparity_count"],
    )
    print(
        "Manifest checks:",
        f"{summary['manifest_checks_passed']}/"
        f"{summary['manifest_check_count']} passed",
    )
    print(
        "Overall passed:",
        summary["overall_passed"],
    )
    print("Report:", args.output)

    if not summary["overall_passed"]:
        failed_cases = [
            result
            for result
            in report["case_results"]
            if not result["passed"]
        ]

        failed_pairs = [
            result
            for result
            in report[
                "counterfactual_results"
            ]
            if not result["passed"]
        ]

        print()
        print(
            json.dumps(
                {
                    "failed_cases": (
                        failed_cases
                    ),
                    "failed_pairs": (
                        failed_pairs
                    ),
                },
                indent=2,
            )
        )

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

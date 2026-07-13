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
    TARGETED_RULE_PROFILES,
    write_json,
)


DEFAULT_CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step11a_policy_rule_coverage_corpus.jsonl"
)

DEFAULT_MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step11a_policy_rule_coverage_manifest.json"
)

DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_policy_assurance_case_v1_1.schema.json"
)

DEFAULT_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "assurance"
    / "step11a_policy_rule_coverage_report.json"
)

FIXED_EVALUATION_TIME = datetime(
    2026,
    7,
    13,
    20,
    30,
    tzinfo=timezone.utc,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the AegisSec 130-case Step 11A policy-rule "
            "coverage assurance corpus."
        )
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_PATH)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    runner = PolicyAssuranceRunner(
        project_root=PROJECT_ROOT,
        schema_path=args.schema,
    )

    report = runner.run(
        corpus_path=args.corpus,
        manifest_path=args.manifest,
        evaluated_at=FIXED_EVALUATION_TIME,
    )

    observed_rules = {
        rule_id
        for result in report["case_results"]
        for rule_id in result["matched_rule_ids"]
    }
    required_target_rules = {
        profile["target_rule_id"]
        for profile in TARGETED_RULE_PROFILES
    }
    missing_target_rules = sorted(required_target_rules - observed_rules)

    report["targeted_rule_coverage"] = {
        "required_target_rules": sorted(required_target_rules),
        "covered_target_rules": sorted(required_target_rules & observed_rules),
        "missing_target_rules": missing_target_rules,
        "complete": not missing_target_rules,
    }

    write_json(args.output, report)

    summary = report["summary"]

    print("AegisSec Step 11A Policy-Rule Coverage Assurance")
    print(
        "Cases:",
        f"{summary['passed_cases']}/{summary['case_count']} passed",
    )
    print(
        "Counterfactual pairs:",
        f"{summary['passed_pairs']}/{summary['pair_count']} passed",
    )
    print(
        "Policy invariant cases:",
        f"{summary['invariant_pass_cases']}/{summary['case_count']} passed",
    )
    print("Sector disparities:", summary["sector_disparity_count"])
    print("Targeted rules covered:", len(required_target_rules) - len(missing_target_rules), "/", len(required_target_rules))
    print("Overall passed:", summary["overall_passed"])
    print("Report:", args.output)

    if not summary["overall_passed"] or missing_target_rules:
        print()
        print(
            json.dumps(
                {
                    "missing_target_rules": missing_target_rules,
                    "failed_cases": [
                        result
                        for result in report["case_results"]
                        if not result["passed"]
                    ],
                    "failed_pairs": [
                        result
                        for result in report["counterfactual_results"]
                        if not result["passed"]
                    ],
                },
                indent=2,
            )
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

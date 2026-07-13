from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.assurance.fairness_robustness import (
    FairnessRobustnessEvaluator,
    write_json,
    write_subgroup_csv,
)


DEFAULT_INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "assurance"
    / "step11a_policy_rule_coverage_report.json"
)

DEFAULT_OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "fairness"
    / "step11a_rule_coverage_evaluation_report.json"
)

DEFAULT_SUBGROUP_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "fairness"
    / "step11a_subgroup_metrics.csv"
)

DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_fairness_robustness_report.schema.json"
)

EVALUATION_TIME = datetime(
    2026,
    7,
    13,
    20,
    45,
    tzinfo=timezone.utc,
)

EXPECTED_REMAINING_BLOCKERS = [
    "Real operational validation has not yet been completed.",
    "Independent security review has not yet been completed.",
]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the Step 11A extended corpus and prove complete "
            "decision-policy rule coverage without claiming production readiness."
        )
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--subgroup-output",
        type=Path,
        default=DEFAULT_SUBGROUP_PATH,
    )
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def main() -> int:
    args = parse_arguments()
    assurance_report = load_json(args.input)

    evaluator = FairnessRobustnessEvaluator()
    report = evaluator.evaluate(
        assurance_report=assurance_report,
        source_report_path=args.input,
        evaluated_at=EVALUATION_TIME,
    )

    schema = load_json(args.schema)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    schema_errors = sorted(
        validator.iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )

    if schema_errors:
        print(
            json.dumps(
                {
                    "valid": False,
                    "schema_errors": [
                        {
                            "path": ".".join(
                                str(part) for part in error.absolute_path
                            ),
                            "message": error.message,
                        }
                        for error in schema_errors
                    ],
                },
                indent=2,
            )
        )
        return 2

    write_json(args.output, report)
    write_subgroup_csv(args.subgroup_output, report["subgroup_metrics"])

    rules = report["rule_coverage"]
    release = report["release_decision"]
    exact = report["exact_match_metrics"]
    safety = report["safety_metrics"]
    counterfactual = report["counterfactual_metrics"]

    governance_failures = []

    if rules["full_rule_coverage_rate"] != 1.0:
        governance_failures.append("Full policy-rule coverage is not 100%.")

    if rules["uncovered_policy_rules"]:
        governance_failures.append(
            "Uncovered policy rules remain: "
            + ", ".join(rules["uncovered_policy_rules"])
        )

    if release["stage_gate_status"] != "PASS":
        governance_failures.append("Controlled stage gate did not pass.")

    if release["production_readiness_status"] != "BLOCKED":
        governance_failures.append(
            "Production readiness must remain BLOCKED at Step 11A."
        )

    if release["blocking_reasons"] != EXPECTED_REMAINING_BLOCKERS:
        governance_failures.append(
            "Remaining production blockers do not match the approved Step 11A set."
        )

    print("AegisSec Step 11A Rule-Coverage Evaluation")
    print(
        "Exact policy cases:",
        f"{exact['exact_case_count']}/{exact['case_count']}",
    )
    print("Under-triage cases:", safety["under_triage_count"])
    print("Safety recall:", f"{safety['safety_recall']:.4f}")
    print(
        "Counterfactual consistency:",
        f"{counterfactual['counterfactual_consistency_rate']:.4f}",
    )
    print("Sector disparities:", counterfactual["sector_disparity_count"])
    print(
        "Policy-rule coverage:",
        f"{rules['covered_policy_rule_count']}/{rules['policy_rule_count']}",
    )
    print("Stage gate:", release["stage_gate_status"])
    print(
        "Production readiness:",
        release["production_readiness_status"],
    )
    print("Report:", args.output)
    print("Subgroup metrics:", args.subgroup_output)

    print()
    print("Remaining production blockers:")
    for reason in release["blocking_reasons"]:
        print(f"  - {reason}")

    if governance_failures:
        print()
        print("Governance failures:")
        for failure in governance_failures:
            print(f"  - {failure}")
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

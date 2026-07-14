from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.metamorphic_assurance import (
    MetamorphicAssuranceHarness,
    save_metamorphic_artifacts,
)
from src.assurance.policy_assurance import load_json


DEFAULT_OUTPUT_DIR = (
    REPOSITORY_ROOT / "data" / "validation_reports" / "metamorphic"
)
DEFAULT_SCHEMA_PATH = (
    REPOSITORY_ROOT / "schemas" / "aegis_metamorphic_assurance_report.schema.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Step 11E metamorphic and monotonic-property assurance."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = MetamorphicAssuranceHarness().run()
    schema = load_json(args.schema)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path)
            print(f"Schema error at {location or '<root>'}: {error.message}")
        return 2
    paths = save_metamorphic_artifacts(report, args.output_dir)
    summary = report["summary"]
    release = report["release_decision"]
    print("AegisSec Step 11E Metamorphic Assurance")
    print("Relations:", summary["relation_count"])
    print("Passed:", summary["passed_count"])
    print("Violations:", summary["violated_count"])
    print("Blocked invalid transformations:", summary["blocked_invalid_transformation_count"])
    print("Harness errors:", summary["harness_error_count"])
    print(
        "Critical relation pass rate:",
        f"{summary['critical_relation_pass_rate']:.4f}",
    )
    print(
        "Sector-neutrality consistency:",
        f"{summary['sector_neutrality_consistency_rate']:.4f}",
    )
    print(
        "Danger-escalation monotonicity:",
        f"{summary['danger_escalation_monotonicity_rate']:.4f}",
    )
    print(
        "Trust fail-closed rate:",
        f"{summary['trust_degradation_fail_closed_rate']:.4f}",
    )
    print(
        "Deadline monotonicity:",
        f"{summary['deadline_monotonicity_rate']:.4f}",
    )
    print(
        "Review monotonicity:",
        f"{summary['review_monotonicity_rate']:.4f}",
    )
    print(
        "Containment monotonicity:",
        f"{summary['containment_monotonicity_rate']:.4f}",
    )
    print(
        "Closure monotonicity:",
        f"{summary['closure_monotonicity_rate']:.4f}",
    )
    print("Trusted inputs unchanged:", summary["trusted_input_integrity_passed"])
    print("Stage gate:", release["stage_gate_status"])
    print("Production readiness:", release["production_readiness_status"])
    print("Report:", paths["report"])
    print("Results CSV:", paths["csv"])
    print("Violations:", paths["violations"])
    print("Integrity record:", paths["integrity"])
    if release["blocking_reasons"]:
        print("\nRemaining production blockers:")
        for reason in release["blocking_reasons"]:
            print(" -", reason)
    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

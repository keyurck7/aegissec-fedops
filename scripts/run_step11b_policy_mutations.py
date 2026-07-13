from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.assurance.policy_mutation import (
    DEFAULT_CATALOG_PATH,
    PolicyMutationHarness,
    load_json,
    sha256_file,
    write_json,
    write_results_csv,
)


DEFAULT_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_policy_mutation_report.json"
)

DEFAULT_RESULTS_CSV_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_mutation_results.csv"
)

DEFAULT_SURVIVORS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_surviving_mutations.json"
)

DEFAULT_INTEGRITY_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_trusted_policy_integrity.sha256"
)

DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_policy_mutation_report.schema.json"
)



def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Execute controlled Step 11B policy mutations against ephemeral "
            "policy copies and enforce a 100% critical mutation defence gate."
        )
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG_PATH,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_REPORT_PATH,
    )
    parser.add_argument(
        "--results-csv",
        type=Path,
        default=DEFAULT_RESULTS_CSV_PATH,
    )
    parser.add_argument(
        "--survivors-output",
        type=Path,
        default=DEFAULT_SURVIVORS_PATH,
    )
    parser.add_argument(
        "--integrity-output",
        type=Path,
        default=DEFAULT_INTEGRITY_PATH,
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
    )
    return parser.parse_args()



def main() -> int:
    args = parse_arguments()

    harness = PolicyMutationHarness(
        project_root=PROJECT_ROOT,
        catalog_path=args.catalog,
    )
    report = harness.run()

    schema = load_json(args.schema)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )

    if errors:
        print(
            json.dumps(
                {
                    "valid": False,
                    "schema_errors": [
                        {
                            "path": ".".join(
                                str(part)
                                for part in error.absolute_path
                            ),
                            "message": error.message,
                        }
                        for error in errors
                    ],
                },
                indent=2,
            )
        )
        return 2

    write_json(args.output, report)
    write_results_csv(args.results_csv, report["results"])
    write_json(
        args.survivors_output,
        {
            "schema_version": "1.0.0",
            "report_id": report["report_id"],
            "surviving_mutation_ids": report[
                "surviving_mutation_ids"
            ],
            "surviving_mutations": [
                result
                for result in report["results"]
                if result["status"] == "SURVIVED"
            ],
        },
    )

    trusted = report["trusted_policy"]
    args.integrity_output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    args.integrity_output.write_text(
        (
            f"{trusted['sha256_after']}  "
            f"{trusted['relative_path']}\n"
        ),
        encoding="utf-8",
    )

    summary = report["summary"]
    release = report["release_decision"]

    print("AegisSec Step 11B Policy Mutation Testing")
    print("Mutations:", summary["mutation_count"])
    print(
        "Blocked at load:",
        summary["blocked_at_load_count"],
    )
    print(
        "Killed by assurance:",
        summary["killed_by_assurance_count"],
    )
    print("Survived:", summary["survived_count"])
    print(
        "Harness errors:",
        summary["harness_error_count"],
    )
    print(
        "Critical mutation defence rate:",
        f"{summary['critical_mutation_defence_rate']:.4f}",
    )
    print(
        "Executable critical kill rate:",
        f"{summary['executable_critical_mutation_kill_rate']:.4f}",
    )
    print(
        "Trusted policy unchanged:",
        summary["trusted_policy_integrity_passed"],
    )
    print("Stage gate:", release["stage_gate_status"])
    print(
        "Production readiness:",
        release["production_readiness_status"],
    )
    print("Report:", args.output)
    print("Results CSV:", args.results_csv)
    print("Survivors:", args.survivors_output)
    print("Integrity record:", args.integrity_output)

    print()
    print("Mutation outcomes:")

    for result in report["results"]:
        oracles = ", ".join(result["detection_oracles"]) or "NONE"
        print(
            f"  {result['mutation_id']}: {result['status']} "
            f"[{oracles}]"
        )

    print()
    print("Remaining production blockers:")

    for reason in release["blocking_reasons"]:
        print(f"  - {reason}")

    print()
    print(
        "Trusted policy SHA-256:",
        sha256_file(harness.trusted_policy_path),
    )

    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

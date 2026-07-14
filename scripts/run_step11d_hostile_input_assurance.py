from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.hostile_input_assurance import (
    DEFAULT_CATALOG_PATH,
    PROJECT_ROOT,
    HostileInputAssuranceHarness,
    sha256_file,
    write_json,
    write_results_csv,
)


DEFAULT_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_hostile_input_report.json"
)
DEFAULT_RESULTS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_hostile_input_results.csv"
)
DEFAULT_UNDETECTED_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_undetected_inputs.json"
)
DEFAULT_INTEGRITY_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_trusted_baseline_integrity.sha256"
)
DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_hostile_input_assurance_report.schema.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Step 11D hostile and malformed input assurance."
    )
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--results-csv", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument(
        "--undetected-output",
        type=Path,
        default=DEFAULT_UNDETECTED_PATH,
    )
    parser.add_argument(
        "--integrity-output",
        type=Path,
        default=DEFAULT_INTEGRITY_PATH,
    )
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = HostileInputAssuranceHarness(
        catalog_path=args.catalog,
        project_root=PROJECT_ROOT,
    ).run()

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
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
        print("Hostile-input report schema validation failed:")
        for error in errors:
            path = ".".join(str(part) for part in error.absolute_path)
            print(f" - {path or '<root>'}: {error.message}")
        return 2

    write_json(args.output, report)
    write_results_csv(args.results_csv, report["results"])
    write_json(
        args.undetected_output,
        {
            "schema_version": "1.0.0",
            "report_id": report["report_id"],
            "undetected_input_ids": report["undetected_input_ids"],
            "undetected_inputs": [
                result
                for result in report["results"]
                if result["outcome"] == "UNDETECTED"
            ],
            "harness_error_input_ids": report[
                "harness_error_input_ids"
            ],
        },
    )

    args.integrity_output.parent.mkdir(parents=True, exist_ok=True)
    args.integrity_output.write_text(
        "".join(
            f"{item['actual_sha256']}  {item['relative_path']}\n"
            for item in report["input_integrity_checks_after"].values()
        ),
        encoding="utf-8",
    )

    summary = report["summary"]
    release = report["release_decision"]
    print("AegisSec Step 11D Hostile Input Assurance")
    print("Scenarios:", summary["scenario_count"])
    print("Rejected:", summary["rejected_count"])
    print("Quarantined:", summary["quarantined_count"])
    print("Normalized safe:", summary["normalized_safe_count"])
    print("Accepted with warning:", summary["accepted_with_warning_count"])
    print("Undetected:", summary["undetected_count"])
    print("Harness errors:", summary["harness_error_count"])
    print(
        "Critical hostile-input defence rate:",
        f"{summary['critical_hostile_input_defence_rate']:.4f}",
    )
    print(
        "Non-finite numeric defence rate:",
        f"{summary['nonfinite_numeric_defence_rate']:.4f}",
    )
    print(
        "Unicode deception defence rate:",
        f"{summary['unicode_deception_defence_rate']:.4f}",
    )
    print(
        "Oversized payload defence rate:",
        f"{summary['oversized_payload_defence_rate']:.4f}",
    )
    print(
        "Malformed identifier defence rate:",
        f"{summary['malformed_identifier_defence_rate']:.4f}",
    )
    print(
        "Missing-value semantic accuracy:",
        f"{summary['missing_value_semantics_defence_rate']:.4f}",
    )
    print(
        "Type-confusion defence rate:",
        f"{summary['type_confusion_defence_rate']:.4f}",
    )
    print(
        "Trusted inputs unchanged:",
        summary["trusted_input_integrity_passed"],
    )
    print("Stage gate:", release["stage_gate_status"])
    print(
        "Production readiness:",
        release["production_readiness_status"],
    )
    print("Report:", args.output)
    print("Results CSV:", args.results_csv)
    print("Undetected inputs:", args.undetected_output)
    print("Integrity record:", args.integrity_output)

    print("\nScenario outcomes:")
    for result in report["results"]:
        oracles = ", ".join(result["detection_oracles"]) or "NONE"
        print(
            f"  {result['scenario_id']}: {result['outcome']} "
            f"[{oracles}]"
        )

    print("\nRemaining production blockers:")
    for reason in release["blocking_reasons"]:
        print(f"  - {reason}")

    print("\nCatalog SHA-256:", sha256_file(args.catalog))
    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.tamper_assurance import (
    DEFAULT_CATALOG_PATH,
    PROJECT_ROOT,
    TamperAssuranceHarness,
    sha256_file,
    write_json,
    write_results_csv,
)


DEFAULT_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_tamper_assurance_report.json"
)
DEFAULT_RESULTS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_tamper_results.csv"
)
DEFAULT_UNDETECTED_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_undetected_attacks.json"
)
DEFAULT_INTEGRITY_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_trusted_baseline_integrity.sha256"
)
DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_tamper_assurance_report.schema.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Step 11C tamper and chain-of-custody assurance."
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
    harness = TamperAssuranceHarness(
        catalog_path=args.catalog,
        project_root=PROJECT_ROOT,
    )
    report = harness.run()

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
        print("Tamper report schema validation failed:")
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
            "undetected_attack_ids": report["undetected_attack_ids"],
            "undetected_attacks": [
                result
                for result in report["results"]
                if result["outcome"] == "UNDETECTED"
            ],
            "harness_error_attack_ids": report[
                "harness_error_attack_ids"
            ],
        },
    )

    args.integrity_output.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for item in report["input_integrity_checks_after"].values():
        lines.append(
            f"{item['actual_sha256']}  {item['relative_path']}\n"
        )
    args.integrity_output.write_text("".join(lines), encoding="utf-8")

    summary = report["summary"]
    release = report["release_decision"]

    print("AegisSec Step 11C Tamper Assurance")
    print("Scenarios:", summary["scenario_count"])
    print("Blocked:", summary["blocked_count"])
    print("Rejected:", summary["rejected_count"])
    print("Quarantined:", summary["quarantined_count"])
    print("Undetected:", summary["undetected_count"])
    print("Harness errors:", summary["harness_error_count"])
    print(
        "Critical tamper defence rate:",
        f"{summary['critical_tamper_defence_rate']:.4f}",
    )
    print(
        "Path escape defence rate:",
        f"{summary['path_escape_defence_rate']:.4f}",
    )
    print(
        "Hash corruption detection rate:",
        f"{summary['hash_corruption_detection_rate']:.4f}",
    )
    print(
        "Identity collision detection rate:",
        f"{summary['identity_collision_detection_rate']:.4f}",
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
    print("Undetected attacks:", args.undetected_output)
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

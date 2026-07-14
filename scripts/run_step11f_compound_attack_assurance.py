from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.compound_attack_assurance import (
    CompoundAttackAssuranceHarness,
    save_compound_attack_artifacts,
)
from src.assurance.policy_assurance import load_json

DEFAULT_OUTPUT_DIR = (
    REPOSITORY_ROOT / "data" / "validation_reports" / "compound_attacks"
)
DEFAULT_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "schemas"
    / "aegis_compound_attack_assurance_report.schema.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Step 11F compound attack-chain assurance."
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = CompoundAttackAssuranceHarness().run()
    schema = load_json(args.schema)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path)
            print(f"Schema error at {location or '<root>'}: {error.message}")
        return 2
    paths = save_compound_attack_artifacts(report, args.output_dir)
    summary = report["summary"]
    release = report["release_decision"]
    print("AegisSec Step 11F Compound Attack-Chain Assurance")
    print("Chains:", summary["chain_count"])
    print("Defended:", summary["defended_critical_count"])
    print("Blocked before decision:", summary["blocked_before_decision_count"])
    print("Rejected by assurance:", summary["rejected_by_assurance_count"])
    print("Quarantined:", summary["quarantined_count"])
    print("Undetected:", summary["undetected_count"])
    print("Harness errors:", summary["harness_error_count"])
    print("Unsafe decision releases:", summary["unsafe_decision_release_count"])
    print("Critical compound-chain defence rate:", f"{summary['critical_compound_chain_defence_rate']:.4f}")
    print("Fail-closed chain handling rate:", f"{summary['fail_closed_chain_handling_rate']:.4f}")
    print("Multi-control detection rate:", f"{summary['multi_control_detection_rate']:.4f}")
    print("Order-sensitive chain consistency:", f"{summary['order_sensitive_chain_consistency_rate']:.4f}")
    print("Cross-layer integrity defence rate:", f"{summary['cross_layer_integrity_defence_rate']:.4f}")
    print("Trusted inputs unchanged:", summary["trusted_input_integrity_passed"])
    print("Stage gate:", release["stage_gate_status"])
    print("Production readiness:", release["production_readiness_status"])
    print("Report:", paths["report"])
    print("Results CSV:", paths["csv"])
    print("Undetected chains:", paths["undetected"])
    print("Integrity record:", paths["integrity"])
    if release["blocking_reasons"]:
        print("\nRemaining production blockers:")
        for reason in release["blocking_reasons"]:
            print(" -", reason)
    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

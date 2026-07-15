from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.policy_assurance import load_json
from src.assurance.temporal_assurance import (
    TemporalAssuranceHarness,
    save_temporal_assurance_artifacts,
)

DEFAULT_OUTPUT_DIR = (
    REPOSITORY_ROOT / "data" / "validation_reports" / "temporal"
)
DEFAULT_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "schemas"
    / "aegis_temporal_assurance_report.schema.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Step 11G temporal, replay, and concurrency assurance."
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = TemporalAssuranceHarness().run()
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
    paths = save_temporal_assurance_artifacts(report, args.output_dir)
    summary = report["summary"]
    release = report["release_decision"]
    print("AegisSec Step 11G Temporal, Replay, and Concurrency Assurance")
    print("Scenarios:", summary["scenario_count"])
    print("Defended:", summary["defended_critical_count"])
    print("Accepted current:", summary["accepted_current_count"])
    print("Rejected stale:", summary["rejected_stale_count"])
    print("Rejected replay:", summary["rejected_replay_count"])
    print("Quarantined conflicts:", summary["quarantined_conflict_count"])
    print("Blocked version drift:", summary["blocked_version_drift_count"])
    print("Blocked integrity changes:", summary["blocked_integrity_change_count"])
    print("Retry required:", summary["retry_required_count"])
    print("Undetected:", summary["undetected_count"])
    print("Harness errors:", summary["harness_error_count"])
    print("Unsafe decision releases:", summary["unsafe_decision_release_count"])
    print(
        "Critical temporal scenario defence rate:",
        f"{summary['critical_temporal_scenario_defence_rate']:.4f}",
    )
    print(
        "Stale evidence rejection rate:",
        f"{summary['stale_evidence_rejection_rate']:.4f}",
    )
    print(
        "Replay detection rate:",
        f"{summary['replay_detection_rate']:.4f}",
    )
    print(
        "TOCTOU detection rate:",
        f"{summary['toctou_detection_rate']:.4f}",
    )
    print(
        "Policy-version consistency rate:",
        f"{summary['policy_version_consistency_rate']:.4f}",
    )
    print(
        "Concurrent conflict containment rate:",
        f"{summary['concurrent_conflict_containment_rate']:.4f}",
    )
    print(
        "Idempotency consistency rate:",
        f"{summary['idempotency_consistency_rate']:.4f}",
    )
    print(
        "Event-order integrity rate:",
        f"{summary['event_order_integrity_rate']:.4f}",
    )
    print("Trusted inputs unchanged:", summary["trusted_input_integrity_passed"])
    print("Stage gate:", release["stage_gate_status"])
    print("Production readiness:", release["production_readiness_status"])
    print("Report:", paths["report"])
    print("Results CSV:", paths["csv"])
    print("Undetected scenarios:", paths["undetected"])
    print("Integrity record:", paths["integrity"])
    if release["blocking_reasons"]:
        print("\nRemaining production blockers:")
        for reason in release["blocking_reasons"]:
            print(" -", reason)
    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

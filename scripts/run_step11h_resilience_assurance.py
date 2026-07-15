from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.resilience_assurance import (
    ResilienceAssuranceHarness,
    load_json,
    save_resilience_assurance_artifacts,
)

DEFAULT_OUTPUT_DIR = (
    REPOSITORY_ROOT / "data" / "validation_reports" / "resilience"
)
DEFAULT_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "schemas"
    / "aegis_resilience_assurance_report.schema.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Step 11H fault-injection, resilience, and recovery assurance."
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = ResilienceAssuranceHarness().run()
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

    paths = save_resilience_assurance_artifacts(report, args.output_dir)
    summary = report["summary"]
    release = report["release_decision"]

    print("AegisSec Step 11H Fault-Injection, Resilience, and Recovery Assurance")
    print("Scenarios:", summary["scenario_count"])
    print("Defended:", summary["defended_critical_count"])
    print("Completed normally:", summary["completed_normally_count"])
    print(
        "Completed degraded, review required:",
        summary["completed_degraded_review_required_count"],
    )
    print("Retry scheduled:", summary["retry_scheduled_count"])
    print("Circuit open:", summary["circuit_open_count"])
    print("Rolled back:", summary["rolled_back_count"])
    print("Quarantined:", summary["quarantined_count"])
    print("Recovered idempotently:", summary["recovered_idempotently_count"])
    print(
        "Blocked dependency failures:",
        summary["blocked_dependency_failure_count"],
    )
    print("Blocked audit failures:", summary["blocked_audit_failure_count"])
    print(
        "Blocked integrity failures:",
        summary["blocked_integrity_failure_count"],
    )
    print("Unsafe decision releases:", summary["unsafe_decision_release_count"])
    print("Silent data loss:", summary["silent_data_loss_count"])
    print("Unbounded retries:", summary["unbounded_retry_count"])
    print("Undetected:", summary["undetected_count"])
    print("Harness errors:", summary["harness_error_count"])
    print(
        "Critical fault-scenario defence rate:",
        f"{summary['critical_fault_scenario_defence_rate']:.4f}",
    )
    print(
        "Rollback correctness rate:",
        f"{summary['rollback_correctness_rate']:.4f}",
    )
    print(
        "Idempotent recovery rate:",
        f"{summary['idempotent_recovery_rate']:.4f}",
    )
    print(
        "Audit-continuity preservation rate:",
        f"{summary['audit_continuity_preservation_rate']:.4f}",
    )
    print(
        "Cache-integrity enforcement rate:",
        f"{summary['cache_integrity_enforcement_rate']:.4f}",
    )
    print(
        "Dependency-failure fail-closed rate:",
        f"{summary['dependency_failure_fail_closed_rate']:.4f}",
    )
    print(
        "Degraded-mode governance rate:",
        f"{summary['degraded_mode_governance_rate']:.4f}",
    )
    print(
        "Poison-message isolation rate:",
        f"{summary['poison_message_isolation_rate']:.4f}",
    )
    print(
        "Restart-recovery consistency rate:",
        f"{summary['restart_recovery_consistency_rate']:.4f}",
    )
    print(
        "Bounded-retry enforcement rate:",
        f"{summary['bounded_retry_enforcement_rate']:.4f}",
    )
    print(
        "Circuit-breaker enforcement rate:",
        f"{summary['circuit_breaker_enforcement_rate']:.4f}",
    )
    print("Trusted inputs unchanged:", summary["trusted_input_integrity_passed"])
    print("Stage gate:", release["stage_gate_status"])
    print("Production readiness:", release["production_readiness_status"])
    print("Report:", paths["report"])
    print("Results CSV:", paths["csv"])
    print("Unsafe-release record:", paths["unsafe"])
    print("Recovery record:", paths["recovery"])
    print("Integrity record:", paths["integrity"])

    if release["blocking_reasons"]:
        print("\nRemaining production blockers:")
        for reason in release["blocking_reasons"]:
            print(" -", reason)

    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

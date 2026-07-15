from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.supply_chain_assurance import (
    SupplyChainAssuranceHarness,
    load_json,
    save_supply_chain_assurance_artifacts,
)

DEFAULT_OUTPUT_DIR = (
    REPOSITORY_ROOT / "data" / "validation_reports" / "supply_chain"
)
DEFAULT_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "schemas"
    / "aegis_supply_chain_assurance_report.schema.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run Step 11I software-supply-chain, build-provenance, "
            "and release-integrity assurance."
        )
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = SupplyChainAssuranceHarness().run()
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

    paths = save_supply_chain_assurance_artifacts(report, args.output_dir)
    summary = report["summary"]
    release = report["release_decision"]

    print("AegisSec Step 11I Supply-Chain and Release-Integrity Assurance")
    print("Scenarios:", summary["scenario_count"])
    print("Defended:", summary["defended_critical_count"])
    print("Release verified:", summary["release_verified_count"])
    print(
        "Release verified with review:",
        summary["release_verified_with_review_count"],
    )
    print(
        "Blocked unpinned dependencies:",
        summary["blocked_unpinned_dependency_count"],
    )
    print(
        "Blocked dependency integrity failures:",
        summary["blocked_dependency_hash_failure_count"],
    )
    print(
        "Blocked build-policy violations:",
        summary["blocked_build_policy_violation_count"],
    )
    print(
        "Blocked provenance failures:",
        summary["blocked_provenance_failure_count"],
    )
    print(
        "Blocked artifact-digest failures:",
        summary["blocked_artifact_digest_failure_count"],
    )
    print(
        "Blocked SBOM reconciliation failures:",
        summary["blocked_sbom_reconciliation_failure_count"],
    )
    print(
        "Blocked signature failures:",
        summary["blocked_signature_failure_count"],
    )
    print(
        "Blocked reproducibility failures:",
        summary["blocked_reproducibility_failure_count"],
    )
    print(
        "Blocked model-provenance failures:",
        summary["blocked_model_provenance_failure_count"],
    )
    print(
        "Quarantined untrusted artifacts:",
        summary["quarantined_untrusted_artifact_count"],
    )
    print(
        "Quarantined release conflicts:",
        summary["quarantined_release_conflict_count"],
    )
    print("Unsafe releases:", summary["unsafe_release_count"])
    print(
        "Unverified artifact releases:",
        summary["unverified_artifact_release_count"],
    )
    print("Undetected:", summary["undetected_count"])
    print("Harness errors:", summary["harness_error_count"])

    rate_fields = [
        "critical_supply_chain_scenario_defence_rate",
        "artifact_digest_verification_rate",
        "dependency_integrity_enforcement_rate",
        "build_provenance_verification_rate",
        "builder_identity_enforcement_rate",
        "source_to_artifact_binding_rate",
        "sbom_to_build_reconciliation_rate",
        "ci_workflow_integrity_rate",
        "model_data_provenance_enforcement_rate",
        "release_manifest_atomicity_rate",
        "rollback_protection_rate",
        "reproducibility_consistency_rate",
        "signature_enforcement_rate",
        "release_conflict_containment_rate",
    ]
    for field in rate_fields:
        print(field + ":", f"{summary[field]:.4f}")

    print("Trusted inputs unchanged:", summary["trusted_input_integrity_passed"])
    print("Stage gate:", release["stage_gate_status"])
    print("Production readiness:", release["production_readiness_status"])
    print("Report:", paths["report"])
    print("Results CSV:", paths["csv"])
    print("Unsafe-release record:", paths["unsafe"])
    print("Release evidence summary:", paths["evidence"])
    print("Integrity record:", paths["integrity"])

    if release["blocking_reasons"]:
        print("\nRemaining production blockers:")
        for reason in release["blocking_reasons"]:
            print(" -", reason)

    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

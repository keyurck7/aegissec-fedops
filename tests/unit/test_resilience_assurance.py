import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.resilience_assurance import (
    ResilienceAssuranceHarness,
    save_resilience_assurance_artifacts,
)


ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "policies" / "assurance" / "resilience_fault_scenario_catalog_v1.yaml"
SCHEMA_PATH = ROOT / "schemas" / "aegis_resilience_assurance_report.schema.json"


def report():
    return ResilienceAssuranceHarness().run()


def test_catalog_contains_42_unique_critical_scenarios() -> None:
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    scenarios = catalog["scenarios"]
    assert len(scenarios) == 42
    assert len({item["scenario_id"] for item in scenarios}) == 42
    assert all(item["severity"] == "critical" for item in scenarios)


def test_report_validates_against_schema() -> None:
    value = report()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = list(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(value)
    )
    assert errors == []


def test_all_fault_scenarios_are_defended() -> None:
    value = report()
    assert value["summary"]["defended_critical_count"] == 42
    assert value["summary"]["critical_fault_scenario_defence_rate"] == 1.0


def test_no_unsafe_release_or_silent_loss() -> None:
    summary = report()["summary"]
    assert summary["unsafe_decision_release_count"] == 0
    assert summary["silent_data_loss_count"] == 0
    assert summary["unbounded_retry_count"] == 0


def test_all_resilience_rates_are_perfect() -> None:
    summary = report()["summary"]
    rate_fields = [
        "rollback_correctness_rate",
        "idempotent_recovery_rate",
        "audit_continuity_preservation_rate",
        "cache_integrity_enforcement_rate",
        "dependency_failure_fail_closed_rate",
        "degraded_mode_governance_rate",
        "poison_message_isolation_rate",
        "restart_recovery_consistency_rate",
        "bounded_retry_enforcement_rate",
        "circuit_breaker_enforcement_rate",
    ]
    assert all(summary[field] == 1.0 for field in rate_fields)


def test_degraded_results_are_review_only() -> None:
    results = [
        item for item in report()["results"] if item["degraded_mode"]
    ]
    assert results
    assert all(item["human_review_required"] for item in results)
    assert all(item["prohibit_closure"] for item in results)
    assert all(not item["automated_release"] for item in results)


def test_report_is_semantically_deterministic() -> None:
    first = report()
    second = report()
    first.pop("generated_at")
    second.pop("generated_at")
    assert first == second


def test_trusted_inputs_are_unchanged() -> None:
    value = report()
    assert value["summary"]["trusted_input_integrity_passed"] is True
    assert all(
        item["passed"] for item in value["input_integrity_checks_after"].values()
    )


def test_artifact_writer_creates_complete_bundle(tmp_path: Path) -> None:
    paths = save_resilience_assurance_artifacts(report(), tmp_path)
    assert set(paths) == {"report", "csv", "unsafe", "recovery", "integrity"}
    assert all(path.is_file() for path in paths.values())
    unsafe = json.loads(paths["unsafe"].read_text(encoding="utf-8"))
    assert unsafe["unsafe_release_scenario_ids"] == []


def test_release_governance_stays_blocked_for_real_validation() -> None:
    value = report()
    release = value["release_decision"]
    assert release["stage_gate_status"] == "PASS"
    assert release["production_readiness_status"] == "BLOCKED"
    assert len(release["blocking_reasons"]) == 2

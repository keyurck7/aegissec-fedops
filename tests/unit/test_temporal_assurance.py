from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from src.assurance.temporal_assurance import TemporalAssuranceHarness

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "temporal_replay_scenario_catalog_v1.yaml"
)
SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_temporal_assurance_report.schema.json"
)


def test_catalog_contains_36_unique_critical_scenarios() -> None:
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    scenarios = catalog["scenarios"]
    assert len(scenarios) == 36
    assert len({item["scenario_id"] for item in scenarios}) == 36
    assert all(item["severity"] == "critical" for item in scenarios)
    assert catalog["deterministic_clock"]["timezone"] == "UTC"


def test_catalog_covers_all_required_temporal_controls() -> None:
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    tags = {
        tag
        for scenario in catalog["scenarios"]
        for tag in scenario["control_tags"]
    }
    assert {
        "stale_evidence",
        "replay",
        "toctou",
        "policy_version",
        "concurrency",
        "idempotency",
        "event_order",
    }.issubset(tags)


def test_trusted_input_integrity_passes() -> None:
    checks = TemporalAssuranceHarness().input_integrity_checks()
    assert len(checks) >= 15
    assert all(item["passed"] for item in checks.values())


def test_baseline_uses_real_validators_and_prior_reports() -> None:
    baseline = TemporalAssuranceHarness()._calibrate_baseline()
    assert baseline
    assert all(item["passed"] for item in baseline.values())
    assert baseline["decision_fixture"]["observed"] is True
    assert baseline["decision_hash"]["observed"] is True


def test_every_temporal_scenario_meets_its_expected_outcome() -> None:
    harness = TemporalAssuranceHarness()
    for scenario in harness.catalog["scenarios"]:
        result = harness.execute_scenario(scenario)
        assert result["defended"] is True, result
        assert result["unsafe_decision_released"] is False
        assert result["outcome"] in scenario["expected_outcomes"]


def test_full_temporal_campaign_passes_every_gate() -> None:
    report = TemporalAssuranceHarness().run()
    summary = report["summary"]
    assert summary["scenario_count"] == 36
    assert summary["defended_critical_count"] == 36
    assert summary["undetected_count"] == 0
    assert summary["harness_error_count"] == 0
    assert summary["unsafe_decision_release_count"] == 0
    assert summary["critical_temporal_scenario_defence_rate"] == 1.0
    assert summary["stale_evidence_rejection_rate"] == 1.0
    assert summary["replay_detection_rate"] == 1.0
    assert summary["toctou_detection_rate"] == 1.0
    assert summary["policy_version_consistency_rate"] == 1.0
    assert summary["concurrent_conflict_containment_rate"] == 1.0
    assert summary["idempotency_consistency_rate"] == 1.0
    assert summary["event_order_integrity_rate"] == 1.0
    assert summary["trusted_input_integrity_passed"] is True
    assert summary["overall_passed"] is True
    assert report["undetected_scenario_ids"] == []
    assert report["unsafe_release_scenario_ids"] == []
    assert report["deterministic_clock"][
        "wall_clock_reads_used_for_scenarios"
    ] is False


def test_generated_report_validates_against_schema() -> None:
    report = TemporalAssuranceHarness().run()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(report)) == []


def test_cli_runner_imports_project_from_any_working_directory(
    tmp_path: Path,
) -> None:
    runner = (
        PROJECT_ROOT / "scripts" / "run_step11g_temporal_assurance.py"
    )
    result = subprocess.run(
        [sys.executable, str(runner), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (
        "Run Step 11G temporal, replay, and concurrency assurance."
        in result.stdout
    )

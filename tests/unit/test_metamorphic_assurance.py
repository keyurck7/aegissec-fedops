from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "metamorphic_relation_catalog_v1.yaml"
)
REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "metamorphic"
    / "step11e_metamorphic_assurance_report.json"
)
RESULTS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "metamorphic"
    / "step11e_relation_results.csv"
)
VIOLATIONS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "metamorphic"
    / "step11e_violations.json"
)
INTEGRITY_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "metamorphic"
    / "step11e_trusted_baseline_integrity.sha256"
)
SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_metamorphic_assurance_report.schema.json"
)
EXPECTED_BLOCKERS = [
    "Real operational validation has not yet been completed.",
    "Independent security review has not yet been completed.",
]


def load_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def load_catalog() -> dict:
    payload = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_catalog_contains_36_unique_critical_relations() -> None:
    relations = load_catalog()["relations"]
    relation_ids = [item["relation_id"] for item in relations]

    assert len(relations) == 36
    assert len(set(relation_ids)) == 36
    assert all(item["severity"] == "critical" for item in relations)
    assert all(item["expected_changed_paths"] for item in relations)
    assert all(item["control_tags"] for item in relations)


def test_required_metamorphic_families_are_present() -> None:
    families = {item["family"] for item in load_catalog()["relations"]}
    required = {
        "sector_neutrality",
        "impact_monotonicity",
        "kev_escalation",
        "exploitation_escalation",
        "exposure_monotonicity",
        "runtime_reachability",
        "mission_escalation",
        "criticality_escalation",
        "cvss_escalation",
        "epss_monotonicity",
        "missing_value_uncertainty",
        "remediation_removal",
        "trust_degradation",
        "affectedness_uncertainty",
        "evidence_removal",
        "cumulative_escalation",
    }
    assert required.issubset(families)


def test_generated_report_validates_against_schema() -> None:
    schema = load_json(SCHEMA_PATH)
    report = load_json(REPORT_PATH)

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )
    assert errors == []


def test_all_critical_relations_pass() -> None:
    report = load_json(REPORT_PATH)
    summary = report["summary"]

    assert summary["relation_count"] == 36
    assert summary["critical_relation_count"] == 36
    assert summary["passed_count"] == 36
    assert summary["violated_count"] == 0
    assert summary["blocked_invalid_transformation_count"] == 0
    assert summary["harness_error_count"] == 0
    assert summary["critical_relation_pass_rate"] == 1.0
    assert summary["overall_passed"] is True

    for result in report["results"]:
        assert result["outcome"] == "PASSED"
        assert result["passed"] is True
        assert result["change_scope_valid"] is True
        assert result["violations"] == []
        assert result["ephemeral_only"] is True
        assert result["error"] is None
        assert result["checks"]
        assert all(check["passed"] for check in result["checks"])


def test_all_property_rates_are_one() -> None:
    summary = load_json(REPORT_PATH)["summary"]
    metrics = [
        "sector_neutrality_consistency_rate",
        "danger_escalation_monotonicity_rate",
        "trust_degradation_fail_closed_rate",
        "deadline_monotonicity_rate",
        "review_monotonicity_rate",
        "containment_monotonicity_rate",
        "closure_monotonicity_rate",
        "evidence_removal_no_confidence_gain_rate",
    ]
    for metric in metrics:
        assert summary[metric] == 1.0


def test_sector_relations_preserve_exact_decisions_and_rules() -> None:
    report = load_json(REPORT_PATH)
    sector_results = [
        item
        for item in report["results"]
        if "sector_neutrality" in item["control_tags"]
    ]
    assert len(sector_results) == 4
    for result in sector_results:
        baseline = result["baseline"]
        transformed = result["transformed"]
        for field in (
            "action",
            "priority",
            "deadline_hours",
            "human_review_required",
            "containment_required",
            "prohibit_closure",
            "matched_rule_ids",
        ):
            assert baseline[field] == transformed[field]


def test_trust_rejection_and_quarantine_fail_closed() -> None:
    report = load_json(REPORT_PATH)
    fail_closed = [
        item
        for item in report["results"]
        if "trust_fail_closed" in item["control_tags"]
    ]
    assert len(fail_closed) == 2
    for result in fail_closed:
        transformed = result["transformed"]
        assert transformed["action"] == "HOLD"
        assert transformed["priority"] in {"HIGH", "CRITICAL", "EMERGENCY"}
        assert transformed["deadline_hours"] <= 4.0
        assert transformed["human_review_required"] is True
        assert transformed["prohibit_closure"] is True


def test_evidence_removal_never_relaxes_decision() -> None:
    report = load_json(REPORT_PATH)
    relations = [
        item
        for item in report["results"]
        if "evidence_removal" in item["control_tags"]
    ]
    assert len(relations) == 2
    for result in relations:
        assert (
            result["transformed"]["input_affectedness_evidence_count"]
            < result["baseline"]["input_affectedness_evidence_count"]
        )
        assert all(check["passed"] for check in result["checks"])


def test_trusted_inputs_remain_unchanged() -> None:
    report = load_json(REPORT_PATH)
    assert report["summary"]["trusted_input_integrity_passed"] is True
    before = report["input_integrity_checks_before"]
    after = report["input_integrity_checks_after"]
    assert set(before) == set(after)
    for name in before:
        assert before[name]["passed"] is True
        assert after[name]["passed"] is True
        assert before[name]["actual_sha256"] == after[name]["actual_sha256"]


def test_release_decision_preserves_honest_blockers() -> None:
    release = load_json(REPORT_PATH)["release_decision"]
    assert release["stage_gate_status"] == "PASS"
    assert release["production_readiness_status"] == "BLOCKED"
    assert release["blocking_reasons"] == EXPECTED_BLOCKERS


def test_csv_violation_and_integrity_artifacts_are_consistent() -> None:
    with RESULTS_PATH.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    violations = load_json(VIOLATIONS_PATH)

    assert len(rows) == 36
    assert violations["violation_relation_ids"] == []
    assert violations["harness_error_relation_ids"] == []
    assert violations["violations"] == []
    assert INTEGRITY_PATH.is_file()
    assert len(INTEGRITY_PATH.read_text(encoding="utf-8").splitlines()) == 10


def test_cli_runner_imports_project_from_any_working_directory(
    tmp_path: Path,
) -> None:
    runner = (
        PROJECT_ROOT
        / "scripts"
        / "run_step11e_metamorphic_assurance.py"
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
        "Run Step 11E metamorphic and monotonic-property assurance."
        in result.stdout
    )

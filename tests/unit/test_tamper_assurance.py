from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.tamper_assurance import (
    TamperAssuranceHarness,
    _freshness_findings,
    _safe_path_findings,
    _signature_findings,
    sha256_file,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "tamper_scenario_catalog_v1.yaml"
)
REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_tamper_assurance_report.json"
)
RESULTS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_tamper_results.csv"
)
UNDETECTED_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_undetected_attacks.json"
)
INTEGRITY_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "tampering"
    / "step11c_trusted_baseline_integrity.sha256"
)
SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_tamper_assurance_report.schema.json"
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


def test_catalog_contains_30_unique_critical_scenarios() -> None:
    scenarios = load_catalog()["scenarios"]
    scenario_ids = [item["scenario_id"] for item in scenarios]

    assert len(scenarios) == 30
    assert len(set(scenario_ids)) == 30
    assert all(item["severity"] == "critical" for item in scenarios)
    assert all(item["handler"] for item in scenarios)
    assert all(item["expected_outcomes"] for item in scenarios)
    assert all(item["expected_oracles"] for item in scenarios)


def test_required_attack_families_are_present() -> None:
    families = {item["family"] for item in load_catalog()["scenarios"]}
    required = {
        "policy_tampering",
        "corpus_tampering",
        "manifest_tampering",
        "fixture_substitution",
        "decision_record_tampering",
        "signature_corruption",
        "evidence_substitution",
        "path_traversal",
        "duplicate_identity",
        "reference_tampering",
        "freshness_tampering",
        "timestamp_tampering",
        "unicode_deception",
        "chain_of_custody",
        "provenance_tampering",
        "integrity_declaration_tampering",
        "validation_attestation_tampering",
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


def test_all_critical_tampering_is_blocked_or_rejected() -> None:
    report = load_json(REPORT_PATH)
    summary = report["summary"]

    assert summary["scenario_count"] == 30
    assert summary["critical_scenario_count"] == 30
    assert summary["blocked_count"] == 7
    assert summary["rejected_count"] == 23
    assert summary["quarantined_count"] == 0
    assert summary["warning_detection_count"] == 0
    assert summary["undetected_count"] == 0
    assert summary["harness_error_count"] == 0
    assert summary["defended_critical_count"] == 30
    assert summary["critical_tamper_defence_rate"] == 1.0
    assert summary["overall_passed"] is True

    for result in report["results"]:
        assert result["outcome"] in {"BLOCKED", "REJECTED"}
        assert result["defended"] is True
        assert result["expectation_met"] is True
        assert result["ephemeral_only"] is True
        assert result["detection_oracles"]
        assert result["findings"]
        assert result["error"] is None


def test_path_hash_and_identity_subgroup_gates_are_100_percent() -> None:
    summary = load_json(REPORT_PATH)["summary"]

    assert summary["path_escape_scenario_count"] == 4
    assert summary["path_escape_defended_count"] == 4
    assert summary["path_escape_defence_rate"] == 1.0

    assert summary["hash_corruption_scenario_count"] >= 10
    assert (
        summary["hash_corruption_detected_count"]
        == summary["hash_corruption_scenario_count"]
    )
    assert summary["hash_corruption_detection_rate"] == 1.0

    assert summary["identity_collision_scenario_count"] >= 6
    assert (
        summary["identity_collision_detected_count"]
        == summary["identity_collision_scenario_count"]
    )
    assert summary["identity_collision_detection_rate"] == 1.0


def test_signature_freshness_timestamp_and_chain_attacks_are_identified() -> None:
    results = {
        item["scenario_id"]: item
        for item in load_json(REPORT_PATH)["results"]
    }

    assert results["TAMPER-SIGNATURE-INVALID-001"][
        "detection_oracles"
    ] == ["SIGNATURE_POLICY"]
    assert results["TAMPER-SIGNATURE-MISSING-REFERENCE-001"][
        "detection_oracles"
    ] == ["SIGNATURE_POLICY"]
    assert "FRESHNESS_CONSISTENCY" in results[
        "TAMPER-STALE-AS-CURRENT-001"
    ]["detection_oracles"]
    assert "TIMESTAMP_CONSISTENCY" in results[
        "TAMPER-FUTURE-COLLECTION-TIMESTAMP-001"
    ]["detection_oracles"]
    assert results["TAMPER-CHAIN-LINK-DELETION-001"][
        "detection_oracles"
    ] == ["CHAIN_OF_CUSTODY"]
    assert results["TAMPER-CHAIN-LINK-REPLACEMENT-001"][
        "detection_oracles"
    ] == ["CHAIN_OF_CUSTODY"]


def test_reference_deletion_injection_and_required_flag_attacks_are_detected() -> None:
    results = {
        item["scenario_id"]: item
        for item in load_json(REPORT_PATH)["results"]
    }
    for scenario_id in (
        "TAMPER-REFERENCE-DELETION-001",
        "TAMPER-REFERENCE-INJECTION-001",
        "TAMPER-REQUIRED-REFERENCE-FLAG-001",
    ):
        assert results[scenario_id]["outcome"] == "REJECTED"
        assert results[scenario_id]["detection_oracles"] == [
            "REFERENCE_SET_INTEGRITY"
        ]


def test_undetected_and_harness_error_artifact_is_empty() -> None:
    payload = load_json(UNDETECTED_PATH)

    assert payload["undetected_attack_ids"] == []
    assert payload["undetected_attacks"] == []
    assert payload["harness_error_attack_ids"] == []


def test_csv_contains_one_row_per_scenario() -> None:
    with RESULTS_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 30
    assert len({row["scenario_id"] for row in rows}) == 30
    assert all(row["ephemeral_only"] == "True" for row in rows)
    assert {row["outcome"] for row in rows} == {"BLOCKED", "REJECTED"}


def test_trusted_input_hashes_are_unchanged_and_integrity_file_matches() -> None:
    report = load_json(REPORT_PATH)
    before = report["input_integrity_checks_before"]
    after = report["input_integrity_checks_after"]

    assert report["summary"]["trusted_input_integrity_passed"] is True
    assert before.keys() == after.keys()
    for name in before:
        assert before[name]["passed"] is True
        assert after[name]["passed"] is True
        assert before[name]["actual_sha256"] == after[name]["actual_sha256"]
        path = PROJECT_ROOT / after[name]["relative_path"]
        assert sha256_file(path) == after[name]["actual_sha256"]

    integrity_lines = {
        line.strip()
        for line in INTEGRITY_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    expected_lines = {
        f"{item['actual_sha256']}  {item['relative_path']}"
        for item in after.values()
    }
    assert integrity_lines == expected_lines


def test_release_governance_preserves_honest_production_blockers() -> None:
    release = load_json(REPORT_PATH)["release_decision"]

    assert release["stage_gate_status"] == "PASS"
    assert release["production_readiness_status"] == "BLOCKED"
    assert release["blocking_reasons"] == EXPECTED_BLOCKERS


def test_low_level_contract_helpers_fail_closed() -> None:
    evidence = load_json(
        PROJECT_ROOT
        / "data/sample_inputs/evidence/valid_log4j_sbom_evidence.json"
    )
    evidence["integrity"]["signature_status"] = "invalid"
    assert {item.oracle for item in _signature_findings(evidence)} == {
        "SIGNATURE_POLICY"
    }

    evidence = load_json(
        PROJECT_ROOT
        / "data/sample_inputs/evidence/valid_log4j_sbom_evidence.json"
    )
    evidence["collection"]["collected_at"] = "2020-01-01T00:00:00Z"
    evidence["freshness"]["age_seconds"] = 1
    assert {
        item.oracle for item in _freshness_findings(evidence)
    } == {"FRESHNESS_CONSISTENCY"}

    findings = _safe_path_findings(PROJECT_ROOT, "../outside.json")
    assert {item.oracle for item in findings} == {"SAFE_PATH"}


def test_harness_reexecution_is_semantically_deterministic() -> None:
    original = load_json(REPORT_PATH)
    rerun = TamperAssuranceHarness(
        catalog_path=CATALOG_PATH,
        project_root=PROJECT_ROOT,
    ).run()

    keys = (
        "summary",
        "quality_gates",
        "results",
        "undetected_attack_ids",
        "harness_error_attack_ids",
        "release_decision",
    )
    for key in keys:
        assert rerun[key] == original[key]


def test_cli_runner_imports_project_from_any_working_directory(tmp_path: Path) -> None:
    runner = (
        PROJECT_ROOT
        / "scripts"
        / "run_step11c_tamper_assurance.py"
    )

    result = subprocess.run(
        [
            sys.executable,
            str(runner),
            "--help",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (
        "Run Step 11C tamper and chain-of-custody assurance."
        in result.stdout
    )

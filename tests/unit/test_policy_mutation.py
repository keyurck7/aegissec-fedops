from __future__ import annotations

import csv
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.policy_mutation import (
    PolicyMutationHarness,
    apply_mutation_operations,
    evaluate_static_security_contract,
    sha256_file,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "policy_mutation_catalog_v1.yaml"
)

REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_policy_mutation_report.json"
)

RESULTS_CSV_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_mutation_results.csv"
)

SURVIVORS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_surviving_mutations.json"
)

INTEGRITY_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "mutation"
    / "step11b_trusted_policy_integrity.sha256"
)

SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_policy_mutation_report.schema.json"
)

TRUSTED_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "federal_base_policy_v1.yaml"
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



def test_mutation_catalog_has_17_unique_critical_mutations() -> None:
    mutations = load_catalog()["mutations"]
    mutation_ids = [mutation["mutation_id"] for mutation in mutations]

    assert len(mutations) == 17
    assert len(set(mutation_ids)) == 17
    assert all(mutation["severity"] == "critical" for mutation in mutations)
    assert all(mutation["operations"] for mutation in mutations)



def test_generated_mutation_report_validates_against_schema() -> None:
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



def test_trusted_policy_calibration_passes_130_cases_and_65_pairs() -> None:
    baseline = load_json(REPORT_PATH)["baseline_calibration"]

    assert baseline == {
        "case_count": 130,
        "passed_case_count": 130,
        "pair_count": 65,
        "passed_pair_count": 65,
        "invariant_pass_case_count": 130,
        "passed": True,
    }



def test_critical_mutation_defence_and_executable_kill_rates_are_100_percent() -> None:
    summary = load_json(REPORT_PATH)["summary"]

    assert summary["critical_mutation_count"] == 17
    assert summary["blocked_at_load_count"] == 1
    assert summary["killed_by_assurance_count"] == 16
    assert summary["survived_count"] == 0
    assert summary["harness_error_count"] == 0
    assert summary["critical_mutation_defence_rate"] == 1.0
    assert summary["executable_critical_mutation_count"] == 16
    assert summary["executable_critical_killed_count"] == 16
    assert summary["executable_critical_mutation_kill_rate"] == 1.0
    assert summary["overall_passed"] is True



def test_each_mutation_is_blocked_or_killed_with_an_identified_oracle() -> None:
    report = load_json(REPORT_PATH)

    for result in report["results"]:
        assert result["status"] in {
            "BLOCKED_AT_LOAD",
            "KILLED_BY_ASSURANCE",
        }
        assert result["detection_oracles"]
        assert result["mutated_policy_sha256"]
        assert (
            result["mutated_policy_sha256"]
            != result["trusted_policy_sha256"]
        )



def test_load_rejection_and_static_only_detection_are_both_demonstrated() -> None:
    results = {
        result["mutation_id"]: result
        for result in load_json(REPORT_PATH)["results"]
    }

    invalid_action = results["MUT-UNRANKED-ACTION-TOKEN-001"]
    assert invalid_action["status"] == "BLOCKED_AT_LOAD"
    assert invalid_action["detection_oracles"] == ["POLICY_LOADER"]
    assert "unranked action" in invalid_action["load_error"]

    overridable_kev = results["MUT-KEV-OVERRIDABLE-001"]
    assert overridable_kev["status"] == "KILLED_BY_ASSURANCE"
    assert overridable_kev["assurance"]["failed_case_count"] == 0
    assert overridable_kev["release_evaluation"]["stage_gate_status"] == "PASS"
    assert overridable_kev["detection_oracles"] == [
        "STATIC_SECURITY_CONTRACT"
    ]



def test_sector_label_injection_is_detected_by_multiple_independent_oracles() -> None:
    result = next(
        item
        for item in load_json(REPORT_PATH)["results"]
        if item["mutation_id"] == "MUT-SECTOR-LABEL-INJECTION-001"
    )

    assert result["status"] == "KILLED_BY_ASSURANCE"
    assert {
        "STATIC_SECURITY_CONTRACT",
        "POLICY_INVARIANT",
        "CASE_ORACLE",
    }.issubset(set(result["detection_oracles"]))
    assert result["assurance"]["invariant_failure_case_count"] > 0



def test_mutation_application_does_not_modify_trusted_policy_object_or_file() -> None:
    catalog = load_catalog()
    trusted_text = TRUSTED_POLICY_PATH.read_text(encoding="utf-8")
    trusted_payload = yaml.safe_load(trusted_text)
    before_hash = sha256_file(TRUSTED_POLICY_PATH)

    mutation = catalog["mutations"][0]
    mutated = apply_mutation_operations(
        trusted_payload,
        mutation["operations"],
    )

    assert mutated != trusted_payload
    assert TRUSTED_POLICY_PATH.read_text(encoding="utf-8") == trusted_text
    assert sha256_file(TRUSTED_POLICY_PATH) == before_hash



def test_static_contract_rejects_critical_rule_becoming_overridable() -> None:
    catalog = load_catalog()
    trusted_policy = yaml.safe_load(
        TRUSTED_POLICY_PATH.read_text(encoding="utf-8")
    )
    mutation = next(
        item
        for item in catalog["mutations"]
        if item["mutation_id"] == "MUT-KEV-OVERRIDABLE-001"
    )
    mutated = apply_mutation_operations(
        trusted_policy,
        mutation["operations"],
    )
    failures = evaluate_static_security_contract(
        mutated,
        catalog["security_contract"],
    )

    assert any(
        failure["code"] == "CRITICAL_RULE_MADE_OVERRIDABLE"
        for failure in failures
    )



def test_survivor_csv_integrity_and_release_governance_artifacts() -> None:
    report = load_json(REPORT_PATH)
    survivors = load_json(SURVIVORS_PATH)

    assert survivors["surviving_mutation_ids"] == []
    assert survivors["surviving_mutations"] == []

    with RESULTS_CSV_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 17
    assert {row["status"] for row in rows} == {
        "BLOCKED_AT_LOAD",
        "KILLED_BY_ASSURANCE",
    }

    integrity_line = INTEGRITY_PATH.read_text(encoding="utf-8").strip()
    assert integrity_line == (
        f"{sha256_file(TRUSTED_POLICY_PATH)}  "
        "policies/decision/federal_base_policy_v1.yaml"
    )

    release = report["release_decision"]
    assert release["stage_gate_status"] == "PASS"
    assert release["production_readiness_status"] == "BLOCKED"
    assert release["blocking_reasons"] == EXPECTED_BLOCKERS



def test_harness_can_recalibrate_trusted_policy_without_mutating_it() -> None:
    before_hash = sha256_file(TRUSTED_POLICY_PATH)
    harness = PolicyMutationHarness(
        project_root=PROJECT_ROOT,
        catalog_path=CATALOG_PATH,
    )
    calibration = harness.calibrate_trusted_policy()

    assert calibration["passed"] is True
    assert calibration["passed_case_count"] == 130
    assert sha256_file(TRUSTED_POLICY_PATH) == before_hash

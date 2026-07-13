from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from src.assurance.policy_assurance import (
    PolicyAssuranceRunner,
    TARGETED_RULE_PROFILES,
    canonical_json_hash,
    load_json,
    load_jsonl,
    sha256_file,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SOURCE_CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_corpus.jsonl"
)

CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step11a_policy_rule_coverage_corpus.jsonl"
)

MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step11a_policy_rule_coverage_manifest.json"
)

CASE_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_policy_assurance_case_v1_1.schema.json"
)

ASSURANCE_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "assurance"
    / "step11a_policy_rule_coverage_report.json"
)

EVALUATION_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "fairness"
    / "step11a_rule_coverage_evaluation_report.json"
)

EXPECTED_BLOCKERS = [
    "Real operational validation has not yet been completed.",
    "Independent security review has not yet been completed.",
]


def assurance_cases() -> list[dict]:
    return load_jsonl(CORPUS_PATH)


def assurance_report() -> dict:
    return load_json(ASSURANCE_REPORT_PATH)


def evaluation_report() -> dict:
    return load_json(EVALUATION_REPORT_PATH)


def test_step11a_corpus_contains_130_cases_and_65_pairs() -> None:
    cases = assurance_cases()
    assert len(cases) == 130
    assert len({case["pair_id"] for case in cases}) == 65


def test_original_120_cases_are_preserved_byte_for_byte_semantically() -> None:
    source = load_jsonl(SOURCE_CORPUS_PATH)
    combined = assurance_cases()[:120]

    assert [case["case_id"] for case in combined] == [
        case["case_id"] for case in source
    ]
    assert [canonical_json_hash(case) for case in combined] == [
        canonical_json_hash(case) for case in source
    ]


def test_targeted_profiles_form_five_balanced_sector_pairs() -> None:
    targeted_names = {
        profile["name"] for profile in TARGETED_RULE_PROFILES
    }
    targeted = [
        case
        for case in assurance_cases()
        if case["scenario"]["operational_profile"] in targeted_names
    ]

    assert len(targeted) == 10
    assert Counter(
        case["scenario"]["operational_profile"] for case in targeted
    ) == {name: 2 for name in targeted_names}

    grouped = defaultdict(list)
    for case in targeted:
        grouped[case["pair_id"]].append(case["sector_label"])

    assert len(grouped) == 5
    assert all(
        sorted(labels) == ["defence_logistics", "healthcare"]
        for labels in grouped.values()
    )


def test_all_130_cases_validate_against_step11a_schema() -> None:
    schema = load_json(CASE_SCHEMA_PATH)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    failures = {
        case["case_id"]: [error.message for error in validator.iter_errors(case)]
        for case in assurance_cases()
        if list(validator.iter_errors(case))
    }

    assert failures == {}


def test_step11a_manifest_hashes_verify() -> None:
    runner = PolicyAssuranceRunner(schema_path=CASE_SCHEMA_PATH)
    manifest = load_json(MANIFEST_PATH)
    checks = runner.verify_manifest(manifest)

    assert checks
    assert all(check["passed"] for check in checks)
    assert sha256_file(CORPUS_PATH) == manifest["artifacts"]["corpus"]["sha256"]


def test_step11a_assurance_report_passes_all_cases_and_pairs() -> None:
    summary = assurance_report()["summary"]

    assert summary["overall_passed"] is True
    assert summary["case_count"] == 130
    assert summary["passed_cases"] == 130
    assert summary["failed_cases"] == 0
    assert summary["pair_count"] == 65
    assert summary["passed_pairs"] == 65
    assert summary["sector_disparity_count"] == 0


def test_each_targeted_profile_triggers_its_named_rule_in_both_sectors() -> None:
    results = assurance_report()["case_results"]

    for profile in TARGETED_RULE_PROFILES:
        selected = [
            result
            for result in results
            if result["operational_profile"] == profile["name"]
        ]

        assert len(selected) == 2
        assert {result["sector_label"] for result in selected} == {
            "healthcare",
            "defence_logistics",
        }
        assert all(
            profile["target_rule_id"] in result["matched_rule_ids"]
            for result in selected
        )
        assert all(result["passed"] for result in selected)


def test_targeted_rule_coverage_contract_is_complete() -> None:
    targeted = assurance_report()["targeted_rule_coverage"]

    assert targeted["complete"] is True
    assert targeted["missing_target_rules"] == []
    assert len(targeted["covered_target_rules"]) == 5


def test_full_decision_policy_rule_coverage_is_22_of_22() -> None:
    coverage = evaluation_report()["rule_coverage"]

    assert coverage["policy_rule_count"] == 22
    assert coverage["covered_policy_rule_count"] == 22
    assert coverage["full_rule_coverage_rate"] == 1.0
    assert coverage["uncovered_policy_rules"] == []


def test_step11a_has_zero_under_triage_and_zero_sector_disparity() -> None:
    report = evaluation_report()

    assert report["safety_metrics"]["under_triage_count"] == 0
    assert report["safety_metrics"]["safety_recall"] == 1.0
    assert report["counterfactual_metrics"]["sector_disparity_count"] == 0
    assert report["counterfactual_metrics"]["counterfactual_consistency_rate"] == 1.0


def test_only_honest_production_blockers_remain() -> None:
    report = evaluation_report()
    release = report["release_decision"]

    assert release["stage_gate_status"] == "PASS"
    assert release["production_readiness_status"] == "BLOCKED"
    assert release["blocking_reasons"] == EXPECTED_BLOCKERS
    assert report["summary"]["production_readiness"] is False

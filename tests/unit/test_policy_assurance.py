from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from src.assurance.policy_assurance import (
    PolicyAssuranceRunner,
    load_json,
    load_jsonl,
    sha256_file,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_corpus.jsonl"
)

MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_manifest.json"
)

REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "assurance"
    / "step9_policy_assurance_report.json"
)


EVALUATION_TIME = datetime(
    2026,
    7,
    13,
    19,
    45,
    tzinfo=timezone.utc,
)


def cases() -> list[dict]:
    return load_jsonl(CORPUS_PATH)


def report() -> dict:
    return load_json(REPORT_PATH)


def test_corpus_contains_120_cases() -> None:
    assert len(cases()) == 120


def test_corpus_contains_60_counterfactual_pairs() -> None:
    pair_ids = {
        case["pair_id"]
        for case in cases()
    }

    assert len(pair_ids) == 60


def test_each_pair_contains_two_sector_labels() -> None:
    grouped = defaultdict(list)

    for case in cases():
        grouped[case["pair_id"]].append(
            case["sector_label"]
        )

    assert all(
        sorted(labels)
        == [
            "defence_logistics",
            "healthcare",
        ]
        for labels in grouped.values()
    )


def test_sector_counts_are_balanced() -> None:
    counts = Counter(
        case["sector_label"]
        for case in cases()
    )

    assert counts == {
        "healthcare": 60,
        "defence_logistics": 60,
    }


def test_affectedness_profiles_are_balanced() -> None:
    counts = Counter(
        case["scenario"][
            "affectedness_profile"
        ]
        for case in cases()
    )

    assert set(counts.values()) == {24}
    assert len(counts) == 5


def test_operational_profiles_are_balanced() -> None:
    counts = Counter(
        case["scenario"][
            "operational_profile"
        ]
        for case in cases()
    )

    assert set(counts.values()) == {10}
    assert len(counts) == 12


def test_case_ids_are_unique() -> None:
    case_ids = [
        case["case_id"]
        for case in cases()
    ]

    assert len(case_ids) == len(
        set(case_ids)
    )


def test_counterfactual_keys_match_within_pairs() -> None:
    grouped = defaultdict(set)

    for case in cases():
        grouped[case["pair_id"]].add(
            case["counterfactual_key"]
        )

    assert all(
        len(keys) == 1
        for keys in grouped.values()
    )


def test_all_cases_validate_against_schema() -> None:
    runner = PolicyAssuranceRunner()

    failures = {
        case["case_id"]:
            runner.validate_case(case)
        for case in cases()
        if runner.validate_case(case)
    }

    assert failures == {}


def test_manifest_hashes_verify() -> None:
    runner = PolicyAssuranceRunner()
    manifest = load_json(MANIFEST_PATH)

    checks = runner.verify_manifest(
        manifest
    )

    assert checks
    assert all(
        check["passed"]
        for check in checks
    )

    corpus_metadata = manifest[
        "artifacts"
    ]["corpus"]

    assert (
        sha256_file(CORPUS_PATH)
        == corpus_metadata["sha256"]
    )


def test_assurance_report_passes() -> None:
    summary = report()["summary"]

    assert summary["overall_passed"] is True
    assert summary["passed_cases"] == 120
    assert summary["failed_cases"] == 0


def test_all_120_cases_match_expected_outputs() -> None:
    results = report()["case_results"]

    assert len(results) == 120

    assert all(
        result["passed"]
        for result in results
    )


def test_all_policy_invariants_pass() -> None:
    results = report()["case_results"]

    assert all(
        result["actual"][
            "invariants_passed"
        ]
        for result in results
    )


def test_zero_sector_counterfactual_disparities() -> None:
    assurance_report = report()

    assert (
        assurance_report["summary"][
            "sector_disparity_count"
        ]
        == 0
    )

    assert all(
        pair["passed"]
        for pair
        in assurance_report[
            "counterfactual_results"
        ]
    )


def test_trust_blocked_cases_hold_high_with_four_hour_deadline() -> None:
    selected = [
        result
        for result
        in report()["case_results"]
        if result[
            "operational_profile"
        ]
        == "trust_blocked"
    ]

    assert len(selected) == 10

    assert all(
        result["actual"]["action"]
        == "HOLD"
        and result["actual"]["priority"]
        == "HIGH"
        and result["actual"][
            "deadline_hours"
        ]
        == 4.0
        for result in selected
    )


def test_active_exploitation_is_emergency_when_affected() -> None:
    selected = [
        result
        for result
        in report()["case_results"]
        if result[
            "operational_profile"
        ]
        == "active_exploitation"
        and result[
            "affectedness_profile"
        ]
        in {
            "affected",
            "probably_affected",
        }
    ]

    assert len(selected) == 4

    assert all(
        result["actual"]["action"]
        == "ACT"
        and result["actual"]["priority"]
        == "EMERGENCY"
        and result["actual"][
            "deadline_hours"
        ]
        == 4.0
        for result in selected
    )


def test_kev_uncertain_cases_hold_critical() -> None:
    selected = [
        result
        for result
        in report()["case_results"]
        if result[
            "operational_profile"
        ]
        == "kev_listed"
        and result[
            "affectedness_profile"
        ]
        in {
            "unknown",
            "probably_not_affected",
        }
    ]

    assert len(selected) == 4

    assert all(
        result["actual"]["action"]
        == "HOLD"
        and result["actual"]["priority"]
        == "CRITICAL"
        for result in selected
    )


def test_fixed_baseline_tracks_informational() -> None:
    selected = [
        result
        for result
        in report()["case_results"]
        if result[
            "operational_profile"
        ]
        == "baseline"
        and result[
            "affectedness_profile"
        ]
        == "fixed"
    ]

    assert len(selected) == 2

    assert all(
        result["actual"]["action"]
        == "TRACK"
        and result["actual"]["priority"]
        == "INFORMATIONAL"
        for result in selected
    )


def test_critical_cvss_does_not_escalate_fixed_case() -> None:
    selected = [
        result
        for result
        in report()["case_results"]
        if result[
            "operational_profile"
        ]
        == "critical_cvss"
        and result[
            "affectedness_profile"
        ]
        == "fixed"
    ]

    assert len(selected) == 2

    assert all(
        result["actual"]["action"]
        == "TRACK"
        and result["actual"]["priority"]
        == "INFORMATIONAL"
        for result in selected
    )


def test_runner_is_deterministic() -> None:
    runner = PolicyAssuranceRunner()

    first = runner.run(
        corpus_path=CORPUS_PATH,
        manifest_path=MANIFEST_PATH,
        evaluated_at=EVALUATION_TIME,
    )

    second = runner.run(
        corpus_path=CORPUS_PATH,
        manifest_path=MANIFEST_PATH,
        evaluated_at=EVALUATION_TIME,
    )

    assert first == second

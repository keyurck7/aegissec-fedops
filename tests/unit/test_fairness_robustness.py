from __future__ import annotations

import json
from pathlib import Path

from jsonschema import (
    Draft202012Validator,
    FormatChecker,
)

from src.assurance.fairness_robustness import (
    FairnessRobustnessEvaluator,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

STEP9_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "assurance"
    / "step9_policy_assurance_report.json"
)

STEP10_REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "fairness"
    / "step10_fairness_robustness_report.json"
)

STEP10_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_fairness_robustness_report.schema.json"
)


def load_json(path: Path) -> dict:
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def report() -> dict:
    return load_json(
        STEP10_REPORT_PATH
    )


def test_gate_policy_loads() -> None:
    evaluator = (
        FairnessRobustnessEvaluator()
    )

    assert (
        evaluator.metadata["policy_id"]
        == "AEGIS-FAIRNESS-ROBUSTNESS-GATES"
    )

    assert len(
        evaluator.required_rule_ids
    ) == 17


def test_step10_report_exists() -> None:
    assert STEP10_REPORT_PATH.exists()


def test_step10_report_validates_against_schema() -> None:
    schema = load_json(
        STEP10_SCHEMA_PATH
    )

    evaluation_report = report()

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    errors = list(
        validator.iter_errors(
            evaluation_report
        )
    )

    assert errors == []


def test_all_cases_match_oracle() -> None:
    metrics = report()[
        "exact_match_metrics"
    ]

    assert (
        metrics[
            "case_exact_match_rate"
        ]
        == 1.0
    )

    assert (
        metrics[
            "exact_case_count"
        ]
        == 120
    )


def test_action_and_priority_are_exact() -> None:
    metrics = report()[
        "exact_match_metrics"
    ]

    assert (
        metrics[
            "action_exact_match_rate"
        ]
        == 1.0
    )

    assert (
        metrics[
            "priority_exact_match_rate"
        ]
        == 1.0
    )


def test_deadline_and_review_are_exact() -> None:
    metrics = report()[
        "exact_match_metrics"
    ]

    assert (
        metrics[
            "deadline_exact_match_rate"
        ]
        == 1.0
    )

    assert (
        metrics[
            "review_exact_match_rate"
        ]
        == 1.0
    )


def test_no_under_triage_exists() -> None:
    metrics = report()[
        "safety_metrics"
    ]

    assert (
        metrics[
            "under_triage_count"
        ]
        == 0
    )

    assert (
        metrics[
            "under_triage_cases"
        ]
        == []
    )


def test_no_over_triage_exists() -> None:
    metrics = report()[
        "safety_metrics"
    ]

    assert (
        metrics[
            "over_triage_count"
        ]
        == 0
    )

    assert (
        metrics[
            "over_triage_cases"
        ]
        == []
    )


def test_safety_recall_is_perfect() -> None:
    assert (
        report()[
            "safety_metrics"
        ]["safety_recall"]
        == 1.0
    )


def test_hold_precision_is_perfect() -> None:
    assert (
        report()[
            "abstention_metrics"
        ]["hold_precision"]
        == 1.0
    )


def test_hold_recall_is_perfect() -> None:
    assert (
        report()[
            "abstention_metrics"
        ]["hold_recall"]
        == 1.0
    )


def test_counterfactual_consistency_is_perfect() -> None:
    metrics = report()[
        "counterfactual_metrics"
    ]

    assert (
        metrics[
            "counterfactual_consistency_rate"
        ]
        == 1.0
    )

    assert (
        metrics[
            "sector_disparity_count"
        ]
        == 0
    )


def test_deadline_and_review_parity_have_no_gaps() -> None:
    metrics = report()[
        "counterfactual_metrics"
    ]

    assert (
        metrics[
            "deadline_pair_max_gap_hours"
        ]
        == 0.0
    )

    assert (
        metrics[
            "review_pair_gap_count"
        ]
        == 0
    )


def test_containment_and_closure_parity_have_no_gaps() -> None:
    metrics = report()[
        "counterfactual_metrics"
    ]

    assert (
        metrics[
            "containment_pair_gap_count"
        ]
        == 0
    )

    assert (
        metrics[
            "closure_pair_gap_count"
        ]
        == 0
    )


def test_escalation_is_monotonic() -> None:
    metrics = report()[
        "monotonicity_metrics"
    ]

    assert (
        metrics[
            "monotonicity_rate"
        ]
        == 1.0
    )

    assert (
        metrics[
            "violation_count"
        ]
        == 0
    )


def test_required_rules_have_complete_coverage() -> None:
    coverage = report()[
        "rule_coverage"
    ]

    assert (
        coverage[
            "required_rule_coverage_rate"
        ]
        == 1.0
    )

    assert (
        coverage[
            "missing_required_rules"
        ]
        == []
    )


def test_full_policy_coverage_is_honestly_incomplete() -> None:
    coverage = report()[
        "rule_coverage"
    ]

    assert (
        coverage[
            "full_rule_coverage_rate"
        ]
        < 1.0
    )

    assert len(
        coverage[
            "uncovered_policy_rules"
        ]
    ) >= 1


def test_bootstrap_lower_bounds_pass() -> None:
    bootstrap = report()[
        "bootstrap"
    ]

    assert (
        bootstrap[
            "case_exact_match_rate"
        ]["lower_bound"]
        >= 0.99
    )

    assert (
        bootstrap[
            "counterfactual_consistency_rate"
        ]["lower_bound"]
        >= 0.99
    )

    assert (
        bootstrap[
            "safety_recall"
        ]["lower_bound"]
        >= 0.99
    )


def test_all_quality_gates_pass() -> None:
    gates = report()[
        "quality_gates"
    ]

    assert gates

    assert all(
        gate["passed"]
        for gate in gates
        if gate[
            "release_blocking"
        ]
    )


def test_stage_passes_but_production_is_blocked() -> None:
    evaluation_report = report()

    assert (
        evaluation_report[
            "summary"
        ]["stage_gate_passed"]
        is True
    )

    assert (
        evaluation_report[
            "summary"
        ]["production_readiness"]
        is False
    )

    assert (
        evaluation_report[
            "release_decision"
        ]["stage_gate_status"]
        == "PASS"
    )

    assert (
        evaluation_report[
            "release_decision"
        ]["production_readiness_status"]
        == "BLOCKED"
    )

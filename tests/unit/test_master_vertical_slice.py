from __future__ import annotations

import numpy as np
import pandas as pd

from src.presentation_demo.master_vertical_slice import (
    agreement_matrix,
    choose_operating_points,
    claim_boundary,
    load_master_vertical_slice,
    metrics_at_threshold,
    screenshot_policy,
    threshold_frontier,
)


def test_metrics_at_threshold() -> None:
    truth = np.array(
        [0, 0, 1, 1]
    )

    probabilities = np.array(
        [0.1, 0.4, 0.8, 0.9]
    )

    metrics = metrics_at_threshold(
        truth,
        probabilities,
        0.5,
    )

    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert (
        metrics["balanced_accuracy"]
        == 1.0
    )


def test_threshold_operating_points() -> None:
    frame = pd.DataFrame(
        {
            "cve": [
                "CVE-2026-10001",
                "CVE-2026-10002",
                "CVE-2026-10003",
                "CVE-2026-10004",
            ],
            "is_kev": [
                0,
                0,
                1,
                1,
            ],
            "predicted_probability": [
                0.1,
                0.4,
                0.8,
                0.9,
            ],
        }
    )

    frontier = threshold_frontier(
        frame,
        0.5,
    )

    assert np.isclose(
        frontier["threshold"],
        0.5,
    ).any()

    operating_points = (
        choose_operating_points(
            frontier,
            0.5,
        )
    )

    policies = set(
        operating_points["policy"]
    )

    assert (
        "CURRENT_HIGH_RECALL"
        in policies
    )

    assert (
        "BEST_F1_DEVELOPMENT"
        in policies
    )


def test_claim_boundary_separates_forecast() -> None:
    boundary = claim_boundary()

    forecast = boundary[
        boundary["question"]
        == "Could exploitation occur soon?"
    ].iloc[0]

    assert (
        forecast["mechanism"]
        == "FIRST EPSS 30-day forecast"
    )

    assert (
        forecast["authority"]
        == "ADVISORY_FORECAST"
    )


def test_prediction_cannot_rewrite_exploitation() -> None:
    matrix = agreement_matrix()

    row = matrix[
        (
            matrix["affectedness"]
            == "AFFECTED"
        )
        & (
            matrix[
                "confirmed_exploitation"
            ]
            == "NOT_OBSERVED"
        )
        & (
            matrix["forecast"]
            == "HIGH"
        )
    ].iloc[0]

    assert (
        row["policy_behavior"]
        == "DO_NOT_MARK_ACTIVE"
    )

    assert (
        row["human_review"]
        == "ESCALATE_PREDICTIVE_REVIEW"
    )


def test_screenshot_policy_fails_closed() -> None:
    policy = screenshot_policy()

    normalization = policy[
        policy["stage"]
        == "NORMALIZATION"
    ].iloc[0]

    assert (
        normalization["behavior"]
        == "Unresolved identity remains UNKNOWN."
    )


def test_live_master_vertical_slice() -> None:
    bundle = (
        load_master_vertical_slice()
    )

    summary = bundle["summary"]

    assert (
        summary["vector"]
        == "A/O/Y/M"
    )

    assert (
        summary["matched_row"]
        == 69
    )

    assert (
        summary["outcome_name"]
        == "OUT_OF_CYCLE"
    )

    assert (
        summary["stage_gate"]
        == "PASS"
    )

    assert (
        summary[
            "final_disposition_status"
        ]
        == "NOT_AUTHORIZED"
    )

    assert (
        summary["model_authority"]
        == "ADVISORY_ONLY"
    )

    assert (
        summary[
            "future_custom_forecast"
        ]
        == "NOT_YET_AUTHORIZED"
    )

    assert (
        summary[
            "production_readiness"
        ]
        == "BLOCKED"
    )

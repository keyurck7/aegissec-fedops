from __future__ import annotations

import numpy as np
import pandas as pd

from src.presentation_demo.real_benchmark_data import (
    engineer_features,
)
from src.presentation_demo.real_model_benchmark import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    calculate_metrics,
    candidate_specs,
    select_threshold,
)


def test_feature_engineering() -> None:
    frame = pd.DataFrame(
        {
            "cve": [
                "CVE-2021-44228",
                "CVE-2024-10001",
            ],
            "epss": [
                0.99,
                0.01,
            ],
            "percentile": [
                0.999,
                0.20,
            ],
        }
    )

    result = engineer_features(
        frame,
        snapshot_date="2026-07-19",
    )

    assert len(result) == 2
    assert result.loc[0, "cve_year"] == 2021
    assert result.loc[0, "epss_ge_0_50"] == 1
    assert result.loc[1, "epss_ge_0_50"] == 0
    assert result.loc[0, "percentile_ge_0_99"] == 1


def test_label_is_not_a_feature() -> None:
    assert LABEL_COLUMN == "is_kev"
    assert LABEL_COLUMN not in FEATURE_COLUMNS


def test_candidate_families_exist() -> None:
    families = {
        specification["family"]
        for specification in candidate_specs()
    }

    assert families == {
        "logistic_regression",
        "random_forest",
        "hist_gradient_boosting",
    }


def test_candidate_names_are_unique() -> None:
    names = [
        specification["name"]
        for specification in candidate_specs()
    ]

    assert len(names) == len(set(names))


def test_threshold_selection_respects_recall() -> None:
    truth = np.array(
        [0, 0, 0, 1, 1, 1]
    )

    probabilities = np.array(
        [0.01, 0.10, 0.30, 0.40, 0.80, 0.95]
    )

    result = select_threshold(
        truth,
        probabilities,
        minimum_recall=0.66,
    )

    assert 0.0 <= result["threshold"] <= 1.0
    assert result["validation_recall"] >= 0.66
    assert 0.0 <= result["validation_precision"] <= 1.0


def test_metrics_include_imbalance_metrics() -> None:
    truth = np.array(
        [0, 0, 0, 0, 1, 1]
    )

    probabilities = np.array(
        [0.01, 0.05, 0.10, 0.30, 0.70, 0.90]
    )

    metrics = calculate_metrics(
        truth,
        probabilities,
        threshold=0.5,
    )

    assert metrics["accuracy"] == 1.0
    assert metrics["balanced_accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["confusion_matrix"] == {
        "true_negative": 4,
        "false_positive": 0,
        "false_negative": 0,
        "true_positive": 2,
    }

    assert 0.0 <= metrics["pr_auc"] <= 1.0
    assert 0.0 <= metrics["roc_auc"] <= 1.0
    assert 0.0 <= metrics["brier_score"] <= 1.0
    assert (
        0.0
        <= metrics["expected_calibration_error"]
        <= 1.0
    )

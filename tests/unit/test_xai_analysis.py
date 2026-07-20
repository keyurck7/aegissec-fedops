from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import src.presentation_demo.xai_analysis as xai
from src.presentation_demo.real_model_benchmark import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
)


def write_sidecar(path: Path) -> None:
    Path(f"{path}.sha256").write_text(
        f"{xai.sha256_file(path)}  {path.name}\n",
        encoding="utf-8",
    )


def build_fixture(tmp_path: Path) -> dict[str, Path]:
    rng = np.random.default_rng(42)

    train = pd.DataFrame(
        rng.normal(
            size=(
                240,
                len(FEATURE_COLUMNS),
            )
        ),
        columns=FEATURE_COLUMNS,
    )

    train[LABEL_COLUMN] = (
        train["epss"]
        + train["percentile"]
        - 0.25 * train["cve_age_years"]
        > 0
    ).astype(int)

    model = Pipeline(
        [
            (
                "scale",
                StandardScaler(),
            ),
            (
                "model",
                LogisticRegression(
                    max_iter=1000,
                    random_state=42,
                ),
            ),
        ]
    )

    model.fit(
        train[FEATURE_COLUMNS],
        train[LABEL_COLUMN],
    )

    evaluation = pd.DataFrame(
        rng.normal(
            size=(
                16,
                len(FEATURE_COLUMNS),
            )
        ),
        columns=FEATURE_COLUMNS,
    )

    probabilities = model.predict_proba(
        evaluation[FEATURE_COLUMNS]
    )[:, 1]

    threshold = float(
        np.median(probabilities)
    )

    predictions = (
        probabilities >= threshold
    ).astype(int)

    positive_indices = np.flatnonzero(
        predictions == 1
    )

    negative_indices = np.flatnonzero(
        predictions == 0
    )

    assert len(positive_indices) >= 2
    assert len(negative_indices) >= 2

    actual = predictions.copy()

    actual[positive_indices[0]] = 1
    actual[positive_indices[1]] = 0
    actual[negative_indices[0]] = 1
    actual[negative_indices[1]] = 0

    evaluation["cve"] = [
        f"CVE-2026-{10000 + index}"
        for index in range(
            len(evaluation)
        )
    ]

    evaluation[LABEL_COLUMN] = actual

    prediction_frame = evaluation[
        [
            "cve",
            LABEL_COLUMN,
        ]
    ].copy()

    prediction_frame[
        "predicted_probability"
    ] = probabilities

    prediction_frame[
        "prediction"
    ] = predictions

    model_path = (
        tmp_path
        / "model.joblib"
    )

    dataset_path = (
        tmp_path
        / "dataset.csv.gz"
    )

    predictions_path = (
        tmp_path
        / "predictions.csv.gz"
    )

    report_path = (
        tmp_path
        / "model_report.json"
    )

    output_dir = (
        tmp_path
        / "xai"
    )

    joblib.dump(
        model,
        model_path,
    )

    evaluation.to_csv(
        dataset_path,
        index=False,
        compression="gzip",
    )

    prediction_frame.to_csv(
        predictions_path,
        index=False,
        compression="gzip",
    )

    report_path.write_text(
        json.dumps(
            {
                "winner": {
                    "candidate_name":
                        "logistic_test",
                    "family":
                        "logistic_regression",
                },
                "test_metrics": {
                    "threshold":
                        threshold,
                },
                "governance": {
                    "label_definition":
                        "CURRENT_CISA_KEV_MEMBERSHIP",
                    "authoritative_policy_engine":
                        "SSVC",
                    "model_authority":
                        "ADVISORY_ONLY",
                    "production_readiness":
                        "BLOCKED",
                },
            }
        ),
        encoding="utf-8",
    )

    for path in (
        model_path,
        dataset_path,
        predictions_path,
        report_path,
    ):
        write_sidecar(path)

    return {
        "model": model_path,
        "dataset": dataset_path,
        "predictions":
            predictions_path,
        "report": report_path,
        "output": output_dir,
    }


def test_classifies_all_binary_outcomes() -> None:
    assert xai.classify_outcome(
        1,
        1,
    ) == "TRUE_POSITIVE"

    assert xai.classify_outcome(
        0,
        1,
    ) == "FALSE_POSITIVE"

    assert xai.classify_outcome(
        1,
        0,
    ) == "FALSE_NEGATIVE"

    assert xai.classify_outcome(
        0,
        0,
    ) == "TRUE_NEGATIVE"


def test_invalid_outcome_is_rejected() -> None:
    with pytest.raises(
        xai.XAIAnalysisError,
        match="must be binary",
    ):
        xai.classify_outcome(
            2,
            1,
        )


def test_sigmoid_is_bounded() -> None:
    assert (
        0.0
        < xai.sigmoid(-100.0)
        < 0.5
    )

    assert xai.sigmoid(0.0) == 0.5

    assert (
        0.5
        < xai.sigmoid(100.0)
        <= 1.0
    )

    assert xai.sigmoid(20.0) < 1.0


def test_safe_ratio() -> None:
    assert xai.safe_ratio(
        2,
        4,
    ) == 0.5

    assert xai.safe_ratio(
        0,
        0,
    ) is None


def test_global_and_local_explanations(
    tmp_path: Path,
) -> None:
    paths = build_fixture(
        tmp_path
    )

    model = joblib.load(
        paths["model"]
    )

    coefficients = (
        xai.global_coefficients(
            model
        )
    )

    assert len(coefficients) == len(
        FEATURE_COLUMNS
    )

    assert set(
        coefficients["direction"]
    ).issubset(
        {
            "TOWARD_KEV_MEMBERSHIP",
            "AWAY_FROM_KEV_MEMBERSHIP",
        }
    )


def test_representative_examples_require_all_outcomes() -> None:
    frame = pd.DataFrame(
        {
            "cve": [
                "CVE-2026-10001"
            ],
            LABEL_COLUMN: [1],
            "prediction": [1],
            "predicted_probability":
                [0.9],
            "outcome_type": [
                "TRUE_POSITIVE"
            ],
        }
    )

    with pytest.raises(
        xai.XAIAnalysisError,
        match="Missing required outcome",
    ):
        xai.representative_examples(
            frame
        )


def test_end_to_end_xai_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = build_fixture(
        tmp_path
    )

    monkeypatch.setattr(
        xai,
        "MODEL_PATH",
        paths["model"],
    )

    monkeypatch.setattr(
        xai,
        "DATASET_PATH",
        paths["dataset"],
    )

    monkeypatch.setattr(
        xai,
        "PREDICTIONS_PATH",
        paths["predictions"],
    )

    monkeypatch.setattr(
        xai,
        "MODEL_REPORT_PATH",
        paths["report"],
    )

    monkeypatch.setattr(
        xai,
        "OUTPUT_DIR",
        paths["output"],
    )

    report = (
        xai.build_xai_artifacts()
    )

    assert (
        report[
            "quality_gate"
        ]["stage_gate"]
        == "PASS"
    )

    assert (
        report[
            "local_explanation"
        ][
            "maximum_probability_reconstruction_error"
        ]
        < 1e-9
    )

    assert set(
        report[
            "weakness_analysis"
        ]["outcome_counts"]
    ) == {
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "FALSE_NEGATIVE",
        "TRUE_NEGATIVE",
    }

    bundle = (
        xai.load_xai_bundle()
    )

    assert len(
        bundle["coefficients"]
    ) == len(FEATURE_COLUMNS)

    assert len(
        bundle["examples"]
    ) == 4

    assert not bundle[
        "contributions"
    ].empty

    assert not bundle[
        "slices"
    ].empty


def test_tampered_input_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    paths = build_fixture(
        tmp_path
    )

    paths["report"].write_text(
        "{}",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        xai,
        "MODEL_PATH",
        paths["model"],
    )

    monkeypatch.setattr(
        xai,
        "DATASET_PATH",
        paths["dataset"],
    )

    monkeypatch.setattr(
        xai,
        "PREDICTIONS_PATH",
        paths["predictions"],
    )

    monkeypatch.setattr(
        xai,
        "MODEL_REPORT_PATH",
        paths["report"],
    )

    monkeypatch.setattr(
        xai,
        "OUTPUT_DIR",
        paths["output"],
    )

    with pytest.raises(
        xai.XAIAnalysisError,
        match="Integrity mismatch",
    ):
        xai.build_xai_artifacts()

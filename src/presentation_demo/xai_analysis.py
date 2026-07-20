"""Explainability and weakness analysis for the KEV benchmark.

The selected model classifies current CISA KEV membership.
It does not predict future exploitation, override SSVC,
change affectedness or authorize remediation.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from src.presentation_demo.real_model_benchmark import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
)


ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "model_benchmark"
)

MODEL_PATH = (
    MODEL_DIR
    / "real_kev_membership_model.joblib"
)

DATASET_PATH = (
    MODEL_DIR
    / "real_epss_kev_benchmark.csv.gz"
)

PREDICTIONS_PATH = (
    MODEL_DIR
    / "real_model_test_predictions.csv.gz"
)

MODEL_REPORT_PATH = (
    MODEL_DIR
    / "real_model_benchmark_report.json"
)

OUTPUT_DIR = MODEL_DIR / "xai"


class XAIAnalysisError(RuntimeError):
    """Raised when XAI evidence cannot be trusted."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def write_sidecar(path: Path) -> None:
    Path(f"{path}.sha256").write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="utf-8",
    )


def verify_sidecar(path: Path) -> None:
    sidecar = Path(f"{path}.sha256")

    if not sidecar.is_file():
        raise XAIAnalysisError(
            f"Missing integrity sidecar: {sidecar}"
        )

    expected = sidecar.read_text(
        encoding="utf-8"
    ).split()[0]

    observed = sha256_file(path)

    if expected != observed:
        raise XAIAnalysisError(
            f"Integrity mismatch for {path}"
        )


def sigmoid(value: float) -> float:
    if value >= 0:
        term = math.exp(-value)
        return 1.0 / (1.0 + term)

    term = math.exp(value)
    return term / (1.0 + term)


def classify_outcome(
    actual: int,
    predicted: int,
) -> str:
    outcomes = {
        (1, 1): "TRUE_POSITIVE",
        (0, 1): "FALSE_POSITIVE",
        (1, 0): "FALSE_NEGATIVE",
        (0, 0): "TRUE_NEGATIVE",
    }

    try:
        return outcomes[
            int(actual),
            int(predicted),
        ]
    except KeyError as exc:
        raise XAIAnalysisError(
            "Actual and predicted values "
            "must be binary."
        ) from exc


def extract_logistic_model(
    model: Any,
):
    if not isinstance(model, Pipeline):
        raise XAIAnalysisError(
            "Expected an sklearn Pipeline."
        )

    if (
        "scale" not in model.named_steps
        or "model" not in model.named_steps
    ):
        raise XAIAnalysisError(
            "Expected scale and model steps."
        )

    scaler = model.named_steps["scale"]
    classifier = model.named_steps["model"]

    if not hasattr(classifier, "coef_"):
        raise XAIAnalysisError(
            "Selected model does not expose "
            "directional coefficients."
        )

    coefficients = np.asarray(
        classifier.coef_,
        dtype=float,
    )

    if coefficients.shape != (
        1,
        len(FEATURE_COLUMNS),
    ):
        raise XAIAnalysisError(
            "Coefficient shape does not match "
            "the feature contract."
        )

    intercept = float(
        np.asarray(
            classifier.intercept_
        )[0]
    )

    return (
        scaler,
        classifier,
        coefficients[0],
        intercept,
    )


def global_coefficients(
    model: Any,
) -> pd.DataFrame:
    (
        scaler,
        _,
        coefficients,
        _,
    ) = extract_logistic_model(model)

    scales = np.asarray(
        scaler.scale_,
        dtype=float,
    )

    if np.any(scales == 0):
        raise XAIAnalysisError(
            "A feature has zero scale."
        )

    frame = pd.DataFrame(
        {
            "feature": FEATURE_COLUMNS,
            "standardized_coefficient":
                coefficients,
            "raw_unit_coefficient":
                coefficients / scales,
            "absolute_coefficient":
                np.abs(coefficients),
            "direction": np.where(
                coefficients >= 0,
                "TOWARD_KEV_MEMBERSHIP",
                "AWAY_FROM_KEV_MEMBERSHIP",
            ),
            "odds_ratio_per_standard_deviation":
                np.exp(
                    np.clip(
                        coefficients,
                        -20,
                        20,
                    )
                ),
        }
    )

    return frame.sort_values(
        [
            "absolute_coefficient",
            "feature",
        ],
        ascending=[
            False,
            True,
        ],
    ).reset_index(drop=True)


def load_joined_predictions() -> pd.DataFrame:
    dataset = pd.read_csv(
        DATASET_PATH
    )

    predictions = pd.read_csv(
        PREDICTIONS_PATH
    )

    required_dataset = {
        "cve",
        LABEL_COLUMN,
        *FEATURE_COLUMNS,
    }

    required_predictions = {
        "cve",
        LABEL_COLUMN,
        "predicted_probability",
        "prediction",
    }

    if not required_dataset.issubset(
        dataset.columns
    ):
        raise XAIAnalysisError(
            "Benchmark dataset is missing "
            "required feature columns."
        )

    if not required_predictions.issubset(
        predictions.columns
    ):
        raise XAIAnalysisError(
            "Prediction artifact is missing "
            "required columns."
        )

    prediction_base = predictions[
        [
            "cve",
            LABEL_COLUMN,
            "predicted_probability",
            "prediction",
        ]
    ].rename(
        columns={
            LABEL_COLUMN:
                "prediction_artifact_label"
        }
    )

    joined = prediction_base.merge(
        dataset[
            [
                "cve",
                LABEL_COLUMN,
                *FEATURE_COLUMNS,
            ]
        ],
        on="cve",
        how="inner",
        validate="one_to_one",
    )

    if len(joined) != len(predictions):
        raise XAIAnalysisError(
            "Predictions did not join one-to-one "
            "with the benchmark dataset."
        )

    if not np.array_equal(
        joined[
            "prediction_artifact_label"
        ].to_numpy(),
        joined[
            LABEL_COLUMN
        ].to_numpy(),
    ):
        raise XAIAnalysisError(
            "Prediction labels do not match "
            "benchmark labels."
        )

    joined["outcome_type"] = [
        classify_outcome(
            actual,
            predicted,
        )
        for actual, predicted in zip(
            joined[LABEL_COLUMN],
            joined["prediction"],
            strict=True,
        )
    ]

    return joined


def representative_examples(
    frame: pd.DataFrame,
) -> pd.DataFrame:
    rules = {
        "TRUE_POSITIVE": False,
        "FALSE_POSITIVE": False,
        "FALSE_NEGATIVE": False,
        "TRUE_NEGATIVE": True,
    }

    examples = []

    for outcome, ascending in rules.items():
        subset = frame[
            frame["outcome_type"] == outcome
        ]

        if subset.empty:
            raise XAIAnalysisError(
                f"Missing required outcome: {outcome}"
            )

        examples.append(
            subset.sort_values(
                "predicted_probability",
                ascending=ascending,
            ).iloc[0]
        )

    return pd.DataFrame(
        examples
    ).reset_index(drop=True)


def local_contributions(
    model: Any,
    examples: pd.DataFrame,
) -> tuple[
    pd.DataFrame,
    pd.DataFrame,
    float,
]:
    (
        scaler,
        _,
        coefficients,
        intercept,
    ) = extract_logistic_model(model)

    transformed = scaler.transform(
        examples[FEATURE_COLUMNS]
    )

    contributions = (
        transformed * coefficients
    )

    example_rows = []
    contribution_rows = []
    maximum_error = 0.0

    for row_index, (_, row) in enumerate(
        examples.iterrows()
    ):
        decision_logit = float(
            intercept
            + contributions[
                row_index
            ].sum()
        )

        reconstructed = sigmoid(
            decision_logit
        )

        observed = float(
            row[
                "predicted_probability"
            ]
        )

        error = abs(
            reconstructed - observed
        )

        maximum_error = max(
            maximum_error,
            error,
        )

        example_rows.append(
            {
                "cve": row["cve"],
                "outcome_type":
                    row["outcome_type"],
                "actual_is_kev":
                    int(row[LABEL_COLUMN]),
                "prediction":
                    int(row["prediction"]),
                "predicted_probability":
                    observed,
                "reconstructed_probability":
                    reconstructed,
                "reconstruction_error":
                    error,
                "decision_logit":
                    decision_logit,
                "epss":
                    float(row["epss"]),
                "percentile":
                    float(
                        row["percentile"]
                    ),
                "cve_year":
                    int(row["cve_year"]),
                "cve_age_years":
                    int(
                        row[
                            "cve_age_years"
                        ]
                    ),
            }
        )

        for feature_index, feature in enumerate(
            FEATURE_COLUMNS
        ):
            value = float(
                contributions[
                    row_index,
                    feature_index,
                ]
            )

            contribution_rows.append(
                {
                    "cve": row["cve"],
                    "outcome_type":
                        row["outcome_type"],
                    "feature": feature,
                    "raw_value":
                        float(row[feature]),
                    "standardized_value":
                        float(
                            transformed[
                                row_index,
                                feature_index,
                            ]
                        ),
                    "logit_contribution":
                        value,
                    "absolute_contribution":
                        abs(value),
                    "direction": (
                        "TOWARD_KEV"
                        if value >= 0
                        else "AWAY_FROM_KEV"
                    ),
                }
            )

    contributions_frame = pd.DataFrame(
        contribution_rows
    ).sort_values(
        [
            "outcome_type",
            "absolute_contribution",
        ],
        ascending=[
            True,
            False,
        ],
    )

    return (
        pd.DataFrame(example_rows),
        contributions_frame,
        maximum_error,
    )


def safe_ratio(
    numerator: int,
    denominator: int,
) -> float | None:
    if denominator == 0:
        return None

    return float(
        numerator / denominator
    )


def weakness_slices(
    frame: pd.DataFrame,
) -> pd.DataFrame:
    sliced = frame.copy()

    sliced["epss_band"] = pd.cut(
        sliced["epss"],
        bins=[
            -1e-12,
            0.01,
            0.10,
            0.50,
            1.0,
        ],
        labels=[
            "0_TO_1_PERCENT",
            "1_TO_10_PERCENT",
            "10_TO_50_PERCENT",
            "50_TO_100_PERCENT",
        ],
        include_lowest=True,
    )

    sliced["age_band"] = pd.cut(
        sliced["cve_age_years"],
        bins=[
            -1,
            2,
            5,
            10,
            20,
            100,
        ],
        labels=[
            "AGE_0_TO_2",
            "AGE_3_TO_5",
            "AGE_6_TO_10",
            "AGE_11_TO_20",
            "AGE_OVER_20",
        ],
    )

    results = []

    for dimension in (
        "epss_band",
        "age_band",
    ):
        grouped = sliced.groupby(
            dimension,
            observed=True,
        )

        for value, group in grouped:
            outcomes = (
                group["outcome_type"]
                .value_counts()
                .to_dict()
            )

            tp = int(
                outcomes.get(
                    "TRUE_POSITIVE",
                    0,
                )
            )

            fp = int(
                outcomes.get(
                    "FALSE_POSITIVE",
                    0,
                )
            )

            fn = int(
                outcomes.get(
                    "FALSE_NEGATIVE",
                    0,
                )
            )

            tn = int(
                outcomes.get(
                    "TRUE_NEGATIVE",
                    0,
                )
            )

            results.append(
                {
                    "slice_dimension":
                        dimension,
                    "slice_value":
                        str(value),
                    "rows":
                        int(len(group)),
                    "true_positive": tp,
                    "false_positive": fp,
                    "false_negative": fn,
                    "true_negative": tn,
                    "precision":
                        safe_ratio(
                            tp,
                            tp + fp,
                        ),
                    "recall":
                        safe_ratio(
                            tp,
                            tp + fn,
                        ),
                    "false_positive_rate":
                        safe_ratio(
                            fp,
                            fp + tn,
                        ),
                    "false_negative_rate":
                        safe_ratio(
                            fn,
                            fn + tp,
                        ),
                }
            )

    return pd.DataFrame(results)


def build_xai_artifacts() -> dict[str, Any]:
    required = (
        MODEL_PATH,
        DATASET_PATH,
        PREDICTIONS_PATH,
        MODEL_REPORT_PATH,
    )

    for path in required:
        if not path.is_file():
            raise XAIAnalysisError(
                f"Missing required artifact: {path}"
            )

        verify_sidecar(path)

    model_report = json.loads(
        MODEL_REPORT_PATH.read_text(
            encoding="utf-8"
        )
    )

    governance = model_report[
        "governance"
    ]

    if (
        governance[
            "authoritative_policy_engine"
        ]
        != "SSVC"
    ):
        raise XAIAnalysisError(
            "SSVC authority is not preserved."
        )

    if (
        governance["model_authority"]
        != "ADVISORY_ONLY"
    ):
        raise XAIAnalysisError(
            "Unexpected model authority."
        )

    if (
        governance[
            "production_readiness"
        ]
        != "BLOCKED"
    ):
        raise XAIAnalysisError(
            "Production readiness must remain "
            "blocked."
        )

    model = joblib.load(
        MODEL_PATH
    )

    coefficients = global_coefficients(
        model
    )

    predictions = load_joined_predictions()

    examples = representative_examples(
        predictions
    )

    (
        example_details,
        contributions,
        reconstruction_error,
    ) = local_contributions(
        model,
        examples,
    )

    slices = weakness_slices(
        predictions
    )

    outcome_counts = (
        predictions[
            "outcome_type"
        ]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    checks = {
        "all_four_outcomes_present": (
            set(outcome_counts)
            == {
                "TRUE_POSITIVE",
                "FALSE_POSITIVE",
                "FALSE_NEGATIVE",
                "TRUE_NEGATIVE",
            }
        ),
        "probability_reconstruction_error_below_1e_9":
            reconstruction_error < 1e-9,
        "label_excluded_from_features":
            LABEL_COLUMN not in FEATURE_COLUMNS,
        "false_positives_detected":
            outcome_counts.get(
                "FALSE_POSITIVE",
                0,
            )
            > 0,
        "false_negatives_detected":
            outcome_counts.get(
                "FALSE_NEGATIVE",
                0,
            )
            > 0,
        "ssvc_authority_preserved":
            governance[
                "authoritative_policy_engine"
            ]
            == "SSVC",
        "model_advisory_only":
            governance[
                "model_authority"
            ]
            == "ADVISORY_ONLY",
        "production_blocked":
            governance[
                "production_readiness"
            ]
            == "BLOCKED",
    }

    stage_gate = (
        "PASS"
        if all(checks.values())
        else "FAIL"
    )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    coefficients_path = (
        OUTPUT_DIR
        / "xai_global_coefficients.csv"
    )

    examples_path = (
        OUTPUT_DIR
        / "xai_representative_examples.csv"
    )

    contributions_path = (
        OUTPUT_DIR
        / "xai_local_contributions.csv"
    )

    slices_path = (
        OUTPUT_DIR
        / "xai_weakness_slices.csv"
    )

    report_path = (
        OUTPUT_DIR
        / "xai_report.json"
    )

    coefficients.to_csv(
        coefficients_path,
        index=False,
    )

    example_details.to_csv(
        examples_path,
        index=False,
    )

    contributions.to_csv(
        contributions_path,
        index=False,
    )

    slices.to_csv(
        slices_path,
        index=False,
    )

    report = {
        "schema_version": "1.0.0",
        "model": {
            "winner":
                model_report[
                    "winner"
                ][
                    "candidate_name"
                ],
            "family":
                model_report[
                    "winner"
                ]["family"],
            "decision_threshold":
                model_report[
                    "test_metrics"
                ]["threshold"],
            "label_definition":
                governance[
                    "label_definition"
                ],
        },
        "global_explanation": {
            "method":
                "STANDARDIZED_LOGISTIC_COEFFICIENTS",
            "coefficient_rows":
                int(len(coefficients)),
        },
        "local_explanation": {
            "method":
                "ADDITIVE_LOGIT_CONTRIBUTIONS",
            "maximum_probability_reconstruction_error":
                reconstruction_error,
        },
        "weakness_analysis": {
            "outcome_counts":
                outcome_counts,
            "slice_rows":
                int(len(slices)),
        },
        "quality_gate": {
            "checks": checks,
            "stage_gate":
                stage_gate,
        },
        "governance": {
            "authoritative_policy_engine":
                "SSVC",
            "model_authority":
                "ADVISORY_ONLY",
            "future_exploitation_prediction":
                False,
            "automated_disposition_permitted":
                False,
            "human_review_required":
                True,
            "production_readiness":
                "BLOCKED",
        },
    }

    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    for path in (
        coefficients_path,
        examples_path,
        contributions_path,
        slices_path,
        report_path,
    ):
        write_sidecar(path)

    return report


def load_xai_bundle() -> dict[str, Any]:
    paths = {
        "report":
            OUTPUT_DIR
            / "xai_report.json",
        "coefficients":
            OUTPUT_DIR
            / "xai_global_coefficients.csv",
        "examples":
            OUTPUT_DIR
            / "xai_representative_examples.csv",
        "contributions":
            OUTPUT_DIR
            / "xai_local_contributions.csv",
        "slices":
            OUTPUT_DIR
            / "xai_weakness_slices.csv",
    }

    for path in paths.values():
        verify_sidecar(path)

    return {
        "report": json.loads(
            paths["report"].read_text(
                encoding="utf-8"
            )
        ),
        "coefficients": pd.read_csv(
            paths["coefficients"]
        ),
        "examples": pd.read_csv(
            paths["examples"]
        ),
        "contributions": pd.read_csv(
            paths["contributions"]
        ),
        "slices": pd.read_csv(
            paths["slices"]
        ),
    }

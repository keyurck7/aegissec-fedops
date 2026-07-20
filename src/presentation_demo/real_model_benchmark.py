"""Real-data benchmark for current CISA KEV membership."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.presentation_demo.real_benchmark_data import (
    sha256_file,
    utc_now,
    write_sidecar,
)


ROOT = Path(__file__).resolve().parents[2]

DEFAULT_DATASET_PATH = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "model_benchmark"
    / "real_epss_kev_benchmark.csv.gz"
)

DEFAULT_MANIFEST_PATH = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "model_benchmark"
    / "real_epss_kev_benchmark_manifest.json"
)

DEFAULT_OUTPUT_DIR = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "model_benchmark"
)

FEATURE_COLUMNS = [
    "epss",
    "percentile",
    "cve_year",
    "cve_age_years",
    "epss_log10",
    "epss_logit",
    "percentile_squared",
    "epss_ge_0_10",
    "epss_ge_0_50",
    "percentile_ge_0_90",
    "percentile_ge_0_99",
]

LABEL_COLUMN = "is_kev"

SEED = 42


class RealModelBenchmarkError(RuntimeError):
    """Raised when the model benchmark fails validation."""


def verify_hash(
    path: Path,
) -> None:
    sidecar = Path(f"{path}.sha256")

    if not sidecar.is_file():
        raise RealModelBenchmarkError(
            f"Missing sidecar: {sidecar}"
        )

    expected = sidecar.read_text(
        encoding="utf-8"
    ).split()[0]

    observed = sha256_file(path)

    if expected != observed:
        raise RealModelBenchmarkError(
            f"Integrity mismatch: {path}"
        )


def expected_calibration_error(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    *,
    bins: int = 10,
) -> float:
    edges = np.linspace(
        0.0,
        1.0,
        bins + 1,
    )

    total = len(y_true)
    error = 0.0

    for lower, upper in zip(
        edges[:-1],
        edges[1:],
        strict=True,
    ):
        if upper == 1.0:
            mask = (
                (probabilities >= lower)
                & (probabilities <= upper)
            )
        else:
            mask = (
                (probabilities >= lower)
                & (probabilities < upper)
            )

        count = int(mask.sum())

        if count == 0:
            continue

        observed_rate = float(
            y_true[mask].mean()
        )

        predicted_rate = float(
            probabilities[mask].mean()
        )

        error += (
            count
            / total
            * abs(
                observed_rate
                - predicted_rate
            )
        )

    return float(error)


def select_threshold(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    *,
    minimum_recall: float = 0.75,
) -> dict[str, float]:
    precision, recall, thresholds = (
        precision_recall_curve(
            y_true,
            probabilities,
        )
    )

    candidates: list[
        tuple[
            float,
            float,
            float,
        ]
    ] = []

    for index, threshold in enumerate(
        thresholds
    ):
        candidate_precision = float(
            precision[index]
        )

        candidate_recall = float(
            recall[index]
        )

        if candidate_recall >= minimum_recall:
            candidates.append(
                (
                    candidate_precision,
                    candidate_recall,
                    float(threshold),
                )
            )

    if not candidates:
        return {
            "threshold": 0.5,
            "validation_precision": 0.0,
            "validation_recall": 0.0,
        }

    best = max(
        candidates,
        key=lambda item: (
            item[0],
            item[1],
            item[2],
        ),
    )

    return {
        "threshold": best[2],
        "validation_precision": best[0],
        "validation_recall": best[1],
    }


def calculate_metrics(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    *,
    threshold: float,
) -> dict[str, Any]:
    predictions = (
        probabilities >= threshold
    ).astype(int)

    matrix = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    )

    return {
        "threshold": float(threshold),
        "rows": int(len(y_true)),
        "positive_rows": int(
            y_true.sum()
        ),
        "prevalence": float(
            y_true.mean()
        ),
        "predicted_positive_rate": float(
            predictions.mean()
        ),
        "accuracy": float(
            accuracy_score(
                y_true,
                predictions,
            )
        ),
        "balanced_accuracy": float(
            balanced_accuracy_score(
                y_true,
                predictions,
            )
        ),
        "precision": float(
            precision_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                y_true,
                probabilities,
            )
        ),
        "pr_auc": float(
            average_precision_score(
                y_true,
                probabilities,
            )
        ),
        "brier_score": float(
            brier_score_loss(
                y_true,
                probabilities,
            )
        ),
        "log_loss": float(
            log_loss(
                y_true,
                np.column_stack(
                    [
                        1.0 - probabilities,
                        probabilities,
                    ]
                ),
                labels=[0, 1],
            )
        ),
        "expected_calibration_error": (
            expected_calibration_error(
                y_true,
                probabilities,
            )
        ),
        "confusion_matrix": {
            "true_negative": int(
                matrix[0, 0]
            ),
            "false_positive": int(
                matrix[0, 1]
            ),
            "false_negative": int(
                matrix[1, 0]
            ),
            "true_positive": int(
                matrix[1, 1]
            ),
        },
    }


def sampled_training_rows(
    frame: pd.DataFrame,
    *,
    negative_to_positive_ratio: int = 12,
) -> pd.DataFrame:
    positives = frame[
        frame[LABEL_COLUMN] == 1
    ]

    negatives = frame[
        frame[LABEL_COLUMN] == 0
    ]

    negative_count = min(
        len(negatives),
        len(positives)
        * negative_to_positive_ratio,
    )

    sampled_negatives = negatives.sample(
        n=negative_count,
        random_state=SEED,
        replace=False,
    )

    return (
        pd.concat(
            [
                positives,
                sampled_negatives,
            ],
            ignore_index=True,
        )
        .sample(
            frac=1.0,
            random_state=SEED,
        )
        .reset_index(drop=True)
    )


def candidate_specs() -> list[
    dict[str, Any]
]:
    return [
        {
            "name": "logistic_c_0_1",
            "family": "logistic_regression",
            "parameters": {
                "C": 0.1,
            },
        },
        {
            "name": "logistic_c_1",
            "family": "logistic_regression",
            "parameters": {
                "C": 1.0,
            },
        },
        {
            "name": "logistic_c_10",
            "family": "logistic_regression",
            "parameters": {
                "C": 10.0,
            },
        },
        {
            "name": "random_forest_depth_10",
            "family": "random_forest",
            "parameters": {
                "max_depth": 10,
                "min_samples_leaf": 4,
            },
        },
        {
            "name": "random_forest_depth_16",
            "family": "random_forest",
            "parameters": {
                "max_depth": 16,
                "min_samples_leaf": 2,
            },
        },
        {
            "name": "hist_gradient_leaf_15",
            "family": "hist_gradient_boosting",
            "parameters": {
                "learning_rate": 0.05,
                "max_leaf_nodes": 15,
            },
        },
        {
            "name": "hist_gradient_leaf_31",
            "family": "hist_gradient_boosting",
            "parameters": {
                "learning_rate": 0.08,
                "max_leaf_nodes": 31,
            },
        },
    ]


def build_estimator(
    specification: Mapping[str, Any],
):
    family = specification["family"]
    parameters = dict(
        specification["parameters"]
    )

    if family == "logistic_regression":
        return Pipeline(
            [
                (
                    "scale",
                    StandardScaler(),
                ),
                (
                    "model",
                    LogisticRegression(
                        C=parameters["C"],
                        class_weight="balanced",
                        max_iter=2500,
                        random_state=SEED,
                    ),
                ),
            ]
        )

    if family == "random_forest":
        return RandomForestClassifier(
            n_estimators=300,
            max_depth=parameters[
                "max_depth"
            ],
            min_samples_leaf=parameters[
                "min_samples_leaf"
            ],
            max_features="sqrt",
            class_weight=(
                "balanced_subsample"
            ),
            n_jobs=-1,
            random_state=SEED,
        )

    if family == (
        "hist_gradient_boosting"
    ):
        return (
            HistGradientBoostingClassifier(
                learning_rate=parameters[
                    "learning_rate"
                ],
                max_leaf_nodes=parameters[
                    "max_leaf_nodes"
                ],
                max_iter=250,
                l2_regularization=0.1,
                class_weight="balanced",
                random_state=SEED,
            )
        )

    raise RealModelBenchmarkError(
        f"Unsupported family: {family}"
    )


def load_dataset(
    dataset_path: Path,
) -> pd.DataFrame:
    verify_hash(dataset_path)

    frame = pd.read_csv(
        dataset_path
    )

    required = set(
        FEATURE_COLUMNS
        + [
            "cve",
            LABEL_COLUMN,
        ]
    )

    if not required.issubset(
        frame.columns
    ):
        missing = sorted(
            required
            - set(frame.columns)
        )

        raise RealModelBenchmarkError(
            f"Dataset missing columns: {missing}"
        )

    if LABEL_COLUMN in FEATURE_COLUMNS:
        raise RealModelBenchmarkError(
            "Leakage firewall violation: "
            "label appears in feature list."
        )

    if frame["cve"].duplicated().any():
        raise RealModelBenchmarkError(
            "Dataset contains duplicate CVEs."
        )

    if set(
        frame[LABEL_COLUMN].unique()
    ) != {0, 1}:
        raise RealModelBenchmarkError(
            "Dataset label must be binary."
        )

    return frame


def feature_importance(
    model,
    x_test: pd.DataFrame,
    y_test: pd.Series,
) -> list[dict[str, Any]]:
    sample_size = min(
        len(x_test),
        20_000,
    )

    sampled = x_test.sample(
        n=sample_size,
        random_state=SEED,
    )

    sampled_y = y_test.loc[
        sampled.index
    ]

    result = permutation_importance(
        model,
        sampled,
        sampled_y,
        scoring="average_precision",
        n_repeats=3,
        random_state=SEED,
        n_jobs=-1,
    )

    rows = [
        {
            "feature": feature,
            "importance_mean": float(
                result.importances_mean[
                    index
                ]
            ),
            "importance_std": float(
                result.importances_std[
                    index
                ]
            ),
        }
        for index, feature in enumerate(
            FEATURE_COLUMNS
        )
    ]

    return sorted(
        rows,
        key=lambda row: (
            -row["importance_mean"],
            row["feature"],
        ),
    )


def run_real_model_benchmark(
    *,
    dataset_path: Path = (
        DEFAULT_DATASET_PATH
    ),
    manifest_path: Path = (
        DEFAULT_MANIFEST_PATH
    ),
    output_dir: Path = (
        DEFAULT_OUTPUT_DIR
    ),
) -> dict[str, Any]:
    verify_hash(manifest_path)

    manifest = json.loads(
        manifest_path.read_text(
            encoding="utf-8"
        )
    )

    frame = load_dataset(
        dataset_path
    )

    train_validation, test = (
        train_test_split(
            frame,
            test_size=0.20,
            random_state=SEED,
            stratify=frame[
                LABEL_COLUMN
            ],
        )
    )

    train, validation = (
        train_test_split(
            train_validation,
            test_size=0.25,
            random_state=SEED,
            stratify=train_validation[
                LABEL_COLUMN
            ],
        )
    )

    sampled_train = (
        sampled_training_rows(
            train
        )
    )

    x_train = sampled_train[
        FEATURE_COLUMNS
    ]

    y_train = sampled_train[
        LABEL_COLUMN
    ]

    x_validation = validation[
        FEATURE_COLUMNS
    ]

    y_validation = validation[
        LABEL_COLUMN
    ]

    candidate_rows: list[
        dict[str, Any]
    ] = []

    fitted_candidates: dict[
        str,
        Any,
    ] = {}

    for specification in (
        candidate_specs()
    ):
        estimator = build_estimator(
            specification
        )

        estimator.fit(
            x_train,
            y_train,
        )

        probabilities = (
            estimator.predict_proba(
                x_validation
            )[:, 1]
        )

        threshold_details = (
            select_threshold(
                y_validation.to_numpy(),
                probabilities,
                minimum_recall=0.75,
            )
        )

        metrics = calculate_metrics(
            y_validation.to_numpy(),
            probabilities,
            threshold=threshold_details[
                "threshold"
            ],
        )

        row = {
            "candidate_name":
                specification["name"],
            "family":
                specification["family"],
            "parameters":
                specification[
                    "parameters"
                ],
            "threshold_selection":
                threshold_details,
            "validation_metrics":
                metrics,
        }

        candidate_rows.append(row)

        fitted_candidates[
            specification["name"]
        ] = estimator

    candidate_rows.sort(
        key=lambda row: (
            -row["validation_metrics"][
                "pr_auc"
            ],
            -row["validation_metrics"][
                "roc_auc"
            ],
            -row["validation_metrics"][
                "balanced_accuracy"
            ],
            row["candidate_name"],
        )
    )

    winner = candidate_rows[0]

    winner_specification = next(
        specification
        for specification in (
            candidate_specs()
        )
        if specification["name"]
        == winner["candidate_name"]
    )

    development_pool = pd.concat(
        [
            train,
            validation,
        ],
        ignore_index=True,
    )

    sampled_development = (
        sampled_training_rows(
            development_pool
        )
    )

    final_model = build_estimator(
        winner_specification
    )

    final_model.fit(
        sampled_development[
            FEATURE_COLUMNS
        ],
        sampled_development[
            LABEL_COLUMN
        ],
    )

    x_test = test[
        FEATURE_COLUMNS
    ]

    y_test = test[
        LABEL_COLUMN
    ]

    test_probabilities = (
        final_model.predict_proba(
            x_test
        )[:, 1]
    )

    selected_threshold = float(
        winner[
            "threshold_selection"
        ]["threshold"]
    )

    test_metrics = calculate_metrics(
        y_test.to_numpy(),
        test_probabilities,
        threshold=selected_threshold,
    )

    predictions = test[
        [
            "cve",
            LABEL_COLUMN,
            "epss",
            "percentile",
            "cve_year",
        ]
    ].copy()

    predictions[
        "predicted_probability"
    ] = test_probabilities

    predictions["prediction"] = (
        test_probabilities
        >= selected_threshold
    ).astype(int)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    model_path = (
        output_dir
        / "real_kev_membership_model.joblib"
    )

    joblib.dump(
        final_model,
        model_path,
    )

    candidates_path = (
        output_dir
        / "real_model_candidates.json"
    )

    candidates_path.write_text(
        json.dumps(
            candidate_rows,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    predictions_path = (
        output_dir
        / "real_model_test_predictions.csv.gz"
    )

    predictions.to_csv(
        predictions_path,
        index=False,
        compression={
            "method": "gzip",
            "mtime": 0,
        },
    )

    importance = feature_importance(
        final_model,
        x_test,
        y_test,
    )

    importance_path = (
        output_dir
        / "real_model_feature_importance.json"
    )

    importance_path.write_text(
        json.dumps(
            importance,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    prevalence = test_metrics[
        "prevalence"
    ]

    quality_checks = {
        "test_positive_rows_at_least_100": (
            test_metrics[
                "positive_rows"
            ]
            >= 100
        ),
        "roc_auc_at_least_0_75": (
            test_metrics["roc_auc"]
            >= 0.75
        ),
        "pr_auc_materially_above_prevalence": (
            test_metrics["pr_auc"]
            >= max(
                0.05,
                prevalence * 5.0,
            )
        ),
        "recall_at_least_0_60": (
            test_metrics["recall"]
            >= 0.60
        ),
        "balanced_accuracy_at_least_0_65": (
            test_metrics[
                "balanced_accuracy"
            ]
            >= 0.65
        ),
        "label_excluded_from_features": (
            LABEL_COLUMN
            not in FEATURE_COLUMNS
        ),
    }

    development_gate = (
        "PASS"
        if all(
            quality_checks.values()
        )
        else "FAIL"
    )

    report = {
        "schema_version": "1.0.0",
        "benchmark_id": (
            "AEG-REAL-MODEL-"
            + hashlib.sha256(
                (
                    manifest[
                        "dataset_sha256"
                    ]
                    + winner[
                        "candidate_name"
                    ]
                ).encode("utf-8")
            ).hexdigest()[:24].upper()
        ),
        "generated_at": utc_now(),
        "dataset": {
            "dataset_id":
                manifest["dataset_id"],
            "rows": int(len(frame)),
            "positive_rows": int(
                frame[
                    LABEL_COLUMN
                ].sum()
            ),
            "prevalence": float(
                frame[
                    LABEL_COLUMN
                ].mean()
            ),
            "snapshot_date":
                manifest[
                    "epss_source"
                ]["score_date"],
        },
        "split": {
            "training_rows": int(
                len(train)
            ),
            "sampled_training_rows": int(
                len(sampled_train)
            ),
            "validation_rows": int(
                len(validation)
            ),
            "test_rows": int(
                len(test)
            ),
            "test_distribution": (
                "NATURAL_PREVALENCE"
            ),
            "random_seed": SEED,
        },
        "features": FEATURE_COLUMNS,
        "leakage_firewall": {
            "label": LABEL_COLUMN,
            "label_in_features": False,
            "ssvc_features_used": False,
            "asset_or_sector_features_used": False,
            "cisa_kev_derived_features_used": False,
        },
        "winner": winner,
        "test_metrics": test_metrics,
        "feature_importance": importance,
        "quality_gate": {
            "checks": quality_checks,
            "development_gate":
                development_gate,
        },
        "artifacts": {
            "model_path": str(
                model_path
            ),
            "model_sha256":
                sha256_file(model_path),
            "candidate_results_path": str(
                candidates_path
            ),
            "test_predictions_path": str(
                predictions_path
            ),
            "feature_importance_path": str(
                importance_path
            ),
        },
        "governance": {
            "label_definition": (
                "CURRENT_CISA_KEV_MEMBERSHIP"
            ),
            "future_exploitation_prediction": False,
            "causal_model": False,
            "independent_from_ssvc": True,
            "authoritative_policy_engine": "SSVC",
            "model_authority": "ADVISORY_ONLY",
            "automated_disposition_permitted": False,
            "production_readiness": "BLOCKED",
            "limitations": [
                "Cross-sectional benchmark, not temporal validation.",
                "EPSS is an input feature and not a complete risk score.",
                "KEV membership represents confirmed historical exploitation.",
                "Results must not be used to replace affectedness or SSVC.",
                "Accuracy is inflated by natural class imbalance and is not the primary model-selection metric."
            ],
        },
    }

    report_path = (
        output_dir
        / "real_model_benchmark_report.json"
    )

    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    model_card_path = (
        output_dir
        / "REAL_MODEL_CARD.md"
    )

    model_card_path.write_text(
        f"""# AegisSec-FedOps Real-Data Benchmark

## Purpose

Classify current CISA KEV membership using public
EPSS-derived features for an academic development
benchmark.

## Selected model

- Candidate: `{winner['candidate_name']}`
- Family: `{winner['family']}`
- Threshold: `{selected_threshold:.6f}`
- Development gate: `{development_gate}`

## Natural-prevalence test metrics

- Accuracy: `{test_metrics['accuracy']:.6f}`
- Balanced accuracy: `{test_metrics['balanced_accuracy']:.6f}`
- Precision: `{test_metrics['precision']:.6f}`
- Recall: `{test_metrics['recall']:.6f}`
- F1: `{test_metrics['f1']:.6f}`
- ROC-AUC: `{test_metrics['roc_auc']:.6f}`
- PR-AUC: `{test_metrics['pr_auc']:.6f}`
- Brier score: `{test_metrics['brier_score']:.6f}`
- ECE: `{test_metrics['expected_calibration_error']:.6f}`

## Governance

This is not a future-exploitation prediction model.
It does not override SSVC, affectedness, human review,
or remediation authority. Production readiness remains
blocked.
""",
        encoding="utf-8",
    )

    for artifact in [
        model_path,
        candidates_path,
        predictions_path,
        importance_path,
        report_path,
        model_card_path,
    ]:
        write_sidecar(artifact)

    return report

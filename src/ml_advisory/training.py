from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .dataset import DEFAULT_TRAINING_POLICY, load_training_policy, rows_for_partition, sha256_value, stable_id


def _frame(rows: Sequence[Mapping[str, Any]]) -> tuple[pd.DataFrame, np.ndarray]:
    return pd.DataFrame([dict(r["features"]) for r in rows]), np.asarray([r["label"] for r in rows])


def _feature_types(frame: pd.DataFrame) -> tuple[list[str], list[str]]:
    numeric, categorical = [], []
    for column in frame.columns:
        if pd.api.types.is_bool_dtype(frame[column]) or pd.api.types.is_numeric_dtype(frame[column]):
            numeric.append(column)
        else:
            categorical.append(column)
    return sorted(numeric), sorted(categorical)


def _multiclass_brier(y_true: np.ndarray, probabilities: np.ndarray, classes: Sequence[str]) -> float:
    lookup = {label: i for i, label in enumerate(classes)}
    actual = np.zeros_like(probabilities)
    for row, label in enumerate(y_true):
        actual[row, lookup[str(label)]] = 1.0
    return float(np.mean(np.sum((probabilities - actual) ** 2, axis=1)))


def _ece(y_true: np.ndarray, probabilities: np.ndarray, classes: Sequence[str], bins: int = 10) -> float:
    predictions = np.argmax(probabilities, axis=1)
    confidence = np.max(probabilities, axis=1)
    lookup = {label: i for i, label in enumerate(classes)}
    correct = np.asarray([predictions[i] == lookup[str(y_true[i])] for i in range(len(y_true))], dtype=float)
    total = len(y_true)
    error = 0.0
    for lower in np.linspace(0.0, 0.9, bins):
        upper = lower + 0.1
        mask = (confidence >= lower) & (confidence < upper if upper < 1.0 else confidence <= upper)
        if mask.any():
            error += abs(float(correct[mask].mean()) - float(confidence[mask].mean())) * float(mask.sum()) / total
    return float(error)


def _evaluate(model: Any, frame: pd.DataFrame, labels: np.ndarray, threshold: float) -> dict[str, Any]:
    probabilities = model.predict_proba(frame)
    classes = list(model.classes_)
    predictions = np.asarray([classes[i] for i in np.argmax(probabilities, axis=1)])
    confidence = np.max(probabilities, axis=1)
    abstained = confidence < threshold
    return {
        "row_count": int(len(labels)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "macro_f1": float(f1_score(labels, predictions, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(labels, predictions, average="weighted", zero_division=0)),
        "log_loss": float(log_loss(labels, probabilities, labels=classes)),
        "multiclass_brier": _multiclass_brier(labels, probabilities, classes),
        "expected_calibration_error": _ece(labels, probabilities, classes),
        "abstention_rate": float(abstained.mean()),
        "coverage_rate": float(1.0 - abstained.mean()),
        "mean_confidence": float(confidence.mean()),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=classes).tolist(),
        "classes": classes,
        "classification_report": classification_report(labels, predictions, labels=classes, output_dict=True, zero_division=0),
    }


def _slice_metrics(model: Any, rows: Sequence[Mapping[str, Any]], field: str, threshold: float) -> dict[str, Any]:
    values = sorted({str(r["features"].get(field)) for r in rows})
    result = {}
    for value in values:
        subset = [r for r in rows if str(r["features"].get(field)) == value]
        if len(subset) < 8:
            continue
        frame, labels = _frame(subset)
        metrics = _evaluate(model, frame, labels, threshold)
        result[value] = {k: metrics[k] for k in ["row_count", "balanced_accuracy", "macro_f1", "abstention_rate", "mean_confidence"]}
    return result


def train_and_evaluate(
    dataset: Mapping[str, Any],
    split: Mapping[str, Any],
    *,
    output_dir: Path | str,
    training_policy_path: Path | str = DEFAULT_TRAINING_POLICY,
) -> dict[str, Any]:
    policy = load_training_policy(training_policy_path)
    config = policy["training"]
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    train_rows = rows_for_partition(dataset, split, "train")
    validation_rows = rows_for_partition(dataset, split, "validation")
    test_rows = rows_for_partition(dataset, split, "test")
    train_frame, train_labels = _frame(train_rows)
    validation_frame, validation_labels = _frame(validation_rows)
    test_frame, test_labels = _frame(test_rows)
    numeric, categorical = _feature_types(train_frame)

    numeric_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median", add_indicator=True)),
        ("scaler", StandardScaler()),
    ])
    categorical_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore")),
    ])
    preprocessor = ColumnTransformer([
        ("numeric", numeric_pipe, numeric),
        ("categorical", categorical_pipe, categorical),
    ])
    forest = RandomForestClassifier(
        n_estimators=int(config["n_estimators"]),
        min_samples_leaf=int(config["min_samples_leaf"]),
        class_weight=str(config["class_weight"]),
        random_state=int(config["random_seed"]),
        n_jobs=-1,
    )
    base = Pipeline([("preprocessor", preprocessor), ("classifier", forest)])
    base.fit(train_frame, train_labels)
    calibration_cv = 3 if min(Counter(train_labels).values()) >= 3 else 2
    model = CalibratedClassifierCV(base, method=str(config["probability_calibration"]), cv=calibration_cv)
    model.fit(train_frame, train_labels)

    threshold = float(config["abstention_threshold"])
    metrics = {
        "validation": _evaluate(model, validation_frame, validation_labels, threshold),
        "test": _evaluate(model, test_frame, test_labels, threshold),
    }

    # Model-agnostic global XAI on the held-out test set.
    importance = permutation_importance(
        model,
        test_frame,
        test_labels,
        scoring="f1_macro",
        n_repeats=8,
        random_state=int(config["random_seed"]),
        n_jobs=-1,
    )
    xai = sorted(
        [
            {"feature": column, "importance_mean": float(importance.importances_mean[i]), "importance_std": float(importance.importances_std[i])}
            for i, column in enumerate(test_frame.columns)
        ],
        key=lambda item: (-item["importance_mean"], item["feature"]),
    )

    fairness = {
        field: _slice_metrics(model, test_rows, field, threshold)
        for field in policy["evaluation"]["fairness_slices"]
    }
    gates = policy["evaluation"]["development_gates"]
    test = metrics["test"]
    gate_checks = {
        "balanced_accuracy": test["balanced_accuracy"] >= float(gates["minimum_balanced_accuracy"]),
        "macro_f1": test["macro_f1"] >= float(gates["minimum_macro_f1"]),
        "calibration": test["expected_calibration_error"] <= float(gates["maximum_expected_calibration_error"]),
        "abstention": test["abstention_rate"] <= float(gates["maximum_abstention_rate"]),
    }

    # Training distribution profile supports deterministic OOD checks.
    profile = {"numeric": {}, "categorical": {}}
    for column in numeric:
        values = pd.to_numeric(train_frame[column], errors="coerce").dropna()
        profile["numeric"][column] = {
            "minimum": float(values.min()) if len(values) else None,
            "maximum": float(values.max()) if len(values) else None,
            "median": float(values.median()) if len(values) else None,
        }
    for column in categorical:
        profile["categorical"][column] = sorted(str(v) for v in train_frame[column].dropna().unique())

    model_path = output / "aegis_ml_advisory_model.joblib"
    joblib.dump(model, model_path)
    model_sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
    report = {
        "schema_version": "1.0.0",
        "report_id": stable_id("AEG-MLT", {"dataset": dataset["dataset_id"], "split": split["split_id"], "model_sha": model_sha}),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "authority": {"role": "INDEPENDENT_ADVISORY_ONLY", "may_override_ssvc": False},
        "dataset": {
            "dataset_id": dataset["dataset_id"],
            "split_id": split["split_id"],
            "production_dataset_eligible": dataset["release"]["production_dataset_eligible"],
            "class_distribution": dataset["class_distribution"],
        },
        "model": {
            "algorithm": config["algorithm"],
            "model_path": str(model_path),
            "model_sha256": model_sha,
            "classes": list(model.classes_),
            "numeric_features": numeric,
            "categorical_features": categorical,
            "abstention_threshold": threshold,
            "training_profile": profile,
        },
        "metrics": metrics,
        "xai": {"method": "held_out_permutation_importance", "feature_importance": xai},
        "fairness_slices": fairness,
        "quality_gate": {
            "checks": gate_checks,
            "stage_gate": "PASS" if all(gate_checks.values()) else "FAIL",
            "production_readiness": "BLOCKED",
            "reason_codes": ["SYNTHETIC_DEVELOPMENT_EVIDENCE_ONLY", "INDEPENDENT_ADVISORY_NO_POLICY_OVERRIDE"],
            "next_stage": "MILESTONE_12F_4_INFERENCE_OOD_AND_AGREEMENT",
        },
    }
    report_path = output / "milestone12f_training_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report

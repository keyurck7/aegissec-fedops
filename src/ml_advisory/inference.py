from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import joblib
import pandas as pd

from .dataset import DEFAULT_TRAINING_POLICY, load_training_policy, stable_id


def predict_advisory(
    feature_view: Mapping[str, Any],
    training_report: Mapping[str, Any],
    *,
    training_policy_path: Path | str = DEFAULT_TRAINING_POLICY,
) -> dict[str, Any]:
    policy = load_training_policy(training_policy_path)
    model_info = training_report["model"]
    model_path = Path(model_info["model_path"])
    observed_sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
    if observed_sha != model_info["model_sha256"]:
        raise RuntimeError("Model artifact integrity verification failed.")
    model = joblib.load(model_path)
    features = dict(feature_view["model_features"])
    frame = pd.DataFrame([features])
    probabilities = model.predict_proba(frame)[0]
    classes = list(model.classes_)
    index = int(probabilities.argmax())
    prediction = classes[index]
    confidence = float(probabilities[index])

    profile = model_info["training_profile"]
    numeric_total = numeric_ood = 0
    for name, limits in profile["numeric"].items():
        value = features.get(name)
        if value is None or limits["minimum"] is None:
            continue
        numeric_total += 1
        numeric_ood += int(float(value) < float(limits["minimum"]) or float(value) > float(limits["maximum"]))
    categorical_total = categorical_ood = 0
    for name, allowed in profile["categorical"].items():
        value = features.get(name)
        if value is None:
            continue
        categorical_total += 1
        categorical_ood += int(str(value) not in set(allowed))
    numeric_rate = numeric_ood / numeric_total if numeric_total else 0.0
    category_rate = categorical_ood / categorical_total if categorical_total else 0.0
    config = policy["training"]
    ood = numeric_rate > float(config["ood_numeric_out_of_range_rate_threshold"]) or category_rate > float(config["ood_unknown_category_rate_threshold"])
    threshold = float(model_info["abstention_threshold"])
    abstained = ood or confidence < threshold
    result = {
        "schema_version": "1.0.0",
        "advisory_id": stable_id("AEG-MLA", {"feature_view_id": feature_view["feature_view_id"], "model_sha": observed_sha}),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "authority": {
            "role": "INDEPENDENT_ADVISORY_ONLY",
            "may_override_ssvc": False,
            "may_authorize_final_disposition": False,
            "agreement_gate_required": True,
        },
        "target": dict(feature_view["target"]),
        "model": {"report_id": training_report["report_id"], "model_sha256": observed_sha},
        "prediction": {
            "predicted_class": None if abstained else prediction,
            "candidate_class": prediction,
            "confidence": confidence,
            "class_probabilities": {classes[i]: float(probabilities[i]) for i in range(len(classes))},
            "abstained": abstained,
        },
        "ood": {
            "status": "OUT_OF_DISTRIBUTION" if ood else "IN_DISTRIBUTION",
            "numeric_out_of_range_rate": numeric_rate,
            "unknown_category_rate": category_rate,
        },
        "release": {
            "stage_gate": "PASS",
            "production_readiness": "BLOCKED",
            "reason_codes": (["ML_ADVISORY_ABSTAINED"] if abstained else ["ML_ADVISORY_ISSUED_DEVELOPMENT_ONLY"]),
            "next_stage": "MILESTONE_12G_AGREEMENT_AND_ESCALATION_GATE",
        },
    }
    return result

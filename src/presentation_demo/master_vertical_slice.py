"""Read-only master presentation adapter.

This module joins the existing governed AegisSec-FedOps
artifacts without recreating affectedness or SSVC decisions.

Authority boundaries:

- Package/version affectedness is deterministic evidence.
- Confirmed exploitation comes from trusted intelligence.
- FIRST EPSS is the current near-term forecast lane.
- The custom model classifies current KEV membership.
- SSVC remains the operational decision authority.
- Final disposition requires human authorization.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    balanced_accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)


ROOT = Path(__file__).resolve().parents[2]

PREFLIGHT_PATH = (
    ROOT
    / "reports"
    / "presentation"
    / "master_vertical_slice_preflight.json"
)


class MasterVerticalSliceError(RuntimeError):
    """Raised when master presentation evidence is invalid."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def verify_sidecar(path: Path) -> None:
    sidecar = Path(f"{path}.sha256")

    if not sidecar.is_file():
        raise MasterVerticalSliceError(
            f"Missing integrity sidecar: {sidecar}"
        )

    parts = sidecar.read_text(
        encoding="utf-8"
    ).strip().split()

    if not parts:
        raise MasterVerticalSliceError(
            f"Empty integrity sidecar: {sidecar}"
        )

    expected = parts[0].casefold()
    observed = sha256_file(path).casefold()

    if expected != observed:
        raise MasterVerticalSliceError(
            f"Integrity verification failed: {path}"
        )


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise MasterVerticalSliceError(
            f"Unable to read JSON artifact {path}: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise MasterVerticalSliceError(
            f"Expected a JSON object: {path}"
        )

    return value


def resolve_manifest_path(
    relative_path: str,
) -> Path:
    path = (
        ROOT
        / relative_path
    ).resolve()

    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise MasterVerticalSliceError(
            "Manifest path escapes the repository."
        ) from exc

    return path


def verify_manifest_artifact(
    relative_path: str,
    expected_sha256: str,
) -> Path:
    path = resolve_manifest_path(
        relative_path
    )

    if not path.is_file():
        raise MasterVerticalSliceError(
            f"Manifest artifact is missing: {path}"
        )

    observed = sha256_file(path)

    if (
        observed.casefold()
        != expected_sha256.casefold()
    ):
        raise MasterVerticalSliceError(
            f"Manifest SHA-256 mismatch: {path}"
        )

    return path


def metrics_at_threshold(
    truth: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, float | int]:
    predictions = (
        probabilities >= threshold
    ).astype(int)

    return {
        "threshold": float(threshold),
        "predicted_positive": int(
            predictions.sum()
        ),
        "precision": float(
            precision_score(
                truth,
                predictions,
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                truth,
                predictions,
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                truth,
                predictions,
                zero_division=0,
            )
        ),
        "balanced_accuracy": float(
            balanced_accuracy_score(
                truth,
                predictions,
            )
        ),
    }


def threshold_frontier(
    predictions: pd.DataFrame,
    current_threshold: float,
) -> pd.DataFrame:
    required = {
        "is_kev",
        "predicted_probability",
    }

    if not required.issubset(
        predictions.columns
    ):
        missing = sorted(
            required
            - set(predictions.columns)
        )

        raise MasterVerticalSliceError(
            "Prediction artifact is missing "
            f"threshold fields: {missing}"
        )

    truth = predictions[
        "is_kev"
    ].to_numpy(dtype=int)

    probabilities = predictions[
        "predicted_probability"
    ].to_numpy(dtype=float)

    quantiles = np.linspace(
        0.80,
        0.9995,
        140,
    )

    thresholds = set(
        np.quantile(
            probabilities,
            quantiles,
        ).tolist()
    )

    thresholds.update(
        {
            0.50,
            float(current_threshold),
            0.90,
            0.95,
            0.975,
            0.99,
            0.995,
        }
    )

    rows = [
        metrics_at_threshold(
            truth,
            probabilities,
            threshold,
        )
        for threshold in sorted(
            thresholds
        )
        if 0.0 <= threshold <= 1.0
    ]

    return pd.DataFrame(
        rows
    ).sort_values(
        "threshold"
    ).reset_index(
        drop=True
    )


def choose_operating_points(
    frontier: pd.DataFrame,
    current_threshold: float,
) -> pd.DataFrame:
    if frontier.empty:
        raise MasterVerticalSliceError(
            "Threshold frontier is empty."
        )

    rows: list[dict[str, Any]] = []

    current_index = (
        frontier["threshold"]
        - current_threshold
    ).abs().idxmin()

    current = frontier.loc[
        current_index
    ]

    rows.append(
        {
            "policy":
                "CURRENT_HIGH_RECALL",
            **current.to_dict(),
            "interpretation": (
                "Current development operating point. "
                "Higher recall with substantial "
                "human-review workload."
            ),
        }
    )

    best_f1 = frontier.sort_values(
        [
            "f1",
            "balanced_accuracy",
            "recall",
        ],
        ascending=[
            False,
            False,
            False,
        ],
    ).iloc[0]

    rows.append(
        {
            "policy":
                "BEST_F1_DEVELOPMENT",
            **best_f1.to_dict(),
            "interpretation": (
                "Best observed F1 on the existing "
                "test predictions. Development-only, "
                "not deployment authorization."
            ),
        }
    )

    recall_candidates = frontier[
        frontier["recall"] >= 0.70
    ]

    if not recall_candidates.empty:
        selected = (
            recall_candidates
            .sort_values(
                [
                    "precision",
                    "threshold",
                ],
                ascending=[
                    False,
                    False,
                ],
            )
            .iloc[0]
        )

        rows.append(
            {
                "policy":
                    "MAX_PRECISION_WITH_RECALL_70",
                **selected.to_dict(),
                "interpretation": (
                    "Highest observed precision while "
                    "retaining at least 70% recall."
                ),
            }
        )

    precision_candidates = frontier[
        frontier["precision"] >= 0.25
    ]

    if not precision_candidates.empty:
        selected = (
            precision_candidates
            .sort_values(
                [
                    "recall",
                    "precision",
                ],
                ascending=[
                    False,
                    False,
                ],
            )
            .iloc[0]
        )

        rows.append(
            {
                "policy":
                    "MAX_RECALL_WITH_PRECISION_25",
                **selected.to_dict(),
                "interpretation": (
                    "Highest observed recall while "
                    "maintaining at least 25% precision."
                ),
            }
        )

    return (
        pd.DataFrame(rows)
        .drop_duplicates(
            subset=["policy"]
        )
        .reset_index(drop=True)
    )


def claim_boundary() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "question":
                    "Is the component present?",
                "mechanism":
                    "Extraction and identity confidence",
                "authority":
                    "EVIDENCE",
            },
            {
                "question":
                    "Is this exact version affected?",
                "mechanism":
                    "Deterministic version-range matching",
                "authority":
                    "AFFECTEDNESS_ENGINE",
            },
            {
                "question":
                    "Is exploitation already confirmed?",
                "mechanism":
                    "CISA KEV and trusted intelligence",
                "authority":
                    "CONFIRMED_THREAT_EVIDENCE",
            },
            {
                "question":
                    "Could exploitation occur soon?",
                "mechanism":
                    "FIRST EPSS 30-day forecast",
                "authority":
                    "ADVISORY_FORECAST",
            },
            {
                "question":
                    "What does the current custom model predict?",
                "mechanism":
                    "Current CISA KEV membership",
                "authority":
                    "ADVISORY_CLASSIFIER",
            },
            {
                "question":
                    "What operational action is required?",
                "mechanism":
                    "Governed SSVC plus human review",
                "authority":
                    "POLICY_AND_HUMAN",
            },
        ]
    )


def agreement_matrix() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "affectedness":
                    "NOT_AFFECTED",
                "confirmed_exploitation":
                    "ANY",
                "forecast":
                    "ANY",
                "policy_behavior":
                    "NO_ASSET_REMEDIATION",
                "human_review":
                    "ONLY_FOR_IDENTITY_OR_EVIDENCE_CONFLICT",
                "reason":
                    "A global CVE does not affect this exact asset version.",
            },
            {
                "affectedness":
                    "AFFECTED",
                "confirmed_exploitation":
                    "ACTIVE_OR_KEV",
                "forecast":
                    "ANY",
                "policy_behavior":
                    "USE_ACTIVE_EXPLOITATION_BRANCH",
                "human_review":
                    "REQUIRED_BY_POLICY",
                "reason":
                    "Confirmed exploitation supersedes probabilistic forecast.",
            },
            {
                "affectedness":
                    "AFFECTED",
                "confirmed_exploitation":
                    "NOT_OBSERVED",
                "forecast":
                    "HIGH",
                "policy_behavior":
                    "DO_NOT_MARK_ACTIVE",
                "human_review":
                    "ESCALATE_PREDICTIVE_REVIEW",
                "reason":
                    "A high forecast raises concern but does not prove exploitation.",
            },
            {
                "affectedness":
                    "UNKNOWN",
                "confirmed_exploitation":
                    "ANY",
                "forecast":
                    "ANY",
                "policy_behavior":
                    "FAIL_CLOSED",
                "human_review":
                    "MANDATORY",
                "reason":
                    "Unknown identity or version evidence blocks automation.",
            },
            {
                "affectedness":
                    "AFFECTED",
                "confirmed_exploitation":
                    "NOT_OBSERVED",
                "forecast":
                    "LOW",
                "policy_behavior":
                    "CONTEXT_DRIVEN",
                "human_review":
                    "MISSION_AND_HUMAN_IMPACT_DEPENDENT",
                "reason":
                    "Low forecast does not remove mission or safety risk.",
            },
        ]
    )


def screenshot_policy() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "stage":
                    "SCREENSHOT_VALIDATION",
                "control":
                    "FILE_SAFETY_AND_AUTHORIZATION",
                "behavior":
                    "Reject unsafe or unauthorized uploads.",
            },
            {
                "stage":
                    "VISUAL_EXTRACTION",
                "control":
                    "PACKAGE_VERSION_CONFIDENCE",
                "behavior":
                    "Produce candidates, never silent certainty.",
            },
            {
                "stage":
                    "IDENTITY_CONFIRMATION",
                "control":
                    "USER_CONFIRMATION_GATE",
                "behavior":
                    "Require confirmation for ambiguous identity or version.",
            },
            {
                "stage":
                    "NORMALIZATION",
                "control":
                    "PURL_CPE_ALIAS_RESOLUTION",
                "behavior":
                    "Unresolved identity remains UNKNOWN.",
            },
            {
                "stage":
                    "AFFECTEDNESS",
                "control":
                    "EXACT_VERSION_RANGE_MATCH",
                "behavior":
                    "Do not ask ML to guess deterministic affectedness.",
            },
            {
                "stage":
                    "FORECAST",
                "control":
                    "FIRST_EPSS_30_DAY_PROBABILITY",
                "behavior":
                    "Expose forecast as advisory threat evidence.",
            },
            {
                "stage":
                    "ACTION",
                "control":
                    "SSVC_AND_HUMAN_REVIEW",
                "behavior":
                    "No automated final disposition.",
            },
        ]
    )


def load_master_vertical_slice() -> dict[str, Any]:
    if not PREFLIGHT_PATH.is_file():
        raise MasterVerticalSliceError(
            "Master vertical-slice preflight is missing."
        )

    verify_sidecar(
        PREFLIGHT_PATH
    )

    preflight = load_json_object(
        PREFLIGHT_PATH
    )

    sources = preflight[
        "source_artifacts"
    ]

    affectedness_meta = sources[
        "affectedness"
    ]

    feature_meta = sources[
        "decision_feature_envelope"
    ]

    ssvc_meta = sources[
        "ssvc"
    ]

    model_meta = preflight[
        "model_contract"
    ]

    affectedness_path = (
        verify_manifest_artifact(
            affectedness_meta["path"],
            affectedness_meta["sha256"],
        )
    )

    feature_path = (
        verify_manifest_artifact(
            feature_meta["path"],
            feature_meta["sha256"],
        )
    )

    ssvc_path = (
        verify_manifest_artifact(
            ssvc_meta["path"],
            ssvc_meta["sha256"],
        )
    )

    model_report_path = (
        verify_manifest_artifact(
            model_meta["report_path"],
            model_meta["report_sha256"],
        )
    )

    prediction_path = (
        verify_manifest_artifact(
            model_meta["prediction_path"],
            model_meta["prediction_sha256"],
        )
    )

    affectedness = load_json_object(
        affectedness_path
    )

    feature_envelope = load_json_object(
        feature_path
    )

    ssvc = load_json_object(
        ssvc_path
    )

    model_report = load_json_object(
        model_report_path
    )

    predictions = pd.read_csv(
        prediction_path
    )

    official = ssvc.get(
        "official_ssvc_decision",
        {},
    )

    if not isinstance(
        official,
        dict,
    ):
        raise MasterVerticalSliceError(
            "Official SSVC decision is missing."
        )

    outcome = official.get(
        "outcome",
        {},
    )

    if not isinstance(
        outcome,
        dict,
    ):
        outcome = {}

    mapping = ssvc.get(
        "mapping",
        {},
    )

    decision_points = mapping.get(
        "decision_points",
        {},
    )

    if not isinstance(
        decision_points,
        dict,
    ):
        raise MasterVerticalSliceError(
            "SSVC decision points are missing."
        )

    point_rows = []

    for point_name, point in (
        decision_points.items()
    ):
        if not isinstance(
            point,
            dict,
        ):
            continue

        reason_codes = point.get(
            "reason_codes",
            [],
        )

        if not isinstance(
            reason_codes,
            list,
        ):
            reason_codes = []

        point_rows.append(
            {
                "decision_point":
                    point_name,
                "status":
                    point.get("status"),
                "key":
                    point.get("key"),
                "name":
                    point.get("name"),
                "mapping_rule_id":
                    point.get(
                        "mapping_rule_id"
                    ),
                "reason_codes":
                    ", ".join(
                        str(value)
                        for value in reason_codes
                    ),
            }
        )

    quality_gates = pd.DataFrame(
        ssvc.get(
            "quality_gates",
            [],
        )
    )

    provenance = pd.DataFrame(
        ssvc.get(
            "provenance",
            [],
        )
    )

    governance = ssvc.get(
        "governance",
        {},
    )

    separation = ssvc.get(
        "separation",
        {},
    )

    if (
        governance.get(
            "stage_gate"
        )
        != "PASS"
    ):
        raise MasterVerticalSliceError(
            "The SSVC stage gate is not PASS."
        )

    if (
        governance.get(
            "production_readiness"
        )
        != "BLOCKED"
    ):
        raise MasterVerticalSliceError(
            "Production readiness must remain BLOCKED."
        )

    if (
        separation.get(
            "final_disposition_status"
        )
        != "NOT_AUTHORIZED"
    ):
        raise MasterVerticalSliceError(
            "Final disposition authority is not separated."
        )

    model_governance = model_report.get(
        "governance",
        {},
    )

    if (
        model_governance.get(
            "model_authority"
        )
        != "ADVISORY_ONLY"
    ):
        raise MasterVerticalSliceError(
            "Unexpected model authority."
        )

    if (
        model_governance.get(
            "production_readiness"
        )
        != "BLOCKED"
    ):
        raise MasterVerticalSliceError(
            "The model must remain production-blocked."
        )

    current_threshold = float(
        model_report[
            "test_metrics"
        ][
            "threshold"
        ]
    )

    frontier = threshold_frontier(
        predictions,
        current_threshold,
    )

    operating_points = (
        choose_operating_points(
            frontier,
            current_threshold,
        )
    )

    summary = {
        "decision_id":
            ssvc.get("decision_id"),
        "cve_id":
            ssvc.get(
                "target",
                {},
            ).get("cve_id"),
        "vector":
            official.get("vector"),
        "matched_row":
            official.get("matched_row"),
        "outcome_key":
            outcome.get("key"),
        "outcome_name":
            outcome.get("name"),
        "outcome_rank":
            outcome.get("rank"),
        "stage_gate":
            governance.get(
                "stage_gate"
            ),
        "human_review_required":
            governance.get(
                "human_review_required"
            ),
        "production_readiness":
            governance.get(
                "production_readiness"
            ),
        "final_disposition_status":
            separation.get(
                "final_disposition_status"
            ),
        "model_winner":
            model_report[
                "winner"
            ][
                "candidate_name"
            ],
        "model_label":
            model_governance.get(
                "label_definition"
            ),
        "model_authority":
            model_governance.get(
                "model_authority"
            ),
        "future_custom_forecast":
            "NOT_YET_AUTHORIZED",
        "near_term_forecast_lane":
            "FIRST_EPSS_30_DAY_ADVISORY",
    }

    assert summary["vector"] == "A/O/Y/M"
    assert summary["matched_row"] == 69
    assert (
        summary["outcome_name"]
        == "OUT_OF_CYCLE"
    )

    return {
        "preflight": preflight,
        "affectedness":
            affectedness,
        "feature_envelope":
            feature_envelope,
        "ssvc":
            ssvc,
        "model_report":
            model_report,
        "predictions":
            predictions,
        "decision_points":
            pd.DataFrame(
                point_rows
            ),
        "quality_gates":
            quality_gates,
        "provenance":
            provenance,
        "threshold_frontier":
            frontier,
        "operating_points":
            operating_points,
        "claim_boundary":
            claim_boundary(),
        "agreement_matrix":
            agreement_matrix(),
        "screenshot_policy":
            screenshot_policy(),
        "summary":
            summary,
        "paths": {
            "affectedness":
                str(affectedness_path),
            "decision_features":
                str(feature_path),
            "ssvc":
                str(ssvc_path),
            "model_report":
                str(model_report_path),
            "predictions":
                str(prediction_path),
        },
    }

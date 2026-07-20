from __future__ import annotations

from typing import Any, Mapping

SSVC_RANK = {"TRACK": 0, "TRACK_STAR": 1, "ATTEND": 2, "ACT": 3, "OUT_OF_CYCLE": 4}
ML_RANK = {"MONITOR": 0, "SCHEDULED": 1, "PRIORITY": 2, "IMMEDIATE": 3}


def evaluate_agreement(ssvc_decision: Mapping[str, Any], ml_advisory: Mapping[str, Any]) -> dict[str, Any]:
    prediction = ml_advisory["prediction"]
    if prediction["abstained"]:
        return {
            "status": "ML_ABSTAINED",
            "escalation_required": True,
            "human_review_required": True,
            "authoritative_decision": "SSVC_REMAINS_AUTHORITATIVE",
            "reason_codes": ["ML_ADVISORY_ABSTAINED", "NO_AUTOMATED_ARBITRATION"],
        }
    outcome = ssvc_decision.get("outcome", {})
    ssvc_name = str(outcome.get("name") or outcome.get("key") or "UNKNOWN").upper().replace("*", "_STAR")
    ml_name = str(prediction["predicted_class"])
    if ssvc_name not in SSVC_RANK:
        return {
            "status": "UNMAPPABLE_SSVC",
            "escalation_required": True,
            "human_review_required": True,
            "authoritative_decision": "SSVC_REMAINS_AUTHORITATIVE",
            "reason_codes": ["SSVC_OUTCOME_UNMAPPABLE", "NO_AUTOMATED_ARBITRATION"],
        }
    delta = ML_RANK[ml_name] - min(SSVC_RANK[ssvc_name], 3)
    status = "AGREE" if abs(delta) <= 0 else ("ML_MORE_URGENT" if delta > 0 else "ML_LESS_URGENT")
    return {
        "status": status,
        "rank_delta": delta,
        "escalation_required": abs(delta) >= 2,
        "human_review_required": delta != 0,
        "authoritative_decision": "SSVC_REMAINS_AUTHORITATIVE",
        "reason_codes": ["INDEPENDENT_ADVISORY_COMPARISON", "ML_CANNOT_OVERRIDE_SSVC"],
    }

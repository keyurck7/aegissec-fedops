from src.ml_advisory.agreement import evaluate_agreement


def test_ml_cannot_override_ssvc_even_when_disagreeing():
    ssvc = {"outcome": {"name": "ATTEND"}}
    advisory = {"prediction": {"abstained": False, "predicted_class": "IMMEDIATE"}}
    result = evaluate_agreement(ssvc, advisory)
    assert result["status"] == "ML_MORE_URGENT"
    assert result["authoritative_decision"] == "SSVC_REMAINS_AUTHORITATIVE"
    assert result["human_review_required"] is True


def test_abstention_forces_human_review():
    result = evaluate_agreement({"outcome": {"name": "ACT"}}, {"prediction": {"abstained": True}})
    assert result["status"] == "ML_ABSTAINED"
    assert result["escalation_required"] is True

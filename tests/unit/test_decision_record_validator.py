from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.domain.decision_hashing import (
    finalize_decision_record_hash,
)
from src.validation.decision_record_validator import (
    DecisionRecordValidator,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SAMPLE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record.json"
)


@pytest.fixture
def validator() -> DecisionRecordValidator:
    return DecisionRecordValidator()


@pytest.fixture
def valid_record() -> dict:
    with SAMPLE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def rehash(record: dict) -> dict:
    return finalize_decision_record_hash(record)


def test_valid_decision_record_is_accepted_with_warnings(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    result = validator.validate(valid_record)

    assert result.valid is True
    assert result.schema_valid is True
    assert result.business_rules_valid is True
    assert result.status == "accepted_with_warnings"

    warning_codes = {warning.code for warning in result.warnings}

    assert "ML_ADVISORY_NOT_RUN" in warning_codes
    assert "HUMAN_DISPOSITION_PENDING" in warning_codes
    assert "CONTROLLED_DECISION_FIXTURE" in warning_codes


def test_unknown_property_is_rejected(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["secret_risk_score"] = 99.9

    result = validator.validate(record)

    assert result.valid is False
    assert result.schema_valid is False


def test_input_path_cannot_escape_project_root(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["input_records"]["asset_context"][
        "relative_path"
    ] = "../outside.json"

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "INPUT_PATH_ESCAPE" in error_codes


def test_input_hash_mismatch_is_rejected(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["input_records"]["asset_context"]["sha256"] = (
        "0" * 64
    )

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "INPUT_RECORD_HASH_MISMATCH" in error_codes


def test_input_record_id_must_match_file(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["input_records"]["asset_context"]["record_id"] = (
        "AEG-AST-WRONG-001"
    )

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "INPUT_RECORD_ID_MISMATCH" in error_codes


def test_final_priority_cannot_fall_below_policy_floor(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["arbitration"]["final_system_priority"] = "MEDIUM"

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "POLICY_FLOOR_VIOLATION" in error_codes


def test_unknown_affectedness_requires_human_review(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["affectedness"]["status"] = "unknown"
    record["arbitration"]["human_review_required"] = False

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False

    assert (
        "UNCERTAIN_AFFECTEDNESS_REQUIRES_REVIEW"
        in error_codes
    )


def test_not_affected_requires_affirmative_evidence(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["affectedness"]["status"] = "not_affected"
    record["affectedness"]["confidence"] = 0.6
    record["affectedness"]["supporting_evidence_ids"] = []

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False

    assert (
        "NEGATIVE_AFFECTEDNESS_WITHOUT_EVIDENCE"
        in error_codes
    )

    assert (
        "NEGATIVE_AFFECTEDNESS_LOW_CONFIDENCE"
        in error_codes
    )


def test_completed_ml_requires_model_metadata(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["ml_advisory"]["status"] = "completed"
    record["ml_advisory"]["probabilities"] = {
        "CRITICAL": 1.0
    }

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "COMPLETED_ML_FIELD_MISSING" in error_codes


def test_ml_probabilities_must_be_normalized(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["ml_advisory"] = {
        "status": "completed",
        "model_id": "AEGIS-RF-001",
        "model_version": "0.1.0",
        "predicted_priority": "CRITICAL",
        "confidence": 0.8,
        "calibrated": True,
        "probabilities": {
            "CRITICAL": 0.8,
            "HIGH": 0.8
        },
        "top_features": [],
        "advisory_only": True,
        "abstention_reason": None,
        "evaluated_at": "2026-07-13T17:20:00Z"
    }

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "ML_PROBABILITIES_NOT_NORMALIZED" in error_codes


def test_kev_affected_vulnerability_requires_act(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["policy_decision"]["action"] = "TRACK"

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "KEV_AFFECTED_REQUIRES_ACT" in error_codes


def test_human_override_requires_governance_fields(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["human_disposition"]["override"] = True

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False

    assert (
        "OVERRIDE_GOVERNANCE_FIELD_MISSING"
        in error_codes
    )


def test_non_overridable_floor_cannot_be_lowered(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["human_disposition"] = {
        "status": "modified",
        "analyst": {
            "name": "Test Analyst",
            "role": "Security Analyst",
            "organization": "AegisSec Test Environment",
            "identity_reference": "ANALYST-001"
        },
        "final_priority": "MEDIUM",
        "final_action": "ATTEND",
        "justification": "Test attempt to lower the priority floor.",
        "override": True,
        "override_reason": "Controlled unit-test override.",
        "approved_by": {
            "name": "Test Risk Owner",
            "role": "Cyber Risk Owner",
            "organization": "AegisSec Test Environment",
            "identity_reference": "RISK-OWNER-001"
        },
        "decided_at": "2026-07-13T17:30:00Z",
        "expires_at": "2026-07-14T17:30:00Z",
        "ticket_reference": "TEST-001"
    }

    record = rehash(record)
    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False

    assert (
        "NON_OVERRIDABLE_POLICY_FLOOR_VIOLATION"
        in error_codes
    )


def test_record_hash_detects_tampering(
    validator: DecisionRecordValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["arbitration"]["uncertainty_level"] = "low"

    result = validator.validate(record)

    error_codes = {error.code for error in result.errors}

    assert result.valid is False
    assert "DECISION_RECORD_HASH_MISMATCH" in error_codes

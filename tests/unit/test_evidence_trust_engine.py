from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from src.governance.evidence_trust_engine import (
    DEFAULT_POLICY_PATH,
    EvidenceTrustEngine,
    TrustPolicyError,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SAMPLE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_requirements_evidence.json"
)


ASSESSMENT_TIME = datetime(
    2026,
    7,
    13,
    18,
    45,
    tzinfo=timezone.utc,
)


@pytest.fixture
def engine() -> EvidenceTrustEngine:
    return EvidenceTrustEngine()


@pytest.fixture
def valid_record() -> dict:
    with SAMPLE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def assess(
    engine: EvidenceTrustEngine,
    record: dict,
):
    return engine.assess(
        record,
        assessed_at=ASSESSMENT_TIME,
    )


def test_policy_weights_sum_to_one(
    engine: EvidenceTrustEngine,
) -> None:
    weight_total = sum(
        configuration["weight"]
        for configuration
        in engine.dimension_policy.values()
    )

    assert weight_total == pytest.approx(1.0)


def test_valid_evidence_receives_high_trust(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    result = assess(engine, valid_record)

    assert result.aggregate_score >= 0.85
    assert result.trust_level == "high"

    assert result.action in {
        "ACCEPT",
        "ACCEPT_WITH_WARNINGS",
    }


def test_assessment_is_deterministic(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    first = assess(engine, valid_record)
    second = assess(engine, valid_record)

    assert first.to_dict() == second.to_dict()


def test_unauthorized_evidence_is_rejected(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["authorization"]["status"] = "unauthorized"

    result = assess(engine, record)

    assert result.action == "REJECT"
    assert result.trust_level == "rejected"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "UNAUTHORIZED_EVIDENCE" in gate_codes


def test_prohibited_use_is_rejected(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["authorization"]["approved_use"] = "prohibited"

    result = assess(engine, record)

    assert result.action == "REJECT"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "PROHIBITED_EVIDENCE_USE" in gate_codes


def test_failed_integrity_is_rejected(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["integrity"]["status"] = "failed"

    result = assess(engine, record)

    assert result.action == "REJECT"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "INTEGRITY_CHECK_FAILED" in gate_codes


def test_invalid_signature_is_rejected(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["integrity"]["signature_status"] = "invalid"

    result = assess(engine, record)

    assert result.action == "REJECT"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "INVALID_DIGITAL_SIGNATURE" in gate_codes


def test_failed_parser_is_rejected(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["parser"]["parse_status"] = "failed"
    record["parser"]["parser_confidence"] = 0.0

    result = assess(engine, record)

    assert result.action == "REJECT"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "PARSER_FAILED" in gate_codes


def test_open_critical_conflict_is_rejected(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["conflicts"] = [
        {
            "conflict_id": "CON-CRITICAL-001",
            "conflict_type": "hash_mismatch",
            "severity": "critical",
            "description": (
                "The observed artifact hash differs from the "
                "expected approved hash."
            ),
            "related_evidence_ids": [
                "AEG-EVD-REQ-000001"
            ],
            "resolution_status": "open"
        }
    ]

    result = assess(engine, record)

    assert result.action == "REJECT"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "OPEN_CRITICAL_CONFLICT" in gate_codes


def test_open_high_conflict_is_quarantined(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["conflicts"] = [
        {
            "conflict_id": "CON-HIGH-001",
            "conflict_type": "version_mismatch",
            "severity": "high",
            "description": (
                "Dependency file and SBOM report different versions."
            ),
            "related_evidence_ids": [
                "AEG-EVD-REQ-000001"
            ],
            "resolution_status": "open"
        }
    ]

    result = assess(engine, record)

    assert result.action == "QUARANTINE"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "OPEN_HIGH_CONFLICT" in gate_codes


def test_stale_evidence_is_quarantined(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["freshness"]["status"] = "stale"
    record["freshness"]["age_seconds"] = 172800
    record["freshness"]["maximum_age_seconds"] = 86400

    result = assess(engine, record)

    assert result.action == "QUARANTINE"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "STALE_OR_EXPIRED_EVIDENCE" in gate_codes


def test_unknown_authorization_is_quarantined(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["authorization"]["status"] = (
        "authorization_unknown"
    )

    result = assess(engine, record)

    assert result.action == "QUARANTINE"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "AUTHORIZATION_REVIEW_REQUIRED" in gate_codes


def test_dimension_floor_prevents_score_compensation(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["parser"]["parse_status"] = "partial"
    record["parser"]["parser_confidence"] = 0.20

    result = assess(engine, record)

    assert result.dimensions[
        "parser_confidence"
    ].below_floor is True

    assert result.action == "QUARANTINE"

    gate_codes = {
        gate.code
        for gate in result.gate_results
    }

    assert "TRUST_DIMENSION_BELOW_FLOOR" in gate_codes


def test_synthetic_evidence_is_explicitly_warned(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["provenance"]["origin_type"] = "synthetic"

    result = assess(engine, record)

    assert result.action == "ACCEPT_WITH_WARNINGS"

    warning_codes = {
        warning.code
        for warning in result.warnings
    }

    assert (
        "NON_OPERATIONAL_EVIDENCE_ORIGIN"
        in warning_codes
    )


def test_apply_assessment_does_not_mutate_input(
    engine: EvidenceTrustEngine,
    valid_record: dict,
) -> None:
    original = copy.deepcopy(valid_record)
    result = assess(engine, valid_record)

    updated = engine.apply_assessment_to_record(
        valid_record,
        result,
    )

    assert valid_record == original
    assert updated is not valid_record

    assert (
        updated["trust"]["overall_score"]
        == result.aggregate_score
    )

    assert (
        updated["trust"]["calculation_policy_id"]
        == "AEGIS-EVIDENCE-TRUST-POLICY:1.0.0"
    )


def test_invalid_policy_weight_total_is_rejected(
    tmp_path: Path,
) -> None:
    with DEFAULT_POLICY_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        policy = yaml.safe_load(file)

    policy["dimensions"]["authenticity"]["weight"] = 0.50

    invalid_policy_path = (
        tmp_path / "invalid_trust_policy.yaml"
    )

    with invalid_policy_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        yaml.safe_dump(
            policy,
            file,
            sort_keys=False,
        )

    with pytest.raises(TrustPolicyError):
        EvidenceTrustEngine(
            policy_path=invalid_policy_path
        )

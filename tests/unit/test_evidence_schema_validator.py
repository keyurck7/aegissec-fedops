from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.validation.evidence_schema_validator import EvidenceSchemaValidator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_requirements_evidence.json"
)


@pytest.fixture
def validator() -> EvidenceSchemaValidator:
    return EvidenceSchemaValidator()


@pytest.fixture
def valid_record() -> dict:
    with SAMPLE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_valid_evidence_record_is_accepted(
    validator: EvidenceSchemaValidator,
    valid_record: dict,
) -> None:
    result = validator.validate(valid_record)

    assert result.valid is True
    assert result.schema_valid is True
    assert result.business_rules_valid is True
    assert result.status == "accepted"
    assert result.errors == []


def test_unknown_property_is_rejected(
    validator: EvidenceSchemaValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["invented_field"] = "not allowed"

    result = validator.validate(record)

    assert result.valid is False
    assert result.schema_valid is False
    assert result.status == "rejected"


def test_unauthorized_evidence_is_rejected(
    validator: EvidenceSchemaValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["authorization"]["status"] = "unauthorized"

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "UNAUTHORIZED_EVIDENCE" in error_codes


def test_verified_integrity_requires_hash(
    validator: EvidenceSchemaValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["integrity"]["content_hash"] = None

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "VERIFIED_WITHOUT_CONTENT_HASH" in error_codes


def test_stale_evidence_cannot_be_high_trust(
    validator: EvidenceSchemaValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["freshness"]["status"] = "stale"
    record["trust"]["summary_level"] = "high"

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "STALE_EVIDENCE_HIGH_TRUST" in error_codes


def test_synthetic_evidence_generates_warning(
    validator: EvidenceSchemaValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["provenance"]["origin_type"] = "synthetic"

    result = validator.validate(record)

    assert result.valid is True
    assert result.status == "accepted_with_warnings"

    warning_codes = {warning.code for warning in result.warnings}
    assert "NON_OBSERVED_EVIDENCE" in warning_codes


def test_unresolved_high_conflict_is_rejected(
    validator: EvidenceSchemaValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["conflicts"] = [
        {
            "conflict_id": "CON-VERSION-001",
            "conflict_type": "version_mismatch",
            "severity": "high",
            "description": (
                "requirements.txt reports Django 3.2.10 while the SBOM "
                "reports Django 4.2.9."
            ),
            "related_evidence_ids": [
                "AEG-EVD-REQ-000001",
                "AEG-EVD-SBOM-000001"
            ],
            "resolution_status": "open"
        }
    ]

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "UNRESOLVED_HIGH_SEVERITY_CONFLICT" in error_codes

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.validation.asset_context_validator import AssetContextValidator


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SAMPLE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)


@pytest.fixture
def validator() -> AssetContextValidator:
    return AssetContextValidator()


@pytest.fixture
def valid_record() -> dict:
    with SAMPLE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_valid_demo_asset_is_accepted_with_warning(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    result = validator.validate(valid_record)

    assert result.valid is True
    assert result.schema_valid is True
    assert result.business_rules_valid is True
    assert result.status == "accepted_with_warnings"

    warning_codes = {warning.code for warning in result.warnings}
    assert "SYNTHETIC_DEMO_CONTEXT" in warning_codes


def test_unknown_property_is_rejected(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["invented_priority"] = "critical"

    result = validator.validate(record)

    assert result.valid is False
    assert result.schema_valid is False
    assert result.status == "rejected"


def test_sector_label_cannot_be_priority_input(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["sector_context"]["sector_label_is_decision_input"] = True

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "SCHEMA_VALIDATION_ERROR" in error_codes


def test_mission_essential_asset_cannot_be_low_criticality(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["criticality"]["level"] = "low"

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "MISSION_CRITICALITY_CONFLICT" in error_codes


def test_high_criticality_production_asset_requires_rto(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["resilience"]["recovery_time_objective_hours"] = None

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "MISSING_RESILIENCE_OBJECTIVE" in error_codes


def test_rto_cannot_exceed_maximum_tolerable_downtime(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["resilience"]["recovery_time_objective_hours"] = 12
    record["resilience"]["maximum_tolerable_downtime_hours"] = 8

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "RTO_EXCEEDS_TOLERABLE_DOWNTIME" in error_codes


def test_severe_impact_requires_evidence(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["impact_assessment"]["availability"]["evidence_ids"] = []

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "SEVERE_IMPACT_WITHOUT_EVIDENCE" in error_codes


def test_missing_health_data_category_is_rejected(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)

    record["data_profile"]["data_categories"] = [
        category
        for category in record["data_profile"]["data_categories"]
        if category != "health_data"
    ]

    result = validator.validate(record)

    assert result.valid is False

    error_codes = {error.code for error in result.errors}
    assert "HEALTH_DATA_CATEGORY_MISSING" in error_codes


def test_unknown_production_exposure_generates_warning(
    validator: AssetContextValidator,
    valid_record: dict,
) -> None:
    record = copy.deepcopy(valid_record)
    record["exposure"]["internet_accessible"] = None

    result = validator.validate(record)

    assert result.valid is True
    assert result.status == "accepted_with_warnings"

    warning_codes = {warning.code for warning in result.warnings}
    assert "PRODUCTION_EXPOSURE_UNKNOWN" in warning_codes

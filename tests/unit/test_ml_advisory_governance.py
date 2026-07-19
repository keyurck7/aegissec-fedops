from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from src.ml_advisory.governance import (
    MLAdvisoryGovernanceError,
    build_ml_feature_view,
    load_governance_policy,
    validate_label_record,
    validate_policy_contract,
    validate_training_pair,
)


ROOT = Path(__file__).resolve().parents[2]
FEATURE_PATH = (
    ROOT
    / "data"
    / "processed"
    / "decision_features"
    / "log4shell-20260718T141317Z-decision-features"
    / "aeg-dfe-aa60735b0e2c053c1b002c64.features.json"
)
SCHEMA_PATH = ROOT / "schemas" / "aegis_ml_feature_view.schema.json"


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def build(
    envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return build_ml_feature_view(
        envelope or load(FEATURE_PATH),
        generated_at="2026-07-19T23:30:00Z",
    )


def label_record(
    *,
    source_type: str = "CONTROLLED_SYNTHETIC_SCENARIO",
    synthetic: bool = True,
    label: str = "IMMEDIATE",
) -> dict[str, Any]:
    envelope = load(FEATURE_PATH)
    target = envelope["target"]
    return {
        "label": label,
        "source_type": source_type,
        "source_record_id": "AEG-LBL-DEMO-0001",
        "source_sha256": hashlib.sha256(
            b"independent-label-source"
        ).hexdigest(),
        "observed_at": "2026-07-19T23:00:00Z",
        "observation_window_days": 30,
        "target": {
            "cve_id": target["cve_id"],
            "asset_id": target["asset_id"],
            "component_purl": target["component"]["purl"],
        },
        "synthetic": synthetic,
    }


def test_policy_contract_is_internally_consistent() -> None:
    policy, digest = load_governance_policy()
    validate_policy_contract(policy)
    assert len(digest) == 64
    assert len(policy["model_features"]) == 50
    assert policy["authority"]["ml_may_override_ssvc"] is False
    assert policy["authority"]["ml_may_authorize_final_disposition"] is False


def test_live_feature_envelope_builds_strict_ml_view() -> None:
    view = build()
    assert len(view["model_features"]) == 50
    assert view["model_features"]["cvss_base_score"] == 10.0
    assert view["model_features"]["epss_probability"] == 0.99999
    assert view["model_features"]["kev_listed"] is True
    assert view["model_features"]["affectedness_status"] == "AFFECTED"
    assert view["authority"]["role"] == "INDEPENDENT_ADVISORY_ONLY"
    assert view["authority"]["ml_may_override_ssvc"] is False
    assert view["release_decision"]["stage_gate"] == "PASS"
    assert view["release_decision"]["production_readiness"] == "BLOCKED"


def test_feature_view_validates_against_schema() -> None:
    schema = load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(build())
    )
    assert errors == []


def test_ssvc_and_governance_outputs_are_isolated_not_consumed() -> None:
    view = build()
    serialized = json.dumps(
        view["model_features"],
        sort_keys=True,
    ).lower()
    for term in (
        "ssvc",
        "official_ssvc_decision",
        "matched_row",
        "outcome",
        "human_review_required",
        "production_readiness",
        "stage_gate",
        "next_stage",
        "final_disposition",
    ):
        assert term not in serialized

    audit = view["exclusion_audit"]
    assert audit["all_prohibited_fields_excluded"] is True
    assert audit["ssvc_output_consumed"] is False
    assert audit["governance_output_consumed"] is False
    assert audit["source_prohibited_path_count"] > 0


def test_sector_is_evaluation_context_not_model_input() -> None:
    view = build()
    assert "primary_sector" not in view["model_features"]
    assert view["evaluation_context"]["primary_sector"] == "healthcare"
    assert (
        view["evaluation_context"]["synthetic_or_demo_context"]
        is True
    )
    assert (
        view["release_decision"]["production_dataset_eligible"]
        is False
    )


def test_missing_required_feature_fails_closed() -> None:
    envelope = load(FEATURE_PATH)
    del envelope["features"]["technical_severity"]["base_score"]
    with pytest.raises(
        MLAdvisoryGovernanceError,
        match="Required ML source feature is missing",
    ):
        build(envelope)


def test_invalid_feature_type_fails_closed() -> None:
    envelope = load(FEATURE_PATH)
    envelope["features"]["exploitation"]["epss"]["probability"] = "0.99"
    with pytest.raises(
        MLAdvisoryGovernanceError,
        match="violates declared type",
    ):
        build(envelope)


def test_failed_upstream_stage_gate_blocks_ml_view() -> None:
    envelope = load(FEATURE_PATH)
    envelope["release_decision"]["stage_gate"] = "FAIL"
    with pytest.raises(
        MLAdvisoryGovernanceError,
        match="stage gate is not eligible",
    ):
        build(envelope)


def test_policy_cannot_allow_prohibited_ssvc_path() -> None:
    policy, _ = load_governance_policy()
    mutated = copy.deepcopy(policy)
    mutated["model_features"].append(
        {
            "feature_id": "forbidden_ssvc_vector",
            "source_path": (
                "$.features.exploitation."
                "ssvc_source_assertion.exploitation"
            ),
            "data_type": "string",
            "required": True,
        }
    )
    with pytest.raises(
        MLAdvisoryGovernanceError,
        match="overlaps prohibited input",
    ):
        validate_policy_contract(mutated)


def test_ssvc_derived_label_is_rejected() -> None:
    record = label_record(
        source_type="SSVC_POLICY_DECISION",
        synthetic=False,
    )
    with pytest.raises(
        MLAdvisoryGovernanceError,
        match="prohibited",
    ):
        validate_label_record(record)


def test_model_prediction_label_is_rejected() -> None:
    record = label_record(
        source_type="MODEL_PREDICTION",
        synthetic=False,
    )
    with pytest.raises(
        MLAdvisoryGovernanceError,
        match="prohibited",
    ):
        validate_label_record(record)


def test_controlled_synthetic_label_is_development_only() -> None:
    validated = validate_label_record(label_record())
    assert validated["synthetic"] is True
    assert validated["independent_source"] is False
    assert validated["production_eligible"] is False
    assert (
        validated["reason_codes"]
        == ["CONTROLLED_SYNTHETIC_LABEL_DEVELOPMENT_ONLY"]
    )


def test_independent_incident_label_is_production_candidate() -> None:
    validated = validate_label_record(
        label_record(
            source_type="INCIDENT_CONFIRMED_EXPLOITATION",
            synthetic=False,
        )
    )
    assert validated["independent_source"] is True
    assert validated["production_eligible"] is True
    assert validated["class_index"] == 3


def test_training_pair_preserves_development_only_boundary() -> None:
    pair = validate_training_pair(
        build(),
        label_record(),
    )
    assert pair["development_eligible"] is True
    assert pair["production_eligible"] is False
    assert pair["reason_codes"] == [
        "TRAINING_PAIR_DEVELOPMENT_ONLY"
    ]


def test_training_pair_identity_mismatch_fails_closed() -> None:
    record = label_record()
    record["target"]["asset_id"] = "WRONG-ASSET"
    with pytest.raises(
        MLAdvisoryGovernanceError,
        match="target identities do not match",
    ):
        validate_training_pair(build(), record)

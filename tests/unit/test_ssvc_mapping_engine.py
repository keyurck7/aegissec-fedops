from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from src.decision_policy.ssvc_engine import (
    build_ssvc_policy_decision,
    sha256_document,
)


ROOT = Path(__file__).resolve().parents[2]
FEATURE_PATH = next(
    (ROOT / "data" / "processed" / "decision_features").rglob("*.features.json")
)
SCHEMA_PATH = ROOT / "schemas" / "aegis_ssvc_policy_decision.schema.json"


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value



def reseal(envelope: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(envelope)
    value["audit"]["canonical_json_sha256"] = "0" * 64
    value["audit"]["canonical_json_sha256"] = sha256_document(value)
    return value

def build(**overrides: Any) -> dict[str, Any]:
    values = {
        "decision_feature_envelope": load(FEATURE_PATH),
        "input_relative_path": FEATURE_PATH.relative_to(ROOT).as_posix(),
        "input_sha256": hashlib.sha256(FEATURE_PATH.read_bytes()).hexdigest(),
        "generated_at": "2026-07-18T15:00:00Z",
    }
    values.update(overrides)
    return build_ssvc_policy_decision(**values)


def test_live_vertical_slice_resolves_official_ssvc_out_of_cycle() -> None:
    report = build()
    points = report["mapping"]["decision_points"]
    assert points["exploitation"]["key"] == "A"
    assert points["system_exposure"]["key"] == "O"
    assert points["automatable"]["key"] == "Y"
    assert points["safety_impact"]["key"] == "M"
    assert points["mission_impact"]["key"] == "MEF"
    assert points["human_impact"]["key"] == "M"
    assert report["official_ssvc_decision"]["vector"] == "A/O/Y/M"
    assert report["official_ssvc_decision"]["matched_row"] == 69
    assert report["official_ssvc_decision"]["outcome"]["name"] == "OUT_OF_CYCLE"
    assert report["governance"]["stage_gate"] == "PASS"


def test_output_validates_against_strict_schema() -> None:
    report = build()
    schema = load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(report)
    )
    assert errors == []


def test_epss_alone_never_proves_active_exploitation() -> None:
    envelope = load(FEATURE_PATH)
    exploitation = envelope["features"]["exploitation"]
    exploitation["known_exploitation_status"] = "UNKNOWN"
    exploitation["kev"]["listed"] = False
    exploitation["ssvc_source_assertion"]["exploitation"] = "unknown"
    exploitation["epss"]["probability"] = 1.0
    report = build(decision_feature_envelope=reseal(envelope))
    assert report["mapping"]["decision_points"]["exploitation"]["status"] == "UNRESOLVED"
    assert report["mapping"]["status"] == "BLOCKED"
    assert report["official_ssvc_decision"]["status"] == "BLOCKED"
    assert "SSVC_EXPLOITATION_UNRESOLVED" in report["mapping"]["blocking_reason_codes"]


def test_unknown_exposure_is_conservatively_assumed_open_and_recorded() -> None:
    envelope = load(FEATURE_PATH)
    exposure = envelope["features"]["exposure_and_reachability"]
    exposure["internet_accessible"] = None
    exposure["externally_accessible"] = None
    exposure["network_zone"] = "unknown"
    exposure["authentication_required"] = None
    exposure["exposure_confidence"] = None
    report = build(decision_feature_envelope=reseal(envelope))
    point = report["mapping"]["decision_points"]["system_exposure"]
    assert point["key"] == "O"
    assert point["mapping_rule_id"] == "EXPOSURE_UNKNOWN_ASSUME_OPEN"
    assert report["mapping"]["assumptions"][0]["reason_code"] == "SSVC_EXPOSURE_OPEN_ASSUMED"
    assert report["governance"]["human_review_required"] is True


def test_unknown_automatable_fails_closed() -> None:
    envelope = load(FEATURE_PATH)
    envelope["features"]["exploitation"]["ssvc_source_assertion"]["automatable"] = "unknown"
    report = build(decision_feature_envelope=reseal(envelope))
    assert report["mapping"]["decision_points"]["automatable"]["status"] == "UNRESOLVED"
    assert report["official_ssvc_decision"]["outcome"] is None
    assert report["governance"]["stage_gate"] == "FAIL"


def test_failed_upstream_stage_cannot_issue_official_outcome() -> None:
    envelope = load(FEATURE_PATH)
    envelope["release_decision"]["stage_gate"] = "FAIL"
    report = build(decision_feature_envelope=reseal(envelope))
    assert report["mapping"]["status"] == "BLOCKED"
    assert report["official_ssvc_decision"]["status"] == "BLOCKED"
    assert "SSVC_INPUT_STAGE_GATE_FAILED" in report["mapping"]["blocking_reason_codes"]


def test_sector_label_cannot_directly_change_ssvc_outcome() -> None:
    baseline = build()
    envelope = load(FEATURE_PATH)
    impact = envelope["features"]["mission_and_sector_impact"]
    impact["primary_sector"] = "fictional-space-mining"
    impact["subsector"] = "irrelevant label"
    changed = build(decision_feature_envelope=reseal(envelope))
    assert changed["official_ssvc_decision"]["matched_row"] == baseline["official_ssvc_decision"]["matched_row"]
    assert changed["official_ssvc_decision"]["outcome"] == baseline["official_ssvc_decision"]["outcome"]


def test_decision_id_is_deterministic_and_time_independent() -> None:
    first = build(generated_at="2026-07-18T15:00:00Z")
    second = build(generated_at="2026-07-19T15:00:00Z")
    assert first["decision_id"] == second["decision_id"]
    assert first["generated_at"] != second["generated_at"]


def test_tampered_input_integrity_fails_closed() -> None:
    envelope = load(FEATURE_PATH)
    envelope["features"]["technical_severity"]["base_score"] = 1.0
    report = build(decision_feature_envelope=envelope)
    assert report["mapping"]["status"] == "BLOCKED"
    assert "SSVC_INPUT_INTEGRITY_FAILED" in report["mapping"]["blocking_reason_codes"]
    assert report["official_ssvc_decision"]["outcome"] is None


def test_production_block_and_separation_are_preserved() -> None:
    report = build()
    assert report["governance"]["production_readiness"] == "BLOCKED"
    assert report["separation"] == {
        "official_ssvc_complete": True,
        "federal_overlay_status": "NOT_APPLIED",
        "ml_advisory_status": "NOT_APPLIED",
        "final_disposition_status": "NOT_AUTHORIZED",
    }
    assert report["governance"]["human_review_required"] is True


def test_provenance_covers_every_decision_point_and_official_row() -> None:
    report = build()
    paths = {entry["decision_path"] for entry in report["provenance"]}
    for name in (
        "exploitation",
        "system_exposure",
        "automatable",
        "safety_impact",
        "mission_impact",
        "human_impact",
    ):
        assert f"/mapping/decision_points/{name}" in paths
    assert "/official_ssvc_decision/outcome" in paths
    assert len(report["provenance"]) >= 8

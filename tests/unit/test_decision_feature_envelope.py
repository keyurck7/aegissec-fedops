from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from src.decision_features.feature_envelope import (
    DecisionFeatureEnvelopeError,
    FeatureInputReference,
    build_decision_feature_envelope,
)


ROOT = Path(__file__).resolve().parents[2]
CANONICAL_PATH = (
    ROOT
    / "data"
    / "processed"
    / "canonical_intelligence"
    / "log4shell-20260715T140904Z"
    / "aeg-cvi-49b4e71ef44a248db7a08e5d.canonical.json"
)
AFFECTEDNESS_PATH = (
    ROOT
    / "data"
    / "processed"
    / "affectedness"
    / "log4shell-20260715T163707Z-affectedness"
    / "aeg-afa-9e7d8f8a03a6a1ec07a6cc0a.adjudication.json"
)
ASSET_PATH = (
    ROOT / "data" / "sample_inputs" / "assets" / "valid_healthcare_asset.json"
)
EVIDENCE_PATH = (
    ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_log4j_sbom_evidence.json"
)
RUNTIME_PATH = (
    ROOT
    / "data"
    / "sample_inputs"
    / "affectedness"
    / "valid_log4shell_runtime_context.json"
)
SCHEMA_PATH = ROOT / "schemas" / "aegis_decision_feature_envelope.schema.json"


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def references() -> dict[str, FeatureInputReference]:
    canonical = load(CANONICAL_PATH)
    affectedness = load(AFFECTEDNESS_PATH)
    asset = load(ASSET_PATH)
    evidence = load(EVIDENCE_PATH)
    runtime = load(RUNTIME_PATH)
    return {
        "canonical_intelligence": FeatureInputReference(
            record_id=canonical["record_id"],
            relative_path=CANONICAL_PATH.relative_to(ROOT).as_posix(),
            sha256=sha256_file(CANONICAL_PATH),
        ),
        "affectedness_adjudication": FeatureInputReference(
            record_id=affectedness["report_id"],
            relative_path=AFFECTEDNESS_PATH.relative_to(ROOT).as_posix(),
            sha256=sha256_file(AFFECTEDNESS_PATH),
        ),
        "asset_context": FeatureInputReference(
            record_id=asset["asset_id"],
            relative_path=ASSET_PATH.relative_to(ROOT).as_posix(),
            sha256=sha256_file(ASSET_PATH),
        ),
        "component_evidence": FeatureInputReference(
            record_id=evidence["evidence_id"],
            relative_path=EVIDENCE_PATH.relative_to(ROOT).as_posix(),
            sha256=sha256_file(EVIDENCE_PATH),
        ),
        "runtime_context": FeatureInputReference(
            record_id=runtime["context_id"],
            relative_path=RUNTIME_PATH.relative_to(ROOT).as_posix(),
            sha256=sha256_file(RUNTIME_PATH),
        ),
    }


def build(**overrides: Any) -> dict[str, Any]:
    values = {
        "canonical_record": load(CANONICAL_PATH),
        "affectedness_report": load(AFFECTEDNESS_PATH),
        "asset_context": load(ASSET_PATH),
        "component_evidence": load(EVIDENCE_PATH),
        "runtime_context": load(RUNTIME_PATH),
        "input_references": references(),
        "generated_at": "2026-07-15T14:09:04Z",
    }
    values.update(overrides)
    return build_decision_feature_envelope(**values)


def test_live_vertical_slice_builds_strict_feature_contract() -> None:
    envelope = build()
    schema = load(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(envelope)
    )
    assert errors == []
    assert envelope["target"]["cve_id"] == "CVE-2021-44228"
    assert envelope["features"]["technical_severity"]["base_score"] == 10.0
    assert (
        envelope["features"]["exploitation"]["known_exploitation_status"]
        == "CONFIRMED_ACTIVE"
    )
    assert envelope["features"]["affectedness"]["status"] == "AFFECTED"
    assert envelope["features"]["asset_criticality"]["level"] == "high"
    assert (
        envelope["features"]["mission_and_sector_impact"]["maximum_severity"]
        == "SEVERE"
    )
    assert (
        envelope["features"]["exposure_and_reachability"]["runtime_reachability"]
        == "UNKNOWN"
    )
    assert envelope["release_decision"]["stage_gate"] == "PASS"
    assert (
        envelope["release_decision"]["next_stage_eligibility"]
        == "REVIEW_REQUIRED_FOR_12E"
    )
    assert envelope["release_decision"]["production_readiness"] == "BLOCKED"


def test_envelope_id_is_deterministic_and_time_independent() -> None:
    first = build(generated_at="2026-07-15T14:09:04Z")
    second = build(generated_at="2026-07-16T14:09:04Z")
    assert first["envelope_id"] == second["envelope_id"]
    assert first["generated_at"] != second["generated_at"]


def test_runtime_reachability_does_not_rewrite_affectedness() -> None:
    runtime = load(RUNTIME_PATH)
    runtime["reachability"] = {
        "status": "REACHABLE",
        "confidence": 0.92,
        "evidence_ids": ["AEG-EVD-RUNTIME-001"],
    }
    envelope = build(runtime_context=runtime)
    assert envelope["features"]["affectedness"]["status"] == "AFFECTED"
    assert (
        envelope["features"]["exposure_and_reachability"]["runtime_reachability"]
        == "REACHABLE"
    )


def test_component_identity_mismatch_fails_closed() -> None:
    runtime = load(RUNTIME_PATH)
    runtime["component"]["version"] = "2.17.1"
    with pytest.raises(DecisionFeatureEnvelopeError, match="identity binding"):
        build(runtime_context=runtime)


def test_failed_upstream_stage_blocks_12e() -> None:
    affectedness = load(AFFECTEDNESS_PATH)
    affectedness["release_decision"]["stage_gate"] = "FAIL"
    envelope = build(affectedness_report=affectedness)
    assert envelope["release_decision"]["stage_gate"] == "FAIL"
    assert (
        envelope["release_decision"]["next_stage_eligibility"]
        == "BLOCKED_FOR_12E"
    )


def test_quarantined_trust_blocks_12e() -> None:
    affectedness = load(AFFECTEDNESS_PATH)
    affectedness["trust"]["combined"]["action"] = "QUARANTINE"
    envelope = build(affectedness_report=affectedness)
    assert envelope["features"]["evidence_trust"]["combined_action"] == "QUARANTINE"
    assert envelope["release_decision"]["stage_gate"] == "FAIL"
    assert (
        envelope["release_decision"]["next_stage_eligibility"]
        == "BLOCKED_FOR_12E"
    )


def test_decision_outputs_are_absent() -> None:
    envelope = build()
    prohibited = {
        "final_priority",
        "priority",
        "action",
        "response_deadline_hours",
        "response_due_at",
        "ssvc_decision",
        "ml_prediction",
        "ml_advisory",
        "arbitration",
        "final_decision",
    }
    observed: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            observed.update(set(value) & prohibited)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(envelope)
    assert observed == set()
    assert envelope["audit"]["prohibited_output_fields_absent"] is True


def test_provenance_is_hash_bound_to_inputs() -> None:
    envelope = build()
    assert len(envelope["provenance"]) >= 24
    input_hashes = envelope["audit"]["input_hashes"]
    path_to_input = {
        reference.relative_path: name
        for name, reference in references().items()
    }
    for entry in envelope["provenance"]:
        source_name = path_to_input[entry["source_relative_path"]]
        assert entry["source_sha256"] == input_hashes[source_name]

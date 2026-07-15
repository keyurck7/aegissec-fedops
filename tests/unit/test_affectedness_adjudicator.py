from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from src.affectedness.affectedness_adjudicator import (
    InputReference,
    build_affectedness_adjudication,
)
from tests.unit.test_canonical_affectedness_adapter import canonical_fixture


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ASSET_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)
EVIDENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_log4j_sbom_evidence.json"
)
RUNTIME_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "affectedness"
    / "valid_log4shell_runtime_context.json"
)
SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_affectedness_adjudication.schema.json"
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def references() -> dict[str, InputReference]:
    return {
        "canonical_intelligence": InputReference(
            "AEG-CVI-0123456789ABCDEF01234567",
            "data/processed/canonical.json",
            "1" * 64,
        ),
        "asset_context": InputReference(
            "AEG-AST-HOSP-SCHED-001",
            "data/sample_inputs/assets/valid_healthcare_asset.json",
            "2" * 64,
        ),
        "component_evidence": InputReference(
            "AEG-EVD-SBOM-LOG4J-001",
            "data/sample_inputs/evidence/valid_log4j_sbom_evidence.json",
            "3" * 64,
        ),
        "runtime_context": InputReference(
            "AEG-RTC-LOG4SHELL-DEMO-001",
            "data/sample_inputs/affectedness/valid_log4shell_runtime_context.json",
            "4" * 64,
        ),
    }


def build(runtime: dict | None = None, canonical: dict | None = None) -> dict:
    return build_affectedness_adjudication(
        canonical_record=canonical or canonical_fixture(),
        asset_context=load(ASSET_PATH),
        component_evidence=load(EVIDENCE_PATH),
        runtime_context=runtime or load(RUNTIME_PATH),
        input_references=references(),
        assessed_at="2026-07-15T14:09:04Z",
    )


def test_live_style_log4shell_is_adjudicated_affected() -> None:
    report = build()
    assert report["adjudication"]["status"] == "AFFECTED"
    assert report["adjudication"]["technical_status"] == "affected"
    assert report["adjudication"]["human_review_required"] is True
    assert report["adjudication"]["closure_prohibited"] is True
    assert report["release_decision"]["stage_gate"] == "PASS"
    assert report["release_decision"]["production_readiness"] == "BLOCKED"


def test_runtime_unknown_does_not_downgrade_package_affectedness() -> None:
    report = build()
    assert report["runtime_context"]["reachability"] == "UNKNOWN"
    assert report["adjudication"]["status"] == "AFFECTED"
    assert "RUNTIME_REACHABILITY_UNKNOWN" in report["adjudication"]["reason_codes"]


def test_mitigation_does_not_rewrite_affected_version() -> None:
    runtime = load(RUNTIME_PATH)
    runtime["configuration"]["status"] = "MITIGATED"
    runtime["configuration"]["mitigation_ids"] = ["MIT-LOG4J-DEMO-001"]
    runtime["configuration"]["evidence_ids"] = ["AEG-EVD-MIT-001"]
    report = build(runtime=runtime)
    assert report["adjudication"]["status"] == "AFFECTED"
    assert "MITIGATION_DOES_NOT_CHANGE_AFFECTED_VERSION" in report["adjudication"]["reason_codes"]


def test_definitive_component_absence_can_establish_not_affected() -> None:
    runtime = load(RUNTIME_PATH)
    runtime["presence"]["status"] = "ABSENT"
    runtime["presence"]["confidence"] = 0.99
    report = build(runtime=runtime)
    assert report["adjudication"]["status"] == "NOT_AFFECTED"
    assert report["adjudication"]["technical_status"] == "not_affected"
    assert report["adjudication"]["closure_prohibited"] is False


def test_component_identity_mismatch_is_conflicted_and_fails_gate() -> None:
    runtime = load(RUNTIME_PATH)
    runtime["component"]["version"] = "2.17.1"
    report = build(runtime=runtime)
    assert report["adjudication"]["status"] == "CONFLICTED"
    assert report["adjudication"]["confidence"] is None
    assert report["release_decision"]["stage_gate"] == "FAIL"


def test_contradictory_package_assertions_are_conflicted() -> None:
    canonical = canonical_fixture()
    contradictory = copy.deepcopy(
        canonical["package_evidence"]["assertions"][0]
    )
    contradictory["source_record_id"] = "GHSA-CONTRADICTORY"
    contradictory["evidence_status"] = "NOT_AFFECTED_SUPPORTED"
    contradictory["range_evaluations"][0]["affected"] = False
    canonical["package_evidence"]["assertions"].append(contradictory)
    report = build(canonical=canonical)
    assert report["adjudication"]["status"] == "CONFLICTED"
    assert any(
        item["code"] == "CONTRADICTORY_PACKAGE_AFFECTEDNESS"
        for item in report["conflicts"]
    )


def test_report_validates_against_schema() -> None:
    report = build()
    schema = load(SCHEMA_PATH)
    errors = list(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(report)
    )
    assert errors == []


def test_segmented_ranges_from_same_record_use_union_semantics() -> None:
    """Nonmatching ranges in one advisory do not negate a matching range."""
    canonical = canonical_fixture()

    affected_assertion = canonical[
        "package_evidence"
    ]["assertions"][0]

    nonmatching_segment = copy.deepcopy(affected_assertion)
    nonmatching_segment["evidence_status"] = "NOT_AFFECTED_SUPPORTED"

    # Keep the same source record. This represents another range segment
    # within the same OSV advisory, not an independent contradictory source.
    nonmatching_segment["source_record_id"] = affected_assertion[
        "source_record_id"
    ]

    for evaluation in nonmatching_segment.get(
        "range_evaluations",
        [],
    ):
        evaluation["affected"] = False
        evaluation["fixed_boundary_reached"] = True
        evaluation["before_introduced"] = False
        evaluation["reason_codes"] = ["FIXED_BOUNDARY_REACHED"]

    canonical["package_evidence"]["assertions"].append(
        nonmatching_segment
    )
    canonical["package_evidence"][
        "aggregate_status"
    ] = "AFFECTED_SUPPORTED"

    report = build(canonical=canonical)

    assert report["adjudication"]["status"] == "AFFECTED"
    assert report["adjudication"]["technical_status"] == "affected"
    assert report["release_decision"]["stage_gate"] == "PASS"
    assert not any(
        conflict["code"] == "CONTRADICTORY_PACKAGE_AFFECTEDNESS"
        for conflict in report["conflicts"]
    )


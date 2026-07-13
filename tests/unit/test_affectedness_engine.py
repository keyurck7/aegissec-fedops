from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.affectedness.affectedness_engine import (
    AffectednessEngine,
)
from src.governance.evidence_trust_engine import (
    EvidenceTrustEngine,
)
from src.validation.decision_record_validator import (
    DecisionRecordValidator,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record.json"
)

UPGRADED_DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_affectedness.json"
)

INTELLIGENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "intelligence"
    / "valid_log4shell_intelligence.json"
)

EVIDENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_log4j_sbom_evidence.json"
)


ASSESSMENT_TIME = datetime(
    2026,
    7,
    13,
    19,
    0,
    tzinfo=timezone.utc,
)


@pytest.fixture
def engine() -> AffectednessEngine:
    return AffectednessEngine()


@pytest.fixture
def component() -> dict:
    with DECISION_PATH.open("r", encoding="utf-8") as file:
        decision = json.load(file)

    return decision["component_instance"]


@pytest.fixture
def intelligence() -> dict:
    with INTELLIGENCE_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


@pytest.fixture
def trust():
    with EVIDENCE_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        evidence = json.load(file)

    return EvidenceTrustEngine().assess(
        evidence,
        assessed_at=ASSESSMENT_TIME,
    )


def assess(
    engine,
    component,
    intelligence,
    trust,
):
    return engine.assess(
        component_instance=component,
        intelligence_record=intelligence,
        evidence_trust=trust,
        assessed_at=ASSESSMENT_TIME,
    )


def test_policy_supports_expected_range_types(
    engine: AffectednessEngine,
) -> None:
    assert engine.supported_range_types == {
        "ECOSYSTEM",
        "SEMVER",
    }


def test_log4j_2141_is_affected(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    result = assess(
        engine,
        component,
        intelligence,
        trust,
    )

    assert result.status == "affected"
    assert result.confidence >= 0.85

    assert (
        result.package_match.method
        == "exact_purl"
    )


def test_assessment_maps_to_decision_record_block(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    result = assess(
        engine,
        component,
        intelligence,
        trust,
    )

    block = result.to_decision_record_block()

    assert block["status"] == "affected"
    assert block["determination_method"] == "version_range"
    assert block["engine_version"] == "0.1.0"


def test_fixed_boundary_is_fixed(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)
    candidate["version"] = "2.15.0"

    result = assess(
        engine,
        candidate,
        intelligence,
        trust,
    )

    assert result.status == "fixed"


def test_version_after_fixed_boundary_is_fixed(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)
    candidate["version"] = "2.16.0"

    result = assess(
        engine,
        candidate,
        intelligence,
        trust,
    )

    assert result.status == "fixed"


def test_version_before_introduction_is_not_affected(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)
    candidate["version"] = "1.2.17"

    result = assess(
        engine,
        candidate,
        intelligence,
        trust,
    )

    assert result.status == "not_affected"


def test_missing_version_is_unknown(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)
    candidate["version"] = None

    result = assess(
        engine,
        candidate,
        intelligence,
        trust,
    )

    assert result.status == "unknown"
    assert result.human_review_required is True


def test_malformed_version_is_unknown(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)
    candidate["version"] = "not-a-real-version!!!"

    result = assess(
        engine,
        candidate,
        intelligence,
        trust,
    )

    assert result.status == "unknown"


def test_no_package_match_is_unknown_not_safe(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)

    candidate["name"] = "different-package"
    candidate["purl"] = (
        "pkg:maven/example/different-package@1.0.0"
    )

    result = assess(
        engine,
        candidate,
        intelligence,
        trust,
    )

    assert result.status == "unknown"

    assert (
        "NO_MATCH_IS_NOT_PROOF_OF_SAFETY"
        in result.reason_codes
    )


def test_partial_range_in_range_is_probably_affected(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    partial = copy.deepcopy(intelligence)

    partial["affected_packages"][0][
        "range_status"
    ] = "partial"

    result = assess(
        engine,
        component,
        partial,
        trust,
    )

    assert result.status == "probably_affected"
    assert result.human_review_required is True


def test_partial_range_outside_is_probably_not_affected(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)
    candidate["version"] = "2.16.0"

    partial = copy.deepcopy(intelligence)

    partial["affected_packages"][0][
        "range_status"
    ] = "partial"

    result = assess(
        engine,
        candidate,
        partial,
        trust,
    )

    assert result.status == "probably_not_affected"
    assert result.human_review_required is True


def test_conflicting_ranges_are_unknown(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    conflicting = copy.deepcopy(intelligence)

    conflicting["affected_packages"][0][
        "range_status"
    ] = "conflicting"

    result = assess(
        engine,
        component,
        conflicting,
        trust,
    )

    assert result.status == "unknown"


def test_quarantined_evidence_forces_unknown(
    engine,
    component,
    intelligence,
) -> None:
    trust = {
        "action": "QUARANTINE",
        "aggregate_score": 0.82,
    }

    result = assess(
        engine,
        component,
        intelligence,
        trust,
    )

    assert result.status == "unknown"

    assert (
        "EVIDENCE_TRUST_QUARANTINED"
        in result.reason_codes
    )


def test_rejected_evidence_forces_unknown(
    engine,
    component,
    intelligence,
) -> None:
    trust = {
        "action": "REJECT",
        "aggregate_score": 0.20,
    }

    result = assess(
        engine,
        component,
        intelligence,
        trust,
    )

    assert result.status == "unknown"

    assert (
        "EVIDENCE_TRUST_REJECTED"
        in result.reason_codes
    )


def test_unsupported_range_type_is_unknown(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    unsupported = copy.deepcopy(intelligence)

    unsupported["affected_packages"][0][
        "ranges"
    ][0]["range_type"] = "GIT"

    result = assess(
        engine,
        component,
        unsupported,
        trust,
    )

    assert result.status == "unknown"


def test_affirmative_not_present_is_not_affected(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    candidate = copy.deepcopy(component)
    candidate["runtime_status"] = "not_present"

    result = assess(
        engine,
        candidate,
        intelligence,
        trust,
    )

    assert result.status == "not_affected"
    assert result.confidence >= 0.85


def test_multiple_package_matches_are_unknown(
    engine,
    component,
    intelligence,
    trust,
) -> None:
    ambiguous = copy.deepcopy(intelligence)

    duplicate = copy.deepcopy(
        ambiguous["affected_packages"][0]
    )

    duplicate["purl"] = None

    ambiguous["affected_packages"].append(
        duplicate
    )

    candidate = copy.deepcopy(component)
    candidate["purl"] = None

    result = assess(
        engine,
        candidate,
        ambiguous,
        trust,
    )

    assert result.status == "unknown"

    assert (
        "MULTIPLE_AFFECTED_PACKAGE_MATCHES"
        in result.reason_codes
    )


def test_upgraded_decision_record_validates() -> None:
    assert UPGRADED_DECISION_PATH.exists()

    validator = DecisionRecordValidator()

    result = validator.validate_file(
        UPGRADED_DECISION_PATH
    )

    assert result.valid is True

    with UPGRADED_DECISION_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        decision = json.load(file)

    assert (
        decision["affectedness"]["status"]
        == "affected"
    )

    assert (
        decision["affectedness"][
            "determination_method"
        ]
        == "version_range"
    )

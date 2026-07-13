from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from src.policy.policy_floor_engine import (
    DEFAULT_POLICY_PATH,
    PolicyConfigurationError,
    PolicyFloorEngine,
)
from src.validation.decision_record_validator import (
    DecisionRecordValidator,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ASSET_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)

INTELLIGENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "intelligence"
    / "valid_log4shell_intelligence.json"
)

DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_affectedness.json"
)

STEP8_DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_policy.json"
)


EVALUATION_TIME = datetime(
    2026,
    7,
    13,
    19,
    15,
    tzinfo=timezone.utc,
)


@pytest.fixture
def engine() -> PolicyFloorEngine:
    return PolicyFloorEngine()


@pytest.fixture
def asset() -> dict:
    with ASSET_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


@pytest.fixture
def intelligence() -> dict:
    with INTELLIGENCE_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


@pytest.fixture
def component() -> dict:
    with DECISION_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        decision = json.load(file)

    return decision["component_instance"]


def affectedness(
    status: str = "affected",
    confidence: float | None = 0.95,
) -> dict:
    return {
        "status": status,
        "confidence": confidence,
        "supporting_evidence_ids": [
            "AEG-EVD-SBOM-LOG4J-001",
            "AEG-EVD-OSV-LOG4J-001",
        ],
    }


def accepted_trust() -> dict:
    return {
        "action": "ACCEPT",
        "aggregate_score": 0.95,
    }


def neutralize_asset(
    asset_record: dict,
) -> dict:
    neutral = copy.deepcopy(asset_record)

    neutral["exposure"][
        "internet_accessible"
    ] = False

    neutral["exposure"][
        "externally_accessible"
    ] = False

    neutral["mission"][
        "mission_essential"
    ] = False

    neutral["criticality"]["level"] = "low"

    for value in neutral[
        "impact_assessment"
    ].values():
        if not isinstance(value, dict):
            continue

        if "severity" in value:
            value["severity"] = "low"
            value["rationale"] = (
                "Controlled low-impact test context."
            )

    return neutral


def neutralize_intelligence(
    intelligence_record: dict,
) -> dict:
    neutral = copy.deepcopy(
        intelligence_record
    )

    neutral["kev"]["status"] = "not_listed"
    neutral["kev"]["date_added"] = None
    neutral["kev"]["due_date"] = None
    neutral["kev"]["required_action"] = None
    neutral["kev"]["evidence_id"] = None

    neutral["exploitation"]["status"] = "unknown"
    neutral["exploitation"]["evidence_ids"] = []

    neutral["epss"] = {
        "status": "available",
        "probability": 0.10,
        "percentile": 0.20,
        "score_date": "2026-07-13",
        "retrieved_at": "2026-07-13T18:00:00Z",
        "evidence_id": "AEG-EVD-EPSS-TEST-001",
        "model_version": "test",
        "missing_reason": None,
    }

    neutral["cvss"]["metrics"][0][
        "base_score"
    ] = 6.5

    neutral["cvss"]["metrics"][0][
        "base_severity"
    ] = "MEDIUM"

    neutral["remediation"]["status"] = (
        "fix_available"
    )

    return neutral


def evaluate(
    engine,
    asset,
    intelligence,
    component,
    affectedness_value,
    trust,
):
    return engine.evaluate(
        asset_context=asset,
        intelligence_record=intelligence,
        component_instance=component,
        affectedness_assessment=(
            affectedness_value
        ),
        evidence_trust=trust,
        evaluated_at=EVALUATION_TIME,
    )


def test_policy_ranks_are_complete(
    engine: PolicyFloorEngine,
) -> None:
    assert set(engine.action_ranks) == {
        "TRACK",
        "TRACK_STAR",
        "ATTEND",
        "ACT",
        "HOLD",
    }

    assert set(engine.priority_ranks) == {
        "INFORMATIONAL",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "EMERGENCY",
    }


def test_policy_rejects_sector_based_rule(
    tmp_path: Path,
) -> None:
    with DEFAULT_POLICY_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        policy = yaml.safe_load(file)

    policy["allowed_context_fields"].append(
        "asset.primary_sector"
    )

    policy["rules"].append(
        {
            "rule_id": "RULE-ILLEGAL-SECTOR-001",
            "version": "1.0.0",
            "description": (
                "Illegal direct sector prioritization."
            ),
            "when": {
                "all": [
                    {
                        "field": "asset.primary_sector",
                        "operator": "eq",
                        "value": "healthcare",
                    }
                ]
            },
            "set": {
                "action_floor": "ACT",
                "priority_floor": "CRITICAL",
                "deadline_hours": 24,
                "human_review_required": True,
                "containment_required": False,
                "prohibit_closure": True,
            },
            "non_overridable": True,
            "evidence_sources": [
                "asset_context"
            ],
        }
    )

    invalid_path = (
        tmp_path / "invalid_sector_policy.yaml"
    )

    with invalid_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        yaml.safe_dump(
            policy,
            file,
            sort_keys=False,
        )

    with pytest.raises(
        PolicyConfigurationError
    ):
        PolicyFloorEngine(invalid_path)


def test_log4shell_is_act_critical(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        asset,
        intelligence,
        component,
        affectedness(),
        accepted_trust(),
    )

    assert result.action == "ACT"
    assert result.minimum_priority == "CRITICAL"
    assert result.response_deadline_hours == 24
    assert result.human_review_required is True
    assert result.invariants_passed is True


def test_affected_baseline_is_attend_high(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        neutralize_asset(asset),
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(),
        accepted_trust(),
    )

    assert result.action == "ATTEND"
    assert result.minimum_priority == "HIGH"


def test_active_exploitation_is_emergency(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    active = copy.deepcopy(intelligence)

    active["exploitation"]["status"] = (
        "active_exploitation"
    )

    result = evaluate(
        engine,
        asset,
        active,
        component,
        affectedness(),
        accepted_trust(),
    )

    assert result.action == "ACT"
    assert result.minimum_priority == "EMERGENCY"
    assert result.response_deadline_hours == 4
    assert result.containment_required is True


def test_unknown_affectedness_is_hold(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        asset,
        intelligence,
        component,
        affectedness(
            status="unknown",
            confidence=None,
        ),
        accepted_trust(),
    )

    assert result.action == "HOLD"
    assert result.minimum_priority == "CRITICAL"
    assert result.human_review_required is True
    assert result.prohibit_closure is True


def test_probably_not_affected_is_hold(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        asset,
        intelligence,
        component,
        affectedness(
            status="probably_not_affected",
            confidence=0.70,
        ),
        accepted_trust(),
    )

    assert result.action == "HOLD"
    assert result.human_review_required is True


def test_fixed_is_track_informational(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        neutralize_asset(asset),
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(
            status="fixed",
            confidence=0.95,
        ),
        accepted_trust(),
    )

    assert result.action == "TRACK"

    assert (
        result.minimum_priority
        == "INFORMATIONAL"
    )


def test_quarantined_trust_forces_hold(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        asset,
        intelligence,
        component,
        affectedness(),
        {
            "action": "QUARANTINE",
            "aggregate_score": 0.80,
        },
    )

    assert result.action == "HOLD"
    assert result.human_review_required is True


def test_rejected_trust_forces_hold(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        asset,
        intelligence,
        component,
        affectedness(),
        {
            "action": "REJECT",
            "aggregate_score": 0.20,
        },
    )

    assert result.action == "HOLD"
    assert result.human_review_required is True


def test_missing_epss_remains_none_and_requires_review(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    scenario_intelligence = (
        neutralize_intelligence(
            intelligence
        )
    )

    scenario_intelligence["epss"] = {
        "status": "missing",
        "probability": None,
        "percentile": None,
        "score_date": None,
        "retrieved_at": None,
        "evidence_id": None,
        "model_version": None,
        "missing_reason": (
            "Controlled test of missing semantics."
        ),
    }

    result = evaluate(
        engine,
        neutralize_asset(asset),
        scenario_intelligence,
        component,
        affectedness(),
        accepted_trust(),
    )

    assert (
        result.context_snapshot[
            "epss.probability"
        ]
        is None
    )

    assert result.human_review_required is True

    assert any(
        rule.rule_id
        == "RULE-EPSS-MISSING-AFFECTED-001"
        for rule in result.matched_rules
    )


def test_internet_exposure_escalates_to_critical(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    scenario_asset = neutralize_asset(asset)

    scenario_asset["exposure"][
        "internet_accessible"
    ] = True

    result = evaluate(
        engine,
        scenario_asset,
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(),
        accepted_trust(),
    )

    assert result.action == "ACT"
    assert result.minimum_priority == "CRITICAL"


def test_severe_impact_escalates_to_critical(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    scenario_asset = neutralize_asset(asset)

    scenario_asset[
        "impact_assessment"
    ]["availability"]["severity"] = "severe"

    result = evaluate(
        engine,
        scenario_asset,
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(),
        accepted_trust(),
    )

    assert result.action == "ACT"
    assert result.minimum_priority == "CRITICAL"


def test_catastrophic_impact_is_emergency(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    scenario_asset = neutralize_asset(asset)

    scenario_asset[
        "impact_assessment"
    ]["availability"]["severity"] = (
        "catastrophic"
    )

    result = evaluate(
        engine,
        scenario_asset,
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(),
        accepted_trust(),
    )

    assert result.action == "ACT"
    assert result.minimum_priority == "EMERGENCY"
    assert result.response_deadline_hours == 4


def test_mission_essential_is_at_least_high(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    scenario_asset = neutralize_asset(asset)

    scenario_asset["mission"][
        "mission_essential"
    ] = True

    result = evaluate(
        engine,
        scenario_asset,
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(),
        accepted_trust(),
    )

    assert (
        engine.action_ranks[result.action]
        >= engine.action_ranks["ATTEND"]
    )

    assert (
        engine.priority_ranks[
            result.minimum_priority
        ]
        >= engine.priority_ranks["HIGH"]
    )


def test_no_fix_requires_containment(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    scenario_intelligence = (
        neutralize_intelligence(
            intelligence
        )
    )

    scenario_intelligence["remediation"][
        "status"
    ] = "no_fix_available"

    result = evaluate(
        engine,
        neutralize_asset(asset),
        scenario_intelligence,
        component,
        affectedness(),
        accepted_trust(),
    )

    assert result.action == "ACT"
    assert result.minimum_priority == "CRITICAL"
    assert result.containment_required is True


def test_sector_label_does_not_change_decision(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    healthcare = copy.deepcopy(asset)

    defence = copy.deepcopy(asset)

    healthcare["sector_context"][
        "primary_sector"
    ] = "healthcare"

    defence["sector_context"][
        "primary_sector"
    ] = "defence_logistics"

    first = evaluate(
        engine,
        healthcare,
        intelligence,
        component,
        affectedness(),
        accepted_trust(),
    )

    second = evaluate(
        engine,
        defence,
        intelligence,
        component,
        affectedness(),
        accepted_trust(),
    )

    assert first.action == second.action

    assert (
        first.minimum_priority
        == second.minimum_priority
    )

    assert (
        first.response_deadline_hours
        == second.response_deadline_hours
    )


def test_impact_escalation_is_monotonic(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    low_asset = neutralize_asset(asset)

    severe_asset = copy.deepcopy(
        low_asset
    )

    severe_asset[
        "impact_assessment"
    ]["availability"]["severity"] = "severe"

    low_result = evaluate(
        engine,
        low_asset,
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(),
        accepted_trust(),
    )

    severe_result = evaluate(
        engine,
        severe_asset,
        neutralize_intelligence(
            intelligence
        ),
        component,
        affectedness(),
        accepted_trust(),
    )

    assert (
        engine.action_ranks[
            severe_result.action
        ]
        >= engine.action_ranks[
            low_result.action
        ]
    )

    assert (
        engine.priority_ranks[
            severe_result.minimum_priority
        ]
        >= engine.priority_ranks[
            low_result.minimum_priority
        ]
    )

    assert (
        severe_result.response_deadline_hours
        <= low_result.response_deadline_hours
    )


def test_all_triggered_rule_floors_are_enforced(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        asset,
        intelligence,
        component,
        affectedness(),
        accepted_trust(),
    )

    for rule in result.matched_rules:
        assert (
            engine.action_ranks[result.action]
            >= engine.action_ranks[
                rule.action_floor
            ]
        )

        assert (
            engine.priority_ranks[
                result.minimum_priority
            ]
            >= engine.priority_ranks[
                rule.priority_floor
            ]
        )

        assert (
            result.response_deadline_hours
            <= rule.deadline_hours
        )


def test_decision_record_block_has_valid_effects(
    engine,
    asset,
    intelligence,
    component,
) -> None:
    result = evaluate(
        engine,
        asset,
        intelligence,
        component,
        affectedness(),
        accepted_trust(),
    )

    block = result.to_decision_record_block()

    effects = {
        rule["effect"]
        for rule in block["triggered_rules"]
    }

    assert "set_action" in effects
    assert "set_priority_floor" in effects
    assert "set_deadline" in effects
    assert "require_human_review" in effects


def test_step8_decision_record_validates() -> None:
    assert STEP8_DECISION_PATH.exists()

    result = (
        DecisionRecordValidator()
        .validate_file(
            STEP8_DECISION_PATH
        )
    )

    assert result.valid is True

    with STEP8_DECISION_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        decision = json.load(file)

    assert (
        decision["policy_decision"]["action"]
        == "ACT"
    )

    assert (
        decision["policy_decision"][
            "minimum_priority"
        ]
        == "CRITICAL"
    )

    assert (
        decision["arbitration"][
            "policy_floor_enforced"
        ]
        is True
    )

from __future__ import annotations

from src.orchestration.assessment_ledger import (
    BLOCKED,
    PASSED,
    RUNNING,
    SKIPPED,
    create_assessment_ledger,
    transition_stage,
    verify_ledger,
)
from src.orchestration.controlled_vertical_adapters import (
    artifact_reference,
    evidence_arbitration_adapter,
    execute_controlled_vertical_slice,
)
from src.orchestration.dynamic_orchestrator import (
    DynamicAssessmentOrchestrator,
    StageResult,
)


def ledger():
    return create_assessment_ledger(
        input_id="AEG-INP-ORCH-TEST",
        input_envelope_sha256=(
            "a" * 64
        ),
        created_by="pytest",
        asset_context_id=(
            "AEG-ASSET-TEST"
        ),
    )


def pass_result(
    context,
):
    del context

    return StageResult(
        status=PASSED,
        message="Stage passed.",
        outputs=(
            {
                "artifact_type": (
                    "TEST_RESULT"
                ),
                "sha256": "b" * 64,
            },
        ),
    )


def complete(
    document,
    stage_id,
):
    document = transition_stage(
        document,
        stage_id=stage_id,
        to_status=RUNNING,
        actor_type="TEST",
        actor_id="pytest",
    )

    return transition_stage(
        document,
        stage_id=stage_id,
        to_status=PASSED,
        actor_type="TEST",
        actor_id="pytest",
    )


def test_missing_required_adapter_blocks():
    orchestrator = (
        DynamicAssessmentOrchestrator(
            adapters={}
        )
    )

    result = orchestrator.run_through(
        ledger=ledger(),
        context={},
        through_stage=(
            "INTAKE_VALIDATION"
        ),
    )

    assert (
        result["stages"][
            "INTAKE_VALIDATION"
        ]["status"]
        == BLOCKED
    )

    assert (
        result["run_status"]
        == "BLOCKED"
    )


def test_missing_optional_adapter_is_skipped():
    document = ledger()

    for stage_id in (
        "INTAKE_VALIDATION",
        "ASSET_CONTEXT",
        "COMPONENT_CORRELATION",
        "EVIDENCE_ARBITRATION",
        "AFFECTEDNESS",
        "DECISION_FEATURE_ENVELOPE",
    ):
        document = complete(
            document,
            stage_id,
        )

    orchestrator = (
        DynamicAssessmentOrchestrator(
            adapters={
                "SSVC": pass_result,
            }
        )
    )

    result = orchestrator.run_through(
        ledger=document,
        context={},
        through_stage="ML_ADVISORY",
    )

    assert (
        result["stages"]["SSVC"][
            "status"
        ]
        == PASSED
    )

    assert (
        result["stages"][
            "ML_ADVISORY"
        ]["status"]
        == SKIPPED
    )


def test_artifact_reference_is_deterministic():
    first = artifact_reference(
        stage_id="AFFECTEDNESS",
        artifact_type="TEST",
        authority=(
            "DETERMINISTIC_ENGINE"
        ),
        document={
            "status": "AFFECTED",
            "score": 1,
        },
    )

    second = artifact_reference(
        stage_id="AFFECTEDNESS",
        artifact_type="TEST",
        authority=(
            "DETERMINISTIC_ENGINE"
        ),
        document={
            "score": 1,
            "status": "AFFECTED",
        },
    )

    assert (
        first["sha256"]
        == second["sha256"]
    )


def test_controlled_vertical_slice_reaches_review():
    document, context = (
        execute_controlled_vertical_slice()
    )

    valid, errors = verify_ledger(
        document
    )

    assert valid, errors

    assert (
        document["run_status"]
        == "AWAITING_HUMAN_REVIEW"
    )

    assert (
        document["stages"][
            "AFFECTEDNESS"
        ]["status"]
        in {
            "PASSED",
            "PASSED_WITH_WARNINGS",
        }
    )

    assert (
        document["stages"]["SSVC"][
            "status"
        ]
        == "PASSED_WITH_WARNINGS"
    )

    assert (
        document["stages"][
            "AGREEMENT_ANALYSIS"
        ]["status"]
        == "PASSED_WITH_WARNINGS"
    )

    assert (
        document["stages"][
            "HUMAN_REVIEW"
        ]["status"]
        == "PENDING"
    )

    assert (
        document["stages"][
            "FINALIZATION"
        ]["status"]
        == "PENDING"
    )

    summary = context[
        "master_vertical_slice"
    ]["summary"]

    assert (
        summary["outcome_name"]
        == "OUT_OF_CYCLE"
    )

    assert (
        summary[
            "final_disposition_status"
        ]
        == "NOT_AUTHORIZED"
    )

    assert (
        summary[
            "production_readiness"
        ]
        == "BLOCKED"
    )


def test_stage_outputs_are_hash_bound():
    document, _ = (
        execute_controlled_vertical_slice()
    )

    for stage_id in (
        "INTAKE_VALIDATION",
        "ASSET_CONTEXT",
        "COMPONENT_CORRELATION",
        "EVIDENCE_ARBITRATION",
        "AFFECTEDNESS",
        "DECISION_FEATURE_ENVELOPE",
        "SSVC",
        "ML_ADVISORY",
        "AGREEMENT_ANALYSIS",
    ):
        outputs = document[
            "stages"
        ][stage_id]["outputs"]

        assert outputs
        assert len(
            outputs[0]["sha256"]
        ) == 64



def test_optional_historical_snapshot_does_not_block_canonical_execution():
    result = evidence_arbitration_adapter(
        {
            "workbench": {
                "governance": {
                    "live_source_precedence": True,
                    "snapshot_authority": (
                        "HISTORICAL_READ_ONLY"
                    ),
                    "scanner_authority": (
                        "ADVISORY_ONLY"
                    ),
                },
                "snapshot_summary": None,
            },
            "master_vertical_slice": {
                "affectedness": {
                    "release_decision": {
                        "stage_gate": "PASS"
                    }
                },
                "feature_envelope": {
                    "release_decision": {
                        "stage_gate": "PASS"
                    }
                },
                "ssvc": {
                    "governance": {
                        "stage_gate": "PASS"
                    }
                },
            },
        }
    )

    assert (
        result.status
        == "PASSED_WITH_WARNINGS"
    )

    assert (
        result.metadata[
            "snapshot_available"
        ]
        is False
    )

    assert (
        result.metadata[
            "authoritative_canonical_fallback"
        ]
        is True
    )

    assert result.outputs

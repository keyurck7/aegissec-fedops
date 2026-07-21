from __future__ import annotations

import copy
import json

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from src.orchestration.assessment_ledger import (
    AssessmentLedgerError,
    BLOCKED,
    PASSED,
    PASSED_WITH_WARNINGS,
    RUNNING,
    SKIPPED,
    create_assessment_ledger,
    load_ledger,
    transition_stage,
    verify_ledger,
    write_ledger_atomic,
)


class Clock:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self) -> str:
        self.counter += 1

        return (
            "2026-07-21T20:00:"
            f"{self.counter:02d}+00:00"
        )


def new_ledger():
    return create_assessment_ledger(
        input_id="AEG-INP-TEST",
        input_envelope_sha256=(
            "a" * 64
        ),
        created_by="pytest",
        asset_context_id=(
            "AEG-ASSET-TEST"
        ),
        clock=Clock(),
    )


def complete(
    ledger,
    stage_id,
    clock,
):
    ledger = transition_stage(
        ledger,
        stage_id=stage_id,
        to_status=RUNNING,
        actor_type="TEST",
        actor_id="pytest",
        message="Stage started.",
        clock=clock,
    )

    return transition_stage(
        ledger,
        stage_id=stage_id,
        to_status=PASSED,
        actor_type="TEST",
        actor_id="pytest",
        message="Stage passed.",
        outputs=[
            {
                "artifact_type": (
                    "TEST_ARTIFACT"
                ),
                "sha256": "b" * 64,
            }
        ],
        clock=clock,
    )


def test_new_ledger_is_valid():
    ledger = new_ledger()

    valid, errors = verify_ledger(
        ledger
    )

    assert valid
    assert errors == []
    assert (
        ledger["run_status"]
        == "CREATED"
    )
    assert len(
        ledger["events"]
    ) == 1


def test_schema_validation():
    schema = json.loads(
        Path(
            "schemas/"
            "aegis_assessment_run_ledger.schema.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    validator = Draft202012Validator(
        schema
    )

    errors = list(
        validator.iter_errors(
            new_ledger()
        )
    )

    assert errors == []


def test_stage_cannot_start_before_dependencies():
    ledger = new_ledger()

    with pytest.raises(
        AssessmentLedgerError,
        match="dependencies",
    ):
        transition_stage(
            ledger,
            stage_id="AFFECTEDNESS",
            to_status=RUNNING,
            actor_type="ENGINE",
            actor_id="affectedness",
        )


def test_terminal_stage_is_immutable():
    clock = Clock()
    ledger = new_ledger()

    ledger = complete(
        ledger,
        "INTAKE_VALIDATION",
        clock,
    )

    with pytest.raises(
        AssessmentLedgerError,
        match="Illegal transition",
    ):
        transition_stage(
            ledger,
            stage_id=(
                "INTAKE_VALIDATION"
            ),
            to_status=RUNNING,
            actor_type="ENGINE",
            actor_id="intake",
            clock=clock,
        )


def test_warning_status_requires_warning():
    clock = Clock()
    ledger = new_ledger()

    ledger = transition_stage(
        ledger,
        stage_id="INTAKE_VALIDATION",
        to_status=RUNNING,
        actor_type="ENGINE",
        actor_id="intake",
        clock=clock,
    )

    with pytest.raises(
        AssessmentLedgerError,
        match="requires at least one warning",
    ):
        transition_stage(
            ledger,
            stage_id=(
                "INTAKE_VALIDATION"
            ),
            to_status=(
                PASSED_WITH_WARNINGS
            ),
            actor_type="ENGINE",
            actor_id="intake",
            clock=clock,
        )


def test_required_stage_cannot_be_skipped_freely():
    ledger = new_ledger()

    with pytest.raises(
        AssessmentLedgerError,
        match="required stage",
    ):
        transition_stage(
            ledger,
            stage_id="ASSET_CONTEXT",
            to_status=SKIPPED,
            actor_type="SYSTEM",
            actor_id="orchestrator",
            reason_code=(
                "MANUAL_SKIP"
            ),
        )


def test_blocked_authoritative_stage_blocks_run():
    clock = Clock()
    ledger = new_ledger()

    ledger = complete(
        ledger,
        "INTAKE_VALIDATION",
        clock,
    )

    ledger = transition_stage(
        ledger,
        stage_id="ASSET_CONTEXT",
        to_status=BLOCKED,
        actor_type="ENGINE",
        actor_id="asset_context",
        reason_code=(
            "ASSET_CONTEXT_MISSING"
        ),
        message=(
            "Asset context is incomplete."
        ),
        clock=clock,
    )

    assert (
        ledger["run_status"]
        == "BLOCKED"
    )

    with pytest.raises(
        AssessmentLedgerError,
        match="dependencies",
    ):
        transition_stage(
            ledger,
            stage_id=(
                "COMPONENT_CORRELATION"
            ),
            to_status=RUNNING,
            actor_type="ENGINE",
            actor_id="correlator",
            clock=clock,
        )


def test_downstream_required_stage_can_skip_after_block():
    clock = Clock()
    ledger = new_ledger()

    ledger = complete(
        ledger,
        "INTAKE_VALIDATION",
        clock,
    )

    ledger = transition_stage(
        ledger,
        stage_id="ASSET_CONTEXT",
        to_status=BLOCKED,
        actor_type="ENGINE",
        actor_id="asset_context",
        reason_code=(
            "ASSET_CONTEXT_MISSING"
        ),
        clock=clock,
    )

    ledger = transition_stage(
        ledger,
        stage_id="COMPONENT_CORRELATION",
        to_status=SKIPPED,
        actor_type="SYSTEM",
        actor_id="orchestrator",
        reason_code=(
            "UPSTREAM_ASSET_CONTEXT_BLOCKED"
        ),
        clock=clock,
    )

    assert (
        ledger["stages"][
            "COMPONENT_CORRELATION"
        ]["status"]
        == SKIPPED
    )


def test_optional_dependency_must_be_terminal():
    clock = Clock()
    ledger = new_ledger()

    for stage_id in (
        "INTAKE_VALIDATION",
        "ASSET_CONTEXT",
        "COMPONENT_CORRELATION",
        "EVIDENCE_ARBITRATION",
        "AFFECTEDNESS",
        "DECISION_FEATURE_ENVELOPE",
        "SSVC",
    ):
        ledger = complete(
            ledger,
            stage_id,
            clock,
        )

    with pytest.raises(
        AssessmentLedgerError,
        match="not terminal",
    ):
        transition_stage(
            ledger,
            stage_id=(
                "AGREEMENT_ANALYSIS"
            ),
            to_status=RUNNING,
            actor_type="ENGINE",
            actor_id="agreement",
            clock=clock,
        )

    ledger = transition_stage(
        ledger,
        stage_id="ML_ADVISORY",
        to_status=SKIPPED,
        actor_type="SYSTEM",
        actor_id="orchestrator",
        reason_code=(
            "MODEL_NOT_AVAILABLE"
        ),
        clock=clock,
    )

    ledger = transition_stage(
        ledger,
        stage_id="AGREEMENT_ANALYSIS",
        to_status=RUNNING,
        actor_type="ENGINE",
        actor_id="agreement",
        clock=clock,
    )

    assert (
        ledger["stages"][
            "AGREEMENT_ANALYSIS"
        ]["status"]
        == RUNNING
    )


def test_human_review_and_finalization_complete_run():
    clock = Clock()
    ledger = new_ledger()

    for stage_id in (
        "INTAKE_VALIDATION",
        "ASSET_CONTEXT",
        "COMPONENT_CORRELATION",
        "EVIDENCE_ARBITRATION",
        "AFFECTEDNESS",
        "DECISION_FEATURE_ENVELOPE",
        "SSVC",
    ):
        ledger = complete(
            ledger,
            stage_id,
            clock,
        )

    ledger = transition_stage(
        ledger,
        stage_id="ML_ADVISORY",
        to_status=SKIPPED,
        actor_type="SYSTEM",
        actor_id="orchestrator",
        reason_code=(
            "MODEL_NOT_REQUIRED"
        ),
        clock=clock,
    )

    ledger = transition_stage(
        ledger,
        stage_id="AGREEMENT_ANALYSIS",
        to_status=SKIPPED,
        actor_type="SYSTEM",
        actor_id="orchestrator",
        reason_code=(
            "NO_MODEL_OUTPUT"
        ),
        clock=clock,
    )

    assert (
        ledger["run_status"]
        == "AWAITING_HUMAN_REVIEW"
    )

    ledger = complete(
        ledger,
        "HUMAN_REVIEW",
        clock,
    )

    ledger = complete(
        ledger,
        "FINALIZATION",
        clock,
    )

    assert (
        ledger["run_status"]
        == "COMPLETED"
    )

    assert (
        ledger["governance"][
            "final_disposition_authority"
        ]
        == "HUMAN"
    )


def test_event_tampering_is_detected():
    ledger = new_ledger()

    tampered = copy.deepcopy(
        ledger
    )

    tampered["events"][0][
        "message"
    ] = "Tampered message"

    valid, errors = verify_ledger(
        tampered
    )

    assert not valid
    assert any(
        "Event hash mismatch"
        in error
        for error in errors
    )


def test_stage_state_tampering_is_detected():
    ledger = new_ledger()

    tampered = copy.deepcopy(
        ledger
    )

    tampered["stages"][
        "INTAKE_VALIDATION"
    ]["status"] = PASSED

    valid, errors = verify_ledger(
        tampered
    )

    assert not valid
    assert any(
        "stage state mismatch"
        in error.lower()
        for error in errors
    )


def test_atomic_round_trip(tmp_path: Path):
    ledger = new_ledger()

    path = (
        tmp_path
        / "assessment.json"
    )

    document_path, sidecar = (
        write_ledger_atomic(
            ledger,
            path,
        )
    )

    assert document_path.is_file()
    assert sidecar.is_file()

    loaded = load_ledger(
        document_path
    )

    assert (
        loaded["assessment_id"]
        == ledger["assessment_id"]
    )

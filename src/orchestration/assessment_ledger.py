"""Tamper-evident assessment run ledger for AegisSec-FedOps."""

from __future__ import annotations

import copy
import hashlib
import json
import os

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = "1.0.0"
GENESIS_HASH = "0" * 64

PENDING = "PENDING"
RUNNING = "RUNNING"
PASSED = "PASSED"
PASSED_WITH_WARNINGS = "PASSED_WITH_WARNINGS"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
SKIPPED = "SKIPPED"

PASS_STATUSES = {
    PASSED,
    PASSED_WITH_WARNINGS,
}

TERMINAL_STATUSES = {
    PASSED,
    PASSED_WITH_WARNINGS,
    BLOCKED,
    FAILED,
    SKIPPED,
}

OPTIONAL_TERMINAL_STATUSES = TERMINAL_STATUSES

ALLOWED_TRANSITIONS = {
    PENDING: {
        RUNNING,
        BLOCKED,
        SKIPPED,
    },
    RUNNING: {
        PASSED,
        PASSED_WITH_WARNINGS,
        BLOCKED,
        FAILED,
    },
    PASSED: set(),
    PASSED_WITH_WARNINGS: set(),
    BLOCKED: set(),
    FAILED: set(),
    SKIPPED: set(),
}

STAGE_DEFINITIONS = (
    {
        "stage_id": "INTAKE_VALIDATION",
        "order": 1,
        "authority": "AUTHORITATIVE",
        "required": True,
        "required_dependencies": [],
        "optional_dependencies": [],
    },
    {
        "stage_id": "ASSET_CONTEXT",
        "order": 2,
        "authority": "AUTHORITATIVE",
        "required": True,
        "required_dependencies": [
            "INTAKE_VALIDATION",
        ],
        "optional_dependencies": [],
    },
    {
        "stage_id": "COMPONENT_CORRELATION",
        "order": 3,
        "authority": "AUTHORITATIVE",
        "required": True,
        "required_dependencies": [
            "INTAKE_VALIDATION",
            "ASSET_CONTEXT",
        ],
        "optional_dependencies": [],
    },
    {
        "stage_id": "EVIDENCE_ARBITRATION",
        "order": 4,
        "authority": "AUTHORITATIVE",
        "required": True,
        "required_dependencies": [
            "COMPONENT_CORRELATION",
        ],
        "optional_dependencies": [],
    },
    {
        "stage_id": "AFFECTEDNESS",
        "order": 5,
        "authority": "AUTHORITATIVE",
        "required": True,
        "required_dependencies": [
            "EVIDENCE_ARBITRATION",
        ],
        "optional_dependencies": [],
    },
    {
        "stage_id": "DECISION_FEATURE_ENVELOPE",
        "order": 6,
        "authority": "AUTHORITATIVE",
        "required": True,
        "required_dependencies": [
            "AFFECTEDNESS",
        ],
        "optional_dependencies": [],
    },
    {
        "stage_id": "SSVC",
        "order": 7,
        "authority": "AUTHORITATIVE",
        "required": True,
        "required_dependencies": [
            "DECISION_FEATURE_ENVELOPE",
        ],
        "optional_dependencies": [],
    },
    {
        "stage_id": "ML_ADVISORY",
        "order": 8,
        "authority": "ADVISORY",
        "required": False,
        "required_dependencies": [
            "DECISION_FEATURE_ENVELOPE",
        ],
        "optional_dependencies": [],
    },
    {
        "stage_id": "AGREEMENT_ANALYSIS",
        "order": 9,
        "authority": "ADVISORY",
        "required": False,
        "required_dependencies": [
            "SSVC",
        ],
        "optional_dependencies": [
            "ML_ADVISORY",
        ],
    },
    {
        "stage_id": "HUMAN_REVIEW",
        "order": 10,
        "authority": "HUMAN",
        "required": True,
        "required_dependencies": [
            "SSVC",
        ],
        "optional_dependencies": [
            "AGREEMENT_ANALYSIS",
        ],
    },
    {
        "stage_id": "FINALIZATION",
        "order": 11,
        "authority": "HUMAN",
        "required": True,
        "required_dependencies": [
            "HUMAN_REVIEW",
        ],
        "optional_dependencies": [],
    },
)


class AssessmentLedgerError(RuntimeError):
    """Raised when a ledger operation violates an orchestration control."""


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def canonical_json_bytes(
    document: Any,
) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(
    payload: bytes,
) -> str:
    return hashlib.sha256(
        payload
    ).hexdigest()


def stage_definition(
    stage_id: str,
) -> dict[str, Any]:
    for definition in STAGE_DEFINITIONS:
        if definition["stage_id"] == stage_id:
            return copy.deepcopy(
                definition
            )

    raise AssessmentLedgerError(
        f"Unknown assessment stage: {stage_id}"
    )


def _event_hash(
    event: dict[str, Any],
) -> str:
    unsigned = {
        key: value
        for key, value in event.items()
        if key != "event_hash"
    }

    return sha256_bytes(
        canonical_json_bytes(unsigned)
    )


def _ledger_hash(
    ledger: dict[str, Any],
) -> str:
    unsigned = {
        key: value
        for key, value in ledger.items()
        if key != "integrity"
    }

    return sha256_bytes(
        canonical_json_bytes(unsigned)
    )


def _assessment_id(
    *,
    input_id: str,
    input_envelope_sha256: str,
    created_at: str,
    created_by: str,
) -> str:
    seed = {
        "input_id": input_id,
        "input_envelope_sha256": (
            input_envelope_sha256
        ),
        "created_at": created_at,
        "created_by": created_by,
    }

    digest = sha256_bytes(
        canonical_json_bytes(seed)
    )

    return (
        "AEG-ASMT-"
        + digest[:24].upper()
    )


def _event_id(
    *,
    assessment_id: str,
    sequence: int,
    timestamp: str,
    event_type: str,
    stage_id: str | None,
    actor_id: str,
) -> str:
    seed = {
        "assessment_id": assessment_id,
        "sequence": sequence,
        "timestamp": timestamp,
        "event_type": event_type,
        "stage_id": stage_id,
        "actor_id": actor_id,
    }

    digest = sha256_bytes(
        canonical_json_bytes(seed)
    )

    return (
        "AEG-EVT-"
        + digest[:20].upper()
    )


def _new_stage_state() -> dict[str, Any]:
    return {
        "status": PENDING,
        "attempt": 0,
        "started_at": None,
        "completed_at": None,
        "reason_code": None,
        "message": None,
        "warnings": [],
        "outputs": [],
    }


def _refresh_integrity(
    ledger: dict[str, Any],
) -> None:
    events = ledger["events"]

    ledger["integrity"] = {
        "algorithm": "SHA-256",
        "genesis_hash": GENESIS_HASH,
        "event_count": len(events),
        "head_event_hash": (
            events[-1]["event_hash"]
        ),
        "ledger_sha256": "",
    }

    ledger["integrity"][
        "ledger_sha256"
    ] = _ledger_hash(ledger)


def _append_event(
    ledger: dict[str, Any],
    *,
    event_type: str,
    stage_id: str | None,
    from_status: str | None,
    to_status: str | None,
    actor_type: str,
    actor_id: str,
    reason_code: str | None,
    message: str | None,
    metadata: dict[str, Any] | None,
    timestamp: str,
) -> None:
    sequence = len(
        ledger["events"]
    ) + 1

    previous_event_hash = (
        ledger["events"][-1][
            "event_hash"
        ]
        if ledger["events"]
        else GENESIS_HASH
    )

    event = {
        "sequence": sequence,
        "event_id": _event_id(
            assessment_id=ledger[
                "assessment_id"
            ],
            sequence=sequence,
            timestamp=timestamp,
            event_type=event_type,
            stage_id=stage_id,
            actor_id=actor_id,
        ),
        "timestamp": timestamp,
        "event_type": event_type,
        "stage_id": stage_id,
        "from_status": from_status,
        "to_status": to_status,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "reason_code": reason_code,
        "message": message,
        "metadata": (
            copy.deepcopy(metadata)
            if metadata
            else {}
        ),
        "previous_event_hash": (
            previous_event_hash
        ),
        "event_hash": "",
    }

    event["event_hash"] = (
        _event_hash(event)
    )

    ledger["events"].append(
        event
    )

    ledger["updated_at"] = timestamp

    _refresh_integrity(
        ledger
    )


def _dependency_errors(
    ledger: dict[str, Any],
    stage_id: str,
) -> list[str]:
    definition = stage_definition(
        stage_id
    )

    errors: list[str] = []

    for dependency in definition[
        "required_dependencies"
    ]:
        status = ledger["stages"][
            dependency
        ]["status"]

        if status not in PASS_STATUSES:
            errors.append(
                f"Required dependency {dependency} "
                f"is {status}, not passed."
            )

    for dependency in definition[
        "optional_dependencies"
    ]:
        status = ledger["stages"][
            dependency
        ]["status"]

        if status not in OPTIONAL_TERMINAL_STATUSES:
            errors.append(
                f"Optional dependency {dependency} "
                f"is {status}, not terminal."
            )

    return errors


def _has_blocked_upstream(
    ledger: dict[str, Any],
    stage_id: str,
) -> bool:
    definition = stage_definition(
        stage_id
    )

    dependencies = (
        definition[
            "required_dependencies"
        ]
        + definition[
            "optional_dependencies"
        ]
    )

    return any(
        ledger["stages"][
            dependency
        ]["status"]
        in {
            BLOCKED,
            FAILED,
            SKIPPED,
        }
        for dependency in dependencies
    )


def _derive_run_status(
    ledger: dict[str, Any],
) -> str:
    stages = ledger["stages"]

    if stages[
        "FINALIZATION"
    ]["status"] in PASS_STATUSES:
        return "COMPLETED"

    authoritative_ids = [
        definition["stage_id"]
        for definition in STAGE_DEFINITIONS
        if definition["authority"]
        == "AUTHORITATIVE"
    ]

    if any(
        stages[stage_id]["status"]
        == FAILED
        for stage_id in authoritative_ids
    ):
        return "FAILED"

    if any(
        stages[stage_id]["status"]
        == BLOCKED
        for stage_id in authoritative_ids
    ):
        return "BLOCKED"

    if (
        stages["SSVC"]["status"]
        in PASS_STATUSES
        and stages[
            "HUMAN_REVIEW"
        ]["status"]
        == PENDING
    ):
        optional_status = stages[
            "AGREEMENT_ANALYSIS"
        ]["status"]

        if optional_status in {
            PASSED,
            PASSED_WITH_WARNINGS,
            FAILED,
            BLOCKED,
            SKIPPED,
        }:
            return (
                "AWAITING_HUMAN_REVIEW"
            )

    if any(
        stage["status"] == RUNNING
        for stage in stages.values()
    ):
        return "IN_PROGRESS"

    if len(ledger["events"]) > 1:
        return "IN_PROGRESS"

    return "CREATED"


def create_assessment_ledger(
    *,
    input_id: str,
    input_envelope_sha256: str,
    created_by: str,
    asset_context_id: str | None = None,
    clock: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    if not input_id.strip():
        raise AssessmentLedgerError(
            "Input ID is required."
        )

    normalized_hash = (
        input_envelope_sha256
        .strip()
        .lower()
    )

    if (
        len(normalized_hash) != 64
        or any(
            character
            not in "0123456789abcdef"
            for character
            in normalized_hash
        )
    ):
        raise AssessmentLedgerError(
            "Input envelope SHA-256 "
            "must contain 64 hexadecimal characters."
        )

    if not created_by.strip():
        raise AssessmentLedgerError(
            "Assessment creator is required."
        )

    created_at = clock()

    assessment_id = _assessment_id(
        input_id=input_id.strip(),
        input_envelope_sha256=(
            normalized_hash
        ),
        created_at=created_at,
        created_by=created_by.strip(),
    )

    stage_plan = [
        copy.deepcopy(definition)
        for definition in STAGE_DEFINITIONS
    ]

    ledger: dict[str, Any] = {
        "schema_version": (
            SCHEMA_VERSION
        ),
        "assessment_id": (
            assessment_id
        ),
        "created_at": created_at,
        "updated_at": created_at,
        "run_status": "CREATED",
        "input_reference": {
            "input_id": input_id.strip(),
            "input_envelope_sha256": (
                normalized_hash
            ),
            "asset_context_id": (
                asset_context_id
            ),
        },
        "stage_plan": stage_plan,
        "stages": {
            definition["stage_id"]: (
                _new_stage_state()
            )
            for definition
            in STAGE_DEFINITIONS
        },
        "events": [],
        "governance": {
            "affectedness_authority": (
                "DETERMINISTIC_ENGINE"
            ),
            "policy_authority": "SSVC",
            "model_authority": (
                "ADVISORY_ONLY"
            ),
            "final_disposition_authority": (
                "HUMAN"
            ),
            "automated_final_disposition_permitted": (
                False
            ),
            "production_readiness": (
                "BLOCKED"
            ),
        },
        "integrity": {},
    }

    _append_event(
        ledger,
        event_type="RUN_CREATED",
        stage_id=None,
        from_status=None,
        to_status=None,
        actor_type="SYSTEM",
        actor_id=created_by.strip(),
        reason_code=None,
        message=(
            "Assessment run ledger created."
        ),
        metadata={
            "asset_context_id": (
                asset_context_id
            ),
        },
        timestamp=created_at,
    )

    ledger["run_status"] = (
        _derive_run_status(ledger)
    )

    _refresh_integrity(
        ledger
    )

    return ledger


def transition_stage(
    ledger: dict[str, Any],
    *,
    stage_id: str,
    to_status: str,
    actor_type: str,
    actor_id: str,
    reason_code: str | None = None,
    message: str | None = None,
    warnings: list[str] | None = None,
    outputs: list[
        dict[str, Any]
    ] | None = None,
    metadata: dict[str, Any] | None = None,
    clock: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    valid, errors = verify_ledger(
        ledger
    )

    if not valid:
        raise AssessmentLedgerError(
            "Ledger integrity verification failed: "
            + "; ".join(errors)
        )

    if actor_type not in {
        "SYSTEM",
        "ENGINE",
        "HUMAN",
        "TEST",
    }:
        raise AssessmentLedgerError(
            f"Unsupported actor type: {actor_type}"
        )

    if not actor_id.strip():
        raise AssessmentLedgerError(
            "Actor ID is required."
        )

    definition = stage_definition(
        stage_id
    )

    current_status = ledger[
        "stages"
    ][stage_id]["status"]

    allowed = ALLOWED_TRANSITIONS[
        current_status
    ]

    if to_status not in allowed:
        raise AssessmentLedgerError(
            f"Illegal transition for {stage_id}: "
            f"{current_status} -> {to_status}"
        )

    normalized_warnings = [
        warning.strip()
        for warning in (
            warnings
            or []
        )
        if warning.strip()
    ]

    normalized_outputs = (
        copy.deepcopy(outputs)
        if outputs
        else []
    )

    if (
        to_status
        == PASSED_WITH_WARNINGS
        and not normalized_warnings
    ):
        raise AssessmentLedgerError(
            "PASSED_WITH_WARNINGS "
            "requires at least one warning."
        )

    if (
        to_status
        in {
            BLOCKED,
            FAILED,
            SKIPPED,
        }
        and not (
            reason_code
            and reason_code.strip()
        )
    ):
        raise AssessmentLedgerError(
            f"{to_status} requires "
            "a reason code."
        )

    if (
        current_status == PENDING
        and to_status == RUNNING
    ):
        dependency_errors = (
            _dependency_errors(
                ledger,
                stage_id,
            )
        )

        if dependency_errors:
            raise AssessmentLedgerError(
                "Stage dependencies are not satisfied: "
                + "; ".join(
                    dependency_errors
                )
            )

    if (
        current_status == PENDING
        and to_status == SKIPPED
        and definition["required"]
        and not _has_blocked_upstream(
            ledger,
            stage_id,
        )
    ):
        raise AssessmentLedgerError(
            "A required stage may only be skipped "
            "after an upstream block, failure or skip."
        )

    updated = copy.deepcopy(
        ledger
    )

    timestamp = clock()

    stage = updated[
        "stages"
    ][stage_id]

    if to_status == RUNNING:
        stage["attempt"] += 1
        stage["started_at"] = timestamp
        stage["completed_at"] = None
    else:
        stage["completed_at"] = timestamp

    stage["status"] = to_status
    stage["reason_code"] = (
        reason_code.strip()
        if reason_code
        else None
    )
    stage["message"] = (
        message.strip()
        if message
        else None
    )
    stage["warnings"] = (
        normalized_warnings
    )
    stage["outputs"] = (
        normalized_outputs
    )

    _append_event(
        updated,
        event_type=(
            "STAGE_TRANSITION"
        ),
        stage_id=stage_id,
        from_status=current_status,
        to_status=to_status,
        actor_type=actor_type,
        actor_id=actor_id.strip(),
        reason_code=(
            reason_code.strip()
            if reason_code
            else None
        ),
        message=(
            message.strip()
            if message
            else None
        ),
        metadata={
            **(
                copy.deepcopy(metadata)
                if metadata
                else {}
            ),
            "warnings": (
                normalized_warnings
            ),
            "outputs": (
                normalized_outputs
            ),
        },
        timestamp=timestamp,
    )

    updated["run_status"] = (
        _derive_run_status(updated)
    )

    _refresh_integrity(
        updated
    )

    valid, errors = verify_ledger(
        updated
    )

    if not valid:
        raise AssessmentLedgerError(
            "Updated ledger failed verification: "
            + "; ".join(errors)
        )

    return updated


def verify_ledger(
    ledger: dict[str, Any],
) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if not isinstance(
        ledger,
        dict,
    ):
        return False, [
            "Ledger must be an object."
        ]

    events = ledger.get("events")

    if not isinstance(
        events,
        list,
    ) or not events:
        return False, [
            "Ledger must contain events."
        ]

    previous_hash = GENESIS_HASH

    reconstructed_status = {
        definition["stage_id"]: (
            PENDING
        )
        for definition
        in STAGE_DEFINITIONS
    }

    for expected_sequence, event in enumerate(
        events,
        start=1,
    ):
        if not isinstance(
            event,
            dict,
        ):
            errors.append(
                f"Event {expected_sequence} "
                "is not an object."
            )
            continue

        if (
            event.get("sequence")
            != expected_sequence
        ):
            errors.append(
                f"Event sequence mismatch "
                f"at {expected_sequence}."
            )

        if (
            event.get(
                "previous_event_hash"
            )
            != previous_hash
        ):
            errors.append(
                f"Previous-event hash mismatch "
                f"at sequence {expected_sequence}."
            )

        observed_hash = (
            event.get("event_hash")
        )

        expected_hash = _event_hash(
            event
        )

        if observed_hash != expected_hash:
            errors.append(
                f"Event hash mismatch "
                f"at sequence {expected_sequence}."
            )

        if isinstance(
            observed_hash,
            str,
        ):
            previous_hash = (
                observed_hash
            )

        stage_id = event.get(
            "stage_id"
        )

        to_status = event.get(
            "to_status"
        )

        if stage_id is not None:
            if (
                stage_id
                not in reconstructed_status
            ):
                errors.append(
                    f"Unknown stage in event "
                    f"{expected_sequence}: "
                    f"{stage_id}"
                )
                continue

            from_status = event.get(
                "from_status"
            )

            expected_from = (
                reconstructed_status[
                    stage_id
                ]
            )

            if from_status != expected_from:
                errors.append(
                    f"Stage history mismatch for "
                    f"{stage_id} at event "
                    f"{expected_sequence}."
                )

            if (
                to_status
                not in ALLOWED_TRANSITIONS[
                    expected_from
                ]
            ):
                errors.append(
                    f"Illegal historical transition "
                    f"for {stage_id}: "
                    f"{expected_from} -> "
                    f"{to_status}"
                )
            else:
                reconstructed_status[
                    stage_id
                ] = to_status

    integrity = ledger.get(
        "integrity"
    )

    if not isinstance(
        integrity,
        dict,
    ):
        errors.append(
            "Integrity block is missing."
        )
    else:
        if (
            integrity.get(
                "event_count"
            )
            != len(events)
        ):
            errors.append(
                "Integrity event count mismatch."
            )

        if (
            integrity.get(
                "head_event_hash"
            )
            != previous_hash
        ):
            errors.append(
                "Integrity head hash mismatch."
            )

        if (
            integrity.get(
                "genesis_hash"
            )
            != GENESIS_HASH
        ):
            errors.append(
                "Genesis hash mismatch."
            )

        if (
            integrity.get(
                "ledger_sha256"
            )
            != _ledger_hash(ledger)
        ):
            errors.append(
                "Ledger SHA-256 mismatch."
            )

    stages = ledger.get(
        "stages"
    )

    if not isinstance(
        stages,
        dict,
    ):
        errors.append(
            "Stage state block is missing."
        )
    else:
        for stage_id, status in (
            reconstructed_status.items()
        ):
            observed_state = stages.get(
                stage_id
            )

            if not isinstance(
                observed_state,
                dict,
            ):
                errors.append(
                    f"Stage state missing: "
                    f"{stage_id}"
                )
                continue

            if (
                observed_state.get(
                    "status"
                )
                != status
            ):
                errors.append(
                    f"Current stage state mismatch: "
                    f"{stage_id}"
                )

    expected_run_status = (
        _derive_run_status(ledger)
    )

    if (
        ledger.get("run_status")
        != expected_run_status
    ):
        errors.append(
            "Run status does not match "
            "derived stage state."
        )

    return not errors, errors


def write_ledger_atomic(
    ledger: dict[str, Any],
    path: Path,
) -> tuple[Path, Path]:
    valid, errors = verify_ledger(
        ledger
    )

    if not valid:
        raise AssessmentLedgerError(
            "Cannot write invalid ledger: "
            + "; ".join(errors)
        )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_name(
        "." + path.name + ".partial"
    )

    payload = canonical_json_bytes(
        ledger
    )

    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(
            handle.fileno()
        )

    os.replace(
        temporary,
        path,
    )

    digest = sha256_bytes(
        payload
    )

    sidecar = Path(
        str(path) + ".sha256"
    )

    sidecar.write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
    )

    return path, sidecar


def load_ledger(
    path: Path,
) -> dict[str, Any]:
    document = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    valid, errors = verify_ledger(
        document
    )

    if not valid:
        raise AssessmentLedgerError(
            "Loaded ledger failed verification: "
            + "; ".join(errors)
        )

    return document

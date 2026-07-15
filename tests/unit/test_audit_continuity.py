from pathlib import Path

import pytest

from src.governance.audit_continuity import (
    AuditContinuityError,
    AuditEvent,
    AuditLedger,
    verify_audit_chain,
)


NOW = "2026-07-15T10:00:00+00:00"


def test_audit_ledger_builds_valid_hash_chain(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.json")
    ledger.append(
        event_id="A-1", event_type="validate", occurred_at=NOW,
        subject_id="D-1", payload={"valid": True}
    )
    ledger.append(
        event_id="A-2", event_type="release", occurred_at=NOW,
        subject_id="D-1", payload={"released": False}
    )
    verification = ledger.verify()
    assert verification.valid
    assert verification.event_count == 2


def test_identical_audit_redrive_is_idempotent(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.json")
    first = ledger.append(
        event_id="A-1", event_type="validate", occurred_at=NOW,
        subject_id="D-1", payload={"valid": True}
    )
    repeated = ledger.append(
        event_id="A-1", event_type="validate", occurred_at=NOW,
        subject_id="D-1", payload={"valid": True}
    )
    assert repeated.event_hash == first.event_hash
    assert ledger.verify().event_count == 1


def test_conflicting_event_id_is_rejected(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.json")
    ledger.append(
        event_id="A-1", event_type="validate", occurred_at=NOW,
        subject_id="D-1", payload={"valid": True}
    )
    with pytest.raises(AuditContinuityError):
        ledger.append(
            event_id="A-1", event_type="validate", occurred_at=NOW,
            subject_id="D-1", payload={"valid": False}
        )


def test_sequence_gap_is_detected() -> None:
    first = AuditEvent(
        sequence=1, event_id="A-1", event_type="validate", occurred_at=NOW,
        subject_id="D-1", payload={}, previous_hash="0" * 64
    ).finalized()
    third = AuditEvent(
        sequence=3, event_id="A-3", event_type="release", occurred_at=NOW,
        subject_id="D-1", payload={}, previous_hash=first.event_hash
    ).finalized()
    result = verify_audit_chain([first, third])
    assert not result.valid
    assert "AUDIT_SEQUENCE_GAP" in result.finding_codes


def test_hash_tamper_is_detected() -> None:
    first = AuditEvent(
        sequence=1, event_id="A-1", event_type="validate", occurred_at=NOW,
        subject_id="D-1", payload={"valid": True}, previous_hash="0" * 64
    ).finalized()
    tampered = AuditEvent.from_dict(first.to_dict() | {"payload": {"valid": False}})
    result = verify_audit_chain([tampered])
    assert not result.valid
    assert "AUDIT_EVENT_HASH_MISMATCH" in result.finding_codes


def test_previous_hash_break_is_detected() -> None:
    first = AuditEvent(
        sequence=1, event_id="A-1", event_type="validate", occurred_at=NOW,
        subject_id="D-1", payload={}, previous_hash="0" * 64
    ).finalized()
    second = AuditEvent(
        sequence=2, event_id="A-2", event_type="release", occurred_at=NOW,
        subject_id="D-1", payload={}, previous_hash="f" * 64
    ).finalized()
    result = verify_audit_chain([first, second])
    assert not result.valid
    assert "AUDIT_PREVIOUS_HASH_MISMATCH" in result.finding_codes

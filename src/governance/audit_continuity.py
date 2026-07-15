from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from src.governance.recovery_checkpoint import atomic_write_json


class AuditContinuityError(RuntimeError):
    """Raised when the audit ledger is structurally invalid."""


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_id: str
    event_type: str
    occurred_at: str
    subject_id: str
    payload: Mapping[str, Any]
    previous_hash: str
    event_hash: str = ""

    def __post_init__(self) -> None:
        if self.sequence < 1:
            raise AuditContinuityError("Audit sequence must be positive.")
        if not self.event_id or not self.event_type or not self.subject_id:
            raise AuditContinuityError(
                "Audit event requires event_id, event_type, and subject_id."
            )
        if self.sequence == 1 and self.previous_hash != "0" * 64:
            raise AuditContinuityError(
                "The first audit event must reference the genesis hash."
            )
        if len(self.previous_hash) != 64:
            raise AuditContinuityError("Audit previous_hash must be SHA-256.")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "subject_id": self.subject_id,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }

    def calculated_hash(self) -> str:
        encoded = json.dumps(
            self.unsigned_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def finalized(self) -> "AuditEvent":
        return AuditEvent(
            **(self.unsigned_dict() | {"event_hash": self.calculated_hash()})
        )

    def verify(self) -> bool:
        return self.event_hash == self.calculated_hash()

    def to_dict(self) -> dict[str, Any]:
        return self.unsigned_dict() | {"event_hash": self.event_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuditEvent":
        return cls(
            sequence=int(value["sequence"]),
            event_id=str(value["event_id"]),
            event_type=str(value["event_type"]),
            occurred_at=str(value["occurred_at"]),
            subject_id=str(value["subject_id"]),
            payload=dict(value.get("payload", {})),
            previous_hash=str(value["previous_hash"]),
            event_hash=str(value.get("event_hash", "")),
        )


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    event_count: int
    last_hash: str | None
    finding_codes: tuple[str, ...]
    gap_sequences: tuple[int, ...] = ()
    duplicate_event_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "event_count": self.event_count,
            "last_hash": self.last_hash,
            "finding_codes": list(self.finding_codes),
            "gap_sequences": list(self.gap_sequences),
            "duplicate_event_ids": list(self.duplicate_event_ids),
        }


def verify_audit_chain(events: Iterable[AuditEvent]) -> AuditVerification:
    ordered = list(events)
    findings: set[str] = set()
    gaps: list[int] = []
    duplicates: list[str] = []
    seen_ids: set[str] = set()
    expected_previous = "0" * 64
    expected_sequence = 1

    for event in ordered:
        if event.sequence != expected_sequence:
            findings.add("AUDIT_SEQUENCE_GAP")
            gaps.append(expected_sequence)
            expected_sequence = event.sequence
        if event.event_id in seen_ids:
            findings.add("AUDIT_DUPLICATE_EVENT_ID")
            duplicates.append(event.event_id)
        seen_ids.add(event.event_id)
        if event.previous_hash != expected_previous:
            findings.add("AUDIT_PREVIOUS_HASH_MISMATCH")
        if not event.verify():
            findings.add("AUDIT_EVENT_HASH_MISMATCH")
        expected_previous = event.event_hash
        expected_sequence = event.sequence + 1

    return AuditVerification(
        valid=not findings,
        event_count=len(ordered),
        last_hash=ordered[-1].event_hash if ordered else None,
        finding_codes=tuple(sorted(findings)),
        gap_sequences=tuple(gaps),
        duplicate_event_ids=tuple(sorted(set(duplicates))),
    )


class AuditLedger:
    """Integrity-chained audit ledger persisted through atomic replacement."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def load(self) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuditContinuityError(
                f"Audit ledger cannot be decoded: {self.path}"
            ) from exc
        if not isinstance(document, dict) or not isinstance(
            document.get("events"), list
        ):
            raise AuditContinuityError("Audit ledger has an invalid structure.")
        events = [AuditEvent.from_dict(item) for item in document["events"]]
        verification = verify_audit_chain(events)
        if not verification.valid:
            raise AuditContinuityError(
                "Audit ledger integrity verification failed: "
                + ", ".join(verification.finding_codes)
            )
        return events

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        occurred_at: str,
        subject_id: str,
        payload: Mapping[str, Any],
        fault_hook=None,
    ) -> AuditEvent:
        events = self.load()
        if any(event.event_id == event_id for event in events):
            existing = next(event for event in events if event.event_id == event_id)
            candidate = AuditEvent(
                sequence=existing.sequence,
                event_id=event_id,
                event_type=event_type,
                occurred_at=occurred_at,
                subject_id=subject_id,
                payload=dict(payload),
                previous_hash=existing.previous_hash,
            ).finalized()
            if candidate.event_hash == existing.event_hash:
                return existing
            raise AuditContinuityError(
                "Audit event ID reuse attempted with different content."
            )
        previous_hash = events[-1].event_hash if events else "0" * 64
        event = AuditEvent(
            sequence=len(events) + 1,
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            subject_id=subject_id,
            payload=dict(payload),
            previous_hash=previous_hash,
        ).finalized()
        updated = events + [event]
        atomic_write_json(
            self.path,
            {
                "schema_version": "1.0.0",
                "event_count": len(updated),
                "last_hash": event.event_hash,
                "events": [item.to_dict() for item in updated],
            },
            fault_hook=fault_hook,
        )
        return event

    def verify(self) -> AuditVerification:
        try:
            events = self.load()
        except AuditContinuityError:
            try:
                document = json.loads(self.path.read_text(encoding="utf-8"))
                raw_events = document.get("events", [])
                events = [AuditEvent.from_dict(item) for item in raw_events]
            except Exception:
                return AuditVerification(
                    valid=False,
                    event_count=0,
                    last_hash=None,
                    finding_codes=("AUDIT_LEDGER_UNREADABLE",),
                )
        return verify_audit_chain(events)

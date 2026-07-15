from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


TEMPORAL_OUTCOMES = {
    "ACCEPTED_CURRENT",
    "REJECTED_STALE",
    "REJECTED_REPLAY",
    "QUARANTINED_CONFLICT",
    "BLOCKED_VERSION_DRIFT",
    "BLOCKED_INTEGRITY_CHANGE",
    "RETRY_REQUIRED",
}


class TemporalGuardError(ValueError):
    """Raised when a temporal control input is structurally invalid."""


@dataclass(frozen=True)
class TemporalFinding:
    code: str
    control: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "control": self.control,
            "message": self.message,
        }


@dataclass
class TemporalGuardResult:
    outcome: str
    defended: bool
    unsafe_decision_released: bool
    findings: list[TemporalFinding] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.outcome not in TEMPORAL_OUTCOMES:
            raise TemporalGuardError(
                f"Unsupported temporal outcome: {self.outcome!r}"
            )

    @property
    def detection_oracles(self) -> list[str]:
        return sorted({item.control for item in self.findings})

    @property
    def finding_codes(self) -> list[str]:
        return sorted({item.code for item in self.findings})

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "defended": self.defended,
            "unsafe_decision_released": self.unsafe_decision_released,
            "detection_oracles": self.detection_oracles,
            "finding_codes": self.finding_codes,
            "findings": [item.to_dict() for item in self.findings],
            "details": copy.deepcopy(self.details),
        }


@dataclass(frozen=True)
class DeterministicClock:
    now: datetime

    def __post_init__(self) -> None:
        if self.now.tzinfo is None:
            raise TemporalGuardError(
                "Deterministic clock must use a timezone-aware datetime."
            )

    @classmethod
    def from_iso(cls, value: str) -> "DeterministicClock":
        return cls(parse_utc(value))

    def isoformat(self) -> str:
        return self.now.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class TemporalEvent:
    event_id: str
    stream_id: str
    sequence: int
    revision: int
    event_time: datetime
    ingestion_time: datetime
    payload_hash: str
    policy_version: str
    transaction_id: str | None = None
    event_type: str = "update"

    def __post_init__(self) -> None:
        if not self.event_id or not self.stream_id:
            raise TemporalGuardError(
                "Temporal event requires event_id and stream_id."
            )
        if self.sequence < 1 or self.revision < 1:
            raise TemporalGuardError(
                "Temporal sequence and revision must be positive integers."
            )
        if self.event_time.tzinfo is None or self.ingestion_time.tzinfo is None:
            raise TemporalGuardError(
                "Temporal event timestamps must be timezone-aware."
            )
        if len(self.payload_hash) != 64 or any(
            character not in "0123456789abcdef"
            for character in self.payload_hash
        ):
            raise TemporalGuardError(
                "Temporal event payload_hash must be lowercase SHA-256."
            )


@dataclass
class TemporalStreamState:
    stream_id: str
    last_sequence: int = 0
    last_revision: int = 0
    last_event_time: datetime | None = None
    latest_payload_hash: str | None = None
    policy_version: str | None = None
    seen_events: dict[str, dict[str, Any]] = field(default_factory=dict)
    seen_payload_hashes: set[str] = field(default_factory=set)
    revoked: bool = False

    def clone(self) -> "TemporalStreamState":
        return copy.deepcopy(self)


@dataclass(frozen=True)
class TemporalSnapshot:
    snapshot_id: str
    logical_times: Mapping[str, datetime]
    policy_version_start: str
    policy_version_end: str
    expected_policy_version: str
    content_hashes_before: Mapping[str, str]
    content_hashes_after: Mapping[str, str]
    transaction_committed: bool = True
    manifest_committed: bool = True
    revoked_record_ids: tuple[str, ...] = ()
    cache_revision: int | None = None
    required_revision: int | None = None


@dataclass(frozen=True)
class TemporalGuardPolicy:
    max_future_skew_seconds: int = 300
    max_clock_skew_seconds: int = 120
    max_snapshot_skew_seconds: int = 60
    expiry_boundary_inclusive: bool = True

    def __post_init__(self) -> None:
        for field_name, value in (
            ("max_future_skew_seconds", self.max_future_skew_seconds),
            ("max_clock_skew_seconds", self.max_clock_skew_seconds),
            ("max_snapshot_skew_seconds", self.max_snapshot_skew_seconds),
        ):
            if value < 0:
                raise TemporalGuardError(
                    f"{field_name} must be non-negative."
                )


def parse_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    else:
        raise TemporalGuardError(
            f"Timestamp must be a string or datetime, not {type(value)!r}."
        )
    if parsed.tzinfo is None:
        raise TemporalGuardError("Timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def canonical_payload_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _finding(code: str, control: str, message: str) -> TemporalFinding:
    return TemporalFinding(code=code, control=control, message=message)


class TemporalDecisionGuard:
    """
    Deterministic temporal guard for event streams and atomic decisions.

    The guard is deliberately free of wall-clock reads. Callers inject an
    explicit clock and explicit stream/snapshot state, making outcomes
    reproducible and suitable for audit and replay.
    """

    def __init__(
        self,
        clock: DeterministicClock,
        policy: TemporalGuardPolicy | None = None,
    ) -> None:
        self.clock = clock
        self.policy = policy or TemporalGuardPolicy()

    def evaluate_freshness(
        self,
        observed_at: str | datetime,
        maximum_age_seconds: int,
        expires_at: str | datetime | None = None,
    ) -> TemporalGuardResult:
        if maximum_age_seconds < 0:
            raise TemporalGuardError(
                "maximum_age_seconds must be non-negative."
            )
        observed = parse_utc(observed_at)
        now = self.clock.now.astimezone(timezone.utc)
        future_delta = (observed - now).total_seconds()
        if future_delta > self.policy.max_future_skew_seconds:
            return TemporalGuardResult(
                outcome="QUARANTINED_CONFLICT",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "FUTURE_OBSERVATION_EXCEEDS_SKEW",
                        "CLOCK_SKEW_GUARD",
                        "Observation time exceeds the permitted future skew.",
                    )
                ],
                details={
                    "observed_at": observed.isoformat(),
                    "evaluated_at": now.isoformat(),
                    "future_skew_seconds": future_delta,
                },
            )
        if expires_at is not None:
            expiry = parse_utc(expires_at)
            expired = (
                now > expiry
                if self.policy.expiry_boundary_inclusive
                else now >= expiry
            )
            if expired:
                return TemporalGuardResult(
                    outcome="REJECTED_STALE",
                    defended=True,
                    unsafe_decision_released=False,
                    findings=[
                        _finding(
                            "EVIDENCE_EXPIRED",
                            "EXPIRY_GUARD",
                            "The record expired before temporal evaluation.",
                        )
                    ],
                    details={
                        "observed_at": observed.isoformat(),
                        "expires_at": expiry.isoformat(),
                        "evaluated_at": now.isoformat(),
                    },
                )
        age_seconds = max(0.0, (now - observed).total_seconds())
        if age_seconds > maximum_age_seconds:
            return TemporalGuardResult(
                outcome="REJECTED_STALE",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "FRESHNESS_WINDOW_EXCEEDED",
                        "FRESHNESS_GUARD",
                        "The record exceeds its permitted freshness window.",
                    )
                ],
                details={
                    "observed_at": observed.isoformat(),
                    "evaluated_at": now.isoformat(),
                    "age_seconds": age_seconds,
                    "maximum_age_seconds": maximum_age_seconds,
                },
            )
        return TemporalGuardResult(
            outcome="ACCEPTED_CURRENT",
            defended=True,
            unsafe_decision_released=False,
            findings=[
                _finding(
                    "RECORD_WITHIN_FRESHNESS_WINDOW",
                    "FRESHNESS_GUARD",
                    "The record is current at the injected evaluation time.",
                )
            ],
            details={
                "observed_at": observed.isoformat(),
                "evaluated_at": now.isoformat(),
                "age_seconds": age_seconds,
                "maximum_age_seconds": maximum_age_seconds,
            },
        )

    def evaluate_event(
        self,
        event: TemporalEvent,
        state: TemporalStreamState,
    ) -> TemporalGuardResult:
        if event.stream_id != state.stream_id:
            raise TemporalGuardError(
                "Event stream_id does not match the supplied stream state."
            )
        now = self.clock.now.astimezone(timezone.utc)
        event_time = event.event_time.astimezone(timezone.utc)
        ingestion_time = event.ingestion_time.astimezone(timezone.utc)
        prior = state.seen_events.get(event.event_id)
        if prior is not None:
            identical = (
                prior["payload_hash"] == event.payload_hash
                and prior["sequence"] == event.sequence
                and prior["revision"] == event.revision
            )
            if identical:
                return TemporalGuardResult(
                    outcome="ACCEPTED_CURRENT",
                    defended=True,
                    unsafe_decision_released=False,
                    findings=[
                        _finding(
                            "IDEMPOTENT_EVENT_REPLAY_NOOP",
                            "IDEMPOTENCY_GUARD",
                            "An identical replay was treated as a no-op.",
                        )
                    ],
                    details={"state_changed": False},
                )
            return TemporalGuardResult(
                outcome="REJECTED_REPLAY",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "EVENT_ID_REUSED_WITH_DIFFERENT_CONTENT",
                        "REPLAY_GUARD",
                        "The same event identifier was reused with different content.",
                    )
                ],
                details={"state_changed": False},
            )
        if event.payload_hash in state.seen_payload_hashes:
            return TemporalGuardResult(
                outcome="REJECTED_REPLAY",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "PAYLOAD_REPLAYED_UNDER_NEW_EVENT_ID",
                        "REPLAY_GUARD",
                        "Previously accepted content was replayed under a new event ID.",
                    )
                ],
                details={"state_changed": False},
            )
        if state.revoked and event.event_type != "revocation":
            return TemporalGuardResult(
                outcome="BLOCKED_INTEGRITY_CHANGE",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "UPDATE_AFTER_REVOCATION",
                        "REVOCATION_GUARD",
                        "A revoked stream cannot receive an ordinary update.",
                    )
                ],
                details={"state_changed": False},
            )
        future_skew = (event_time - now).total_seconds()
        if future_skew > self.policy.max_future_skew_seconds:
            return TemporalGuardResult(
                outcome="QUARANTINED_CONFLICT",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "EVENT_TIME_EXCEEDS_FUTURE_SKEW",
                        "CLOCK_SKEW_GUARD",
                        "Event time exceeds the permitted future skew.",
                    )
                ],
                details={"state_changed": False},
            )
        ingestion_lead = (event_time - ingestion_time).total_seconds()
        if ingestion_lead > self.policy.max_clock_skew_seconds:
            return TemporalGuardResult(
                outcome="QUARANTINED_CONFLICT",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "INGESTION_PRECEDES_EVENT_BEYOND_SKEW",
                        "CLOCK_SKEW_GUARD",
                        "Ingestion precedes the claimed event time beyond tolerance.",
                    )
                ],
                details={"state_changed": False},
            )
        if state.policy_version is not None and (
            event.policy_version != state.policy_version
        ):
            return TemporalGuardResult(
                outcome="BLOCKED_VERSION_DRIFT",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "EVENT_POLICY_VERSION_DRIFT",
                        "POLICY_VERSION_PIN",
                        "The event policy version differs from the pinned stream version.",
                    )
                ],
                details={"state_changed": False},
            )
        if state.last_sequence > 0:
            if event.sequence < state.last_sequence:
                return TemporalGuardResult(
                    outcome="REJECTED_REPLAY",
                    defended=True,
                    unsafe_decision_released=False,
                    findings=[
                        _finding(
                            "EVENT_SEQUENCE_ROLLBACK",
                            "EVENT_ORDER_GUARD",
                            "Event sequence moved backwards.",
                        )
                    ],
                    details={"state_changed": False},
                )
            if event.sequence == state.last_sequence:
                if event.revision < state.last_revision:
                    return TemporalGuardResult(
                        outcome="REJECTED_STALE",
                        defended=True,
                        unsafe_decision_released=False,
                        findings=[
                            _finding(
                                "STALE_REVISION_FOR_CURRENT_SEQUENCE",
                                "REVISION_GUARD",
                                "An older revision attempted to replace the current state.",
                            )
                        ],
                        details={"state_changed": False},
                    )
                return TemporalGuardResult(
                    outcome="QUARANTINED_CONFLICT",
                    defended=True,
                    unsafe_decision_released=False,
                    findings=[
                        _finding(
                            "CONFLICTING_UPDATE_FOR_CURRENT_SEQUENCE",
                            "CONCURRENCY_GUARD",
                            "Concurrent content conflicts at the current sequence.",
                        )
                    ],
                    details={"state_changed": False},
                )
            if event.sequence > state.last_sequence + 1:
                return TemporalGuardResult(
                    outcome="QUARANTINED_CONFLICT",
                    defended=True,
                    unsafe_decision_released=False,
                    findings=[
                        _finding(
                            "EVENT_SEQUENCE_GAP",
                            "EVENT_ORDER_GUARD",
                            "A sequence gap prevents a complete state reconstruction.",
                        )
                    ],
                    details={"state_changed": False},
                )
            if event.revision <= state.last_revision:
                return TemporalGuardResult(
                    outcome="REJECTED_STALE",
                    defended=True,
                    unsafe_decision_released=False,
                    findings=[
                        _finding(
                            "EVENT_REVISION_NOT_MONOTONIC",
                            "REVISION_GUARD",
                            "The new event does not advance the stream revision.",
                        )
                    ],
                    details={"state_changed": False},
                )
            if state.last_event_time is not None:
                rollback = (
                    state.last_event_time.astimezone(timezone.utc)
                    - event_time
                ).total_seconds()
                if rollback > self.policy.max_clock_skew_seconds:
                    return TemporalGuardResult(
                        outcome="QUARANTINED_CONFLICT",
                        defended=True,
                        unsafe_decision_released=False,
                        findings=[
                            _finding(
                                "EVENT_TIME_ROLLBACK",
                                "EVENT_ORDER_GUARD",
                                "A later sequence carries a materially older event time.",
                            )
                        ],
                        details={"state_changed": False},
                    )
        state.last_sequence = event.sequence
        state.last_revision = event.revision
        state.last_event_time = event_time
        state.latest_payload_hash = event.payload_hash
        state.policy_version = state.policy_version or event.policy_version
        state.seen_events[event.event_id] = {
            "payload_hash": event.payload_hash,
            "sequence": event.sequence,
            "revision": event.revision,
        }
        state.seen_payload_hashes.add(event.payload_hash)
        if event.event_type == "revocation":
            state.revoked = True
        return TemporalGuardResult(
            outcome="ACCEPTED_CURRENT",
            defended=True,
            unsafe_decision_released=False,
            findings=[
                _finding(
                    "EVENT_ACCEPTED_MONOTONICALLY",
                    "EVENT_ORDER_GUARD",
                    "The event advanced the stream monotonically.",
                )
            ],
            details={"state_changed": True},
        )

    def evaluate_snapshot(
        self,
        snapshot: TemporalSnapshot,
    ) -> TemporalGuardResult:
        if snapshot.policy_version_start != snapshot.expected_policy_version:
            return TemporalGuardResult(
                outcome="BLOCKED_VERSION_DRIFT",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "SNAPSHOT_POLICY_VERSION_NOT_PINNED",
                        "POLICY_VERSION_PIN",
                        "Snapshot began under an unexpected policy version.",
                    )
                ],
            )
        if snapshot.policy_version_end != snapshot.policy_version_start:
            return TemporalGuardResult(
                outcome="BLOCKED_VERSION_DRIFT",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "POLICY_CHANGED_DURING_EVALUATION",
                        "POLICY_VERSION_PIN",
                        "Policy version changed while the decision was evaluated.",
                    )
                ],
            )
        changed = sorted(
            key
            for key in set(snapshot.content_hashes_before)
            | set(snapshot.content_hashes_after)
            if snapshot.content_hashes_before.get(key)
            != snapshot.content_hashes_after.get(key)
        )
        if changed:
            return TemporalGuardResult(
                outcome="BLOCKED_INTEGRITY_CHANGE",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "SNAPSHOT_CONTENT_CHANGED_AFTER_VALIDATION",
                        "TOCTOU_GUARD",
                        "One or more decision inputs changed after validation.",
                    )
                ],
                details={"changed_inputs": changed},
            )
        if snapshot.revoked_record_ids:
            return TemporalGuardResult(
                outcome="BLOCKED_INTEGRITY_CHANGE",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "SNAPSHOT_CONTAINS_REVOKED_RECORD",
                        "REVOCATION_GUARD",
                        "A record was revoked before decision release.",
                    )
                ],
                details={
                    "revoked_record_ids": list(snapshot.revoked_record_ids)
                },
            )
        if not snapshot.transaction_committed or not snapshot.manifest_committed:
            return TemporalGuardResult(
                outcome="RETRY_REQUIRED",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "ATOMIC_SNAPSHOT_NOT_COMMITTED",
                        "ATOMICITY_GUARD",
                        "The decision snapshot is incomplete and must be retried.",
                    )
                ],
            )
        if snapshot.logical_times:
            times = [
                value.astimezone(timezone.utc)
                for value in snapshot.logical_times.values()
            ]
            spread = (max(times) - min(times)).total_seconds()
            if spread > self.policy.max_snapshot_skew_seconds:
                return TemporalGuardResult(
                    outcome="RETRY_REQUIRED",
                    defended=True,
                    unsafe_decision_released=False,
                    findings=[
                        _finding(
                            "SNAPSHOT_LOGICAL_TIME_SKEW",
                            "SNAPSHOT_CONSISTENCY_GUARD",
                            "Decision inputs are not from one coherent logical time.",
                        )
                    ],
                    details={"logical_time_spread_seconds": spread},
                )
        if (
            snapshot.cache_revision is not None
            and snapshot.required_revision is not None
            and snapshot.cache_revision < snapshot.required_revision
        ):
            return TemporalGuardResult(
                outcome="REJECTED_STALE",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "CACHE_REVISION_STALE",
                        "CACHE_FRESHNESS_GUARD",
                        "Cached state is older than the required authoritative revision.",
                    )
                ],
            )
        return TemporalGuardResult(
            outcome="ACCEPTED_CURRENT",
            defended=True,
            unsafe_decision_released=False,
            findings=[
                _finding(
                    "ATOMIC_SNAPSHOT_ACCEPTED",
                    "SNAPSHOT_CONSISTENCY_GUARD",
                    "The decision snapshot is coherent and unchanged.",
                )
            ],
        )

    def evaluate_policy_pin(
        self,
        expected_version: str,
        observed_version: str,
        start_sha256: str | None = None,
        end_sha256: str | None = None,
    ) -> TemporalGuardResult:
        if observed_version != expected_version:
            return TemporalGuardResult(
                outcome="BLOCKED_VERSION_DRIFT",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "POLICY_VERSION_MISMATCH",
                        "POLICY_VERSION_PIN",
                        "Observed policy version differs from the pinned version.",
                    )
                ],
            )
        if (
            start_sha256 is not None
            and end_sha256 is not None
            and start_sha256 != end_sha256
        ):
            return TemporalGuardResult(
                outcome="BLOCKED_INTEGRITY_CHANGE",
                defended=True,
                unsafe_decision_released=False,
                findings=[
                    _finding(
                        "POLICY_BYTES_CHANGED_WITHOUT_VERSION_CHANGE",
                        "TOCTOU_GUARD",
                        "Policy content changed while retaining the same version.",
                    )
                ],
            )
        return TemporalGuardResult(
            outcome="ACCEPTED_CURRENT",
            defended=True,
            unsafe_decision_released=False,
            findings=[
                _finding(
                    "POLICY_VERSION_PIN_VERIFIED",
                    "POLICY_VERSION_PIN",
                    "Policy version and content pin are consistent.",
                )
            ],
        )

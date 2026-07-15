from __future__ import annotations

from datetime import timezone

import pytest

from src.governance.temporal_guard import (
    DeterministicClock,
    TemporalDecisionGuard,
    TemporalEvent,
    TemporalGuardError,
    TemporalSnapshot,
    TemporalStreamState,
    canonical_payload_hash,
    parse_utc,
)


def guard() -> TemporalDecisionGuard:
    return TemporalDecisionGuard(
        DeterministicClock.from_iso("2026-07-13T17:03:00Z")
    )


def event(
    event_id: str = "EV-001",
    sequence: int = 1,
    revision: int = 1,
    payload: str = "baseline",
    event_time: str = "2026-07-13T17:00:00Z",
    ingestion_time: str = "2026-07-13T17:00:10Z",
    policy_version: str = "1.0.0",
    event_type: str = "update",
) -> TemporalEvent:
    return TemporalEvent(
        event_id=event_id,
        stream_id="STREAM-001",
        sequence=sequence,
        revision=revision,
        event_time=parse_utc(event_time),
        ingestion_time=parse_utc(ingestion_time),
        payload_hash=canonical_payload_hash(payload),
        policy_version=policy_version,
        event_type=event_type,
    )


def test_parse_utc_requires_timezone() -> None:
    with pytest.raises(TemporalGuardError):
        parse_utc("2026-07-13T17:03:00")
    assert parse_utc("2026-07-13T17:03:00Z").tzinfo == timezone.utc


def test_freshness_accepts_current_and_rejects_stale() -> None:
    current = guard().evaluate_freshness(
        "2026-07-13T17:01:00Z", 86400
    )
    stale = guard().evaluate_freshness(
        "2026-07-12T16:00:00Z", 86400
    )
    assert current.outcome == "ACCEPTED_CURRENT"
    assert stale.outcome == "REJECTED_STALE"


def test_expiry_boundary_is_inclusive() -> None:
    at_boundary = guard().evaluate_freshness(
        "2026-07-13T17:01:00Z",
        86400,
        expires_at="2026-07-13T17:03:00Z",
    )
    after_boundary = guard().evaluate_freshness(
        "2026-07-13T17:01:00Z",
        86400,
        expires_at="2026-07-13T17:02:59Z",
    )
    assert at_boundary.outcome == "ACCEPTED_CURRENT"
    assert after_boundary.outcome == "REJECTED_STALE"


def test_future_observation_is_quarantined() -> None:
    result = guard().evaluate_freshness(
        "2026-07-13T17:20:00Z", 86400
    )
    assert result.outcome == "QUARANTINED_CONFLICT"
    assert "CLOCK_SKEW_GUARD" in result.detection_oracles


def test_identical_event_replay_is_idempotent() -> None:
    state = TemporalStreamState(stream_id="STREAM-001")
    first = event()
    assert guard().evaluate_event(first, state).outcome == "ACCEPTED_CURRENT"
    before = state.clone()
    replay = guard().evaluate_event(first, state)
    assert replay.outcome == "ACCEPTED_CURRENT"
    assert replay.details["state_changed"] is False
    assert state == before


def test_event_id_reuse_with_changed_content_is_rejected() -> None:
    state = TemporalStreamState(stream_id="STREAM-001")
    guard().evaluate_event(event(), state)
    replay = event(payload="changed")
    result = guard().evaluate_event(replay, state)
    assert result.outcome == "REJECTED_REPLAY"
    assert "REPLAY_GUARD" in result.detection_oracles


def test_sequence_gap_and_policy_version_drift_fail_closed() -> None:
    state = TemporalStreamState(stream_id="STREAM-001")
    guard().evaluate_event(event(), state)
    gap = guard().evaluate_event(
        event(event_id="EV-003", sequence=3, revision=2, payload="gap"), state
    )
    drift = guard().evaluate_event(
        event(
            event_id="EV-002",
            sequence=2,
            revision=2,
            policy_version="1.1.0",
            payload="drift",
        ),
        state,
    )
    assert gap.outcome == "QUARANTINED_CONFLICT"
    assert drift.outcome == "BLOCKED_VERSION_DRIFT"


def test_snapshot_detects_toctou_and_version_drift() -> None:
    base = dict(
        snapshot_id="SNAP-001",
        logical_times={"evidence": parse_utc("2026-07-13T17:02:30Z")},
        expected_policy_version="1.0.0",
        content_hashes_before={"evidence": "a" * 64},
        transaction_committed=True,
        manifest_committed=True,
    )
    changed = TemporalSnapshot(
        **base,
        policy_version_start="1.0.0",
        policy_version_end="1.0.0",
        content_hashes_after={"evidence": "b" * 64},
    )
    drift = TemporalSnapshot(
        **base,
        policy_version_start="1.0.0",
        policy_version_end="1.1.0",
        content_hashes_after={"evidence": "a" * 64},
    )
    assert guard().evaluate_snapshot(changed).outcome == "BLOCKED_INTEGRITY_CHANGE"
    assert guard().evaluate_snapshot(drift).outcome == "BLOCKED_VERSION_DRIFT"


def test_atomic_snapshot_and_stale_cache_are_distinguished() -> None:
    common = dict(
        snapshot_id="SNAP-001",
        logical_times={
            "asset": parse_utc("2026-07-13T17:02:30Z"),
            "evidence": parse_utc("2026-07-13T17:02:40Z"),
        },
        policy_version_start="1.0.0",
        policy_version_end="1.0.0",
        expected_policy_version="1.0.0",
        content_hashes_before={"evidence": "a" * 64},
        content_hashes_after={"evidence": "a" * 64},
        transaction_committed=True,
        manifest_committed=True,
    )
    current = TemporalSnapshot(
        **common, cache_revision=3, required_revision=3
    )
    stale = TemporalSnapshot(
        **common, cache_revision=2, required_revision=3
    )
    assert guard().evaluate_snapshot(current).outcome == "ACCEPTED_CURRENT"
    assert guard().evaluate_snapshot(stale).outcome == "REJECTED_STALE"

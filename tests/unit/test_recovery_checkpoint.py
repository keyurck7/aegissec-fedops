from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.governance.recovery_checkpoint import (
    InjectedPersistenceFault,
    RecoveryCheckpoint,
    RecoveryCheckpointStore,
    RecoveryConflictError,
    RecoveryIntegrityError,
    atomic_write_bundle,
    atomic_write_bytes,
)


def checkpoint(*, completed: bool = False, owner: str = "worker-a") -> RecoveryCheckpoint:
    now = datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc).isoformat()
    return RecoveryCheckpoint(
        operation_id="OP-TEST",
        transaction_id="TX-TEST",
        state="completed" if completed else "validated",
        owner_id=owner,
        sequence=2 if completed else 1,
        policy_version="1.0.0",
        input_hashes={"input": "a" * 64},
        output_hashes={"output": "b" * 64} if completed else {},
        created_at=now,
        updated_at=now,
        completed=completed,
    )


def test_checkpoint_hash_round_trip(tmp_path: Path) -> None:
    store = RecoveryCheckpointStore(tmp_path)
    saved = store.save(checkpoint())
    loaded = store.load(saved.operation_id)
    assert loaded.verify()
    assert loaded.content_sha256 == saved.content_sha256


def test_corrupted_checkpoint_is_rejected(tmp_path: Path) -> None:
    store = RecoveryCheckpointStore(tmp_path)
    saved = store.save(checkpoint())
    path = store.path_for(saved.operation_id)
    text = path.read_text(encoding="utf-8").replace("validated", "completed")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(RecoveryIntegrityError):
        store.load(saved.operation_id)


def test_completed_recovery_is_idempotent(tmp_path: Path) -> None:
    store = RecoveryCheckpointStore(tmp_path)
    saved = store.save(checkpoint(completed=True))
    outcome, recovered = store.recover(
        checkpoint(completed=True), recovery_owner="worker-a"
    )
    assert outcome == "RECOVERED_IDEMPOTENTLY"
    assert recovered.content_sha256 == saved.content_sha256


def test_split_brain_recovery_is_rejected(tmp_path: Path) -> None:
    store = RecoveryCheckpointStore(tmp_path)
    store.save(checkpoint(owner="worker-a"))
    with pytest.raises(RecoveryConflictError):
        store.recover(
            checkpoint(completed=True, owner="worker-b"),
            recovery_owner="worker-b",
        )


def test_atomic_write_failure_preserves_previous_value(tmp_path: Path) -> None:
    target = tmp_path / "record.json"
    target.write_bytes(b"before")

    def hook(point: str, _target: Path, _temporary: Path) -> None:
        if point == "after_replace":
            raise InjectedPersistenceFault(point)

    with pytest.raises(InjectedPersistenceFault):
        atomic_write_bytes(target, b"after", fault_hook=hook)
    assert target.read_bytes() == b"before"


def test_atomic_write_failure_removes_new_partial_file(tmp_path: Path) -> None:
    target = tmp_path / "record.json"

    def hook(point: str, _target: Path, _temporary: Path) -> None:
        if point == "after_temp_fsync":
            raise InjectedPersistenceFault(point)

    with pytest.raises(InjectedPersistenceFault):
        atomic_write_bytes(target, b"after", fault_hook=hook)
    assert not target.exists()


def test_atomic_bundle_rolls_back_all_targets(tmp_path: Path) -> None:
    first = tmp_path / "payload.json"
    second = tmp_path / "manifest.json"
    first.write_bytes(b"first-before")
    second.write_bytes(b"second-before")

    def hook(point: str, _target: Path, _temporary: Path) -> None:
        if point == "after_bundle_replace_1":
            raise InjectedPersistenceFault(point)

    with pytest.raises(InjectedPersistenceFault):
        atomic_write_bundle(
            {first: b"first-after", second: b"second-after"},
            fault_hook=hook,
        )
    assert first.read_bytes() == b"first-before"
    assert second.read_bytes() == b"second-before"


def test_atomic_bundle_commits_all_targets(tmp_path: Path) -> None:
    first = tmp_path / "payload.json"
    second = tmp_path / "manifest.json"
    atomic_write_bundle({first: b"first", second: b"second"})
    assert first.read_bytes() == b"first"
    assert second.read_bytes() == b"second"

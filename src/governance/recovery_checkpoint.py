from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


class RecoveryCheckpointError(RuntimeError):
    """Base error for recovery checkpoint operations."""


class RecoveryIntegrityError(RecoveryCheckpointError):
    """Raised when a persisted checkpoint fails integrity verification."""


class RecoveryConflictError(RecoveryCheckpointError):
    """Raised when two recovery owners conflict for one operation."""


class InjectedPersistenceFault(RecoveryCheckpointError):
    """Raised by deterministic fault injection during persistence."""


@dataclass(frozen=True)
class RecoveryCheckpoint:
    operation_id: str
    transaction_id: str
    state: str
    owner_id: str
    sequence: int
    policy_version: str
    input_hashes: Mapping[str, str]
    output_hashes: Mapping[str, str]
    created_at: str
    updated_at: str
    completed: bool = False
    recovery_attempt: int = 0
    content_sha256: str = ""

    def __post_init__(self) -> None:
        if not self.operation_id or not self.transaction_id or not self.owner_id:
            raise RecoveryCheckpointError(
                "Checkpoint requires operation_id, transaction_id, and owner_id."
            )
        if self.sequence < 1:
            raise RecoveryCheckpointError("Checkpoint sequence must be positive.")
        if self.recovery_attempt < 0:
            raise RecoveryCheckpointError(
                "Checkpoint recovery_attempt must be non-negative."
            )
        for field_name, value in (
            ("created_at", self.created_at),
            ("updated_at", self.updated_at),
        ):
            normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                raise RecoveryCheckpointError(
                    f"Checkpoint {field_name} must include a timezone."
                )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "transaction_id": self.transaction_id,
            "state": self.state,
            "owner_id": self.owner_id,
            "sequence": self.sequence,
            "policy_version": self.policy_version,
            "input_hashes": dict(sorted(self.input_hashes.items())),
            "output_hashes": dict(sorted(self.output_hashes.items())),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed": self.completed,
            "recovery_attempt": self.recovery_attempt,
        }

    def calculated_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self.unsigned_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    def finalized(self) -> "RecoveryCheckpoint":
        values = self.unsigned_dict()
        values["content_sha256"] = self.calculated_sha256()
        return RecoveryCheckpoint(**values)

    def verify(self) -> bool:
        return (
            isinstance(self.content_sha256, str)
            and len(self.content_sha256) == 64
            and self.content_sha256 == self.calculated_sha256()
        )

    def to_dict(self) -> dict[str, Any]:
        return self.unsigned_dict() | {"content_sha256": self.content_sha256}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecoveryCheckpoint":
        return cls(
            operation_id=str(value["operation_id"]),
            transaction_id=str(value["transaction_id"]),
            state=str(value["state"]),
            owner_id=str(value["owner_id"]),
            sequence=int(value["sequence"]),
            policy_version=str(value["policy_version"]),
            input_hashes=dict(value.get("input_hashes", {})),
            output_hashes=dict(value.get("output_hashes", {})),
            created_at=str(value["created_at"]),
            updated_at=str(value["updated_at"]),
            completed=bool(value.get("completed", False)),
            recovery_attempt=int(value.get("recovery_attempt", 0)),
            content_sha256=str(value.get("content_sha256", "")),
        )


FaultHook = Callable[[str, Path, Path], None]


def atomic_write_bytes(
    target: Path | str,
    data: bytes,
    *,
    mode: int = 0o600,
    fault_hook: FaultHook | None = None,
) -> None:
    """Durably replace a file or leave its previous value untouched.

    The write occurs in the target directory, is flushed and fsynced, and is
    installed with os.replace. A caller-supplied deterministic fault hook can
    raise at named boundaries without corrupting the existing target.
    """

    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    previous_bytes = target_path.read_bytes() if target_path.exists() else None
    temporary_path: Path | None = None

    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            dir=target_path.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if fault_hook is not None:
            fault_hook("after_temp_fsync", target_path, temporary_path)
        os.replace(temporary_path, target_path)
        temporary_path = None
        if fault_hook is not None:
            fault_hook("after_replace", target_path, target_path)
        directory_descriptor = os.open(target_path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        if fault_hook is not None:
            fault_hook("after_directory_fsync", target_path, target_path)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        if previous_bytes is not None and (
            not target_path.exists() or target_path.read_bytes() != previous_bytes
        ):
            restore_descriptor, restore_name = tempfile.mkstemp(
                prefix=f".{target_path.name}.restore.",
                suffix=".tmp",
                dir=target_path.parent,
            )
            restore_path = Path(restore_name)
            with os.fdopen(restore_descriptor, "wb") as handle:
                handle.write(previous_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(restore_path, target_path)
        elif previous_bytes is None and target_path.exists():
            target_path.unlink(missing_ok=True)
        raise


def atomic_write_json(
    target: Path | str,
    value: Any,
    *,
    fault_hook: FaultHook | None = None,
) -> None:
    payload = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    atomic_write_bytes(target, payload, fault_hook=fault_hook)


class RecoveryCheckpointStore:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, operation_id: str) -> Path:
        if not operation_id or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
            for character in operation_id
        ):
            raise RecoveryCheckpointError("Invalid operation_id for checkpoint path.")
        return self.root / f"{operation_id}.checkpoint.json"

    def save(
        self,
        checkpoint: RecoveryCheckpoint,
        *,
        fault_hook: FaultHook | None = None,
    ) -> RecoveryCheckpoint:
        finalized = checkpoint.finalized()
        atomic_write_json(
            self.path_for(finalized.operation_id),
            finalized.to_dict(),
            fault_hook=fault_hook,
        )
        return finalized

    def load(self, operation_id: str) -> RecoveryCheckpoint:
        path = self.path_for(operation_id)
        if not path.is_file():
            raise FileNotFoundError(path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RecoveryIntegrityError(
                f"Checkpoint could not be decoded: {path}"
            ) from exc
        checkpoint = RecoveryCheckpoint.from_dict(document)
        if not checkpoint.verify():
            raise RecoveryIntegrityError(
                f"Checkpoint integrity verification failed: {path}"
            )
        return checkpoint

    def recover(
        self,
        proposed: RecoveryCheckpoint,
        *,
        recovery_owner: str,
    ) -> tuple[str, RecoveryCheckpoint]:
        try:
            existing = self.load(proposed.operation_id)
        except FileNotFoundError:
            recovered = self.save(
                RecoveryCheckpoint(
                    **(
                        proposed.unsigned_dict()
                        | {
                            "owner_id": recovery_owner,
                            "recovery_attempt": proposed.recovery_attempt + 1,
                        }
                    )
                )
            )
            return "RECOVERED_IDEMPOTENTLY", recovered

        if existing.transaction_id != proposed.transaction_id:
            raise RecoveryConflictError(
                "Operation ID is already bound to another transaction."
            )
        if existing.owner_id != recovery_owner and not existing.completed:
            raise RecoveryConflictError(
                "An incomplete checkpoint is owned by another recovery worker."
            )
        if existing.verify() and existing.completed:
            return "RECOVERED_IDEMPOTENTLY", existing
        if existing.input_hashes != proposed.input_hashes:
            raise RecoveryConflictError(
                "Recovery input hashes do not match the persisted checkpoint."
            )
        updated = RecoveryCheckpoint(
            **(
                existing.unsigned_dict()
                | {
                    "owner_id": recovery_owner,
                    "state": proposed.state,
                    "sequence": max(existing.sequence, proposed.sequence),
                    "output_hashes": dict(proposed.output_hashes),
                    "updated_at": proposed.updated_at,
                    "completed": proposed.completed,
                    "recovery_attempt": existing.recovery_attempt + 1,
                }
            )
        )
        return "RECOVERED_IDEMPOTENTLY", self.save(updated)

    def quarantine(self, operation_id: str, reason: str) -> Path:
        source = self.path_for(operation_id)
        if not source.exists():
            raise FileNotFoundError(source)
        quarantine_dir = self.root / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        target = quarantine_dir / source.name
        os.replace(source, target)
        reason_path = target.with_suffix(target.suffix + ".reason.json")
        atomic_write_json(
            reason_path,
            {
                "operation_id": operation_id,
                "reason": reason,
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return target


def atomic_write_bundle(
    files: Mapping[Path | str, bytes],
    *,
    fault_hook: Callable[[str, Path, Path], None] | None = None,
) -> None:
    """Atomically install a small governed file bundle with rollback.

    Each file is staged and fsynced before any replacement occurs. If a fault
    is raised during commit, every target is restored to its original state.
    This is a filesystem transaction for assurance artifacts and manifests,
    not a substitute for a transactional database.
    """

    normalized = {Path(path): data for path, data in files.items()}
    if not normalized:
        raise RecoveryCheckpointError("atomic_write_bundle requires files.")
    previous = {
        path: path.read_bytes() if path.exists() else None
        for path in normalized
    }
    staged: dict[Path, Path] = {}
    try:
        for target, data in normalized.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".bundle.tmp",
                dir=target.parent,
            )
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            staged[target] = temporary
        if fault_hook is not None:
            first = next(iter(normalized))
            fault_hook("before_bundle_commit", first, staged[first])
        for index, (target, temporary) in enumerate(staged.items(), start=1):
            os.replace(temporary, target)
            if fault_hook is not None:
                fault_hook(f"after_bundle_replace_{index}", target, target)
        staged.clear()
        for directory in sorted({path.parent for path in normalized}, key=str):
            descriptor = os.open(directory, os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if fault_hook is not None:
            first = next(iter(normalized))
            fault_hook("after_bundle_commit", first, first)
    except BaseException:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
        for target, old_data in previous.items():
            if old_data is None:
                target.unlink(missing_ok=True)
            else:
                atomic_write_bytes(target, old_data)
        raise

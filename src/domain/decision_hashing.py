from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    """Hash a file without loading the complete file into memory."""
    file_path = Path(path)
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def canonical_record_bytes(record: dict[str, Any]) -> bytes:
    """
    Canonicalize a Decision Record for hashing.

    audit.record_hash is excluded because the record cannot contain its own
    digest while that digest is being calculated.
    """
    canonical_record = copy.deepcopy(record)

    audit = canonical_record.get("audit")

    if isinstance(audit, dict):
        audit.pop("record_hash", None)

    return json.dumps(
        canonical_record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_decision_record_hash(record: dict[str, Any]) -> str:
    """Calculate the canonical SHA-256 hash of a Decision Record."""
    return sha256_bytes(canonical_record_bytes(record))


def finalize_decision_record_hash(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Return a deep-copied record containing its calculated hash."""
    finalized = copy.deepcopy(record)

    if "audit" not in finalized or not isinstance(finalized["audit"], dict):
        raise ValueError("Decision Record requires an audit object.")

    finalized["audit"]["record_hash"] = compute_decision_record_hash(
        finalized
    )

    return finalized


def verify_decision_record_hash(record: dict[str, Any]) -> bool:
    """Verify that the stored Decision Record hash is correct."""
    audit = record.get("audit")

    if not isinstance(audit, dict):
        return False

    stored_hash = audit.get("record_hash")

    if not isinstance(stored_hash, str):
        return False

    calculated_hash = compute_decision_record_hash(record)

    return stored_hash == calculated_hash

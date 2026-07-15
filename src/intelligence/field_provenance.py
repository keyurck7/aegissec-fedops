from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from src.intelligence.official_source import canonical_json_bytes


@dataclass(frozen=True)
class ProvenanceContext:
    source_name: str
    source_record_id: str
    source_authority: str
    retrieved_at: str
    artifact_sha256: str
    envelope_id: str | None = None


def stable_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def stable_identifier(prefix: str, value: Any, *, length: int = 24) -> str:
    normalized_prefix = prefix.strip().upper()
    if not normalized_prefix or not normalized_prefix.replace("-", "").isalnum():
        raise ValueError("Identifier prefix must be alphanumeric with optional hyphens.")
    if length < 12 or length > 64:
        raise ValueError("Identifier digest length must be within [12, 64].")
    return f"{normalized_prefix}-{stable_digest(value)[:length].upper()}"


def build_field_provenance(
    *,
    field_path: str,
    value: Any,
    context: ProvenanceContext,
    extraction_method: str,
    source_pointer: str,
) -> dict[str, Any]:
    if not field_path.startswith("/"):
        raise ValueError("field_path must be an absolute JSON Pointer.")
    if not source_pointer.startswith("/"):
        raise ValueError("source_pointer must be an absolute JSON Pointer.")
    if not extraction_method.strip():
        raise ValueError("extraction_method is required.")
    return {
        "field_path": field_path,
        "source_name": context.source_name,
        "source_record_id": context.source_record_id,
        "source_authority": context.source_authority,
        "source_envelope_id": context.envelope_id,
        "source_artifact_sha256": context.artifact_sha256,
        "source_pointer": source_pointer,
        "retrieved_at": context.retrieved_at,
        "extraction_method": extraction_method,
        "value_sha256": stable_digest(value),
    }


def assert_provenance_coverage(
    record: Mapping[str, Any],
    *,
    required_field_paths: set[str],
) -> None:
    entries = record.get("field_provenance")
    if not isinstance(entries, list):
        raise ValueError("Canonical record field_provenance must be a list.")
    observed = {
        str(item.get("field_path"))
        for item in entries
        if isinstance(item, Mapping)
    }
    missing = sorted(required_field_paths - observed)
    if missing:
        raise ValueError(f"Missing field provenance for: {missing}")

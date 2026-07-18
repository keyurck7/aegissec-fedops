from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.decision_features.feature_envelope import (
    FeatureInputReference,
    build_decision_feature_envelope,
    canonical_json_bytes,
)


DEFAULT_CANONICAL_SCHEMA = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_canonical_vulnerability_intelligence.schema.json"
)
DEFAULT_AFFECTEDNESS_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_affectedness_adjudication.schema.json"
)
DEFAULT_ASSET_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_asset_context.schema.json"
)
DEFAULT_EVIDENCE_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_evidence_record.schema.json"
)
DEFAULT_RUNTIME_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_component_runtime_context.schema.json"
)
DEFAULT_OUTPUT_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_decision_feature_envelope.schema.json"
)


class Milestone12DExecutionError(RuntimeError):
    """Raised when the operational feature-envelope run cannot proceed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Milestone12DExecutionError(
            f"Unable to read JSON object {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise Milestone12DExecutionError(f"Expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_json(
    document: Mapping[str, Any],
    schema_path: Path,
    label: str,
) -> None:
    schema = load_json(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(dict(document)),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        details = []
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path)
            details.append(f"{location or '<root>'}: {error.message}")
        raise Milestone12DExecutionError(
            f"{label} schema validation failed: " + "; ".join(details)
        )


def relative_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError as exc:
        raise Milestone12DExecutionError(
            f"Input path must remain inside the repository: {resolved}"
        ) from exc


def verify_integrity_companion(
    document_path: Path,
    record_id: str,
    suffix: str,
) -> None:
    integrity_path = document_path.parent / (
        record_id.casefold() + suffix
    )
    if not integrity_path.is_file():
        raise Milestone12DExecutionError(
            f"Integrity companion is missing: {integrity_path}"
        )
    parts = integrity_path.read_text(encoding="utf-8").strip().split()
    if not parts:
        raise Milestone12DExecutionError(
            f"Integrity companion is empty: {integrity_path}"
        )
    expected = parts[0].casefold()
    observed = sha256_file(document_path)
    if expected != observed:
        raise Milestone12DExecutionError(
            f"Integrity verification failed for {document_path}"
        )
    if canonical_json_bytes(load_json(document_path)) != document_path.read_bytes():
        raise Milestone12DExecutionError(
            f"Document is not canonical JSON: {document_path}"
        )


def verify_affectedness_input_bindings(
    affectedness: Mapping[str, Any],
    actual_paths: Mapping[str, Path],
) -> None:
    declared = affectedness.get("inputs")
    if not isinstance(declared, Mapping):
        raise Milestone12DExecutionError(
            "Affectedness report does not contain input references."
        )
    mapping = {
        "canonical_intelligence": "canonical_intelligence",
        "asset_context": "asset_context",
        "component_evidence": "component_evidence",
        "runtime_context": "runtime_context",
    }
    for affectedness_name, actual_name in mapping.items():
        reference = declared.get(affectedness_name)
        if not isinstance(reference, Mapping):
            raise Milestone12DExecutionError(
                f"Affectedness input reference is missing: {affectedness_name}"
            )
        observed_hash = sha256_file(actual_paths[actual_name])
        if str(reference.get("sha256", "")).casefold() != observed_hash:
            raise Milestone12DExecutionError(
                f"Affectedness input hash does not match {actual_name}."
            )


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Milestone 12D deterministic decision-feature construction."
        )
    )
    parser.add_argument("--canonical", type=Path, required=True)
    parser.add_argument("--affectedness", type=Path, required=True)
    parser.add_argument("--asset", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--runtime-context", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument(
        "--output-schema",
        type=Path,
        default=DEFAULT_OUTPUT_SCHEMA,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = {
        "canonical_intelligence": args.canonical.resolve(),
        "affectedness_adjudication": args.affectedness.resolve(),
        "asset_context": args.asset.resolve(),
        "component_evidence": args.evidence.resolve(),
        "runtime_context": args.runtime_context.resolve(),
    }
    for label, path in paths.items():
        if not path.is_file():
            raise Milestone12DExecutionError(
                f"Missing {label} input: {path}"
            )
        relative_path(path)

    output_dir = args.output_dir.resolve()
    try:
        output_dir.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise Milestone12DExecutionError(
            "Output directory must remain inside the repository."
        ) from exc
    if output_dir.exists() and any(output_dir.iterdir()):
        raise Milestone12DExecutionError(
            f"Output directory must be new or empty: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    canonical = load_json(paths["canonical_intelligence"])
    affectedness = load_json(paths["affectedness_adjudication"])
    asset = load_json(paths["asset_context"])
    evidence = load_json(paths["component_evidence"])
    runtime = load_json(paths["runtime_context"])

    validate_json(canonical, DEFAULT_CANONICAL_SCHEMA, "Canonical intelligence")
    validate_json(
        affectedness,
        DEFAULT_AFFECTEDNESS_SCHEMA,
        "Affectedness adjudication",
    )
    validate_json(asset, DEFAULT_ASSET_SCHEMA, "Asset context")
    validate_json(evidence, DEFAULT_EVIDENCE_SCHEMA, "Component evidence")
    validate_json(runtime, DEFAULT_RUNTIME_SCHEMA, "Runtime context")

    verify_integrity_companion(
        paths["canonical_intelligence"],
        str(canonical["record_id"]),
        ".integrity.sha256",
    )
    verify_integrity_companion(
        paths["affectedness_adjudication"],
        str(affectedness["report_id"]),
        ".integrity.sha256",
    )
    verify_affectedness_input_bindings(affectedness, paths)

    references = {
        "canonical_intelligence": FeatureInputReference(
            record_id=str(canonical["record_id"]),
            relative_path=relative_path(paths["canonical_intelligence"]),
            sha256=sha256_file(paths["canonical_intelligence"]),
        ),
        "affectedness_adjudication": FeatureInputReference(
            record_id=str(affectedness["report_id"]),
            relative_path=relative_path(paths["affectedness_adjudication"]),
            sha256=sha256_file(paths["affectedness_adjudication"]),
        ),
        "asset_context": FeatureInputReference(
            record_id=str(asset["asset_id"]),
            relative_path=relative_path(paths["asset_context"]),
            sha256=sha256_file(paths["asset_context"]),
        ),
        "component_evidence": FeatureInputReference(
            record_id=str(evidence["evidence_id"]),
            relative_path=relative_path(paths["component_evidence"]),
            sha256=sha256_file(paths["component_evidence"]),
        ),
        "runtime_context": FeatureInputReference(
            record_id=str(runtime["context_id"]),
            relative_path=relative_path(paths["runtime_context"]),
            sha256=sha256_file(paths["runtime_context"]),
        ),
    }

    envelope = build_decision_feature_envelope(
        canonical_record=canonical,
        affectedness_report=affectedness,
        asset_context=asset,
        component_evidence=evidence,
        runtime_context=runtime,
        input_references=references,
        generated_at=args.generated_at,
    )
    validate_json(envelope, args.output_schema, "Decision feature envelope")

    envelope_name = envelope["envelope_id"].casefold() + ".features.json"
    integrity_name = envelope["envelope_id"].casefold() + ".integrity.sha256"
    envelope_path = output_dir / envelope_name
    integrity_path = output_dir / integrity_name
    summary_path = output_dir / "milestone12d_decision_feature_summary.json"

    envelope_bytes = canonical_json_bytes(envelope)
    envelope_hash = hashlib.sha256(envelope_bytes).hexdigest()
    summary = {
        "schema_version": "1.0.0",
        "envelope_id": envelope["envelope_id"],
        "envelope_path": relative_path(envelope_path),
        "envelope_sha256": envelope_hash,
        "target": envelope["target"],
        "affectedness": envelope["features"]["affectedness"]["status"],
        "cvss_base_score": envelope["features"]["technical_severity"]["base_score"],
        "known_exploitation_status": envelope["features"]["exploitation"]["known_exploitation_status"],
        "epss_probability": envelope["features"]["exploitation"]["epss"]["probability"],
        "asset_criticality": envelope["features"]["asset_criticality"]["level"],
        "maximum_impact_severity": envelope["features"]["mission_and_sector_impact"]["maximum_severity"],
        "runtime_reachability": envelope["features"]["exposure_and_reachability"]["runtime_reachability"],
        "uncertainty_level": envelope["features"]["uncertainty_and_conflicts"]["level"],
        "human_review_required": envelope["features"]["governance"]["human_review_required"],
        "stage_gate": envelope["release_decision"]["stage_gate"],
        "next_stage_eligibility": envelope["release_decision"]["next_stage_eligibility"],
        "production_readiness": envelope["release_decision"]["production_readiness"],
        "provenance_entry_count": len(envelope["provenance"]),
    }

    atomic_write(envelope_path, envelope_bytes)
    atomic_write(
        integrity_path,
        f"{envelope_hash}  {envelope_name}\n".encode("utf-8"),
    )
    atomic_write(summary_path, canonical_json_bytes(summary))

    print("=" * 86)
    print("MILESTONE 12D DECISION FEATURE ENVELOPE")
    print("=" * 86)
    print("Envelope ID:", envelope["envelope_id"])
    print("CVE:", envelope["target"]["cve_id"])
    print("Component:", envelope["target"]["component"]["purl"])
    print("Affectedness:", summary["affectedness"])
    print("CVSS:", summary["cvss_base_score"])
    print("Known exploitation:", summary["known_exploitation_status"])
    print("EPSS:", summary["epss_probability"])
    print("Asset criticality:", summary["asset_criticality"])
    print("Maximum impact:", summary["maximum_impact_severity"])
    print("Runtime reachability:", summary["runtime_reachability"])
    print("Uncertainty:", summary["uncertainty_level"])
    print("Human review required:", summary["human_review_required"])
    print("Stage gate:", summary["stage_gate"])
    print("Next stage:", summary["next_stage_eligibility"])
    print("Production readiness:", summary["production_readiness"])
    print("Provenance entries:", summary["provenance_entry_count"])
    print("Report:", envelope_path)
    print("Integrity:", integrity_path)
    print("Summary:", summary_path)
    print("All Milestone 12D quality gates:", summary["stage_gate"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

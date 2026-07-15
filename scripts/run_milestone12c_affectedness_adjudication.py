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

from src.affectedness.affectedness_adjudicator import (
    InputReference,
    build_affectedness_adjudication,
    canonical_json_bytes,
)


DEFAULT_ASSET = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)
DEFAULT_EVIDENCE = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_log4j_sbom_evidence.json"
)
DEFAULT_RUNTIME = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "affectedness"
    / "valid_log4shell_runtime_context.json"
)
DEFAULT_REPORT_SCHEMA = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_affectedness_adjudication.schema.json"
)
DEFAULT_RUNTIME_SCHEMA = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_component_runtime_context.schema.json"
)
DEFAULT_CANONICAL_SCHEMA = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_canonical_vulnerability_intelligence.schema.json"
)
DEFAULT_ASSET_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_asset_context.schema.json"
)
DEFAULT_EVIDENCE_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_evidence_record.schema.json"
)


class Milestone12CExecutionError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Milestone12CExecutionError(
            f"Unable to read JSON object {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise Milestone12CExecutionError(
            f"Expected JSON object: {path}"
        )
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
            location = ".".join(
                str(part) for part in error.absolute_path
            )
            details.append(
                f"{location or '<root>'}: {error.message}"
            )
        raise Milestone12CExecutionError(
            f"{label} schema validation failed: " + "; ".join(details)
        )


def relative_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError as exc:
        raise Milestone12CExecutionError(
            f"Input path must remain inside the repository: {resolved}"
        ) from exc


def verify_canonical_integrity(
    canonical_path: Path,
    canonical: Mapping[str, Any],
) -> None:
    expected_name = (
        str(canonical["record_id"]).casefold()
        + ".integrity.sha256"
    )
    integrity_path = canonical_path.parent / expected_name
    if not integrity_path.exists():
        raise Milestone12CExecutionError(
            f"Canonical integrity record is missing: {integrity_path}"
        )
    parts = integrity_path.read_text(encoding="utf-8").strip().split()
    if not parts:
        raise Milestone12CExecutionError(
            "Canonical integrity record is empty."
        )
    expected_hash = parts[0].casefold()
    observed_hash = sha256_file(canonical_path)
    if expected_hash != observed_hash:
        raise Milestone12CExecutionError(
            "Canonical intelligence integrity verification failed."
        )
    if canonical_json_bytes(dict(canonical)) != canonical_path.read_bytes():
        raise Milestone12CExecutionError(
            "Canonical intelligence file is not canonical JSON."
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
            "Run Milestone 12C evidence-governed affectedness adjudication."
        )
    )
    parser.add_argument("--canonical", type=Path, required=True)
    parser.add_argument("--asset", type=Path, default=DEFAULT_ASSET)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument(
        "--runtime-context",
        type=Path,
        default=DEFAULT_RUNTIME,
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--assessed-at", default=None)
    parser.add_argument(
        "--report-schema",
        type=Path,
        default=DEFAULT_REPORT_SCHEMA,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = {
        "canonical_intelligence": args.canonical.resolve(),
        "asset_context": args.asset.resolve(),
        "component_evidence": args.evidence.resolve(),
        "runtime_context": args.runtime_context.resolve(),
    }
    for label, path in paths.items():
        if not path.is_file():
            raise Milestone12CExecutionError(
                f"Missing {label} input: {path}"
            )

    output_dir = args.output_dir.resolve()
    try:
        output_dir.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise Milestone12CExecutionError(
            "Output directory must remain inside the repository."
        ) from exc
    if output_dir.exists() and any(output_dir.iterdir()):
        raise Milestone12CExecutionError(
            f"Output directory must be new or empty: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    canonical = load_json(paths["canonical_intelligence"])
    asset = load_json(paths["asset_context"])
    evidence = load_json(paths["component_evidence"])
    runtime = load_json(paths["runtime_context"])

    validate_json(
        canonical,
        DEFAULT_CANONICAL_SCHEMA,
        "Canonical intelligence",
    )
    validate_json(asset, DEFAULT_ASSET_SCHEMA, "Asset context")
    validate_json(
        evidence,
        DEFAULT_EVIDENCE_SCHEMA,
        "Component evidence",
    )
    validate_json(runtime, DEFAULT_RUNTIME_SCHEMA, "Runtime context")
    verify_canonical_integrity(
        paths["canonical_intelligence"],
        canonical,
    )

    assessed_at = (
        args.assessed_at
        or runtime.get("observed_at")
        or canonical.get("generated_at")
    )
    references = {
        "canonical_intelligence": InputReference(
            record_id=str(canonical["record_id"]),
            relative_path=relative_path(paths["canonical_intelligence"]),
            sha256=sha256_file(paths["canonical_intelligence"]),
        ),
        "asset_context": InputReference(
            record_id=str(asset["asset_id"]),
            relative_path=relative_path(paths["asset_context"]),
            sha256=sha256_file(paths["asset_context"]),
        ),
        "component_evidence": InputReference(
            record_id=str(evidence["evidence_id"]),
            relative_path=relative_path(paths["component_evidence"]),
            sha256=sha256_file(paths["component_evidence"]),
        ),
        "runtime_context": InputReference(
            record_id=str(runtime["context_id"]),
            relative_path=relative_path(paths["runtime_context"]),
            sha256=sha256_file(paths["runtime_context"]),
        ),
    }

    report = build_affectedness_adjudication(
        canonical_record=canonical,
        asset_context=asset,
        component_evidence=evidence,
        runtime_context=runtime,
        input_references=references,
        assessed_at=str(assessed_at),
    )
    validate_json(report, args.report_schema, "Affectedness report")

    report_name = report["report_id"].casefold() + ".adjudication.json"
    integrity_name = report["report_id"].casefold() + ".integrity.sha256"
    report_path = output_dir / report_name
    report_bytes = canonical_json_bytes(report)
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    integrity_path = output_dir / integrity_name
    summary_path = output_dir / "milestone12c_affectedness_summary.json"

    summary = {
        "schema_version": "1.0.0",
        "report_id": report["report_id"],
        "report_path": relative_path(report_path),
        "report_sha256": report_hash,
        "status": report["adjudication"]["status"],
        "technical_status": report["adjudication"]["technical_status"],
        "confidence": report["adjudication"]["confidence"],
        "human_review_required": report["adjudication"][
            "human_review_required"
        ],
        "closure_prohibited": report["adjudication"][
            "closure_prohibited"
        ],
        "stage_gate": report["release_decision"]["stage_gate"],
        "policy_eligibility": report["release_decision"][
            "policy_eligibility"
        ],
        "production_readiness": report["release_decision"][
            "production_readiness"
        ],
    }

    atomic_write(report_path, report_bytes)
    atomic_write(
        integrity_path,
        f"{report_hash}  {report_name}\n".encode("utf-8"),
    )
    atomic_write(summary_path, canonical_json_bytes(summary))

    print("=" * 78)
    print("MILESTONE 12C EVIDENCE-GOVERNED AFFECTEDNESS ADJUDICATION")
    print("=" * 78)
    print(f"Report ID: {report['report_id']}")
    print(f"CVE: {report['target']['cve_id']}")
    print(
        "Component: "
        f"{report['target']['component']['package_name']}@"
        f"{report['target']['component']['version']}"
    )
    print(f"Asset: {report['target']['asset_id']}")
    print(f"Technical status: {report['adjudication']['technical_status']}")
    print(f"Adjudication status: {report['adjudication']['status']}")
    print(f"Confidence: {report['adjudication']['confidence']}")
    print(
        "Runtime reachability: "
        f"{report['runtime_context']['reachability']}"
    )
    print(
        "Blocking conflicts: "
        f"{sum(item['blocking'] for item in report['conflicts'])}"
    )
    print(
        "Human review required: "
        f"{report['adjudication']['human_review_required']}"
    )
    print(
        "Closure prohibited: "
        f"{report['adjudication']['closure_prohibited']}"
    )
    print(f"Stage gate: {report['release_decision']['stage_gate']}")
    print(
        "Policy eligibility: "
        f"{report['release_decision']['policy_eligibility']}"
    )
    print(
        "Production readiness: "
        f"{report['release_decision']['production_readiness']}"
    )
    print(f"Report: {report_path}")
    print(f"Integrity: {integrity_path}")
    print(f"Summary: {summary_path}")
    print("All Milestone 12C quality gates: " + report["release_decision"]["stage_gate"])

    return 0 if report["release_decision"]["stage_gate"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

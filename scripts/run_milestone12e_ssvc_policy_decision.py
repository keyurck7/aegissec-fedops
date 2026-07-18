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

from src.decision_policy.ssvc_engine import (
    SSVCPolicyDecisionError,
    build_ssvc_policy_decision,
    canonical_json_bytes,
)


DEFAULT_OUTPUT_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_ssvc_policy_decision.schema.json"
)


class Milestone12EExecutionError(RuntimeError):
    """Raised when the operational SSVC policy run cannot proceed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Milestone12EExecutionError(f"Unable to read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise Milestone12EExecutionError(f"Expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError as exc:
        raise Milestone12EExecutionError(
            f"Input path must remain inside the repository: {resolved}"
        ) from exc


def verify_integrity_companion(path: Path, digest: str) -> None:
    companions = sorted(path.parent.glob("*.integrity.sha256"))
    matching = []
    for companion in companions:
        parts = companion.read_text(encoding="utf-8").strip().split()
        if len(parts) >= 2 and Path(parts[-1]).name == path.name:
            matching.append((companion, parts[0].casefold()))
    if len(matching) != 1:
        raise Milestone12EExecutionError(
            f"Expected exactly one integrity companion for {path.name}."
        )
    companion, expected = matching[0]
    if expected != digest.casefold():
        raise Milestone12EExecutionError(
            f"Integrity companion mismatch: {companion}"
        )


def validate_json(document: Mapping[str, Any], schema_path: Path) -> None:
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
        raise Milestone12EExecutionError(
            "SSVC output schema validation failed: " + "; ".join(details)
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
        description="Run Milestone 12E governed official SSVC policy evaluation."
    )
    parser.add_argument("--features", type=Path, required=True)
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
    feature_path = args.features.resolve()
    if not feature_path.is_file():
        raise Milestone12EExecutionError(
            f"Decision-feature envelope not found: {feature_path}"
        )
    feature_relative = relative_path(feature_path)
    feature_sha = sha256_file(feature_path)
    verify_integrity_companion(feature_path, feature_sha)
    feature_envelope = load_json(feature_path)

    try:
        report = build_ssvc_policy_decision(
            decision_feature_envelope=feature_envelope,
            input_relative_path=feature_relative,
            input_sha256=feature_sha,
            generated_at=args.generated_at,
        )
    except SSVCPolicyDecisionError as exc:
        raise Milestone12EExecutionError(str(exc)) from exc

    validate_json(report, args.output_schema.resolve())
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise Milestone12EExecutionError(
            f"Output directory must be empty: {output_dir}"
        )

    report_name = report["decision_id"].casefold() + ".ssvc.json"
    report_path = output_dir / report_name
    integrity_path = output_dir / (
        report["decision_id"].casefold() + ".integrity.sha256"
    )
    summary_path = output_dir / "milestone12e_ssvc_summary.json"

    report_bytes = json.dumps(
        report,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8") + b"\n"
    report_sha = hashlib.sha256(report_bytes).hexdigest()
    summary = {
        "schema_version": "1.0.0",
        "decision_id": report["decision_id"],
        "decision_path": relative_path(report_path),
        "decision_sha256": report_sha,
        "input_envelope_id": report["input"]["envelope_id"],
        "mapping_status": report["mapping"]["status"],
        "official_ssvc_status": report["official_ssvc_decision"]["status"],
        "vector": report["official_ssvc_decision"]["vector"],
        "matched_row": report["official_ssvc_decision"]["matched_row"],
        "outcome": report["official_ssvc_decision"]["outcome"],
        "human_review_required": report["governance"]["human_review_required"],
        "stage_gate": report["governance"]["stage_gate"],
        "production_readiness": report["governance"]["production_readiness"],
        "next_stage": report["governance"]["next_stage"],
        "provenance_entry_count": len(report["provenance"]),
    }

    atomic_write(report_path, report_bytes)
    atomic_write(
        integrity_path,
        f"{report_sha}  {report_name}\n".encode("utf-8"),
    )
    atomic_write(
        summary_path,
        json.dumps(summary, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )

    points = report["mapping"]["decision_points"]
    outcome = report["official_ssvc_decision"]["outcome"]
    print("=" * 78)
    print("MILESTONE 12E GOVERNED OFFICIAL SSVC POLICY DECISION")
    print("=" * 78)
    print(f"Decision ID: {report['decision_id']}")
    print(f"CVE: {report['target'].get('cve_id')}")
    print(f"Exploitation: {points['exploitation']['name']} ({points['exploitation']['key']})")
    print(f"System exposure: {points['system_exposure']['name']} ({points['system_exposure']['key']})")
    print(f"Automatable: {points['automatable']['name']} ({points['automatable']['key']})")
    print(f"Safety impact: {points['safety_impact']['name']} ({points['safety_impact']['key']})")
    print(f"Mission impact: {points['mission_impact']['name']} ({points['mission_impact']['key']})")
    print(f"Human impact: {points['human_impact']['name']} ({points['human_impact']['key']})")
    print(f"Vector: {report['official_ssvc_decision']['vector']}")
    print(f"Matched row: {report['official_ssvc_decision']['matched_row']}")
    print(f"Outcome: {None if outcome is None else outcome['name']}")
    print(f"Human review required: {report['governance']['human_review_required']}")
    print(f"Stage gate: {report['governance']['stage_gate']}")
    print(f"Production readiness: {report['governance']['production_readiness']}")
    print(f"Next stage: {report['governance']['next_stage']}")
    print(f"Report: {report_path}")
    print(f"Integrity: {integrity_path}")
    print(f"Summary: {summary_path}")
    print("All Milestone 12E quality gates: " + (
        "PASS" if all(gate["pass"] for gate in report["quality_gates"]) else "FAIL"
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

# AEGIS_REPOSITORY_IMPORT_BOOTSTRAP
import sys as _aegis_sys
from pathlib import Path as _AegisPath

_AEGIS_REPOSITORY_ROOT = _AegisPath(__file__).resolve().parents[1]

if str(_AEGIS_REPOSITORY_ROOT) not in _aegis_sys.path:
    _aegis_sys.path.insert(0, str(_AEGIS_REPOSITORY_ROOT))

from src.ml_advisory.agreement import evaluate_agreement
from src.ml_advisory.dataset import build_dataset, deterministic_group_split
from src.ml_advisory.governance import build_ml_feature_view
from src.ml_advisory.inference import predict_advisory
from src.ml_advisory.synthetic import generate_development_pairs
from src.ml_advisory.training import train_and_evaluate


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feature-envelope", required=True, type=Path)
    parser.add_argument("--ssvc-decision", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--synthetic-rows", type=int, default=480)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    envelope = load(args.feature_envelope)
    ssvc = load(args.ssvc_decision)
    base_view = build_ml_feature_view(envelope, generated_at=generated_at)
    pairs = generate_development_pairs(base_view, count=args.synthetic_rows)
    dataset = build_dataset(pairs, generated_at=generated_at)
    split = deterministic_group_split(dataset)
    dataset_path = args.output_dir / "milestone12f_dataset.json"
    split_path = args.output_dir / "milestone12f_split.json"
    write(dataset_path, dataset)
    write(split_path, split)
    report = train_and_evaluate(dataset, split, output_dir=args.output_dir)
    advisory = predict_advisory(base_view, report)
    agreement = evaluate_agreement(ssvc, advisory)
    advisory_path = args.output_dir / "milestone12f_ml_advisory.json"
    agreement_path = args.output_dir / "milestone12g_agreement_preview.json"
    write(advisory_path, advisory)
    write(agreement_path, agreement)
    artifacts = sorted(p for p in args.output_dir.iterdir() if p.is_file())
    integrity = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}
    integrity_path = args.output_dir / "artifact_integrity.json"
    write(integrity_path, integrity)
    summary = {
        "dataset_id": dataset["dataset_id"],
        "rows": len(dataset["rows"]),
        "class_distribution": dataset["class_distribution"],
        "split_counts": split["counts"],
        "test_metrics": report["metrics"]["test"],
        "training_stage_gate": report["quality_gate"]["stage_gate"],
        "advisory": advisory["prediction"],
        "agreement": agreement,
        "production_readiness": "BLOCKED",
        "next_stage": "MILESTONE_12G_AGREEMENT_AND_ESCALATION_GATE",
    }
    print("=" * 76)
    print("MILESTONE 12F FULL INDEPENDENT ML ADVISORY PIPELINE")
    print("=" * 76)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("Evidence directory:", args.output_dir)
    return 0 if report["quality_gate"]["stage_gate"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

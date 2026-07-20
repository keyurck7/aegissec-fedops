from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .governance import (
    DEFAULT_POLICY_PATH,
    MLAdvisoryGovernanceError,
    load_governance_policy,
    validate_training_pair,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TRAINING_POLICY = ROOT / "policies" / "ml" / "ml_dataset_training_policy_v1.yaml"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{sha256_value(value)[:24].upper()}"


def load_training_policy(path: Path | str = DEFAULT_TRAINING_POLICY) -> dict[str, Any]:
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise MLAdvisoryGovernanceError("ML dataset policy must be a YAML object.")
    return document


def _forbidden_feature_names(policy: Mapping[str, Any]) -> set[str]:
    return {
        str(value).strip().lower()
        for value in policy["dataset"]["prohibited_feature_terms"]
    }


def _prohibited_term_exceptions(
    policy: Mapping[str, Any],
) -> dict[str, set[str]]:
    raw = policy["dataset"].get("prohibited_term_exceptions", {})
    if not isinstance(raw, Mapping):
        raise MLAdvisoryGovernanceError(
            "dataset.prohibited_term_exceptions must be a mapping."
        )

    exceptions: dict[str, set[str]] = {}
    for feature_name, record in raw.items():
        if not isinstance(record, Mapping):
            raise MLAdvisoryGovernanceError(
                "Each prohibited-term exception must be a mapping."
            )
        matched_terms = record.get("matched_terms", [])
        if not isinstance(matched_terms, list) or not matched_terms:
            raise MLAdvisoryGovernanceError(
                f"Exception {feature_name!r} must declare matched_terms."
            )
        exceptions[str(feature_name).strip().lower()] = {
            str(term).strip().lower() for term in matched_terms
        }
    return exceptions


def _approved_model_feature_names(
    governance_policy_path: Path | str,
) -> set[str]:
    governance_policy, _ = load_governance_policy(governance_policy_path)
    features = governance_policy.get("model_features", [])
    if not isinstance(features, list):
        raise MLAdvisoryGovernanceError(
            "Governance model_features must be a list."
        )
    approved = {
        str(record["feature_id"])
        for record in features
        if isinstance(record, Mapping) and "feature_id" in record
    }
    if not approved:
        raise MLAdvisoryGovernanceError(
            "Governance model-feature allowlist is empty."
        )
    return approved


def leakage_audit(
    feature_names: Iterable[str],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    forbidden = _forbidden_feature_names(policy)
    exceptions = _prohibited_term_exceptions(policy)
    violations: list[str] = []
    exempted: list[dict[str, Any]] = []

    for name in sorted({str(value) for value in feature_names}):
        normalized = name.strip().lower()
        matched_terms = {
            term for term in forbidden if term in normalized
        }
        if not matched_terms:
            continue

        approved_terms = exceptions.get(normalized)
        if (
            approved_terms is not None
            and matched_terms <= approved_terms
        ):
            exempted.append({
                "feature_name": name,
                "matched_terms": sorted(matched_terms),
                "disposition": "APPROVED_PRE_POLICY_FEATURE_EXCEPTION",
            })
            continue

        violations.append(name)

    return {
        "status": "PASS" if not violations else "FAIL",
        "violations": violations,
        "exempted_features": exempted,
        "forbidden_terms": sorted(forbidden),
    }


def build_dataset(
    pairs: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    governance_policy_path: Path | str = DEFAULT_POLICY_PATH,
    training_policy_path: Path | str = DEFAULT_TRAINING_POLICY,
    generated_at: str | None = None,
) -> dict[str, Any]:
    policy = load_training_policy(training_policy_path)
    rows: list[dict[str, Any]] = []
    feature_names: set[str] = set()
    synthetic_count = 0

    for feature_view, label_record in pairs:
        validated = validate_training_pair(
            feature_view,
            label_record,
            policy_path=governance_policy_path,
        )
        features = dict(feature_view["model_features"])
        feature_names.update(features)
        label = validated["label"]
        synthetic = bool(label["synthetic"])
        synthetic_count += int(synthetic)
        target = dict(feature_view["target"])
        row_identity = {
            "feature_view_id": feature_view["feature_view_id"],
            "label_source_record_id": label["source_record_id"],
            "target": target,
        }
        rows.append({
            "row_id": stable_id("AEG-MLR", row_identity),
            "feature_view_id": feature_view["feature_view_id"],
            "target": target,
            "features": features,
            "label": label["label"],
            "class_index": label["class_index"],
            "label_provenance": {
                "source_type": label["source_type"],
                "source_record_id": label["source_record_id"],
                "source_sha256": label["source_sha256"],
                "observed_at": label["observed_at"],
                "observation_window_days": label["observation_window_days"],
                "synthetic": synthetic,
                "independent_source": label["independent_source"],
                "production_eligible": label["production_eligible"],
            },
            "feature_contract_sha256": feature_view["contract"]["policy_sha256"],
            "feature_view_sha256": sha256_value(feature_view),
            "label_record_sha256": sha256_value(label_record),
        })

    approved_feature_names = _approved_model_feature_names(
        governance_policy_path
    )
    unapproved_feature_names = sorted(
        feature_names - approved_feature_names
    )
    if unapproved_feature_names:
        raise MLAdvisoryGovernanceError(
            "Dataset contains features outside the governed allowlist: "
            f"{unapproved_feature_names}"
        )

    audit = leakage_audit(feature_names, policy)
    audit["governance_allowlist_status"] = "PASS"
    audit["approved_feature_count"] = len(approved_feature_names)
    if audit["status"] != "PASS":
        raise MLAdvisoryGovernanceError(
            f"Dataset leakage firewall rejected features: {audit['violations']}"
        )

    labels = Counter(row["label"] for row in rows)
    dataset_policy = policy["dataset"]
    minimum_rows = int(dataset_policy["minimum_rows"])
    minimum_class_rows = int(dataset_policy["minimum_class_rows"])
    classes_ok = bool(labels) and min(labels.values()) >= minimum_class_rows
    size_ok = len(rows) >= minimum_rows
    production_eligible = bool(rows) and synthetic_count == 0 and all(
        row["label_provenance"]["production_eligible"] for row in rows
    )

    created = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    dataset = {
        "schema_version": "1.0.0",
        "dataset_id": stable_id("AEG-MLD", {"rows": [r["row_id"] for r in rows]}),
        "generated_at": created,
        "authority": {
            "role": "INDEPENDENT_ADVISORY_ONLY",
            "may_override_ssvc": False,
            "may_authorize_final_disposition": False,
        },
        "feature_names": sorted(feature_names),
        "class_distribution": dict(sorted(labels.items())),
        "rows": rows,
        "quality": {
            "row_count": len(rows),
            "synthetic_row_count": synthetic_count,
            "independent_row_count": len(rows) - synthetic_count,
            "minimum_rows_met": size_ok,
            "minimum_class_rows_met": classes_ok,
            "leakage_audit": audit,
            "duplicate_row_ids": len(rows) - len({r["row_id"] for r in rows}),
        },
        "release": {
            "stage_gate": "PASS" if size_ok and classes_ok and audit["status"] == "PASS" else "FAIL",
            "production_dataset_eligible": production_eligible,
            "production_readiness": "BLOCKED",
            "reason_codes": (
                ["CONTROLLED_SYNTHETIC_DATASET_DEVELOPMENT_ONLY"]
                if synthetic_count else ["INDEPENDENT_OUTCOME_DATASET"]
            ),
            "next_stage": "MILESTONE_12F_3_MODEL_TRAINING_EVALUATION",
        },
    }
    if dataset["quality"]["duplicate_row_ids"]:
        raise MLAdvisoryGovernanceError("Duplicate dataset row identities detected.")
    return dataset


def _group_key(row: Mapping[str, Any]) -> str:
    target = row["target"]
    return f"{target['asset_id']}|{target['cve_id']}"


def deterministic_group_split(
    dataset: Mapping[str, Any],
    *,
    training_policy_path: Path | str = DEFAULT_TRAINING_POLICY,
) -> dict[str, Any]:
    policy = load_training_policy(training_policy_path)
    split = policy["dataset"]["split"]
    seed = int(split["random_seed"])
    train_fraction = float(split["train_fraction"])
    validation_fraction = float(split["validation_fraction"])
    rows = list(dataset["rows"])

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[_group_key(row)].append(dict(row))

    rng = random.Random(seed)
    group_names = sorted(groups)
    rng.shuffle(group_names)

    # Greedy class-aware allocation keeps whole asset/CVE groups isolated.
    desired = {
        "train": len(rows) * train_fraction,
        "validation": len(rows) * validation_fraction,
        "test": len(rows) * (1.0 - train_fraction - validation_fraction),
    }
    buckets: dict[str, list[dict[str, Any]]] = {"train": [], "validation": [], "test": []}
    group_assignment: dict[str, str] = {}
    for group in group_names:
        candidates = sorted(
            buckets,
            key=lambda name: (len(buckets[name]) / max(desired[name], 1.0), name),
        )
        chosen = candidates[0]
        buckets[chosen].extend(groups[group])
        group_assignment[group] = chosen

    all_ids = {name: {r["row_id"] for r in values} for name, values in buckets.items()}
    overlap = {
        "train_validation": sorted(all_ids["train"] & all_ids["validation"]),
        "train_test": sorted(all_ids["train"] & all_ids["test"]),
        "validation_test": sorted(all_ids["validation"] & all_ids["test"]),
    }
    if any(overlap.values()):
        raise MLAdvisoryGovernanceError("Dataset split row leakage detected.")

    group_sets = {name: {_group_key(r) for r in values} for name, values in buckets.items()}
    if group_sets["train"] & group_sets["validation"] or group_sets["train"] & group_sets["test"] or group_sets["validation"] & group_sets["test"]:
        raise MLAdvisoryGovernanceError("Dataset split group leakage detected.")

    return {
        "schema_version": "1.0.0",
        "split_id": stable_id("AEG-MLS", {k: sorted(v) for k, v in all_ids.items()}),
        "strategy": split["strategy"],
        "random_seed": seed,
        "dataset_id": dataset["dataset_id"],
        "partitions": {name: [r["row_id"] for r in values] for name, values in buckets.items()},
        "group_assignment": group_assignment,
        "counts": {name: len(values) for name, values in buckets.items()},
        "class_distribution": {
            name: dict(sorted(Counter(r["label"] for r in values).items()))
            for name, values in buckets.items()
        },
        "leakage_check": {"status": "PASS", "overlap": overlap},
    }


def rows_for_partition(dataset: Mapping[str, Any], split: Mapping[str, Any], partition: str) -> list[dict[str, Any]]:
    wanted = set(split["partitions"][partition])
    return [dict(row) for row in dataset["rows"] if row["row_id"] in wanted]

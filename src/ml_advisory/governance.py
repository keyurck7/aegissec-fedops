from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "ml"
    / "ml_advisory_governance_policy_v1.yaml"
)


class MLAdvisoryGovernanceError(RuntimeError):
    """Raised when the independent-ML governance boundary is violated."""


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _stable_identifier(prefix: str, value: Mapping[str, Any]) -> str:
    digest = _sha256_bytes(_canonical_json_bytes(value))[:24].upper()
    return f"{prefix}-{digest}"


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MLAdvisoryGovernanceError(f"{label} must be a JSON object.")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise MLAdvisoryGovernanceError(f"{label} must be a list.")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MLAdvisoryGovernanceError(f"{label} must be a non-empty string.")
    return value.strip()


def _parse_timestamp(value: Any, label: str) -> str:
    text = _text(value, label).replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise MLAdvisoryGovernanceError(
            f"{label} must be an ISO-8601 timestamp."
        ) from exc
    if moment.tzinfo is None:
        raise MLAdvisoryGovernanceError(
            f"{label} must include an explicit timezone."
        )
    return moment.astimezone(timezone.utc).isoformat()


def _load_policy_document(
    path: Path | str = DEFAULT_POLICY_PATH,
) -> tuple[dict[str, Any], str]:
    policy_path = Path(path)
    if not policy_path.is_file():
        raise FileNotFoundError(f"ML governance policy not found: {policy_path}")
    raw = policy_path.read_bytes()
    value = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise MLAdvisoryGovernanceError(
            "ML governance policy must be a YAML object."
        )
    return value, _sha256_bytes(raw)


def _path_segments(path: str) -> list[str]:
    if not path.startswith("$."):
        raise MLAdvisoryGovernanceError(
            f"Governed field path must start with '$.': {path}"
        )
    segments = path[2:].split(".")
    if not segments or any(not segment for segment in segments):
        raise MLAdvisoryGovernanceError(f"Invalid governed field path: {path}")
    if any("[" in segment or "]" in segment for segment in segments):
        raise MLAdvisoryGovernanceError(
            f"Array-index paths are not permitted in the model contract: {path}"
        )
    return segments


_MISSING = object()


def _get_path(document: Mapping[str, Any], path: str) -> Any:
    current: Any = document
    for segment in _path_segments(path):
        if not isinstance(current, Mapping) or segment not in current:
            return _MISSING
        current = current[segment]
    return current


def _flatten(
    value: Any,
    path: str = "$",
) -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key in sorted(value):
            child_path = f"{path}.{key}"
            yield from _flatten(value[key], child_path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten(item, f"{path}[{index}]")
        return
    yield path, value


def _matches_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + ".") or path.startswith(
        prefix + "["
    )


def _contains_forbidden_term(value: Any, terms: set[str]) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().lower() in terms:
                return True
            if _contains_forbidden_term(child, terms):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_forbidden_term(item, terms) for item in value)
    if isinstance(value, str):
        normalized = value.strip().upper()
        return normalized in {
            "SSVC_POLICY_DECISION",
            "SSVC_OUTCOME",
            "SSVC_VECTOR",
            "POLICY_RULE_DERIVATION",
            "MODEL_PREDICTION",
            "FINAL_DISPOSITION",
            "HUMAN_RELABELED_FROM_SSVC",
        }
    return False


def _validate_value(
    feature: Mapping[str, Any],
    value: Any,
) -> None:
    feature_id = _text(feature.get("feature_id"), "feature_id")
    nullable = bool(feature.get("nullable", False))
    if value is None:
        if nullable:
            return
        raise MLAdvisoryGovernanceError(
            f"Feature {feature_id} is null but the contract does not allow null."
        )

    data_type = _text(feature.get("data_type"), f"{feature_id}.data_type")

    if data_type == "boolean":
        valid_type = isinstance(value, bool)
    elif data_type == "integer":
        valid_type = isinstance(value, int) and not isinstance(value, bool)
    elif data_type == "number":
        valid_type = (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
        )
    elif data_type == "string":
        valid_type = isinstance(value, str) and bool(value.strip())
    else:
        raise MLAdvisoryGovernanceError(
            f"Unsupported feature data type {data_type!r} for {feature_id}."
        )

    if not valid_type:
        raise MLAdvisoryGovernanceError(
            f"Feature {feature_id} violates declared type {data_type}."
        )

    minimum = feature.get("minimum")
    maximum = feature.get("maximum")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        if isinstance(minimum, (int, float)) and numeric < float(minimum):
            raise MLAdvisoryGovernanceError(
                f"Feature {feature_id} is below the contract minimum."
            )
        if isinstance(maximum, (int, float)) and numeric > float(maximum):
            raise MLAdvisoryGovernanceError(
                f"Feature {feature_id} exceeds the contract maximum."
            )

    allowed_values = feature.get("allowed_values")
    if allowed_values is not None:
        allowed = _list(allowed_values, f"{feature_id}.allowed_values")
        if value not in allowed:
            raise MLAdvisoryGovernanceError(
                f"Feature {feature_id} contains an unregistered value: {value!r}"
            )


def validate_policy_contract(
    policy: Mapping[str, Any],
) -> None:
    required_sections = {
        "policy",
        "authority",
        "source_contract",
        "model_features",
        "evaluation_context",
        "prohibited_inputs",
        "label_contract",
        "release",
    }
    missing = required_sections - set(policy)
    if missing:
        raise MLAdvisoryGovernanceError(
            f"ML governance policy missing sections: {sorted(missing)}"
        )

    features = _list(policy["model_features"], "model_features")
    if not features:
        raise MLAdvisoryGovernanceError(
            "The model feature allowlist must not be empty."
        )

    prohibited = _mapping(policy["prohibited_inputs"], "prohibited_inputs")
    prefixes = {
        _text(item, "prohibited path prefix")
        for item in _list(prohibited.get("path_prefixes"), "path_prefixes")
    }
    exact_paths = {
        _text(item, "prohibited exact path")
        for item in _list(prohibited.get("exact_paths"), "exact_paths")
    }

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()

    for item in features:
        feature = _mapping(item, "model feature")
        feature_id = _text(feature.get("feature_id"), "feature_id")
        source_path = _text(feature.get("source_path"), "source_path")
        _path_segments(source_path)

        if feature_id in seen_ids:
            raise MLAdvisoryGovernanceError(
                f"Duplicate model feature id: {feature_id}"
            )
        if source_path in seen_paths:
            raise MLAdvisoryGovernanceError(
                f"Duplicate model source path: {source_path}"
            )
        if source_path in exact_paths or any(
            _matches_prefix(source_path, prefix) for prefix in prefixes
        ):
            raise MLAdvisoryGovernanceError(
                f"Allowed model feature overlaps prohibited input: {source_path}"
            )

        seen_ids.add(feature_id)
        seen_paths.add(source_path)

    authority = _mapping(policy["authority"], "authority")
    if authority.get("ml_may_override_ssvc") is not False:
        raise MLAdvisoryGovernanceError(
            "The ML advisory must not be authorized to override SSVC."
        )
    if authority.get("ml_may_authorize_final_disposition") is not False:
        raise MLAdvisoryGovernanceError(
            "The ML advisory must not authorize final disposition."
        )

    label = _mapping(policy["label_contract"], "label_contract")
    classes = _list(label.get("allowed_classes"), "allowed_classes")
    if len(classes) < 2 or len(set(classes)) != len(classes):
        raise MLAdvisoryGovernanceError(
            "Label classes must contain at least two unique values."
        )

    accepted = set(
        _list(
            label.get("accepted_independent_source_types"),
            "accepted_independent_source_types",
        )
    )
    prohibited_sources = set(
        _list(label.get("prohibited_source_types"), "prohibited_source_types")
    )
    if accepted & prohibited_sources:
        raise MLAdvisoryGovernanceError(
            "Accepted and prohibited label source types must not overlap."
        )


def load_governance_policy(
    path: Path | str = DEFAULT_POLICY_PATH,
) -> tuple[dict[str, Any], str]:
    policy, digest = _load_policy_document(path)
    validate_policy_contract(policy)
    return policy, digest


def build_ml_feature_view(
    envelope: Mapping[str, Any],
    *,
    generated_at: str,
    policy_path: Path | str = DEFAULT_POLICY_PATH,
) -> dict[str, Any]:
    source = _mapping(envelope, "decision feature envelope")
    policy, policy_sha256 = load_governance_policy(policy_path)

    contract = _mapping(source.get("contract"), "envelope.contract")
    source_contract = _mapping(policy["source_contract"], "source_contract")

    expected_contract_id = _text(
        source_contract.get("required_contract_id"),
        "source_contract.required_contract_id",
    )
    expected_contract_version = _text(
        source_contract.get("required_contract_version"),
        "source_contract.required_contract_version",
    )

    if contract.get("contract_id") != expected_contract_id:
        raise MLAdvisoryGovernanceError(
            "Decision feature envelope contract id is not approved for ML use."
        )
    if contract.get("contract_version") != expected_contract_version:
        raise MLAdvisoryGovernanceError(
            "Decision feature envelope contract version is not approved."
        )

    release_decision = _mapping(
        source.get("release_decision"),
        "envelope.release_decision",
    )
    required_gate = _text(
        source_contract.get("required_upstream_stage_gate"),
        "source_contract.required_upstream_stage_gate",
    )
    if release_decision.get("stage_gate") != required_gate:
        raise MLAdvisoryGovernanceError(
            "Upstream decision-feature stage gate is not eligible for ML use."
        )

    model_features: dict[str, Any] = {}
    feature_provenance: list[dict[str, Any]] = []

    for raw_feature in _list(policy["model_features"], "model_features"):
        feature = _mapping(raw_feature, "model feature")
        feature_id = _text(feature.get("feature_id"), "feature_id")
        source_path = _text(feature.get("source_path"), "source_path")
        value = _get_path(source, source_path)

        if value is _MISSING:
            if bool(feature.get("required", False)):
                raise MLAdvisoryGovernanceError(
                    f"Required ML source feature is missing: {source_path}"
                )
            value = None

        _validate_value(feature, value)
        model_features[feature_id] = value
        feature_provenance.append(
            {
                "feature_id": feature_id,
                "source_path": source_path,
                "data_type": feature["data_type"],
                "required": bool(feature.get("required", False)),
                "nullable": bool(feature.get("nullable", False)),
            }
        )

    evaluation_context: dict[str, Any] = {}
    for raw_context in _list(
        policy["evaluation_context"],
        "evaluation_context",
    ):
        context = _mapping(raw_context, "evaluation context field")
        field_id = _text(context.get("field_id"), "field_id")
        source_path = _text(context.get("source_path"), "source_path")
        value = _get_path(source, source_path)
        evaluation_context[field_id] = None if value is _MISSING else value

    prohibited = _mapping(policy["prohibited_inputs"], "prohibited_inputs")
    prefixes = [
        _text(item, "prohibited path prefix")
        for item in _list(prohibited.get("path_prefixes"), "path_prefixes")
    ]
    exact_paths = {
        _text(item, "prohibited exact path")
        for item in _list(prohibited.get("exact_paths"), "exact_paths")
    }
    key_names = {
        _text(item, "prohibited key name").lower()
        for item in _list(prohibited.get("key_names"), "key_names")
    }

    isolated_paths = sorted(
        {
            path
            for path, _ in _flatten(source)
            if path in exact_paths
            or any(_matches_prefix(path, prefix) for prefix in prefixes)
            or any(segment.lower() in key_names for segment in path.split("."))
        }
    )

    for feature_id in model_features:
        if feature_id.lower() in key_names:
            raise MLAdvisoryGovernanceError(
                f"Prohibited key escaped into model feature view: {feature_id}"
            )

    target = _mapping(source.get("target"), "envelope.target")
    component = _mapping(target.get("component"), "envelope.target.component")

    source_envelope_id = _text(
        source.get("envelope_id"),
        "envelope.envelope_id",
    )
    created_at = _parse_timestamp(generated_at, "generated_at")

    identity = {
        "source_envelope_id": source_envelope_id,
        "policy_sha256": policy_sha256,
        "model_features": model_features,
        "target": {
            "cve_id": target.get("cve_id"),
            "asset_id": target.get("asset_id"),
            "component_purl": component.get("purl"),
        },
    }

    synthetic_context = evaluation_context.get("synthetic_or_demo_context") is True

    feature_view = {
        "schema_version": "1.0.0",
        "feature_view_id": _stable_identifier("AEG-MLF", identity),
        "generated_at": created_at,
        "authority": {
            "role": policy["authority"]["ml_role"],
            "ssvc_role": policy["authority"]["ssvc_role"],
            "ml_may_override_ssvc": False,
            "ml_may_authorize_final_disposition": False,
            "agreement_gate_required": True,
        },
        "contract": {
            "contract_id": policy["policy"]["contract_id"],
            "contract_version": policy["policy"]["contract_version"],
            "policy_id": policy["policy"]["policy_id"],
            "policy_version": policy["policy"]["version"],
            "policy_sha256": policy_sha256,
        },
        "source": {
            "envelope_id": source_envelope_id,
            "envelope_contract_id": contract["contract_id"],
            "envelope_contract_version": contract["contract_version"],
        },
        "target": {
            "cve_id": target.get("cve_id"),
            "asset_id": target.get("asset_id"),
            "component_purl": component.get("purl"),
        },
        "model_features": model_features,
        "feature_provenance": feature_provenance,
        "evaluation_context": evaluation_context,
        "exclusion_audit": {
            "source_prohibited_paths_present": isolated_paths,
            "source_prohibited_path_count": len(isolated_paths),
            "all_prohibited_fields_excluded": True,
            "ssvc_output_consumed": False,
            "governance_output_consumed": False,
        },
        "release_decision": {
            "stage_gate": policy["release"]["development_stage_gate"],
            "production_readiness": policy["release"]["production_readiness"],
            "production_dataset_eligible": not synthetic_context,
            "reason_codes": (
                ["SYNTHETIC_CONTEXT_DEVELOPMENT_ONLY"]
                if synthetic_context
                else ["ML_FEATURE_BOUNDARY_ACCEPTED"]
            ),
            "next_stage": policy["release"]["next_stage"],
        },
    }

    if _contains_forbidden_term(feature_view["model_features"], key_names):
        raise MLAdvisoryGovernanceError(
            "A prohibited SSVC or governance term escaped into model features."
        )

    return feature_view


def validate_label_record(
    label_record: Mapping[str, Any],
    *,
    policy_path: Path | str = DEFAULT_POLICY_PATH,
) -> dict[str, Any]:
    record = _mapping(label_record, "label record")
    policy, policy_sha256 = load_governance_policy(policy_path)
    contract = _mapping(policy["label_contract"], "label_contract")

    required_fields = {
        _text(item, "required label field")
        for item in _list(contract.get("required_fields"), "required_fields")
    }
    missing = sorted(field for field in required_fields if field not in record)
    if missing:
        raise MLAdvisoryGovernanceError(
            f"Label record missing required fields: {missing}"
        )

    if _contains_forbidden_term(record, {
        "ssvc_decision",
        "official_ssvc_decision",
        "matched_row",
        "outcome",
        "policy_decision",
        "production_readiness",
        "stage_gate",
        "final_disposition",
        "model_prediction",
    }):
        raise MLAdvisoryGovernanceError(
            "Label record contains prohibited policy or model-derived content."
        )

    label = _text(record.get("label"), "label")
    allowed_classes = _list(contract.get("allowed_classes"), "allowed_classes")
    if label not in allowed_classes:
        raise MLAdvisoryGovernanceError(
            f"Unregistered advisory label: {label}"
        )

    source_type = _text(record.get("source_type"), "source_type")
    prohibited_types = set(
        _list(contract.get("prohibited_source_types"), "prohibited_source_types")
    )
    if source_type in prohibited_types:
        raise MLAdvisoryGovernanceError(
            f"Prohibited label source type: {source_type}"
        )

    synthetic = record.get("synthetic")
    if not isinstance(synthetic, bool):
        raise MLAdvisoryGovernanceError(
            "label_record.synthetic must be a boolean."
        )

    accepted_types = set(
        _list(
            contract.get("accepted_independent_source_types"),
            "accepted_independent_source_types",
        )
    )
    controlled_synthetic = _text(
        contract.get("controlled_synthetic_source_type"),
        "controlled_synthetic_source_type",
    )

    if synthetic:
        if not bool(contract.get("synthetic_permitted_for_development", False)):
            raise MLAdvisoryGovernanceError(
                "Synthetic labels are disabled by policy."
            )
        if source_type != controlled_synthetic:
            raise MLAdvisoryGovernanceError(
                "Synthetic labels must use the controlled synthetic source type."
            )
        independent_source = False
        production_eligible = bool(
            contract.get("synthetic_production_eligible", False)
        )
        reason_codes = ["CONTROLLED_SYNTHETIC_LABEL_DEVELOPMENT_ONLY"]
    else:
        if source_type not in accepted_types:
            raise MLAdvisoryGovernanceError(
                f"Label source type is not independently approved: {source_type}"
            )
        independent_source = True
        production_eligible = True
        reason_codes = ["INDEPENDENT_OUTCOME_LABEL_ACCEPTED"]

    source_sha256 = _text(record.get("source_sha256"), "source_sha256")
    if not re_fullmatch_sha256(source_sha256):
        raise MLAdvisoryGovernanceError(
            "source_sha256 must contain exactly 64 lowercase hexadecimal characters."
        )

    observation_window_days = record.get("observation_window_days")
    if (
        not isinstance(observation_window_days, int)
        or isinstance(observation_window_days, bool)
        or observation_window_days <= 0
    ):
        raise MLAdvisoryGovernanceError(
            "observation_window_days must be a positive integer."
        )

    target = _mapping(record.get("target"), "label_record.target")
    for key in ("cve_id", "asset_id", "component_purl"):
        _text(target.get(key), f"label_record.target.{key}")

    validated = {
        "label": label,
        "class_index": allowed_classes.index(label),
        "source_type": source_type,
        "source_record_id": _text(
            record.get("source_record_id"),
            "source_record_id",
        ),
        "source_sha256": source_sha256,
        "observed_at": _parse_timestamp(record.get("observed_at"), "observed_at"),
        "observation_window_days": observation_window_days,
        "target": dict(target),
        "synthetic": synthetic,
        "independent_source": independent_source,
        "production_eligible": production_eligible,
        "policy_sha256": policy_sha256,
        "reason_codes": reason_codes,
    }
    return validated


def re_fullmatch_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def validate_training_pair(
    feature_view: Mapping[str, Any],
    label_record: Mapping[str, Any],
    *,
    policy_path: Path | str = DEFAULT_POLICY_PATH,
) -> dict[str, Any]:
    view = _mapping(feature_view, "feature view")
    validated_label = validate_label_record(
        label_record,
        policy_path=policy_path,
    )
    target = _mapping(view.get("target"), "feature_view.target")

    if dict(target) != validated_label["target"]:
        raise MLAdvisoryGovernanceError(
            "Feature view and label target identities do not match."
        )

    feature_release = _mapping(
        view.get("release_decision"),
        "feature_view.release_decision",
    )
    development_eligible = feature_release.get("stage_gate") == "PASS"
    production_eligible = bool(
        feature_release.get("production_dataset_eligible", False)
    ) and bool(validated_label["production_eligible"])

    return {
        "pair_id": _stable_identifier(
            "AEG-MLP",
            {
                "feature_view_id": view.get("feature_view_id"),
                "label_source_sha256": validated_label["source_sha256"],
                "label": validated_label["label"],
            },
        ),
        "feature_view_id": view.get("feature_view_id"),
        "label": validated_label,
        "development_eligible": development_eligible,
        "production_eligible": production_eligible,
        "reason_codes": (
            ["TRAINING_PAIR_PRODUCTION_ELIGIBLE"]
            if production_eligible
            else ["TRAINING_PAIR_DEVELOPMENT_ONLY"]
        ),
    }

from __future__ import annotations

import itertools
from collections.abc import Mapping
from typing import Any


PINNED_CONTRACT_SHA256 = {
    "deployer_policy": "539bee121237a3fac29e4c49f7e190f3c96b6b80dbea25526228993118e889ca",
    "deployer_table": "2dda887610160a0eb6b831d94f4d5bb489e8bebd92e53af84fb1535eb752f3e2",
    "human_impact_table": "d6ca20ec0d4c123df9239a8b61d790cd702185c2dbd2676f34fbef3d51dcb3fc",
    "mapping_policy": "cd5f28ca14ec03c5bf278ad769d6b2915060244521d794cc44591a4c99752ee2",
    "reason_registry": "cfde36547d5e06e9f127699adc17725610316bf863918a464f2df01b799dd178",
}

EXPECTED_DECISION_POINTS = {
    "exploitation": ("E", "1.1.0", ("N", "P", "A")),
    "system_exposure": ("EXP", "1.0.1", ("S", "C", "O")),
    "automatable": ("A", "2.0.0", ("N", "Y")),
    "safety_impact": ("SI", "2.0.1", ("N", "M", "R", "C")),
    "mission_impact": ("MI", "2.0.0", ("D", "MSC", "MEF", "MF")),
    "human_impact": ("HI", "2.0.2", ("L", "M", "H", "VH")),
}

EXPECTED_OUTCOMES = {
    "D": ("DEFER", 0),
    "S": ("SCHEDULED", 1),
    "O": ("OUT_OF_CYCLE", 2),
    "I": ("IMMEDIATE", 3),
}

EXPECTED_HUMAN_IMPACT = {
    ("N", "D"): "L",
    ("N", "MSC"): "L",
    ("N", "MEF"): "M",
    ("N", "MF"): "VH",
    ("M", "D"): "L",
    ("M", "MSC"): "L",
    ("M", "MEF"): "M",
    ("M", "MF"): "VH",
    ("R", "D"): "M",
    ("R", "MSC"): "H",
    ("R", "MEF"): "H",
    ("R", "MF"): "VH",
    ("C", "D"): "VH",
    ("C", "MSC"): "VH",
    ("C", "MEF"): "VH",
    ("C", "MF"): "VH",
}

REQUIRED_REASON_CODES = {
    "SSVC_INPUT_CONTRACT_VERIFIED",
    "SSVC_INPUT_INTEGRITY_VERIFIED",
    "SSVC_INPUT_STAGE_GATE_FAILED",
    "SSVC_EXPLOITATION_ACTIVE",
    "SSVC_EXPLOITATION_PUBLIC_POC",
    "SSVC_EXPLOITATION_NONE",
    "SSVC_EXPLOITATION_UNRESOLVED",
    "SSVC_EXPOSURE_OPEN",
    "SSVC_EXPOSURE_CONTROLLED",
    "SSVC_EXPOSURE_SMALL",
    "SSVC_EXPOSURE_OPEN_ASSUMED",
    "SSVC_AUTOMATABLE_YES",
    "SSVC_AUTOMATABLE_NO",
    "SSVC_AUTOMATABLE_UNRESOLVED",
    "SSVC_SAFETY_IMPACT_MAPPED",
    "SSVC_MISSION_IMPACT_MAPPED",
    "SSVC_HUMAN_IMPACT_DERIVED",
    "SSVC_HUMAN_IMPACT_UNRESOLVED",
    "SSVC_OFFICIAL_ROW_MATCHED",
    "SSVC_OFFICIAL_ROW_NOT_FOUND",
    "SSVC_DECISION_DEFER",
    "SSVC_DECISION_SCHEDULED",
    "SSVC_DECISION_OUT_OF_CYCLE",
    "SSVC_DECISION_IMMEDIATE",
    "SSVC_HUMAN_REVIEW_PRESERVED",
    "SSVC_PRODUCTION_BLOCK_PRESERVED",
    "SSVC_FEDERAL_OVERLAY_NOT_APPLIED",
    "SSVC_ML_ADVISORY_NOT_APPLIED",
    "SSVC_FINAL_DISPOSITION_NOT_AUTHORIZED",
    "SSVC_SAFETY_IMPACT_UNRESOLVED",
    "SSVC_MISSION_IMPACT_UNRESOLVED",
    "SSVC_INPUT_INTEGRITY_FAILED",
    "SSVC_BLOCKING_CONFLICT_PRESENT",
    "SSVC_NO_BLOCKING_CONFLICTS",
    "SSVC_MANDATORY_POINTS_RESOLVED",
    "SSVC_POLICY_HASHES_VERIFIED",
    "SSVC_REASON_REGISTRY_VERIFIED",
    "SSVC_PROVENANCE_COMPLETE",
    "SSVC_MAPPING_BLOCKED",
}


class SSVCContractAssuranceError(RuntimeError):
    """Raised when the pinned SSVC policy contract is unsafe or inconsistent."""


def _mapping(value: Any, label: str, errors: list[str]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{label} must be an object")
    return {}


def _rows(value: Any, label: str, errors: list[str]) -> list[Any]:
    if isinstance(value, list):
        return value
    errors.append(f"{label} must be an array")
    return []


def _require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def _exact(value: Any, expected: Any, label: str, errors: list[str]) -> None:
    _require(value == expected, f"{label}: expected {expected!r}, observed {value!r}", errors)


def _deployer_vector(row: Mapping[str, Any], errors: list[str], row_index: int) -> tuple[str, str, str, str]:
    inputs = _mapping(row.get("inputs"), f"deployer row {row_index} inputs", errors)
    values: list[str] = []
    for name in ("exploitation", "system_exposure", "automatable", "human_impact"):
        point = _mapping(inputs.get(name), f"deployer row {row_index} {name}", errors)
        key = point.get("key")
        values.append(key if isinstance(key, str) else "<INVALID>")
    return tuple(values)  # type: ignore[return-value]


def validate_ssvc_contract_documents(
    *,
    deployer_policy: Mapping[str, Any],
    mapping_policy: Mapping[str, Any],
    deployer_table: Mapping[str, Any],
    human_impact_table: Mapping[str, Any],
    reason_registry: Mapping[str, Any],
    digests: Mapping[str, str] | None = None,
    enforce_pinned_hashes: bool = True,
) -> dict[str, Any]:
    """Validate the complete pinned SSVC policy contract before evaluation."""

    errors: list[str] = []

    if enforce_pinned_hashes:
        _require(digests is not None, "contract digests are required", errors)
        if digests is not None:
            for name, expected in PINNED_CONTRACT_SHA256.items():
                observed = digests.get(name)
                _exact(observed, expected, f"{name} SHA-256", errors)

    policy = _mapping(deployer_policy.get("policy"), "deployer policy metadata", errors)
    _exact(policy.get("policy_id"), "AEGIS-SSVC-DEPLOYER-POLICY", "policy ID", errors)
    _exact(policy.get("version"), "1.0.0", "policy version", errors)
    _exact(policy.get("engine_version"), "1.0.0", "engine version", errors)

    upstream = _mapping(policy.get("upstream_contract"), "upstream contract", errors)
    _exact(upstream.get("contract_id"), "AEGIS-DECISION-FEATURE-CONTRACT", "upstream contract ID", errors)
    _exact(upstream.get("version"), "1.0.0", "upstream contract version", errors)

    official = _mapping(policy.get("official_model"), "official model", errors)
    _exact(official.get("namespace"), "ssvc", "official namespace", errors)
    _exact(official.get("decision_table_key"), "DP", "decision table key", errors)
    _exact(official.get("decision_table_version"), "1.0.0", "decision table version", errors)
    _exact(official.get("outcome_key"), "DSOI", "outcome key", errors)
    _exact(official.get("outcome_version"), "1.0.0", "outcome version", errors)

    points = _mapping(deployer_policy.get("decision_points"), "decision points", errors)
    _exact(set(points), set(EXPECTED_DECISION_POINTS), "decision point names", errors)
    for name, (key, version, ordered_keys) in EXPECTED_DECISION_POINTS.items():
        point = _mapping(points.get(name), f"decision point {name}", errors)
        _exact(point.get("namespace"), "ssvc", f"{name} namespace", errors)
        _exact(point.get("key"), key, f"{name} key", errors)
        _exact(point.get("version"), version, f"{name} version", errors)
        _exact(tuple(point.get("ordered_keys", [])), ordered_keys, f"{name} ordered keys", errors)

    outcomes = _mapping(deployer_policy.get("outcomes"), "outcomes", errors)
    _exact(set(outcomes), set(EXPECTED_OUTCOMES), "outcome keys", errors)
    for key, (name, rank) in EXPECTED_OUTCOMES.items():
        outcome = _mapping(outcomes.get(key), f"outcome {key}", errors)
        _exact(outcome.get("name"), name, f"outcome {key} name", errors)
        _exact(outcome.get("rank"), rank, f"outcome {key} rank", errors)

    governance = _mapping(deployer_policy.get("governance"), "governance policy", errors)
    required_governance = {
        "unknown_exploitation": "BLOCK",
        "unknown_automatable": "BLOCK",
        "unknown_human_impact": "BLOCK",
        "unknown_system_exposure": "ASSUME_OPEN_WITH_RECORDED_JUSTIFICATION",
        "upstream_stage_gate_must_pass": True,
        "upstream_integrity_must_verify": True,
        "blocking_conflicts_must_be_zero": True,
        "preserve_upstream_human_review": True,
        "production_readiness": "BLOCKED",
        "next_stage": "MILESTONE_12F_INDEPENDENT_ML_ADVISORY",
        "official_and_extension_outputs_must_remain_separate": True,
        "sector_label_must_not_directly_select_ssvc_outcome": True,
        "epss_must_not_replace_exploitation_state": True,
    }
    for name, expected in required_governance.items():
        _exact(governance.get(name), expected, f"governance.{name}", errors)

    mapping_meta = _mapping(mapping_policy.get("mapping_policy"), "mapping policy metadata", errors)
    _exact(mapping_meta.get("policy_id"), "AEGIS-SSVC-12D-MAPPING-POLICY", "mapping policy ID", errors)
    _exact(mapping_meta.get("version"), "1.0.0", "mapping policy version", errors)
    mapping_input = _mapping(mapping_policy.get("input_contract"), "mapping input contract", errors)
    _exact(mapping_input.get("contract_id"), "AEGIS-DECISION-FEATURE-CONTRACT", "mapping input contract ID", errors)
    _exact(mapping_input.get("version"), "1.0.0", "mapping input contract version", errors)

    mappings = _mapping(mapping_policy.get("mappings"), "mapping rules", errors)
    _exact(_mapping(mappings.get("exploitation"), "exploitation mapping", errors).get("unknown_action"), "BLOCK", "exploitation unknown action", errors)
    _exact(_mapping(mappings.get("system_exposure"), "exposure mapping", errors).get("unknown_action"), "ASSUME_OPEN_WITH_RECORDED_JUSTIFICATION", "exposure unknown action", errors)
    automatable = _mapping(mappings.get("automatable"), "automatable mapping", errors)
    _exact(automatable.get("unknown_action"), "BLOCK", "automatable unknown action", errors)
    _exact(automatable.get("cvss_only_inference_allowed"), False, "CVSS-only automatable inference", errors)
    _exact(_mapping(mappings.get("safety_impact"), "safety mapping", errors).get("unknown_action"), "BLOCK", "safety unknown action", errors)
    _exact(_mapping(mappings.get("mission_impact"), "mission mapping", errors).get("unknown_action"), "BLOCK", "mission unknown action", errors)
    human_mapping = _mapping(mappings.get("human_impact"), "human impact mapping", errors)
    _exact(human_mapping.get("unknown_action"), "BLOCK", "human impact unknown action", errors)
    _exact(human_mapping.get("decision_table"), "policies/decision/ssvc_human_impact_decision_table_v1.yaml", "human impact decision table path", errors)

    required_provenance = _mapping(mapping_policy.get("required_provenance"), "required provenance", errors)
    for name in (
        "record_source_feature_paths",
        "record_mapping_rule_id",
        "record_assumptions",
        "record_policy_hashes",
        "record_decision_table_row",
    ):
        _exact(required_provenance.get(name), True, f"required_provenance.{name}", errors)

    deployer_meta = _mapping(deployer_table.get("decision_table"), "deployer table metadata", errors)
    _exact(deployer_meta.get("namespace"), "ssvc", "deployer table namespace", errors)
    _exact(deployer_meta.get("key"), "DP", "deployer table key", errors)
    _exact(deployer_meta.get("version"), "1.0.0", "deployer table version", errors)
    _exact(tuple(deployer_meta.get("input_order", [])), ("exploitation", "system_exposure", "automatable", "human_impact"), "deployer input order", errors)
    _exact(deployer_meta.get("expected_row_count"), 72, "deployer expected row count", errors)

    deployer_rows = _rows(deployer_table.get("rows"), "deployer rows", errors)
    _exact(len(deployer_rows), 72, "deployer row count", errors)
    expected_vectors = list(itertools.product(("N", "P", "A"), ("S", "C", "O"), ("N", "Y"), ("L", "M", "H", "VH")))
    observed_vectors: list[tuple[str, str, str, str]] = []
    observed_outcomes: dict[tuple[str, str, str, str], int] = {}
    rank_map = {key: rank for key, (_, rank) in EXPECTED_OUTCOMES.items()}

    for index, raw in enumerate(deployer_rows):
        row = _mapping(raw, f"deployer row {index}", errors)
        _exact(row.get("row"), index, f"deployer row index {index}", errors)
        vector = _deployer_vector(row, errors, index)
        observed_vectors.append(vector)
        if index < len(expected_vectors):
            _exact(vector, expected_vectors[index], f"deployer row {index} vector", errors)
        outcome_key = row.get("outcome_key")
        _require(outcome_key in rank_map, f"deployer row {index} has invalid outcome {outcome_key!r}", errors)
        if outcome_key in rank_map:
            observed_outcomes[vector] = rank_map[outcome_key]

    _exact(len(set(observed_vectors)), 72, "deployer unique vector count", errors)
    _exact(set(observed_vectors), set(expected_vectors), "deployer vector coverage", errors)

    orders = (
        {value: index for index, value in enumerate(("N", "P", "A"))},
        {value: index for index, value in enumerate(("S", "C", "O"))},
        {value: index for index, value in enumerate(("N", "Y"))},
        {value: index for index, value in enumerate(("L", "M", "H", "VH"))},
    )
    if len(observed_outcomes) == 72:
        for lower, lower_rank in observed_outcomes.items():
            for upper, upper_rank in observed_outcomes.items():
                comparable = all(orders[i][lower[i]] <= orders[i][upper[i]] for i in range(4))
                if comparable and lower_rank > upper_rank:
                    errors.append(
                        "deployer monotonicity violation: "
                        f"{lower} rank {lower_rank} exceeds {upper} rank {upper_rank}"
                    )

    human_meta = _mapping(human_impact_table.get("decision_table"), "human impact table metadata", errors)
    _exact(human_meta.get("namespace"), "ssvc", "human table namespace", errors)
    _exact(human_meta.get("key"), "HI", "human table key", errors)
    _exact(human_meta.get("version"), "1.0.0", "human table version", errors)
    _exact(tuple(human_meta.get("input_order", [])), ("safety_impact", "mission_impact"), "human table input order", errors)
    _exact(human_meta.get("expected_row_count"), 16, "human expected row count", errors)

    human_rows = _rows(human_impact_table.get("rows"), "human impact rows", errors)
    _exact(len(human_rows), 16, "human impact row count", errors)
    expected_human_vectors = list(itertools.product(("N", "M", "R", "C"), ("D", "MSC", "MEF", "MF")))
    observed_human: dict[tuple[str, str], str] = {}
    observed_human_vectors: list[tuple[str, str]] = []
    for index, raw in enumerate(human_rows):
        row = _mapping(raw, f"human impact row {index}", errors)
        _exact(row.get("row"), index, f"human impact row index {index}", errors)
        vector = (row.get("safety_impact_key"), row.get("mission_impact_key"))
        observed_human_vectors.append(vector)  # type: ignore[arg-type]
        if index < len(expected_human_vectors):
            _exact(vector, expected_human_vectors[index], f"human impact row {index} vector", errors)
        human_key = row.get("human_impact_key")
        _require(human_key in {"L", "M", "H", "VH"}, f"human impact row {index} has invalid output {human_key!r}", errors)
        if isinstance(vector[0], str) and isinstance(vector[1], str) and isinstance(human_key, str):
            observed_human[vector] = human_key

    _exact(len(set(observed_human_vectors)), 16, "human impact unique vector count", errors)
    _exact(set(observed_human_vectors), set(expected_human_vectors), "human impact vector coverage", errors)
    _exact(observed_human, EXPECTED_HUMAN_IMPACT, "human impact mapping", errors)

    registry_meta = _mapping(reason_registry.get("registry"), "reason registry metadata", errors)
    _exact(registry_meta.get("registry_id"), "AEGIS-SSVC-REASON-CODES", "reason registry ID", errors)
    _exact(registry_meta.get("version"), "1.0.0", "reason registry version", errors)
    _exact(registry_meta.get("closed_registry"), True, "reason registry closed flag", errors)
    reason_rows = _rows(reason_registry.get("codes"), "reason codes", errors)
    observed_codes: list[str] = []
    for index, raw in enumerate(reason_rows):
        entry = _mapping(raw, f"reason code row {index}", errors)
        code = entry.get("code")
        _require(isinstance(code, str) and bool(code), f"reason code row {index} has invalid code", errors)
        if isinstance(code, str):
            observed_codes.append(code)
    _exact(len(observed_codes), len(set(observed_codes)), "reason code uniqueness", errors)
    _require(REQUIRED_REASON_CODES.issubset(set(observed_codes)), "reason registry is missing engine-required codes", errors)

    if errors:
        raise SSVCContractAssuranceError(
            "SSVC contract assurance failed:\n - " + "\n - ".join(sorted(set(errors)))
        )

    return {
        "status": "PASS",
        "pinned_hashes_verified": bool(enforce_pinned_hashes),
        "deployer_row_count": len(deployer_rows),
        "deployer_unique_vector_count": len(set(observed_vectors)),
        "human_impact_row_count": len(human_rows),
        "human_impact_unique_vector_count": len(set(observed_human_vectors)),
        "reason_code_count": len(observed_codes),
        "monotonicity_violations": 0,
    }

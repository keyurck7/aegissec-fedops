from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

import src.decision_policy.ssvc_contract_assurance as contract_assurance
from src.decision_policy.ssvc_engine import (
    SSVCPolicyDecisionError,
    build_ssvc_policy_decision,
)


ROOT = Path(__file__).resolve().parents[2]
FEATURE_PATH = next(
    (ROOT / "data" / "processed" / "decision_features").rglob(
        "*.features.json"
    )
)
POLICY_PATHS = {
    "deployer_policy": ROOT / "policies/decision/ssvc_deployer_policy_v1.yaml",
    "deployer_table": ROOT / "policies/decision/ssvc_deployer_decision_table_v1.yaml",
    "human_impact_table": ROOT / "policies/decision/ssvc_human_impact_decision_table_v1.yaml",
    "mapping_policy": ROOT / "policies/decision/ssvc_mapping_policy_v1.yaml",
    "reason_registry": ROOT / "policies/decision/ssvc_reason_codes_v1.yaml",
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "decision_feature_envelope": load_json(FEATURE_PATH),
        "input_relative_path": FEATURE_PATH.relative_to(ROOT).as_posix(),
        "input_sha256": digest(FEATURE_PATH),
        "generated_at": "2026-07-19T16:00:00Z",
    }
    values.update(overrides)
    return build_ssvc_policy_decision(**values)


def write_yaml(tmp_path: Path, name: str, document: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    return path


def repin(
    monkeypatch: pytest.MonkeyPatch,
    contract_name: str,
    path: Path,
) -> None:
    monkeypatch.setitem(
        contract_assurance.PINNED_CONTRACT_SHA256,
        contract_name,
        digest(path),
    )


def test_runtime_accepts_the_exact_pinned_contract() -> None:
    report = build()
    assert report["governance"]["stage_gate"] == "PASS"
    assert report["audit"]["policy_hashes_verified"] is True
    assert report["audit"]["table_row_count"] == 72
    assert report["audit"]["human_impact_row_count"] == 16


def test_runtime_rejects_semantically_equivalent_hash_drift(
    tmp_path: Path,
) -> None:
    original = POLICY_PATHS["deployer_policy"].read_text(encoding="utf-8")
    path = tmp_path / "deployer-policy.yaml"
    path.write_text(
        original + "\n# semantically inert byte-level drift\n",
        encoding="utf-8",
    )
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == yaml.safe_load(
        original
    )
    assert digest(path) != digest(POLICY_PATHS["deployer_policy"])

    with pytest.raises(
        SSVCPolicyDecisionError,
        match="deployer_policy SHA-256",
    ):
        build(deployer_policy_path=path)


def test_runtime_rejects_duplicate_vector_even_if_digest_is_repinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = yaml.safe_load(
        POLICY_PATHS["deployer_table"].read_text(encoding="utf-8")
    )
    document["rows"][1]["inputs"] = copy.deepcopy(
        document["rows"][0]["inputs"]
    )
    path = write_yaml(tmp_path, "deployer-table.yaml", document)
    repin(monkeypatch, "deployer_table", path)

    with pytest.raises(
        SSVCPolicyDecisionError,
        match="deployer unique vector count",
    ):
        build(deployer_table_path=path)


def test_runtime_rejects_human_impact_semantic_drift_when_repinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = yaml.safe_load(
        POLICY_PATHS["human_impact_table"].read_text(encoding="utf-8")
    )
    document["rows"][0]["human_impact_key"] = "VH"
    path = write_yaml(tmp_path, "human-impact-table.yaml", document)
    repin(monkeypatch, "human_impact_table", path)

    with pytest.raises(
        SSVCPolicyDecisionError,
        match="human impact mapping",
    ):
        build(human_impact_table_path=path)


def test_runtime_rejects_fail_open_mapping_when_repinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = yaml.safe_load(
        POLICY_PATHS["mapping_policy"].read_text(encoding="utf-8")
    )
    document["mappings"]["automatable"]["unknown_action"] = "ASSUME_NO"
    path = write_yaml(tmp_path, "mapping-policy.yaml", document)
    repin(monkeypatch, "mapping_policy", path)

    with pytest.raises(
        SSVCPolicyDecisionError,
        match="automatable unknown action",
    ):
        build(mapping_policy_path=path)


def test_runtime_rejects_reason_registry_weakening_when_repinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = yaml.safe_load(
        POLICY_PATHS["reason_registry"].read_text(encoding="utf-8")
    )
    document["registry"]["closed_registry"] = False
    path = write_yaml(tmp_path, "reason-registry.yaml", document)
    repin(monkeypatch, "reason_registry", path)

    with pytest.raises(
        SSVCPolicyDecisionError,
        match="reason registry must be closed",
    ):
        build(reason_registry_path=path)

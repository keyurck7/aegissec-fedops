from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest
import yaml

from src.decision_policy.ssvc_contract_assurance import (
    SSVCContractAssuranceError,
    validate_ssvc_contract_documents,
)

ROOT = Path(__file__).resolve().parents[2]
PATHS = {
    "deployer_policy": ROOT / "policies/decision/ssvc_deployer_policy_v1.yaml",
    "deployer_table": ROOT / "policies/decision/ssvc_deployer_decision_table_v1.yaml",
    "human_impact_table": ROOT / "policies/decision/ssvc_human_impact_decision_table_v1.yaml",
    "mapping_policy": ROOT / "policies/decision/ssvc_mapping_policy_v1.yaml",
    "reason_registry": ROOT / "policies/decision/ssvc_reason_codes_v1.yaml",
}


def documents() -> dict:
    return {
        name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, path in PATHS.items()
    }


def digests() -> dict[str, str]:
    return {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in PATHS.items()
    }


def validate(docs: dict, *, hashes: bool = False):
    return validate_ssvc_contract_documents(
        **docs,
        digests=digests() if hashes else None,
        enforce_pinned_hashes=hashes,
    )


def test_pinned_contract_passes_complete_assurance() -> None:
    result = validate(documents(), hashes=True)
    assert result["status"] == "PASS"
    assert result["deployer_unique_vector_count"] == 72
    assert result["human_impact_unique_vector_count"] == 16
    assert result["monotonicity_violations"] == 0


def test_pinned_digest_drift_is_rejected() -> None:
    docs = documents()
    observed = digests()
    observed["deployer_table"] = "0" * 64
    with pytest.raises(SSVCContractAssuranceError, match="deployer_table SHA-256"):
        validate_ssvc_contract_documents(
            **docs,
            digests=observed,
            enforce_pinned_hashes=True,
        )


def test_duplicate_deployer_vector_is_rejected() -> None:
    docs = documents()
    docs["deployer_table"]["rows"][1]["inputs"] = copy.deepcopy(
        docs["deployer_table"]["rows"][0]["inputs"]
    )
    with pytest.raises(SSVCContractAssuranceError, match="deployer unique vector count"):
        validate(docs)


def test_missing_deployer_row_is_rejected() -> None:
    docs = documents()
    docs["deployer_table"]["rows"].pop()
    with pytest.raises(SSVCContractAssuranceError, match="deployer row count"):
        validate(docs)


def test_deployer_row_reordering_is_rejected() -> None:
    docs = documents()
    rows = docs["deployer_table"]["rows"]
    rows[0], rows[1] = rows[1], rows[0]
    rows[0]["row"] = 0
    rows[1]["row"] = 1
    with pytest.raises(SSVCContractAssuranceError, match="deployer row 0 vector"):
        validate(docs)


def test_non_monotonic_outcome_mutation_is_rejected() -> None:
    docs = documents()
    docs["deployer_table"]["rows"][0]["outcome_key"] = "I"
    with pytest.raises(SSVCContractAssuranceError, match="monotonicity violation"):
        validate(docs)


def test_duplicate_human_impact_vector_is_rejected() -> None:
    docs = documents()
    docs["human_impact_table"]["rows"][1]["safety_impact_key"] = "N"
    docs["human_impact_table"]["rows"][1]["mission_impact_key"] = "D"
    with pytest.raises(SSVCContractAssuranceError, match="human impact unique vector count"):
        validate(docs)


def test_human_impact_semantic_mutation_is_rejected() -> None:
    docs = documents()
    docs["human_impact_table"]["rows"][0]["human_impact_key"] = "VH"
    with pytest.raises(SSVCContractAssuranceError, match="human impact mapping"):
        validate(docs)


def test_policy_version_drift_is_rejected() -> None:
    docs = documents()
    docs["deployer_policy"]["policy"]["version"] = "1.0.1"
    with pytest.raises(SSVCContractAssuranceError, match="policy version"):
        validate(docs)


def test_fail_open_mapping_mutation_is_rejected() -> None:
    docs = documents()
    docs["mapping_policy"]["mappings"]["automatable"]["unknown_action"] = "ASSUME_NO"
    with pytest.raises(SSVCContractAssuranceError, match="automatable unknown action"):
        validate(docs)


def test_reason_registry_open_or_incomplete_is_rejected() -> None:
    docs = documents()
    docs["reason_registry"]["registry"]["closed_registry"] = False
    docs["reason_registry"]["codes"] = docs["reason_registry"]["codes"][:-1]
    with pytest.raises(SSVCContractAssuranceError) as captured:
        validate(docs)
    message = str(captured.value)
    assert "reason registry closed flag" in message
    assert "reason registry is missing engine-required codes" in message

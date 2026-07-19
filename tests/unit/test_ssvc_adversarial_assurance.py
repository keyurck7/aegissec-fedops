from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest
import yaml

from src.decision_policy.ssvc_contract_assurance import (
    PINNED_CONTRACT_SHA256,
    SSVCContractAssuranceError,
    validate_ssvc_contract_documents,
)


ROOT = Path(__file__).resolve().parents[2]

CONTRACT_PATHS = {
    "deployer_policy": (
        ROOT
        / "policies"
        / "decision"
        / "ssvc_deployer_policy_v1.yaml"
    ),
    "deployer_table": (
        ROOT
        / "policies"
        / "decision"
        / "ssvc_deployer_decision_table_v1.yaml"
    ),
    "human_impact_table": (
        ROOT
        / "policies"
        / "decision"
        / "ssvc_human_impact_decision_table_v1.yaml"
    ),
    "mapping_policy": (
        ROOT
        / "policies"
        / "decision"
        / "ssvc_mapping_policy_v1.yaml"
    ),
    "reason_registry": (
        ROOT
        / "policies"
        / "decision"
        / "ssvc_reason_codes_v1.yaml"
    ),
}


SEMANTIC_MUTATIONS = (
    "FAIL_OPEN_AUTOMATABLE",
    "FAIL_OPEN_EXPLOITATION",
    "DUPLICATE_DEPLOYER_VECTOR",
    "MISSING_DEPLOYER_ROW",
    "IMMEDIATE_RANK_DOWNGRADE",
    "OUTCOME_NAME_DRIFT",
    "HUMAN_IMPACT_DOWNGRADE",
    "DEPLOYER_INPUT_ORDER_PERMUTATION",
    "REOPEN_REASON_REGISTRY",
    "REMOVE_REQUIRED_REASON_CODE",
    "ENABLE_SECTOR_OUTCOME_SELECTION",
    "ALLOW_EPSS_TO_REPLACE_EXPLOITATION",
    "UNBLOCK_PRODUCTION",
    "REDIRECT_NEXT_STAGE",
    "DISABLE_POLICY_HASH_PROVENANCE",
    "REORDER_EXPLOITATION_KEYS",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_contract() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, str],
]:
    documents: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}

    for name, path in CONTRACT_PATHS.items():
        assert path.is_file(), f"Missing contract file: {path}"

        document = yaml.safe_load(
            path.read_text(encoding="utf-8")
        )

        assert isinstance(document, dict)

        documents[name] = document
        digests[name] = sha256(path)

    return documents, digests


def validate(
    documents: dict[str, dict[str, Any]],
    digests: dict[str, str],
    *,
    enforce_pinned_hashes: bool,
) -> dict[str, Any]:
    return validate_ssvc_contract_documents(
        deployer_policy=documents["deployer_policy"],
        mapping_policy=documents["mapping_policy"],
        deployer_table=documents["deployer_table"],
        human_impact_table=documents["human_impact_table"],
        reason_registry=documents["reason_registry"],
        digests=digests,
        enforce_pinned_hashes=enforce_pinned_hashes,
    )


def apply_mutation(
    mutation_id: str,
    documents: dict[str, dict[str, Any]],
) -> None:
    if mutation_id == "FAIL_OPEN_AUTOMATABLE":
        documents["mapping_policy"]["mappings"][
            "automatable"
        ]["unknown_action"] = "ASSUME_NO"

    elif mutation_id == "FAIL_OPEN_EXPLOITATION":
        documents["mapping_policy"]["mappings"][
            "exploitation"
        ]["unknown_action"] = "ASSUME_NONE"

    elif mutation_id == "DUPLICATE_DEPLOYER_VECTOR":
        rows = documents["deployer_table"]["rows"]

        rows[1]["inputs"] = copy.deepcopy(
            rows[0]["inputs"]
        )

    elif mutation_id == "MISSING_DEPLOYER_ROW":
        documents["deployer_table"]["rows"].pop()

    elif mutation_id == "IMMEDIATE_RANK_DOWNGRADE":
        documents["deployer_policy"]["outcomes"][
            "I"
        ]["rank"] = 0

    elif mutation_id == "OUTCOME_NAME_DRIFT":
        documents["deployer_policy"]["outcomes"][
            "O"
        ]["name"] = "ROUTINE"

    elif mutation_id == "HUMAN_IMPACT_DOWNGRADE":
        documents["human_impact_table"]["rows"][
            -1
        ]["human_impact_key"] = "L"

    elif mutation_id == "DEPLOYER_INPUT_ORDER_PERMUTATION":
        documents["deployer_table"]["decision_table"][
            "input_order"
        ] = [
            "system_exposure",
            "exploitation",
            "automatable",
            "human_impact",
        ]

    elif mutation_id == "REOPEN_REASON_REGISTRY":
        documents["reason_registry"]["registry"][
            "closed_registry"
        ] = False

    elif mutation_id == "REMOVE_REQUIRED_REASON_CODE":
        documents["reason_registry"]["codes"] = [
            entry
            for entry in documents[
                "reason_registry"
            ]["codes"]
            if entry.get("code") != "SSVC_MAPPING_BLOCKED"
        ]

    elif mutation_id == "ENABLE_SECTOR_OUTCOME_SELECTION":
        documents["deployer_policy"]["governance"][
            "sector_label_must_not_directly_select_ssvc_outcome"
        ] = False

    elif mutation_id == "ALLOW_EPSS_TO_REPLACE_EXPLOITATION":
        documents["deployer_policy"]["governance"][
            "epss_must_not_replace_exploitation_state"
        ] = False

    elif mutation_id == "UNBLOCK_PRODUCTION":
        documents["deployer_policy"]["governance"][
            "production_readiness"
        ] = "READY"

    elif mutation_id == "REDIRECT_NEXT_STAGE":
        documents["deployer_policy"]["governance"][
            "next_stage"
        ] = "PRODUCTION_DEPLOYMENT"

    elif mutation_id == "DISABLE_POLICY_HASH_PROVENANCE":
        documents["mapping_policy"][
            "required_provenance"
        ]["record_policy_hashes"] = False

    elif mutation_id == "REORDER_EXPLOITATION_KEYS":
        documents["deployer_policy"]["decision_points"][
            "exploitation"
        ]["ordered_keys"] = ["A", "P", "N"]

    else:
        raise AssertionError(
            f"Unknown semantic mutation: {mutation_id}"
        )


def test_current_contract_digests_equal_pinned_values() -> None:
    _, digests = load_contract()

    assert digests == PINNED_CONTRACT_SHA256


def test_exact_pinned_contract_is_accepted() -> None:
    documents, digests = load_contract()

    result = validate(
        documents,
        digests,
        enforce_pinned_hashes=True,
    )

    assert result["pinned_hashes_verified"] is True
    assert result["deployer_row_count"] == 72
    assert result["human_impact_row_count"] == 16


def test_byte_level_drift_is_rejected() -> None:
    documents, digests = load_contract()

    # Simulates semantically inert text drift, such as a comment
    # being added to a governed policy file.
    digests["deployer_policy"] = "0" * 64

    with pytest.raises(
        SSVCContractAssuranceError,
    ):
        validate(
            documents,
            digests,
            enforce_pinned_hashes=True,
        )


@pytest.mark.parametrize(
    "mutation_id",
    SEMANTIC_MUTATIONS,
)
def test_semantic_mutation_is_rejected_even_after_repinning(
    mutation_id: str,
) -> None:
    documents, digests = load_contract()

    apply_mutation(
        mutation_id,
        documents,
    )

    # Hash enforcement is intentionally disabled here.
    #
    # This simulates an attacker or careless maintainer changing
    # the contract and then repinning its new hash. Structural and
    # semantic validation must still reject the weakened contract.
    with pytest.raises(
        SSVCContractAssuranceError,
    ):
        validate(
            documents,
            digests,
            enforce_pinned_hashes=False,
        )


def test_mutation_catalog_covers_required_attack_classes() -> None:
    assert len(SEMANTIC_MUTATIONS) == 16

    joined = " ".join(SEMANTIC_MUTATIONS)

    assert "FAIL_OPEN" in joined
    assert "DUPLICATE" in joined
    assert "MISSING" in joined
    assert "DOWNGRADE" in joined
    assert "REASON" in joined
    assert "SECTOR" in joined
    assert "EPSS" in joined
    assert "PRODUCTION" in joined
    assert "PROVENANCE" in joined

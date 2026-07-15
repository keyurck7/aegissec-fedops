from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from src.assurance.supply_chain_assurance import (
    SupplyChainAssuranceHarness,
    save_supply_chain_assurance_artifacts,
)


def test_catalog_contains_48_unique_critical_scenarios() -> None:
    harness = SupplyChainAssuranceHarness()
    scenarios = harness.catalog["scenarios"]
    assert len(scenarios) == 48
    assert len({item["scenario_id"] for item in scenarios}) == 48
    assert all(item["severity"] == "critical" for item in scenarios)


def test_complete_campaign_passes_all_gates() -> None:
    report = SupplyChainAssuranceHarness().run()
    summary = report["summary"]
    assert summary["scenario_count"] == 48
    assert summary["defended_critical_count"] == 48
    assert summary["unsafe_release_count"] == 0
    assert summary["unverified_artifact_release_count"] == 0
    assert summary["undetected_count"] == 0
    assert summary["harness_error_count"] == 0
    assert summary["overall_passed"] is True
    assert all(gate["passed"] for gate in report["quality_gates"])
    assert report["release_decision"]["stage_gate_status"] == "PASS"
    assert report["release_decision"]["production_readiness_status"] == "BLOCKED"


def test_campaign_outcomes_match_expected_distribution() -> None:
    report = SupplyChainAssuranceHarness().run()
    outcomes = Counter(item["outcome"] for item in report["results"])
    assert outcomes == {
        "RELEASE_VERIFIED": 1,
        "RELEASE_VERIFIED_WITH_REVIEW": 1,
        "BLOCKED_UNPINNED_DEPENDENCY": 2,
        "BLOCKED_DEPENDENCY_HASH_FAILURE": 7,
        "BLOCKED_BUILD_POLICY_VIOLATION": 8,
        "BLOCKED_PROVENANCE_FAILURE": 8,
        "BLOCKED_SIGNATURE_FAILURE": 2,
        "BLOCKED_ARTIFACT_DIGEST_FAILURE": 3,
        "QUARANTINED_RELEASE_CONFLICT": 2,
        "BLOCKED_REPRODUCIBILITY_FAILURE": 2,
        "QUARANTINED_UNTRUSTED_ARTIFACT": 1,
        "BLOCKED_SBOM_RECONCILIATION_FAILURE": 6,
        "BLOCKED_MODEL_PROVENANCE_FAILURE": 5,
    }


def test_review_release_never_automates_or_closes() -> None:
    report = SupplyChainAssuranceHarness().run()
    review = [
        item
        for item in report["results"]
        if item["outcome"] == "RELEASE_VERIFIED_WITH_REVIEW"
    ]
    assert len(review) == 1
    assert review[0]["automated_release"] is False
    assert review[0]["human_review_required"] is True
    assert review[0]["prohibit_closure"] is True


def test_all_control_rates_are_one() -> None:
    summary = SupplyChainAssuranceHarness().run()["summary"]
    rate_fields = [
        "critical_supply_chain_scenario_defence_rate",
        "artifact_digest_verification_rate",
        "dependency_integrity_enforcement_rate",
        "build_provenance_verification_rate",
        "builder_identity_enforcement_rate",
        "source_to_artifact_binding_rate",
        "sbom_to_build_reconciliation_rate",
        "ci_workflow_integrity_rate",
        "model_data_provenance_enforcement_rate",
        "release_manifest_atomicity_rate",
        "rollback_protection_rate",
        "reproducibility_consistency_rate",
        "signature_enforcement_rate",
        "release_conflict_containment_rate",
    ]
    assert all(summary[field] == 1.0 for field in rate_fields)


def test_artifacts_are_written_and_consistent(tmp_path: Path) -> None:
    report = SupplyChainAssuranceHarness().run()
    paths = save_supply_chain_assurance_artifacts(report, tmp_path)
    assert all(path.is_file() for path in paths.values())
    stored = json.loads(paths["report"].read_text())
    assert stored["report_id"] == "AEG-SUPPLY-CHAIN-STEP11I-001"
    with paths["csv"].open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 48
    unsafe = json.loads(paths["unsafe"].read_text())
    assert unsafe["unsafe_releases"] == []


def test_campaign_is_semantically_deterministic() -> None:
    first = SupplyChainAssuranceHarness().run()
    second = SupplyChainAssuranceHarness().run()
    assert first == second

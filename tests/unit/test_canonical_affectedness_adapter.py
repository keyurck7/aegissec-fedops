from __future__ import annotations

from src.affectedness.canonical_adapter import (
    canonical_intelligence_trust_view,
    intelligence_record_from_canonical,
)


def canonical_fixture() -> dict:
    return {
        "record_id": "AEG-CVI-0123456789ABCDEF01234567",
        "target": {
            "cve_id": "CVE-2021-44228",
            "component": {
                "package_name": "org.apache.logging.log4j:log4j-core",
                "ecosystem": "Maven",
                "version": "2.14.1",
            },
        },
        "identifiers": {
            "primary_cve": "CVE-2021-44228",
            "aliases": ["GHSA-jfh8-c2jp-5v3q"],
        },
        "package_evidence": {
            "source": "OSV",
            "exact_target_record_ids": ["GHSA-jfh8-c2jp-5v3q"],
            "assertions": [
                {
                    "ecosystem": "Maven",
                    "package_name": "org.apache.logging.log4j:log4j-core",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
                    "explicit_version_match": False,
                    "range_evaluations": [
                        {
                            "range_index": 0,
                            "segment_index": 0,
                            "range_type": "ECOSYSTEM",
                            "introduced": "2.13.0",
                            "fixed": "2.15.0",
                            "last_affected": None,
                            "valid": True,
                            "affected": True,
                            "fixed_boundary_reached": False,
                            "before_introduced": False,
                            "reason_codes": ["VERSION_WITHIN_AFFECTED_RANGE"],
                            "error": None,
                        }
                    ],
                    "fixed_versions": ["2.15.0"],
                    "evidence_status": "AFFECTED_SUPPORTED",
                    "affected_index": 0,
                    "source_record_id": "GHSA-jfh8-c2jp-5v3q",
                }
            ],
            "aggregate_status": "AFFECTED_SUPPORTED",
        },
        "source_assertions": [
            {"validation_status": "accepted"},
            {"validation_status": "accepted"},
            {"validation_status": "accepted"},
            {"validation_status": "accepted"},
        ],
        "correlation_controls": {
            "exact_target_correlation_required": True,
            "source_count_is_consensus": False,
            "consensus_inference_permitted": False,
            "adjacent_record_isolation": True,
            "missing_numeric_values_coerced_to_zero": False,
            "conflicts": [],
            "assertion_differences": [],
        },
        "freshness": {"blocking_findings": []},
        "quality": {
            "source_bundle_verification": "PASS",
            "quality_gates": [
                {"gate_id": f"M12B-GATE-{index}", "pass": True}
                for index in range(8)
            ],
            "warnings": [],
        },
    }


def policy_fixture() -> dict:
    return {
        "canonical_intelligence_trust": {
            "weights": {
                "quality_gates": 0.50,
                "source_validation": 0.25,
                "freshness": 0.15,
                "correlation_controls": 0.10,
            },
            "accept_threshold": 0.85,
            "warning_threshold": 0.70,
        }
    }


def test_adapter_reconstructs_ranges_for_independent_evaluation() -> None:
    adapted = intelligence_record_from_canonical(canonical_fixture())
    package = adapted["affected_packages"][0]
    assert package["range_status"] == "available"
    assert package["ranges"] == [
        {
            "range_type": "ECOSYSTEM",
            "introduced": "2.13.0",
            "fixed": "2.15.0",
            "last_affected": None,
        }
    ]


def test_canonical_trust_accepts_complete_verified_record() -> None:
    result = canonical_intelligence_trust_view(
        canonical_fixture(),
        policy_fixture(),
    )
    assert result.action == "ACCEPT"
    assert result.aggregate_score == 1.0

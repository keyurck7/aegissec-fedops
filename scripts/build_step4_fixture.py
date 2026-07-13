from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.domain.decision_hashing import (
    finalize_decision_record_hash,
    sha256_file,
)
from src.validation.asset_context_validator import AssetContextValidator
from src.validation.evidence_schema_validator import EvidenceSchemaValidator
from src.validation.vulnerability_intelligence_validator import (
    VulnerabilityIntelligenceValidator,
)


SBOM_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "hospital_scheduling"
    / "log4j_component_sbom.json"
)

EVIDENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_log4j_sbom_evidence.json"
)

ASSET_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)

INTELLIGENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "intelligence"
    / "valid_log4shell_intelligence.json"
)

DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record.json"
)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False,
            sort_keys=False,
        )
        file.write("\n")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return payload


def relative(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def build_sbom() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": (
            "urn:uuid:7a75a7aa-f54c-4e54-97a5-"
            "aegissec000001"
        ),
        "version": 1,
        "metadata": {
            "timestamp": "2026-07-13T17:00:00Z",
            "component": {
                "type": "application",
                "name": "hospital-scheduling-demo",
                "version": "1.0.0"
            }
        },
        "components": [
            {
                "type": "library",
                "group": "org.apache.logging.log4j",
                "name": "log4j-core",
                "version": "2.14.1",
                "scope": "required",
                "purl": (
                    "pkg:maven/org.apache.logging.log4j/"
                    "log4j-core@2.14.1"
                )
            }
        ]
    }


def build_evidence_record() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "evidence_id": "AEG-EVD-SBOM-LOG4J-001",
        "evidence_type": "sbom_cyclonedx",
        "title": (
            "Controlled hospital scheduling CycloneDX SBOM"
        ),
        "description": (
            "Synthetic demonstration SBOM containing log4j-core 2.14.1 "
            "for Decision Record contract validation."
        ),

        "source": {
            "source_id": "SRC-DEMO-SBOM-LOG4J",
            "source_name": "AegisSec Controlled SBOM Fixture",
            "source_category": "authorized_internal",
            "source_authority": "high",
            "publisher": "AegisSec Project Team",
            "source_url": None,
            "api_endpoint": None,
            "external_reference": "DEMO-SBOM-LOG4J-001"
        },

        "authorization": {
            "status": "authorized",
            "collection_basis": "approved_test_fixture",
            "approved_use": "testing",
            "authorization_reference": "AEGIS-DEMO-DATA-POLICY-V1",
            "contains_restricted_data": False,
            "restrictions": [
                "Controlled demonstration use only"
            ]
        },

        "classification": {
            "data_sensitivity": "internal",
            "handling_label": "internal_use_only",
            "contains_personal_data": False,
            "contains_security_sensitive_data": False
        },

        "collection": {
            "collected_at": "2026-07-13T17:01:00Z",
            "valid_from": "2026-07-13T17:00:00Z",
            "valid_until": None,
            "collection_method": "local_generation",
            "collector": "AegisSec Step 4 Fixture Builder",
            "collection_run_id": "RUN-STEP4-FIXTURE-001"
        },

        "artifact": {
            "filename": SBOM_PATH.name,
            "media_type": "application/json",
            "storage_location": relative(SBOM_PATH),
            "size_bytes": SBOM_PATH.stat().st_size,
            "encoding": "utf-8"
        },

        "integrity": {
            "status": "verified",
            "hash_algorithm": "sha256",
            "content_hash": sha256_file(SBOM_PATH),
            "signature_status": "not_present",
            "signature_reference": None
        },

        "freshness": {
            "evaluated_at": "2026-07-13T17:02:00Z",
            "status": "current",
            "age_seconds": 120,
            "maximum_age_seconds": 86400,
            "freshness_policy_id": "FRESHNESS-SBOM-V1"
        },

        "parser": {
            "parser_name": "AegisSec CycloneDX Parser",
            "parser_version": "0.1.0",
            "parse_status": "success",
            "parser_confidence": 1.0,
            "warnings": []
        },

        "provenance": {
            "origin_type": "synthetic",
            "parent_evidence_ids": [],
            "transformation_steps": [
                {
                    "step_id": "STEP-SBOM-001",
                    "operation": (
                        "Generate controlled CycloneDX fixture"
                    ),
                    "tool": "build_step4_fixture",
                    "tool_version": "0.1.0",
                    "configuration_hash": None,
                    "executed_at": "2026-07-13T17:00:00Z"
                }
            ],
            "reproducible": True
        },

        "trust": {
            "authenticity": {
                "score": 1.0,
                "status": "confirmed",
                "reason_codes": [
                    "CONTROLLED_FIXTURE_SOURCE"
                ]
            },
            "integrity": {
                "score": 1.0,
                "status": "confirmed",
                "reason_codes": [
                    "SHA256_VERIFIED"
                ]
            },
            "completeness": {
                "score": 0.9,
                "status": "estimated",
                "reason_codes": [
                    "COMPONENT_IDENTITY_COMPLETE"
                ]
            },
            "freshness": {
                "score": 1.0,
                "status": "confirmed",
                "reason_codes": [
                    "WITHIN_FRESHNESS_WINDOW"
                ]
            },
            "consistency": {
                "score": 1.0,
                "status": "confirmed",
                "reason_codes": [
                    "NO_CONFLICTS_DETECTED"
                ]
            },
            "source_authority": {
                "score": 0.9,
                "status": "confirmed",
                "reason_codes": [
                    "AUTHORIZED_INTERNAL_FIXTURE"
                ]
            },
            "parser_confidence": {
                "score": 1.0,
                "status": "confirmed",
                "reason_codes": [
                    "PARSER_COMPLETED_SUCCESSFULLY"
                ]
            },
            "identity_confidence": {
                "score": 1.0,
                "status": "confirmed",
                "reason_codes": [
                    "PURL_AND_VERSION_PRESENT"
                ]
            },
            "overall_score": 0.97,
            "summary_level": "high",
            "calculation_policy_id": "TRUST-POLICY-V1"
        },

        "validation": {
            "schema_valid": True,
            "business_rules_valid": True,
            "status": "accepted_with_warnings",
            "validated_at": "2026-07-13T17:03:00Z",
            "validator_version": "0.1.0",
            "errors": [],
            "warnings": [
                {
                    "code": "NON_OBSERVED_EVIDENCE",
                    "message": (
                        "This SBOM is a synthetic controlled fixture."
                    ),
                    "field_path": "provenance.origin_type"
                }
            ]
        },

        "component_summary": {
            "component_count": 1,
            "direct_dependency_count": 1,
            "transitive_dependency_count": 0,
            "components_with_versions": 1,
            "components_with_purl": 1
        },

        "asset_references": [
            "AEG-AST-HOSP-SCHED-001"
        ],

        "conflicts": [],

        "tags": [
            "controlled-fixture",
            "cyclonedx",
            "log4j"
        ],

        "created_at": "2026-07-13T17:03:00Z",
        "updated_at": None
    }


def build_reference(
    record_type: str,
    path: Path,
    record_id: str,
    schema_version: str,
    validation_status: str,
) -> dict[str, Any]:
    return {
        "record_type": record_type,
        "record_id": record_id,
        "schema_version": schema_version,
        "relative_path": relative(path),
        "sha256": sha256_file(path),
        "validation_status": validation_status,
        "required_for_decision": True
    }


def build_decision_record(
    asset: dict[str, Any],
    intelligence: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema_version": "1.0.0",
        "decision_id": "AEG-DEC-LOG4J-HOSP-001",
        "decision_status": "pending_human_review",
        "decision_type": "vulnerability_prioritization",

        "input_records": {
            "asset_context": build_reference(
                record_type="asset_context",
                path=ASSET_PATH,
                record_id=asset["asset_id"],
                schema_version=asset["schema_version"],
                validation_status="accepted_with_warnings",
            ),

            "vulnerability_intelligence": build_reference(
                record_type="vulnerability_intelligence",
                path=INTELLIGENCE_PATH,
                record_id=intelligence["intelligence_id"],
                schema_version=intelligence["schema_version"],
                validation_status="accepted_with_warnings",
            ),

            "evidence_records": [
                build_reference(
                    record_type="evidence_record",
                    path=EVIDENCE_PATH,
                    record_id=evidence["evidence_id"],
                    schema_version=evidence["schema_version"],
                    validation_status="accepted_with_warnings",
                )
            ]
        },

        "component_instance": {
            "component_id": "AEG-CMP-LOG4J-CORE-001",
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "ecosystem": "Maven",
            "purl": (
                "pkg:maven/org.apache.logging.log4j/"
                "log4j-core@2.14.1"
            ),
            "dependency_scope": "direct",
            "runtime_status": "present_runtime_unknown",
            "evidence_ids": [
                "AEG-EVD-SBOM-LOG4J-001"
            ]
        },

        "affectedness": {
            "status": "affected",
            "confidence": 0.99,
            "determination_method": (
                "controlled_fixture_assertion"
            ),
            "engine_version": "fixture-0.1.0",
            "reason_codes": [
                "COMPONENT_VERSION_IN_AFFECTED_RANGE",
                "PURL_MATCH_CONFIRMED"
            ],
            "supporting_evidence_ids": [
                "AEG-EVD-SBOM-LOG4J-001",
                "AEG-EVD-OSV-LOG4J-001"
            ],
            "uncertainty_factors": [
                "Runtime reachability has not yet been evaluated"
            ],
            "determined_at": "2026-07-13T17:10:00Z"
        },

        "policy_decision": {
            "status": "completed",
            "execution_mode": "controlled_fixture_assertion",
            "policy_id": "AEGIS-FEDERAL-BASE-POLICY",
            "policy_version": "fixture-0.1.0",
            "action": "ACT",
            "minimum_priority": "CRITICAL",
            "response_deadline_hours": 24,
            "response_due_at": "2026-07-14T17:10:00Z",

            "triggered_rules": [
                {
                    "rule_id": "RULE-KEV-AFFECTED-001",
                    "rule_version": "0.1.0",
                    "description": (
                        "A KEV-listed vulnerability confirmed as affected "
                        "establishes an ACT decision and Critical floor."
                    ),
                    "effect": "set_priority_floor",
                    "non_overridable": True,
                    "supporting_evidence_ids": [
                        "AEG-EVD-KEV-LOG4J-001",
                        "AEG-EVD-SBOM-LOG4J-001"
                    ]
                },

                {
                    "rule_id": "RULE-HUMAN-REVIEW-001",
                    "rule_version": "0.1.0",
                    "description": (
                        "Known exploitation affecting a high-criticality "
                        "production asset requires accountable review."
                    ),
                    "effect": "require_human_review",
                    "non_overridable": True,
                    "supporting_evidence_ids": [
                        "AEG-EVD-KEV-LOG4J-001",
                        "AEG-EVD-REQ-000001"
                    ]
                }
            ],

            "evaluated_at": "2026-07-13T17:10:30Z"
        },

        "ml_advisory": {
            "status": "not_run",
            "model_id": None,
            "model_version": None,
            "predicted_priority": None,
            "confidence": None,
            "calibrated": None,
            "probabilities": {},
            "top_features": [],
            "advisory_only": True,
            "abstention_reason": (
                "The independent ML advisory model has not yet been "
                "implemented."
            ),
            "evaluated_at": None
        },

        "arbitration": {
            "status": "policy_only",
            "final_system_priority": "CRITICAL",
            "final_action": "ACT",
            "decision_basis": "policy_only",
            "human_review_required": True,
            "reason_codes": [
                "POLICY_FLOOR_APPLIED",
                "ML_NOT_RUN",
                "KNOWN_EXPLOITATION",
                "HUMAN_AUTHORIZATION_REQUIRED"
            ],
            "uncertainty_level": "medium",
            "policy_floor_enforced": True,
            "evaluated_at": "2026-07-13T17:11:00Z"
        },

        "human_disposition": {
            "status": "pending",
            "analyst": None,
            "final_priority": None,
            "final_action": None,
            "justification": None,
            "override": False,
            "override_reason": None,
            "approved_by": None,
            "decided_at": None,
            "expires_at": None,
            "ticket_reference": None
        },

        "provenance": {
            "origin_type": "controlled_fixture",
            "workflow_version": "step4-contract-0.1.0",
            "execution_environment": (
                "AegisSec Datalab controlled demonstration environment"
            ),
            "generated_at": "2026-07-13T17:12:00Z"
        },

        "audit": {
            "workflow_run_id": "RUN-STEP4-DECISION-001",
            "created_by": "AegisSec Step 4 Fixture Builder",
            "hash_algorithm": "sha256",
            "canonicalization_policy_id": "AEGIS-CANONICAL-JSON-V1",
            "previous_record_hash": None,
            "record_hash": "0" * 64,
            "immutable": True,
            "generated_at": "2026-07-13T17:12:00Z"
        },

        "created_at": "2026-07-13T17:12:00Z",
        "updated_at": None
    }

    return finalize_decision_record_hash(record)


def main() -> int:
    write_json(SBOM_PATH, build_sbom())
    write_json(EVIDENCE_PATH, build_evidence_record())

    evidence_validator = EvidenceSchemaValidator()
    asset_validator = AssetContextValidator()
    intelligence_validator = VulnerabilityIntelligenceValidator()

    evidence_result = evidence_validator.validate_file(EVIDENCE_PATH)
    asset_result = asset_validator.validate_file(ASSET_PATH)
    intelligence_result = intelligence_validator.validate_file(
        INTELLIGENCE_PATH
    )

    validation_results = {
        "evidence": evidence_result,
        "asset": asset_result,
        "intelligence": intelligence_result,
    }

    invalid_inputs = [
        name
        for name, result in validation_results.items()
        if not result.valid
    ]

    if invalid_inputs:
        raise RuntimeError(
            f"Cannot build Decision Record. Invalid inputs: "
            f"{invalid_inputs}"
        )

    asset = load_json(ASSET_PATH)
    intelligence = load_json(INTELLIGENCE_PATH)
    evidence = load_json(EVIDENCE_PATH)

    decision = build_decision_record(
        asset=asset,
        intelligence=intelligence,
        evidence=evidence,
    )

    write_json(DECISION_PATH, decision)

    print("Created Step 4 fixtures:")
    print(f"  SBOM:     {relative(SBOM_PATH)}")
    print(f"  Evidence: {relative(EVIDENCE_PATH)}")
    print(f"  Decision: {relative(DECISION_PATH)}")
    print(f"  Hash:     {decision['audit']['record_hash']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

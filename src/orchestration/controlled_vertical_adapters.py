"""Governed adapters for the validated Log4Shell vertical slice."""

from __future__ import annotations

import json

from pathlib import Path
from typing import Any, Mapping

import pandas as pd

from src.intake.unified_gateway import (
    ingest_bytes,
    verify_envelope_integrity,
)
from src.orchestration.assessment_ledger import (
    BLOCKED,
    PASSED,
    PASSED_WITH_WARNINGS,
    canonical_json_bytes,
    create_assessment_ledger,
    sha256_bytes,
)
from src.orchestration.dynamic_orchestrator import (
    DynamicAssessmentOrchestrator,
    StageResult,
)
from src.presentation_demo.master_vertical_slice import (
    load_master_vertical_slice,
)
from src.presentation_demo.unified_scan_workbench import (
    run_unified_scan,
)


ROOT = Path(__file__).resolve().parents[2]

DEMO_SBOM = (
    ROOT
    / "data"
    / "demo"
    / "aegissec_demo_project.cdx.json"
)

DEMO_ASSET = (
    ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)


def json_safe(
    value: Any,
) -> Any:
    if isinstance(
        value,
        pd.DataFrame,
    ):
        return value.to_dict(
            orient="records"
        )

    if isinstance(
        value,
        Path,
    ):
        return str(value)

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
        ),
    ):
        return [
            json_safe(item)
            for item in value
        ]

    if hasattr(
        value,
        "item",
    ):
        try:
            return value.item()
        except Exception:
            pass

    return value


def artifact_reference(
    *,
    stage_id: str,
    artifact_type: str,
    authority: str,
    document: Any,
    source_path: str | None = None,
) -> dict[str, Any]:
    safe_document = json_safe(
        document
    )

    digest = sha256_bytes(
        canonical_json_bytes(
            safe_document
        )
    )

    reference = {
        "stage_id": stage_id,
        "artifact_type": artifact_type,
        "authority": authority,
        "sha256": digest,
        "serialization": (
            "CANONICAL_SORTED_JSON"
        ),
    }

    if source_path:
        reference["source_path"] = (
            source_path
        )

    return reference


def build_controlled_context() -> dict[str, Any]:
    if not DEMO_SBOM.is_file():
        raise FileNotFoundError(
            DEMO_SBOM
        )

    if not DEMO_ASSET.is_file():
        raise FileNotFoundError(
            DEMO_ASSET
        )

    payload = DEMO_SBOM.read_bytes()

    envelope = ingest_bytes(
        payload,
        filename=DEMO_SBOM.name,
        authorized=True,
        declared_media_type=(
            "application/json"
        ),
    )

    workbench = run_unified_scan(
        payload,
        filename=DEMO_SBOM.name,
        authorized=True,
        declared_media_type=(
            "application/json"
        ),
    )

    asset_context = json.loads(
        DEMO_ASSET.read_text(
            encoding="utf-8"
        )
    )

    master = (
        load_master_vertical_slice()
    )

    return {
        "execution_lane": (
            "CONTROLLED_LOG4SHELL_VERTICAL_SLICE"
        ),
        "input_envelope": envelope,
        "workbench": workbench,
        "asset_context": asset_context,
        "master_vertical_slice": master,
        "source_paths": {
            "sbom": str(
                DEMO_SBOM.relative_to(ROOT)
            ),
            "asset_context": str(
                DEMO_ASSET.relative_to(ROOT)
            ),
        },
    }


def intake_validation_adapter(
    context: dict[str, Any],
) -> StageResult:
    envelope = context[
        "input_envelope"
    ]

    if not verify_envelope_integrity(
        envelope
    ):
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "INPUT_ENVELOPE_INTEGRITY_FAILED"
            ),
            message=(
                "Canonical input envelope integrity "
                "verification failed."
            ),
        )

    if (
        envelope["validation"][
            "stage_gate"
        ]
        != "PASS"
    ):
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "INPUT_VALIDATION_STAGE_FAILED"
            ),
            message=(
                "The canonical intake stage gate "
                "did not pass."
            ),
        )

    warnings = tuple(
        envelope["validation"][
            "warnings"
        ]
    )

    status = (
        PASSED_WITH_WARNINGS
        if warnings
        else PASSED
    )

    return StageResult(
        status=status,
        message=(
            "Canonical input envelope verified."
        ),
        warnings=warnings,
        outputs=(
            artifact_reference(
                stage_id=(
                    "INTAKE_VALIDATION"
                ),
                artifact_type=(
                    "UNIFIED_INPUT_ENVELOPE"
                ),
                authority=(
                    "INPUT_EVIDENCE_ONLY"
                ),
                document=envelope,
                source_path=context[
                    "source_paths"
                ]["sbom"],
            ),
        ),
        metadata={
            "input_id": (
                envelope["input_id"]
            ),
            "format": envelope[
                "detection"
            ]["format"],
            "component_count": (
                envelope["statistics"][
                    "component_count"
                ]
            ),
        },
    )


def asset_context_adapter(
    context: dict[str, Any],
) -> StageResult:
    asset = context[
        "asset_context"
    ]

    required_fields = {
        "asset_id",
        "asset_name",
        "exposure",
        "criticality",
        "impact_assessment",
    }

    missing = sorted(
        required_fields
        - set(asset)
    )

    if missing:
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "CONTROLLED_ASSET_CONTEXT_INCOMPLETE"
            ),
            message=(
                "Controlled asset context is missing: "
                + ", ".join(missing)
            ),
        )

    return StageResult(
        status=PASSED_WITH_WARNINGS,
        message=(
            "Controlled, previously validated asset "
            "context registered for the vertical slice."
        ),
        warnings=(
            "This adapter accepts the controlled validated "
            "sample asset. General uploaded asset validation "
            "will be integrated in a later stage.",
        ),
        outputs=(
            artifact_reference(
                stage_id="ASSET_CONTEXT",
                artifact_type=(
                    "CONTROLLED_ASSET_CONTEXT"
                ),
                authority=(
                    "AUTHORITATIVE_CONTEXT"
                ),
                document=asset,
                source_path=context[
                    "source_paths"
                ]["asset_context"],
            ),
        ),
        metadata={
            "asset_id": asset[
                "asset_id"
            ],
            "criticality": asset[
                "criticality"
            ].get("level"),
            "internet_accessible": (
                asset["exposure"].get(
                    "internet_accessible"
                )
            ),
        },
    )


def component_correlation_adapter(
    context: dict[str, Any],
) -> StageResult:
    workbench = context[
        "workbench"
    ]

    scan = workbench.get(
        "scan"
    )

    if scan is None:
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "COMPONENT_CORRELATION_UNAVAILABLE"
            ),
            message=(
                workbench.get(
                    "scan_error"
                )
                or (
                    "No governed component correlation "
                    "result was produced."
                )
            ),
        )

    matched = scan[
        "matched_components"
    ]

    unmatched = scan[
        "unmatched_components"
    ]

    findings = scan[
        "vulnerability_findings"
    ]

    summary = {
        "scan_eligible_components": (
            workbench[
                "exact_scan_components"
            ]
        ),
        "matched_components": len(
            matched
        ),
        "unmatched_components": len(
            unmatched
        ),
        "vulnerability_findings": len(
            findings
        ),
        "cve_identifiers": (
            workbench["cve_ids"]
        ),
    }

    warnings: tuple[str, ...] = ()

    if len(unmatched):
        warnings = (
            f"{len(unmatched)} scan-eligible components "
            "did not match the governed risk mart.",
        )

    return StageResult(
        status=(
            PASSED_WITH_WARNINGS
            if warnings
            else PASSED
        ),
        message=(
            "Canonical components were correlated "
            "with the governed vulnerability risk mart."
        ),
        warnings=warnings,
        outputs=(
            artifact_reference(
                stage_id=(
                    "COMPONENT_CORRELATION"
                ),
                artifact_type=(
                    "COMPONENT_CORRELATION_SUMMARY"
                ),
                authority=(
                    "AUTHORITATIVE_CORRELATION"
                ),
                document=summary,
            ),
        ),
        metadata=summary,
    )


def evidence_arbitration_adapter(
    context: dict[str, Any],
) -> StageResult:
    workbench = context[
        "workbench"
    ]

    governance = workbench[
        "governance"
    ]

    snapshot = workbench[
        "snapshot_summary"
    ]

    if (
        governance[
            "live_source_precedence"
        ]
        is not True
    ):
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "LIVE_SOURCE_PRECEDENCE_NOT_PRESERVED"
            ),
            message=(
                "Evidence arbitration cannot proceed "
                "without live-source precedence."
            ),
        )

    if snapshot is None:
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "GOVERNED_SNAPSHOT_UNAVAILABLE"
            ),
            message=(
                "Janvi's governed intelligence "
                "snapshot is unavailable."
            ),
        )

    arbitration = {
        "live_source_precedence": True,
        "snapshot_authority": (
            governance[
                "snapshot_authority"
            ]
        ),
        "scanner_authority": (
            governance[
                "scanner_authority"
            ]
        ),
        "snapshot_total_cves": (
            snapshot["total_cves"]
        ),
        "snapshot_kev_cves": (
            snapshot["kev_cves"]
        ),
        "snapshot_missing_epss": (
            snapshot["missing_epss"]
        ),
    }

    return StageResult(
        status=PASSED_WITH_WARNINGS,
        message=(
            "Evidence precedence and source "
            "authority were preserved."
        ),
        warnings=(
            "The July 14 intelligence provider is "
            "historical and read-only. Fresher validated "
            "live evidence retains precedence.",
        ),
        outputs=(
            artifact_reference(
                stage_id=(
                    "EVIDENCE_ARBITRATION"
                ),
                artifact_type=(
                    "EVIDENCE_PRECEDENCE_DECISION"
                ),
                authority=(
                    "AUTHORITATIVE_GOVERNANCE"
                ),
                document=arbitration,
            ),
        ),
        metadata=arbitration,
    )


def affectedness_adapter(
    context: dict[str, Any],
) -> StageResult:
    report = context[
        "master_vertical_slice"
    ]["affectedness"]

    gate = report[
        "release_decision"
    ]["stage_gate"]

    if gate != "PASS":
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "AFFECTEDNESS_STAGE_GATE_FAILED"
            ),
            message=(
                "The existing deterministic "
                "affectedness gate did not pass."
            ),
            outputs=(
                artifact_reference(
                    stage_id="AFFECTEDNESS",
                    artifact_type=(
                        "AFFECTEDNESS_ADJUDICATION"
                    ),
                    authority=(
                        "DETERMINISTIC_ENGINE"
                    ),
                    document=report,
                ),
            ),
        )

    adjudication = report[
        "adjudication"
    ]

    warnings = tuple(
        str(code)
        for code in adjudication.get(
            "reason_codes",
            [],
        )
        if (
            "UNKNOWN" in str(code)
            or "REVIEW" in str(code)
        )
    )

    return StageResult(
        status=(
            PASSED_WITH_WARNINGS
            if warnings
            else PASSED
        ),
        message=(
            "Existing deterministic affectedness "
            "adjudication was registered."
        ),
        warnings=warnings,
        outputs=(
            artifact_reference(
                stage_id="AFFECTEDNESS",
                artifact_type=(
                    "AFFECTEDNESS_ADJUDICATION"
                ),
                authority=(
                    "DETERMINISTIC_ENGINE"
                ),
                document=report,
                source_path=str(
                    context[
                        "master_vertical_slice"
                    ]["paths"][
                        "affectedness"
                    ]
                ),
            ),
        ),
        metadata={
            "status": adjudication[
                "status"
            ],
            "technical_status": (
                adjudication.get(
                    "technical_status"
                )
            ),
            "human_review_required": (
                adjudication.get(
                    "human_review_required"
                )
            ),
        },
    )


def decision_feature_adapter(
    context: dict[str, Any],
) -> StageResult:
    envelope = context[
        "master_vertical_slice"
    ]["feature_envelope"]

    release = envelope[
        "release_decision"
    ]

    if release[
        "stage_gate"
    ] != "PASS":
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "DECISION_FEATURE_GATE_FAILED"
            ),
            message=(
                "The existing Decision Feature "
                "Envelope gate did not pass."
            ),
            outputs=(
                artifact_reference(
                    stage_id=(
                        "DECISION_FEATURE_ENVELOPE"
                    ),
                    artifact_type=(
                        "DECISION_FEATURE_ENVELOPE"
                    ),
                    authority=(
                        "AUTHORITATIVE_FEATURE_CONTRACT"
                    ),
                    document=envelope,
                ),
            ),
        )

    return StageResult(
        status=PASSED,
        message=(
            "Existing Decision Feature Envelope "
            "was registered without rewriting features."
        ),
        outputs=(
            artifact_reference(
                stage_id=(
                    "DECISION_FEATURE_ENVELOPE"
                ),
                artifact_type=(
                    "DECISION_FEATURE_ENVELOPE"
                ),
                authority=(
                    "AUTHORITATIVE_FEATURE_CONTRACT"
                ),
                document=envelope,
                source_path=str(
                    context[
                        "master_vertical_slice"
                    ]["paths"][
                        "decision_features"
                    ]
                ),
            ),
        ),
        metadata={
            "envelope_id": envelope[
                "envelope_id"
            ],
            "stage_gate": release[
                "stage_gate"
            ],
            "next_stage_eligibility": (
                release[
                    "next_stage_eligibility"
                ]
            ),
            "production_readiness": (
                release[
                    "production_readiness"
                ]
            ),
        },
    )


def ssvc_adapter(
    context: dict[str, Any],
) -> StageResult:
    master = context[
        "master_vertical_slice"
    ]

    report = master["ssvc"]
    summary = master["summary"]

    if (
        report["governance"][
            "stage_gate"
        ]
        != "PASS"
    ):
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "SSVC_STAGE_GATE_FAILED"
            ),
            message=(
                "The existing governed SSVC "
                "decision gate did not pass."
            ),
            outputs=(
                artifact_reference(
                    stage_id="SSVC",
                    artifact_type=(
                        "SSVC_POLICY_DECISION"
                    ),
                    authority="SSVC",
                    document=report,
                ),
            ),
        )

    if (
        summary[
            "production_readiness"
        ]
        != "BLOCKED"
    ):
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "SSVC_PRODUCTION_BLOCK_MISSING"
            ),
            message=(
                "SSVC output does not preserve "
                "the production block."
            ),
        )

    return StageResult(
        status=PASSED_WITH_WARNINGS,
        message=(
            "Existing governed SSVC decision "
            "was registered as authoritative policy output."
        ),
        warnings=(
            "SSVC requires mandatory human review. "
            "No final disposition is authorized.",
        ),
        outputs=(
            artifact_reference(
                stage_id="SSVC",
                artifact_type=(
                    "SSVC_POLICY_DECISION"
                ),
                authority="SSVC",
                document=report,
                source_path=str(
                    master["paths"]["ssvc"]
                ),
            ),
        ),
        metadata={
            "decision_id": summary[
                "decision_id"
            ],
            "cve_id": summary[
                "cve_id"
            ],
            "vector": summary[
                "vector"
            ],
            "matched_row": summary[
                "matched_row"
            ],
            "outcome": summary[
                "outcome_name"
            ],
            "human_review_required": (
                summary[
                    "human_review_required"
                ]
            ),
            "final_disposition_status": (
                summary[
                    "final_disposition_status"
                ]
            ),
            "production_readiness": (
                summary[
                    "production_readiness"
                ]
            ),
        },
    )


def ml_advisory_adapter(
    context: dict[str, Any],
) -> StageResult:
    master = context[
        "master_vertical_slice"
    ]

    report = master[
        "model_report"
    ]

    summary = master[
        "summary"
    ]

    if (
        summary[
            "model_authority"
        ]
        != "ADVISORY_ONLY"
    ):
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "MODEL_AUTHORITY_BOUNDARY_FAILED"
            ),
            message=(
                "The model output is not marked "
                "ADVISORY_ONLY."
            ),
        )

    return StageResult(
        status=PASSED_WITH_WARNINGS,
        message=(
            "Existing model report was registered "
            "as advisory analytics."
        ),
        warnings=(
            "The current classifier predicts present "
            "CISA KEV membership, not future exploitation.",
            "The model cannot override affectedness or SSVC.",
        ),
        outputs=(
            artifact_reference(
                stage_id="ML_ADVISORY",
                artifact_type=(
                    "ML_ADVISORY_MODEL_REPORT"
                ),
                authority=(
                    "ADVISORY_ONLY"
                ),
                document=report,
                source_path=str(
                    master["paths"][
                        "model_report"
                    ]
                ),
            ),
        ),
        metadata={
            "model_authority": (
                summary[
                    "model_authority"
                ]
            ),
            "model_label": summary[
                "model_label"
            ],
            "model_winner": summary[
                "model_winner"
            ],
            "future_custom_forecast": (
                summary[
                    "future_custom_forecast"
                ]
            ),
        },
    )


def agreement_adapter(
    context: dict[str, Any],
) -> StageResult:
    master = context[
        "master_vertical_slice"
    ]

    matrix = master[
        "agreement_matrix"
    ]

    summary = master[
        "summary"
    ]

    document = {
        "policy_matrix": (
            matrix.to_dict(
                orient="records"
            )
        ),
        "authoritative_outcome": (
            summary["outcome_name"]
        ),
        "model_authority": (
            summary["model_authority"]
        ),
        "human_review_required": (
            summary[
                "human_review_required"
            ]
        ),
        "final_disposition_status": (
            summary[
                "final_disposition_status"
            ]
        ),
    }

    if (
        document[
            "model_authority"
        ]
        != "ADVISORY_ONLY"
    ):
        return StageResult(
            status=BLOCKED,
            reason_code=(
                "AGREEMENT_AUTHORITY_BOUNDARY_FAILED"
            ),
            message=(
                "Agreement analysis does not "
                "preserve advisory-only model authority."
            ),
        )

    return StageResult(
        status=PASSED_WITH_WARNINGS,
        message=(
            "Policy and advisory analytics "
            "were compared without changing SSVC."
        ),
        warnings=(
            "Human review remains mandatory.",
            "Final disposition remains NOT_AUTHORIZED.",
        ),
        outputs=(
            artifact_reference(
                stage_id=(
                    "AGREEMENT_ANALYSIS"
                ),
                artifact_type=(
                    "POLICY_MODEL_AGREEMENT_ANALYSIS"
                ),
                authority=(
                    "SSVC_REMAINS_AUTHORITATIVE"
                ),
                document=document,
            ),
        ),
        metadata={
            "authoritative_decision": (
                "SSVC_REMAINS_AUTHORITATIVE"
            ),
            "human_review_required": (
                True
            ),
            "final_disposition_status": (
                document[
                    "final_disposition_status"
                ]
            ),
        },
    )


def controlled_adapter_registry():
    return {
        "INTAKE_VALIDATION": (
            intake_validation_adapter
        ),
        "ASSET_CONTEXT": (
            asset_context_adapter
        ),
        "COMPONENT_CORRELATION": (
            component_correlation_adapter
        ),
        "EVIDENCE_ARBITRATION": (
            evidence_arbitration_adapter
        ),
        "AFFECTEDNESS": (
            affectedness_adapter
        ),
        "DECISION_FEATURE_ENVELOPE": (
            decision_feature_adapter
        ),
        "SSVC": ssvc_adapter,
        "ML_ADVISORY": (
            ml_advisory_adapter
        ),
        "AGREEMENT_ANALYSIS": (
            agreement_adapter
        ),
    }


def execute_controlled_vertical_slice():
    context = (
        build_controlled_context()
    )

    envelope = context[
        "input_envelope"
    ]

    asset = context[
        "asset_context"
    ]

    ledger = create_assessment_ledger(
        input_id=envelope[
            "input_id"
        ],
        input_envelope_sha256=(
            envelope["integrity"][
                "envelope_sha256"
            ]
        ),
        created_by=(
            "aegissec-dynamic-orchestrator"
        ),
        asset_context_id=asset[
            "asset_id"
        ],
    )

    orchestrator = (
        DynamicAssessmentOrchestrator(
            adapters=(
                controlled_adapter_registry()
            ),
        )
    )

    ledger = orchestrator.run_through(
        ledger=ledger,
        context=context,
        through_stage=(
            "AGREEMENT_ANALYSIS"
        ),
    )

    return ledger, context

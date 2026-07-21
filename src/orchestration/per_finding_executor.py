"""Fail-closed per-finding assessment execution for AegisSec-FedOps."""

from __future__ import annotations

import hashlib
import json
import os
import re

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


from src.affectedness.affectedness_adjudicator import (
    InputReference,
    build_affectedness_adjudication,
)
from src.affectedness.canonical_adapter import (
    intelligence_record_from_canonical,
)
from src.decision_features.feature_envelope import (
    FeatureInputReference,
    build_decision_feature_envelope,
)
from src.decision_policy.ssvc_engine import (
    build_ssvc_policy_decision,
)
from src.orchestration.assessment_ledger import (
    BLOCKED,
    FAILED,
    PASSED,
    PASSED_WITH_WARNINGS,
    RUNNING,
    SKIPPED,
    create_assessment_ledger,
    transition_stage,
    verify_ledger,
)
from src.orchestration.finding_assessment_request import (
    canonical_json_bytes,
    sha256_bytes,
    verify_finding_assessment_request,
)


ROOT = Path(__file__).resolve().parents[2]

CANONICAL_ROOT = (
    ROOT
    / "data"
    / "processed"
    / "canonical_intelligence"
)

DEFAULT_REQUEST_MANIFEST = (
    ROOT
    / "reports"
    / "orchestration"
    / "m13b2b_finding_assessment_requests.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "reports"
    / "orchestration"
    / "m13b2d_per_finding_execution.json"
)

CONTROLLED_ASSET_PATH = (
    ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)

CONTROLLED_EVIDENCE_PATH = (
    ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_log4j_sbom_evidence.json"
)

CONTROLLED_RUNTIME_PATH = (
    ROOT
    / "data"
    / "sample_inputs"
    / "affectedness"
    / "valid_log4shell_runtime_context.json"
)

CVE_PATTERN = re.compile(
    r"CVE-\d{4}-\d{4,}",
    re.IGNORECASE,
)

STATUS_EXECUTED = (
    "EXECUTED_AWAITING_HUMAN_REVIEW"
)

STATUS_IDENTITY_BLOCKED = (
    "BLOCKED_IDENTITY_INCOMPLETE"
)

STATUS_CANONICAL_BLOCKED = (
    "BLOCKED_CANONICAL_INTELLIGENCE_UNAVAILABLE"
)

STATUS_ATTRIBUTION_BLOCKED = (
    "BLOCKED_RANGE_ATTRIBUTION_UNRESOLVED"
)

STATUS_RANGE_BLOCKED = (
    "BLOCKED_RANGE_UNAVAILABLE"
)

STATUS_PROFILE_BLOCKED = (
    "BLOCKED_EXECUTION_PROFILE_UNAVAILABLE"
)

STATUS_INTEGRITY_BLOCKED = (
    "BLOCKED_REQUEST_INTEGRITY_FAILED"
)

STATUS_EXECUTION_FAILED = (
    "FAILED_DETERMINISTIC_EXECUTION"
)


class PerFindingExecutionError(
    RuntimeError
):
    """Raised when the execution manifest cannot be generated safely."""


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def json_load(
    path: Path,
) -> dict[str, Any]:
    value = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        value,
        dict,
    ):
        raise PerFindingExecutionError(
            f"Expected a JSON object: {path}"
        )

    return value


def file_sha256(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def relative_path(
    path: Path,
) -> str:
    return path.relative_to(
        ROOT
    ).as_posix()


def write_json_atomic(
    document: Mapping[str, Any],
    path: Path,
) -> tuple[Path, Path]:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = canonical_json_bytes(
        document
    )

    temporary = path.with_name(
        "." + path.name + ".partial"
    )

    with temporary.open(
        "wb"
    ) as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(
            handle.fileno()
        )

    os.replace(
        temporary,
        path,
    )

    digest = sha256_bytes(
        payload
    )

    sidecar = Path(
        str(path) + ".sha256"
    )

    sidecar.write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
    )

    return path, sidecar


def base_purl(
    value: Any,
) -> str | None:
    if not value:
        return None

    return str(
        value
    ).strip().lower().split(
        "@",
        1,
    )[0]


def package_leaf(
    value: Any,
) -> str | None:
    if not value:
        return None

    normalized = str(
        value
    ).strip().lower()

    normalized = normalized.split(
        "@",
        1,
    )[0]

    normalized = normalized.rsplit(
        "/",
        1,
    )[-1]

    normalized = normalized.rsplit(
        ":",
        1,
    )[-1]

    return normalized


def package_matches(
    component: Mapping[str, Any],
    package: Mapping[str, Any],
) -> bool:
    component_purl = base_purl(
        component.get("purl")
    )

    package_purl = base_purl(
        package.get("purl")
    )

    if (
        component_purl
        and package_purl
        and component_purl
        == package_purl
    ):
        return True

    component_name = package_leaf(
        component.get("name")
    )

    package_name = package_leaf(
        package.get("package_name")
        or package.get("name")
    )

    if not (
        component_name
        and package_name
        and component_name
        == package_name
    ):
        return False

    component_ecosystem = str(
        component.get(
            "ecosystem"
        )
        or ""
    ).strip().lower()

    package_ecosystem = str(
        package.get(
            "ecosystem"
        )
        or ""
    ).strip().lower()

    return (
        not component_ecosystem
        or not package_ecosystem
        or component_ecosystem
        == package_ecosystem
    )


def has_usable_ranges(
    package: Mapping[str, Any],
) -> bool:
    ranges = package.get(
        "ranges"
    )

    if not isinstance(
        ranges,
        list,
    ):
        return False

    return any(
        isinstance(item, Mapping)
        and any(
            item.get(field)
            is not None
            for field in (
                "introduced",
                "fixed",
                "last_affected",
            )
        )
        for item in ranges
    )


def collect_cves(
    value: Any,
) -> set[str]:
    observed: set[str] = set()

    if isinstance(
        value,
        Mapping,
    ):
        for key, item in value.items():
            observed.update(
                collect_cves(key)
            )

            observed.update(
                collect_cves(item)
            )

    elif isinstance(
        value,
        list,
    ):
        for item in value:
            observed.update(
                collect_cves(item)
            )

    elif isinstance(
        value,
        str,
    ):
        observed.update(
            match.upper()
            for match
            in CVE_PATTERN.findall(
                value
            )
        )

    return observed


def primary_cves(
    document: Mapping[str, Any],
    adapted: Mapping[str, Any],
) -> set[str]:
    observed: set[str] = set()

    identifiers = document.get(
        "identifiers"
    )

    if isinstance(
        identifiers,
        Mapping,
    ):
        value = identifiers.get(
            "primary_cve"
        )

        if isinstance(
            value,
            str,
        ):
            observed.add(
                value.upper()
            )

    target = document.get(
        "target"
    )

    if isinstance(
        target,
        Mapping,
    ):
        value = target.get(
            "cve_id"
        )

        if isinstance(
            value,
            str,
        ):
            observed.add(
                value.upper()
            )

    canonical_id = adapted.get(
        "canonical_id"
    )

    if isinstance(
        canonical_id,
        str,
    ) and CVE_PATTERN.fullmatch(
        canonical_id
    ):
        observed.add(
            canonical_id.upper()
        )

    return observed


def build_canonical_catalog() -> list[
    dict[str, Any]
]:
    catalog: list[
        dict[str, Any]
    ] = []

    for path in sorted(
        CANONICAL_ROOT.rglob(
            "aeg-cvi-*.canonical.json"
        )
    ):
        try:
            document = json_load(
                path
            )

            adapted = (
                intelligence_record_from_canonical(
                    document
                )
            )

        except Exception:
            continue

        primaries = primary_cves(
            document,
            adapted,
        )

        all_cves = collect_cves(
            document
        )

        all_cves.update(
            collect_cves(
                adapted
            )
        )

        catalog.append(
            {
                "path": path,
                "document": document,
                "adapted": adapted,
                "primary_cves": (
                    primaries
                ),
                "adjacent_cves": (
                    all_cves
                    - primaries
                ),
                "packages": [
                    package
                    for package
                    in adapted.get(
                        "affected_packages",
                        [],
                    )
                    if isinstance(
                        package,
                        Mapping,
                    )
                ],
            }
        )

    return catalog


def find_primary_record(
    catalog: list[
        dict[str, Any]
    ],
    cve_id: str,
) -> dict[str, Any] | None:
    matches = [
        record
        for record in catalog
        if cve_id.upper()
        in record[
            "primary_cves"
        ]
    ]

    if len(matches) == 1:
        return matches[0]

    return None


def is_adjacent_cve(
    catalog: list[
        dict[str, Any]
    ],
    cve_id: str,
) -> bool:
    return any(
        cve_id.upper()
        in record[
            "adjacent_cves"
        ]
        for record in catalog
    )


def matched_package(
    record: Mapping[str, Any],
    component: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    matches = [
        package
        for package
        in record["packages"]
        if package_matches(
            component,
            package,
        )
    ]

    if len(matches) == 1:
        return matches[0]

    return None


def controlled_profile_available(
    request: Mapping[str, Any],
) -> bool:
    unit = request[
        "unit_of_assessment"
    ]

    component = unit[
        "component"
    ]

    return (
        unit["cve_id"]
        == "CVE-2021-44228"
        and base_purl(
            component.get("purl")
        )
        == (
            "pkg:maven/"
            "org.apache.logging.log4j/"
            "log4j-core"
        )
        and component.get(
            "version"
        )
        == "2.14.1"
        and CONTROLLED_ASSET_PATH.is_file()
        and CONTROLLED_EVIDENCE_PATH.is_file()
        and CONTROLLED_RUNTIME_PATH.is_file()
    )


def output_reference(
    *,
    artifact_type: str,
    authority: str,
    path: Path,
) -> dict[str, Any]:
    return {
        "artifact_type": (
            artifact_type
        ),
        "authority": authority,
        "relative_path": (
            relative_path(path)
        ),
        "sha256": file_sha256(
            path
        ),
    }


def pass_stage(
    ledger: dict[str, Any],
    *,
    stage_id: str,
    message: str,
    outputs: list[
        dict[str, Any]
    ] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    ledger = transition_stage(
        ledger,
        stage_id=stage_id,
        to_status=RUNNING,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=(
            f"{stage_id} started."
        ),
    )

    normalized_warnings = (
        warnings
        or []
    )

    return transition_stage(
        ledger,
        stage_id=stage_id,
        to_status=(
            PASSED_WITH_WARNINGS
            if normalized_warnings
            else PASSED
        ),
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=message,
        warnings=(
            normalized_warnings
        ),
        outputs=(
            outputs
            or []
        ),
    )


def block_stage(
    ledger: dict[str, Any],
    *,
    stage_id: str,
    reason_code: str,
    message: str,
) -> dict[str, Any]:
    return transition_stage(
        ledger,
        stage_id=stage_id,
        to_status=BLOCKED,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        reason_code=reason_code,
        message=message,
    )


def new_request_ledger(
    request: Mapping[str, Any],
) -> dict[str, Any]:
    return create_assessment_ledger(
        input_id=request[
            "request_id"
        ],
        input_envelope_sha256=(
            request["integrity"][
                "request_sha256"
            ]
        ),
        created_by=(
            "aegissec-per-finding-executor"
        ),
        asset_context_id=(
            request[
                "unit_of_assessment"
            ]["asset_id"]
        ),
    )


def establish_common_stages(
    ledger: dict[str, Any],
    request: Mapping[str, Any],
    *,
    through_correlation: bool,
) -> dict[str, Any]:
    ledger = pass_stage(
        ledger,
        stage_id=(
            "INTAKE_VALIDATION"
        ),
        message=(
            "Finding request integrity "
            "and input boundary verified."
        ),
        outputs=[
            {
                "artifact_type": (
                    "FINDING_ASSESSMENT_REQUEST"
                ),
                "authority": (
                    "ASSESSMENT_INPUT_ONLY"
                ),
                "request_id": (
                    request["request_id"]
                ),
                "sha256": (
                    request["integrity"][
                        "request_sha256"
                    ]
                ),
            }
        ],
    )

    ledger = pass_stage(
        ledger,
        stage_id="ASSET_CONTEXT",
        message=(
            "Asset context reference accepted "
            "for controlled pilot execution."
        ),
        outputs=[
            {
                "artifact_type": (
                    "ASSET_CONTEXT_REFERENCE"
                ),
                "authority": (
                    "AUTHORITATIVE_CONTEXT"
                ),
                "asset_id": (
                    request[
                        "unit_of_assessment"
                    ]["asset_id"]
                ),
                "sha256": (
                    request[
                        "asset_context"
                    ]["sha256"]
                ),
            }
        ],
    )

    if through_correlation:
        ledger = pass_stage(
            ledger,
            stage_id=(
                "COMPONENT_CORRELATION"
            ),
            message=(
                "Canonical component-CVE "
                "correlation verified."
            ),
            outputs=[
                {
                    "artifact_type": (
                        "COMPONENT_CVE_CORRELATION"
                    ),
                    "authority": (
                        "CORRELATION_EVIDENCE_ONLY"
                    ),
                    "sha256": (
                        request[
                            "evidence_snapshot"
                        ][
                            "correlation_row_sha256"
                        ]
                    ),
                }
            ],
        )

    return ledger


def execute_controlled_pipeline(
    request: Mapping[str, Any],
    record: Mapping[str, Any],
    ledger: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    request_id = request[
        "request_id"
    ]

    output_directory = (
        ROOT
        / "reports"
        / "orchestration"
        / "per_finding"
        / request_id.lower()
    )

    canonical_path = Path(
        record["path"]
    )

    canonical = record[
        "document"
    ]

    asset = json_load(
        CONTROLLED_ASSET_PATH
    )

    evidence = json_load(
        CONTROLLED_EVIDENCE_PATH
    )

    runtime = json_load(
        CONTROLLED_RUNTIME_PATH
    )

    generated_at = utc_now()

    ledger = pass_stage(
        ledger,
        stage_id=(
            "EVIDENCE_ARBITRATION"
        ),
        message=(
            "Primary CVE attribution, package "
            "identity and range evidence verified."
        ),
        outputs=[
            {
                "artifact_type": (
                    "CANONICAL_INTELLIGENCE_RECORD"
                ),
                "authority": (
                    "AUTHORITATIVE_RANGE_EVIDENCE"
                ),
                "relative_path": (
                    relative_path(
                        canonical_path
                    )
                ),
                "sha256": file_sha256(
                    canonical_path
                ),
            }
        ],
        warnings=[
            (
                "Controlled pilot profile uses "
                "validated demonstration evidence."
            )
        ],
    )

    affectedness_references = {
        "canonical_intelligence": (
            InputReference(
                canonical["record_id"],
                relative_path(
                    canonical_path
                ),
                file_sha256(
                    canonical_path
                ),
            )
        ),
        "asset_context": (
            InputReference(
                asset["asset_id"],
                relative_path(
                    CONTROLLED_ASSET_PATH
                ),
                file_sha256(
                    CONTROLLED_ASSET_PATH
                ),
            )
        ),
        "component_evidence": (
            InputReference(
                evidence["evidence_id"],
                relative_path(
                    CONTROLLED_EVIDENCE_PATH
                ),
                file_sha256(
                    CONTROLLED_EVIDENCE_PATH
                ),
            )
        ),
        "runtime_context": (
            InputReference(
                runtime["context_id"],
                relative_path(
                    CONTROLLED_RUNTIME_PATH
                ),
                file_sha256(
                    CONTROLLED_RUNTIME_PATH
                ),
            )
        ),
    }

    ledger = transition_stage(
        ledger,
        stage_id="AFFECTEDNESS",
        to_status=RUNNING,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=(
            "Deterministic affectedness "
            "execution started."
        ),
    )

    affectedness = (
        build_affectedness_adjudication(
            canonical_record=canonical,
            asset_context=asset,
            component_evidence=evidence,
            runtime_context=runtime,
            input_references=(
                affectedness_references
            ),
            assessed_at=generated_at,
        )
    )

    affectedness_path = (
        output_directory
        / "affectedness.json"
    )

    write_json_atomic(
        affectedness,
        affectedness_path,
    )

    affectedness_status = (
        affectedness[
            "adjudication"
        ]["status"]
    )

    ledger = transition_stage(
        ledger,
        stage_id="AFFECTEDNESS",
        to_status=(
            PASSED_WITH_WARNINGS
            if affectedness[
                "adjudication"
            ][
                "human_review_required"
            ]
            else PASSED
        ),
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=(
            "Deterministic affectedness "
            f"completed as {affectedness_status}."
        ),
        warnings=(
            affectedness[
                "adjudication"
            ].get(
                "uncertainty_factors",
                [],
            )
        ),
        outputs=[
            output_reference(
                artifact_type=(
                    "AFFECTEDNESS_ADJUDICATION"
                ),
                authority=(
                    "DETERMINISTIC_ENGINE"
                ),
                path=(
                    affectedness_path
                ),
            )
        ],
    )

    feature_references = {
        "canonical_intelligence": (
            FeatureInputReference(
                record_id=(
                    canonical[
                        "record_id"
                    ]
                ),
                relative_path=(
                    relative_path(
                        canonical_path
                    )
                ),
                sha256=file_sha256(
                    canonical_path
                ),
            )
        ),
        "affectedness_adjudication": (
            FeatureInputReference(
                record_id=(
                    affectedness[
                        "report_id"
                    ]
                ),
                relative_path=(
                    relative_path(
                        affectedness_path
                    )
                ),
                sha256=file_sha256(
                    affectedness_path
                ),
            )
        ),
        "asset_context": (
            FeatureInputReference(
                record_id=asset[
                    "asset_id"
                ],
                relative_path=(
                    relative_path(
                        CONTROLLED_ASSET_PATH
                    )
                ),
                sha256=file_sha256(
                    CONTROLLED_ASSET_PATH
                ),
            )
        ),
        "component_evidence": (
            FeatureInputReference(
                record_id=evidence[
                    "evidence_id"
                ],
                relative_path=(
                    relative_path(
                        CONTROLLED_EVIDENCE_PATH
                    )
                ),
                sha256=file_sha256(
                    CONTROLLED_EVIDENCE_PATH
                ),
            )
        ),
        "runtime_context": (
            FeatureInputReference(
                record_id=runtime[
                    "context_id"
                ],
                relative_path=(
                    relative_path(
                        CONTROLLED_RUNTIME_PATH
                    )
                ),
                sha256=file_sha256(
                    CONTROLLED_RUNTIME_PATH
                ),
            )
        ),
    }

    ledger = transition_stage(
        ledger,
        stage_id=(
            "DECISION_FEATURE_ENVELOPE"
        ),
        to_status=RUNNING,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=(
            "Decision Feature Envelope "
            "generation started."
        ),
    )

    feature_envelope = (
        build_decision_feature_envelope(
            canonical_record=canonical,
            affectedness_report=(
                affectedness
            ),
            asset_context=asset,
            component_evidence=evidence,
            runtime_context=runtime,
            input_references=(
                feature_references
            ),
            generated_at=generated_at,
        )
    )

    feature_path = (
        output_directory
        / "decision_feature_envelope.json"
    )

    write_json_atomic(
        feature_envelope,
        feature_path,
    )

    if (
        feature_envelope[
            "release_decision"
        ]["stage_gate"]
        != "PASS"
    ):
        ledger = transition_stage(
            ledger,
            stage_id=(
                "DECISION_FEATURE_ENVELOPE"
            ),
            to_status=FAILED,
            actor_type="ENGINE",
            actor_id=(
                "aegissec-per-finding-executor"
            ),
            reason_code=(
                "DECISION_FEATURE_GATE_FAILED"
            ),
            message=(
                "Decision Feature Envelope "
                "failed its stage gate."
            ),
            outputs=[
                output_reference(
                    artifact_type=(
                        "DECISION_FEATURE_ENVELOPE"
                    ),
                    authority=(
                        "AUTHORITATIVE_FEATURE_CONTRACT"
                    ),
                    path=feature_path,
                )
            ],
        )

        raise PerFindingExecutionError(
            "Decision Feature Envelope "
            "stage gate failed."
        )

    ledger = transition_stage(
        ledger,
        stage_id=(
            "DECISION_FEATURE_ENVELOPE"
        ),
        to_status=PASSED,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=(
            "Decision Feature Envelope "
            "passed its governed contract."
        ),
        outputs=[
            output_reference(
                artifact_type=(
                    "DECISION_FEATURE_ENVELOPE"
                ),
                authority=(
                    "AUTHORITATIVE_FEATURE_CONTRACT"
                ),
                path=feature_path,
            )
        ],
    )

    ledger = transition_stage(
        ledger,
        stage_id="SSVC",
        to_status=RUNNING,
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=(
            "Authoritative SSVC evaluation started."
        ),
    )

    ssvc = build_ssvc_policy_decision(
        decision_feature_envelope=(
            feature_envelope
        ),
        input_relative_path=(
            relative_path(
                feature_path
            )
        ),
        input_sha256=file_sha256(
            feature_path
        ),
        generated_at=generated_at,
    )

    ssvc_path = (
        output_directory
        / "ssvc_decision.json"
    )

    write_json_atomic(
        ssvc,
        ssvc_path,
    )

    if (
        ssvc["governance"][
            "stage_gate"
        ]
        != "PASS"
    ):
        ledger = transition_stage(
            ledger,
            stage_id="SSVC",
            to_status=FAILED,
            actor_type="ENGINE",
            actor_id=(
                "aegissec-per-finding-executor"
            ),
            reason_code=(
                "SSVC_STAGE_GATE_FAILED"
            ),
            message=(
                "SSVC failed its governed stage gate."
            ),
            outputs=[
                output_reference(
                    artifact_type=(
                        "SSVC_POLICY_DECISION"
                    ),
                    authority="SSVC",
                    path=ssvc_path,
                )
            ],
        )

        raise PerFindingExecutionError(
            "SSVC stage gate failed."
        )

    ledger = transition_stage(
        ledger,
        stage_id="SSVC",
        to_status=(
            PASSED_WITH_WARNINGS
        ),
        actor_type="ENGINE",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        message=(
            "SSVC completed. Human review "
            "and final authorization remain required."
        ),
        warnings=[
            (
                "SSVC is authoritative, but "
                "final disposition remains human."
            )
        ],
        outputs=[
            output_reference(
                artifact_type=(
                    "SSVC_POLICY_DECISION"
                ),
                authority="SSVC",
                path=ssvc_path,
            )
        ],
    )

    ledger = transition_stage(
        ledger,
        stage_id="ML_ADVISORY",
        to_status=SKIPPED,
        actor_type="SYSTEM",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        reason_code=(
            "ML_NOT_REQUIRED_FOR_DETERMINISTIC_EXECUTION"
        ),
        message=(
            "ML advisory is not required "
            "to establish deterministic affectedness."
        ),
    )

    ledger = transition_stage(
        ledger,
        stage_id=(
            "AGREEMENT_ANALYSIS"
        ),
        to_status=SKIPPED,
        actor_type="SYSTEM",
        actor_id=(
            "aegissec-per-finding-executor"
        ),
        reason_code=(
            "NO_NEW_ML_ADVISORY_OUTPUT"
        ),
        message=(
            "No new ML output was generated "
            "for this per-finding execution."
        ),
    )

    summary = {
        "request_id": request_id,
        "cve_id": (
            request[
                "unit_of_assessment"
            ]["cve_id"]
        ),
        "component": (
            request[
                "unit_of_assessment"
            ]["component"]
        ),
        "affectedness_status": (
            affectedness[
                "adjudication"
            ]["status"]
        ),
        "affectedness_confidence": (
            affectedness[
                "adjudication"
            ]["confidence"]
        ),
        "affectedness_human_review_required": (
            affectedness[
                "adjudication"
            ][
                "human_review_required"
            ]
        ),
        "ssvc_vector": (
            ssvc[
                "official_ssvc_decision"
            ]["vector"]
        ),
        "ssvc_matched_row": (
            ssvc[
                "official_ssvc_decision"
            ]["matched_row"]
        ),
        "ssvc_outcome": (
            ssvc[
                "official_ssvc_decision"
            ]["outcome"]["name"]
        ),
        "final_disposition_status": (
            ssvc["separation"][
                "final_disposition_status"
            ]
        ),
        "production_readiness": (
            ssvc["governance"][
                "production_readiness"
            ]
        ),
        "human_review_required": (
            ssvc["governance"][
                "human_review_required"
            ]
        ),
        "artifacts": {
            "affectedness": (
                output_reference(
                    artifact_type=(
                        "AFFECTEDNESS_ADJUDICATION"
                    ),
                    authority=(
                        "DETERMINISTIC_ENGINE"
                    ),
                    path=(
                        affectedness_path
                    ),
                )
            ),
            "decision_features": (
                output_reference(
                    artifact_type=(
                        "DECISION_FEATURE_ENVELOPE"
                    ),
                    authority=(
                        "AUTHORITATIVE_FEATURE_CONTRACT"
                    ),
                    path=feature_path,
                )
            ),
            "ssvc": (
                output_reference(
                    artifact_type=(
                        "SSVC_POLICY_DECISION"
                    ),
                    authority="SSVC",
                    path=ssvc_path,
                )
            ),
        },
    }

    return ledger, summary


def execute_request(
    request: Mapping[str, Any],
    catalog: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    ledger = new_request_ledger(
        request
    )

    unit = request[
        "unit_of_assessment"
    ]

    cve_id = unit.get(
        "cve_id"
    )

    component = unit[
        "component"
    ]

    base = {
        "request_id": (
            request[
                "request_id"
            ]
        ),
        "asset_id": (
            unit["asset_id"]
        ),
        "component": component,
        "cve_id": cve_id,
        "execution_status": None,
        "reason_code": None,
        "summary": None,
    }

    if not (
        verify_finding_assessment_request(
            request
        )
    ):
        ledger = block_stage(
            ledger,
            stage_id=(
                "INTAKE_VALIDATION"
            ),
            reason_code=(
                "FINDING_REQUEST_INTEGRITY_FAILED"
            ),
            message=(
                "Finding request integrity "
                "verification failed."
            ),
        )

        base[
            "execution_status"
        ] = STATUS_INTEGRITY_BLOCKED

        base["reason_code"] = (
            "FINDING_REQUEST_INTEGRITY_FAILED"
        )

        base["ledger"] = ledger

        return base

    ledger = establish_common_stages(
        ledger,
        request,
        through_correlation=False,
    )

    if (
        request["status"]
        == "BLOCKED"
    ):
        ledger = block_stage(
            ledger,
            stage_id=(
                "COMPONENT_CORRELATION"
            ),
            reason_code=(
                "FINDING_IDENTITY_INCOMPLETE"
            ),
            message=(
                "Exact canonical component "
                "identity is incomplete."
            ),
        )

        base[
            "execution_status"
        ] = STATUS_IDENTITY_BLOCKED

        base["reason_code"] = (
            "FINDING_IDENTITY_INCOMPLETE"
        )

        base["ledger"] = ledger

        return base

    ledger = pass_stage(
        ledger,
        stage_id=(
            "COMPONENT_CORRELATION"
        ),
        message=(
            "Exact canonical component "
            "identity and CVE association verified."
        ),
        outputs=[
            {
                "artifact_type": (
                    "COMPONENT_CVE_CORRELATION"
                ),
                "authority": (
                    "CORRELATION_EVIDENCE_ONLY"
                ),
                "sha256": (
                    request[
                        "evidence_snapshot"
                    ][
                        "correlation_row_sha256"
                    ]
                ),
            }
        ],
    )

    if not isinstance(
        cve_id,
        str,
    ):
        ledger = block_stage(
            ledger,
            stage_id=(
                "EVIDENCE_ARBITRATION"
            ),
            reason_code=(
                "CVE_IDENTIFIER_UNAVAILABLE"
            ),
            message=(
                "No valid CVE identifier is available."
            ),
        )

        base[
            "execution_status"
        ] = STATUS_CANONICAL_BLOCKED

        base["reason_code"] = (
            "CVE_IDENTIFIER_UNAVAILABLE"
        )

        base["ledger"] = ledger

        return base

    record = find_primary_record(
        catalog,
        cve_id,
    )

    if record is None:
        if is_adjacent_cve(
            catalog,
            cve_id,
        ):
            reason = (
                "AFFECTEDNESS_INTELLIGENCE_"
                "ATTRIBUTION_UNRESOLVED"
            )

            status = (
                STATUS_ATTRIBUTION_BLOCKED
            )

            message = (
                "The CVE is adjacent to a canonical "
                "record but is not its primary range target."
            )

        else:
            reason = (
                "AFFECTEDNESS_CANONICAL_"
                "INTELLIGENCE_UNAVAILABLE"
            )

            status = (
                STATUS_CANONICAL_BLOCKED
            )

            message = (
                "No canonical package-range "
                "intelligence exists for this CVE."
            )

        ledger = block_stage(
            ledger,
            stage_id=(
                "EVIDENCE_ARBITRATION"
            ),
            reason_code=reason,
            message=message,
        )

        base[
            "execution_status"
        ] = status

        base[
            "reason_code"
        ] = reason

        base["ledger"] = ledger

        return base

    package = matched_package(
        record,
        component,
    )

    if (
        package is None
        or not has_usable_ranges(
            package
        )
    ):
        ledger = pass_stage(
            ledger,
            stage_id=(
                "EVIDENCE_ARBITRATION"
            ),
            message=(
                "Primary CVE attribution verified."
            ),
        )

        ledger = block_stage(
            ledger,
            stage_id=(
                "AFFECTEDNESS"
            ),
            reason_code=(
                "AFFECTEDNESS_INTELLIGENCE_"
                "RANGE_UNAVAILABLE"
            ),
            message=(
                "No unambiguous package range is "
                "available for this component."
            ),
        )

        base[
            "execution_status"
        ] = STATUS_RANGE_BLOCKED

        base["reason_code"] = (
            "AFFECTEDNESS_INTELLIGENCE_"
            "RANGE_UNAVAILABLE"
        )

        base["ledger"] = ledger

        return base

    if not controlled_profile_available(
        request
    ):
        ledger = pass_stage(
            ledger,
            stage_id=(
                "EVIDENCE_ARBITRATION"
            ),
            message=(
                "Primary CVE attribution and "
                "range evidence verified."
            ),
        )

        ledger = block_stage(
            ledger,
            stage_id="AFFECTEDNESS",
            reason_code=(
                "CONTROLLED_EXECUTION_"
                "PROFILE_UNAVAILABLE"
            ),
            message=(
                "A validated execution profile "
                "is not yet available for this request."
            ),
        )

        base[
            "execution_status"
        ] = STATUS_PROFILE_BLOCKED

        base["reason_code"] = (
            "CONTROLLED_EXECUTION_"
            "PROFILE_UNAVAILABLE"
        )

        base["ledger"] = ledger

        return base

    try:
        ledger, summary = (
            execute_controlled_pipeline(
                request,
                record,
                ledger,
            )
        )

    except Exception as exc:
        current = ledger[
            "stages"
        ]["AFFECTEDNESS"][
            "status"
        ]

        if current == RUNNING:
            ledger = transition_stage(
                ledger,
                stage_id="AFFECTEDNESS",
                to_status=FAILED,
                actor_type="ENGINE",
                actor_id=(
                    "aegissec-per-finding-executor"
                ),
                reason_code=(
                    "DETERMINISTIC_EXECUTION_FAILED"
                ),
                message=(
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        base[
            "execution_status"
        ] = STATUS_EXECUTION_FAILED

        base["reason_code"] = (
            "DETERMINISTIC_EXECUTION_FAILED"
        )

        base["summary"] = {
            "error_type": (
                type(exc).__name__
            ),
            "error_message": str(
                exc
            ),
        }

        base["ledger"] = ledger

        return base

    valid, errors = verify_ledger(
        ledger
    )

    if not valid:
        raise PerFindingExecutionError(
            "Executed request produced an "
            "invalid ledger: "
            + "; ".join(errors)
        )

    base[
        "execution_status"
    ] = STATUS_EXECUTED

    base["reason_code"] = (
        "DETERMINISTIC_PIPELINE_EXECUTED"
    )

    base["summary"] = summary
    base["ledger"] = ledger

    return base


def queue_lane(
    status: str,
) -> str:
    if status == STATUS_EXECUTED:
        return (
            "HUMAN_DECISION_REQUIRED"
        )

    if status == STATUS_IDENTITY_BLOCKED:
        return (
            "IDENTITY_REMEDIATION"
        )

    if status in {
        STATUS_CANONICAL_BLOCKED,
        STATUS_ATTRIBUTION_BLOCKED,
        STATUS_RANGE_BLOCKED,
        STATUS_PROFILE_BLOCKED,
    }:
        return (
            "EVIDENCE_REMEDIATION"
        )

    return "ENGINE_EXCEPTION_REVIEW"


def build_execution_manifest(
    *,
    request_manifest_path: Path = (
        DEFAULT_REQUEST_MANIFEST
    ),
) -> dict[str, Any]:
    request_manifest = json_load(
        request_manifest_path
    )

    catalog = (
        build_canonical_catalog()
    )

    results = [
        execute_request(
            request,
            catalog,
        )
        for request
        in request_manifest[
            "requests"
        ]
    ]

    counts: dict[
        str,
        int,
    ] = {}

    for result in results:
        status = result[
            "execution_status"
        ]

        counts[status] = (
            counts.get(
                status,
                0,
            )
            + 1
        )

        result["queue_lane"] = (
            queue_lane(status)
        )

    executed = [
        result
        for result in results
        if result[
            "execution_status"
        ]
        == STATUS_EXECUTED
    ]

    human_review_count = sum(
        result["queue_lane"]
        == "HUMAN_DECISION_REQUIRED"
        for result in results
    )

    identity_remediation_count = sum(
        result["queue_lane"]
        == "IDENTITY_REMEDIATION"
        for result in results
    )

    evidence_remediation_count = sum(
        result["queue_lane"]
        == "EVIDENCE_REMEDIATION"
        for result in results
    )

    engine_exception_count = sum(
        result["queue_lane"]
        == "ENGINE_EXCEPTION_REVIEW"
        for result in results
    )

    unsigned = {
        "schema_version": "1.0.0",
        "generated_at": utc_now(),
        "source_manifest": {
            "relative_path": (
                relative_path(
                    request_manifest_path
                )
            ),
            "sha256": file_sha256(
                request_manifest_path
            ),
            "request_count": len(
                request_manifest[
                    "requests"
                ]
            ),
        },
        "canonical_catalog": {
            "record_count": len(
                catalog
            ),
            "primary_cves": sorted(
                {
                    cve_id
                    for record
                    in catalog
                    for cve_id
                    in record[
                        "primary_cves"
                    ]
                }
            ),
            "adjacent_cves": sorted(
                {
                    cve_id
                    for record
                    in catalog
                    for cve_id
                    in record[
                        "adjacent_cves"
                    ]
                }
            ),
        },
        "statistics": {
            "total_requests": len(
                results
            ),
            "execution_status_counts": (
                dict(
                    sorted(
                        counts.items()
                    )
                )
            ),
            "executed_count": len(
                executed
            ),
            "human_decision_queue": (
                human_review_count
            ),
            "identity_remediation_queue": (
                identity_remediation_count
            ),
            "evidence_remediation_queue": (
                evidence_remediation_count
            ),
            "engine_exception_queue": (
                engine_exception_count
            ),
        },
        "results": results,
        "governance": {
            "affectedness_authority": (
                "DETERMINISTIC_ENGINE"
            ),
            "policy_authority": (
                "SSVC"
            ),
            "model_authority": (
                "ADVISORY_ONLY"
            ),
            "automated_final_disposition_permitted": (
                False
            ),
            "final_disposition_authority": (
                "HUMAN"
            ),
            "no_match_means_safe": (
                False
            ),
            "production_readiness": (
                "BLOCKED"
            ),
        },
    }

    return {
        **unsigned,
        "integrity": {
            "manifest_sha256": (
                sha256_bytes(
                    canonical_json_bytes(
                        unsigned
                    )
                )
            ),
        },
    }


def verify_execution_manifest(
    manifest: Mapping[str, Any],
) -> bool:
    integrity = manifest.get(
        "integrity"
    )

    if not isinstance(
        integrity,
        Mapping,
    ):
        return False

    expected = integrity.get(
        "manifest_sha256"
    )

    if not isinstance(
        expected,
        str,
    ):
        return False

    unsigned = {
        key: value
        for key, value
        in manifest.items()
        if key != "integrity"
    }

    observed = sha256_bytes(
        canonical_json_bytes(
            unsigned
        )
    )

    return observed == expected

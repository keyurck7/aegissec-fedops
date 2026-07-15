from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from src.affectedness.affectedness_engine import AffectednessEngine
from src.affectedness.canonical_adapter import (
    CanonicalAffectednessAdapterError,
    canonical_intelligence_trust_view,
    component_instance_from_canonical,
    detect_package_assertion_conflicts,
    intelligence_record_from_canonical,
)
from src.governance.evidence_trust_engine import EvidenceTrustEngine
from src.intelligence.official_source import canonical_json_bytes


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ADJUDICATION_POLICY = (
    PROJECT_ROOT
    / "policies"
    / "affectedness"
    / "affectedness_adjudication_policy_v1.yaml"
)


class AffectednessAdjudicationError(RuntimeError):
    """Raised when affectedness adjudication cannot be executed safely."""


@dataclass(frozen=True)
class InputReference:
    record_id: str
    relative_path: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "record_id": self.record_id,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
        }


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_document(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(dict(value)))


def stable_identifier(prefix: str, identity: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(dict(identity))
    ).hexdigest()[:24].upper()
    return f"{prefix}-{digest}"


def _load_policy(path: Path | str) -> tuple[dict[str, Any], str]:
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(
            f"Affectedness adjudication policy not found: {policy_path}"
        )
    raw = policy_path.read_bytes()
    document = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise AffectednessAdjudicationError(
            "Affectedness adjudication policy must be a YAML object."
        )
    required = {
        "policy",
        "canonical_intelligence_trust",
        "state_mapping",
        "runtime_semantics",
        "human_review",
        "closure",
        "release",
    }
    missing = required - set(document)
    if missing:
        raise AffectednessAdjudicationError(
            f"Affectedness adjudication policy missing sections: {sorted(missing)}"
        )
    return document, hashlib.sha256(raw).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AffectednessAdjudicationError(
            f"{label} must be a JSON object."
        )
    return value


def _strings(values: list[Any]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _quality_gate(
    gate_id: str,
    metric: str,
    observed: Any,
    expected: Any,
    passed: bool,
) -> dict[str, Any]:
    return {
        "gate_id": gate_id,
        "metric": metric,
        "observed": observed,
        "expected": expected,
        "pass": bool(passed),
    }


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise AffectednessAdjudicationError(
            "An ISO-8601 assessment timestamp is required."
        )
    text = value.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AffectednessAdjudicationError(
            f"Invalid assessment timestamp: {value!r}"
        ) from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _component_identity(
    canonical_record: Mapping[str, Any],
) -> dict[str, str]:
    target = _mapping(canonical_record.get("target"), "target")
    component = _mapping(target.get("component"), "target.component")
    return {
        "package_name": str(component.get("package_name", "")).strip(),
        "ecosystem": str(component.get("ecosystem", "")).strip(),
        "version": str(component.get("version", "")).strip(),
    }


def _runtime_component_identity(
    runtime_context: Mapping[str, Any],
) -> dict[str, Any]:
    component = _mapping(
        runtime_context.get("component"),
        "runtime_context.component",
    )
    return {
        "component_id": str(component.get("component_id", "")).strip(),
        "package_name": str(component.get("package_name", "")).strip(),
        "ecosystem": str(component.get("ecosystem", "")).strip(),
        "version": str(component.get("version", "")).strip(),
        "purl": component.get("purl"),
    }


def _identity_conflicts(
    canonical_record: Mapping[str, Any],
    asset_context: Mapping[str, Any],
    component_evidence: Mapping[str, Any],
    runtime_context: Mapping[str, Any],
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    asset_id = str(asset_context.get("asset_id", "")).strip()
    runtime_asset_id = str(runtime_context.get("asset_id", "")).strip()
    if asset_id != runtime_asset_id:
        conflicts.append(
            {
                "code": "ASSET_IDENTITY_MISMATCH",
                "blocking": True,
                "message": (
                    "Runtime context is bound to a different asset than the "
                    "validated asset context."
                ),
                "evidence": {
                    "asset_context": asset_id,
                    "runtime_context": runtime_asset_id,
                },
            }
        )

    evidence_assets = {
        str(value)
        for value in component_evidence.get("asset_references", [])
        if isinstance(value, str)
    }
    if asset_id not in evidence_assets:
        conflicts.append(
            {
                "code": "EVIDENCE_ASSET_BINDING_MISSING",
                "blocking": True,
                "message": (
                    "Component evidence does not explicitly reference the "
                    "adjudicated asset."
                ),
                "evidence": {
                    "asset_id": asset_id,
                    "evidence_asset_references": sorted(evidence_assets),
                },
            }
        )

    canonical_component = _component_identity(canonical_record)
    runtime_component = _runtime_component_identity(runtime_context)
    differences = {
        key: {
            "canonical": canonical_component[key],
            "runtime": runtime_component[key],
        }
        for key in ("package_name", "ecosystem", "version")
        if canonical_component[key].casefold()
        != str(runtime_component[key]).casefold()
    }
    if differences:
        conflicts.append(
            {
                "code": "COMPONENT_IDENTITY_MISMATCH",
                "blocking": True,
                "message": (
                    "Runtime component identity does not match the component "
                    "used for official-source correlation."
                ),
                "evidence": differences,
            }
        )

    controls = _mapping(
        canonical_record.get("correlation_controls"),
        "correlation_controls",
    )
    for item in controls.get("conflicts", []):
        if isinstance(item, Mapping) and item.get("blocking") is True:
            conflicts.append(
                {
                    "code": "BLOCKING_CANONICAL_SOURCE_CONFLICT",
                    "blocking": True,
                    "message": (
                        "Canonical intelligence contains a blocking source "
                        "correlation conflict."
                    ),
                    "evidence": dict(item),
                }
            )

    conflicts.extend(detect_package_assertion_conflicts(canonical_record))
    return conflicts


def _combined_trust(
    component_assessment: Any,
    canonical_assessment: Any,
) -> dict[str, Any]:
    rank = {
        "ACCEPT": 0,
        "ACCEPT_WITH_WARNINGS": 1,
        "QUARANTINE": 2,
        "REJECT": 3,
    }
    component_action = str(component_assessment.action).upper()
    canonical_action = str(canonical_assessment.action).upper()
    action = max(
        (component_action, canonical_action),
        key=lambda value: rank[value],
    )
    scores = [
        value
        for value in (
            component_assessment.aggregate_score,
            canonical_assessment.aggregate_score,
        )
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    reason_codes = [
        f"COMPONENT_EVIDENCE_{component_action}",
        *canonical_assessment.reason_codes,
    ]
    return {
        "action": action,
        "aggregate_score": round(min(scores), 4) if scores else None,
        "reason_codes": _strings(reason_codes),
    }


def _runtime_values(
    runtime_context: Mapping[str, Any],
) -> tuple[str, str, str, list[str]]:
    presence = _mapping(runtime_context.get("presence"), "presence")
    reachability = _mapping(
        runtime_context.get("reachability"),
        "reachability",
    )
    configuration = _mapping(
        runtime_context.get("configuration"),
        "configuration",
    )
    evidence_ids = _strings(
        list(presence.get("evidence_ids", []))
        + list(reachability.get("evidence_ids", []))
        + list(configuration.get("evidence_ids", []))
    )
    return (
        str(presence.get("status", "UNKNOWN")).upper(),
        str(reachability.get("status", "UNKNOWN")).upper(),
        str(configuration.get("status", "UNKNOWN")).upper(),
        evidence_ids,
    )


def build_affectedness_adjudication(
    *,
    canonical_record: Mapping[str, Any],
    asset_context: Mapping[str, Any],
    component_evidence: Mapping[str, Any],
    runtime_context: Mapping[str, Any],
    input_references: Mapping[str, InputReference],
    assessed_at: str,
    policy_path: Path | str = DEFAULT_ADJUDICATION_POLICY,
) -> dict[str, Any]:
    policy, policy_sha256 = _load_policy(policy_path)
    assessment_time = _parse_time(assessed_at)
    generated_at = assessment_time.isoformat()

    required_refs = {
        "canonical_intelligence",
        "asset_context",
        "component_evidence",
        "runtime_context",
    }
    if set(input_references) != required_refs:
        raise AffectednessAdjudicationError(
            "input_references must contain exactly "
            f"{sorted(required_refs)}."
        )

    presence, reachability, configuration, runtime_evidence_ids = (
        _runtime_values(runtime_context)
    )
    component_evidence_id = str(
        component_evidence.get("evidence_id", "AEG-EVD-UNKNOWN")
    )
    runtime_component = _runtime_component_identity(runtime_context)

    component_trust = EvidenceTrustEngine().assess(
        dict(component_evidence),
        assessed_at=assessment_time,
    )
    canonical_trust = canonical_intelligence_trust_view(
        canonical_record,
        policy,
    )
    combined_trust = _combined_trust(component_trust, canonical_trust)

    conflicts = _identity_conflicts(
        canonical_record,
        asset_context,
        component_evidence,
        runtime_context,
    )
    blocking_conflicts = [
        item for item in conflicts if item.get("blocking") is True
    ]

    component_instance = component_instance_from_canonical(
        canonical_record,
        component_id=runtime_component["component_id"],
        runtime_presence=presence,
        evidence_ids=[component_evidence_id, *runtime_evidence_ids],
    )
    intelligence_record = intelligence_record_from_canonical(
        canonical_record
    )
    technical = AffectednessEngine().assess(
        component_instance=component_instance,
        intelligence_record=intelligence_record,
        evidence_trust=combined_trust,
        assessed_at=assessment_time,
    )
    technical_dict = technical.to_dict()

    state_mapping = _mapping(policy.get("state_mapping"), "state_mapping")
    try:
        adjudication_status = str(state_mapping[technical.status])
    except KeyError as exc:
        raise AffectednessAdjudicationError(
            f"No adjudication mapping for technical status {technical.status!r}."
        ) from exc
    if blocking_conflicts:
        adjudication_status = "CONFLICTED"

    reason_codes = list(technical.reason_codes)
    uncertainty = list(technical.uncertainty_factors)
    if blocking_conflicts:
        reason_codes.extend(item["code"] for item in blocking_conflicts)
        reason_codes.append("AFFECTEDNESS_CONFLICTED")
        uncertainty.append(
            "Blocking cross-record or source conflicts prevent a safe affectedness conclusion."
        )
    if reachability == "UNKNOWN":
        reason_codes.append("RUNTIME_REACHABILITY_UNKNOWN")
        uncertainty.append(
            "Runtime reachability has not been established. This does not negate package affectedness."
        )
    elif reachability == "NOT_REACHABLE":
        reason_codes.append("RUNTIME_NOT_REACHABLE_OBSERVED")
    else:
        reason_codes.append("RUNTIME_REACHABLE_OBSERVED")

    if configuration == "MITIGATED":
        reason_codes.append("MITIGATION_DOES_NOT_CHANGE_AFFECTED_VERSION")
        uncertainty.append(
            "A mitigation may reduce exploitability but does not make an affected software version not affected."
        )
    elif configuration == "VULNERABLE":
        reason_codes.append("VULNERABLE_CONFIGURATION_OBSERVED")
    else:
        reason_codes.append("CONFIGURATION_STATUS_UNKNOWN")

    if technical.status == "probably_not_affected":
        reason_codes.append("NEGATIVE_CLAIM_FAIL_CLOSED_TO_UNKNOWN")
        uncertainty.append(
            "Incomplete evidence cannot support a definitive not-affected closure."
        )

    asset_environment = _mapping(
        asset_context.get("environment"),
        "asset_context.environment",
    )
    mission = _mapping(asset_context.get("mission"), "asset_context.mission")
    component_has_warnings = component_trust.action == "ACCEPT_WITH_WARNINGS"
    canonical_has_warnings = canonical_trust.action == "ACCEPT_WITH_WARNINGS"
    review_always = set(
        _mapping(policy.get("human_review"), "human_review").get(
            "always_required_for", []
        )
    )
    human_review_required = adjudication_status in review_always
    if adjudication_status == "AFFECTED":
        human_review_required = human_review_required or any(
            (
                reachability == "UNKNOWN",
                component_has_warnings,
                canonical_has_warnings,
                asset_environment.get("lifecycle_stage") == "production",
                mission.get("mission_essential") is True,
            )
        )

    closure_policy = _mapping(policy.get("closure"), "closure")
    not_affected_confidence = (
        technical.confidence
        if isinstance(technical.confidence, (int, float))
        else 0.0
    )
    definitive_negative = technical.status in {"fixed", "not_affected"}
    closure_prohibited = (
        adjudication_status in set(closure_policy.get("prohibited_for", []))
        or bool(blocking_conflicts)
        or (
            adjudication_status == "NOT_AFFECTED"
            and (
                not definitive_negative
                or not_affected_confidence
                < float(closure_policy["minimum_not_affected_confidence"])
            )
        )
    )

    confidence = None if adjudication_status == "CONFLICTED" else technical.confidence
    evidence_ids = _strings(
        list(technical.supporting_evidence_ids)
        + [
            f"CANONICAL:{canonical_record.get('record_id')}",
            f"ASSET:{asset_context.get('asset_id')}",
            f"RUNTIME:{runtime_context.get('context_id')}",
        ]
    )

    target = _mapping(canonical_record.get("target"), "target")
    target_component = _component_identity(canonical_record)
    target_block = {
        "cve_id": str(target.get("cve_id")),
        "asset_id": str(asset_context.get("asset_id")),
        "component": {
            "component_id": runtime_component["component_id"],
            **target_component,
            "purl": runtime_component.get("purl") or component_instance.get("purl"),
        },
    }

    exact_target_ids = _mapping(
        canonical_record.get("package_evidence"),
        "package_evidence",
    ).get("exact_target_record_ids", [])
    technical_executed = technical.determination_method != "not_run"
    negative_closure_safe = (
        adjudication_status != "NOT_AFFECTED"
        or not closure_prohibited
    )

    quality_gates = [
        _quality_gate(
            "M12C-INPUT-REFERENCES",
            "required_input_reference_count",
            len(input_references),
            4,
            len(input_references) == 4,
        ),
        _quality_gate(
            "M12C-CANONICAL-TRUST",
            "canonical_intelligence_trust_action",
            canonical_trust.action,
            ["ACCEPT", "ACCEPT_WITH_WARNINGS"],
            canonical_trust.action in {"ACCEPT", "ACCEPT_WITH_WARNINGS"},
        ),
        _quality_gate(
            "M12C-COMPONENT-TRUST",
            "component_evidence_trust_action",
            component_trust.action,
            ["ACCEPT", "ACCEPT_WITH_WARNINGS"],
            component_trust.action in {"ACCEPT", "ACCEPT_WITH_WARNINGS"},
        ),
        _quality_gate(
            "M12C-ASSET-BINDING",
            "asset_identity_conflicts",
            [
                item["code"]
                for item in conflicts
                if item["code"] in {
                    "ASSET_IDENTITY_MISMATCH",
                    "EVIDENCE_ASSET_BINDING_MISSING",
                }
            ],
            [],
            not any(
                item["code"] in {
                    "ASSET_IDENTITY_MISMATCH",
                    "EVIDENCE_ASSET_BINDING_MISSING",
                }
                for item in conflicts
            ),
        ),
        _quality_gate(
            "M12C-COMPONENT-BINDING",
            "component_identity_conflicts",
            [
                item["code"]
                for item in conflicts
                if item["code"] == "COMPONENT_IDENTITY_MISMATCH"
            ],
            [],
            not any(
                item["code"] == "COMPONENT_IDENTITY_MISMATCH"
                for item in conflicts
            ),
        ),
        _quality_gate(
            "M12C-EXACT-TARGET-PACKAGE",
            "exact_target_package_record_count",
            len(exact_target_ids),
            ">=1",
            len(exact_target_ids) >= 1,
        ),
        _quality_gate(
            "M12C-BLOCKING-CONFLICTS",
            "blocking_conflict_count",
            len(blocking_conflicts),
            0,
            not blocking_conflicts,
        ),
        _quality_gate(
            "M12C-TECHNICAL-ENGINE",
            "technical_affectedness_engine_executed",
            technical_executed,
            True,
            technical_executed,
        ),
        _quality_gate(
            "M12C-NEGATIVE-CLOSURE",
            "negative_affectedness_closure_safe",
            negative_closure_safe,
            True,
            negative_closure_safe,
        ),
        _quality_gate(
            "M12C-RUNTIME-SEMANTICS",
            "reachability_or_mitigation_overrode_package_affectedness",
            False,
            False,
            True,
        ),
        _quality_gate(
            "M12C-PRODUCTION-BLOCK",
            "production_readiness",
            "BLOCKED",
            "BLOCKED",
            True,
        ),
    ]
    stage_gate_pass = all(item["pass"] for item in quality_gates)

    release = _mapping(policy.get("release"), "release")
    policy_eligibility = _mapping(
        release.get("policy_eligibility"),
        "release.policy_eligibility",
    )[adjudication_status]
    blocking_reasons = list(release.get("remaining_blockers", []))
    if adjudication_status in {"UNKNOWN", "CONFLICTED"}:
        blocking_reasons.insert(
            0,
            "Affectedness is not sufficiently resolved for automated policy execution.",
        )
    if human_review_required:
        blocking_reasons.append(
            "Accountable human review is required for this adjudication."
        )

    input_hashes = {
        name: reference.sha256
        for name, reference in sorted(input_references.items())
    }
    policy_meta = _mapping(policy.get("policy"), "policy")
    report_id = stable_identifier(
        "AEG-AFA",
        {
            "inputs": input_hashes,
            "policy_sha256": policy_sha256,
            "target": target_block,
        },
    )

    report = {
        "schema_version": "1.0.0",
        "report_id": report_id,
        "generated_at": generated_at,
        "policy": {
            "policy_id": str(policy_meta["policy_id"]),
            "version": str(policy_meta["version"]),
            "engine_version": str(policy_meta["engine_version"]),
            "sha256": policy_sha256,
        },
        "inputs": {
            name: reference.to_dict()
            for name, reference in input_references.items()
        },
        "target": target_block,
        "trust": {
            "component_evidence": component_trust.to_dict(),
            "canonical_intelligence": canonical_trust.to_dict(),
            "combined": combined_trust,
        },
        "technical_assessment": technical_dict,
        "adjudication": {
            "status": adjudication_status,
            "technical_status": technical.status,
            "confidence": confidence,
            "determination_basis": (
                "canonical_official_intelligence_plus_component_evidence_"
                "and_runtime_context"
            ),
            "reason_codes": _strings(reason_codes),
            "supporting_evidence_ids": evidence_ids,
            "uncertainty_factors": _strings(uncertainty),
            "human_review_required": human_review_required,
            "closure_prohibited": closure_prohibited,
        },
        "runtime_context": {
            "presence": presence,
            "reachability": reachability,
            "configuration": configuration,
            "affectedness_semantics": (
                "Runtime reachability and mitigation influence exploitability "
                "and remediation handling, but do not rewrite whether the "
                "observed software version falls in an affected range."
            ),
        },
        "conflicts": conflicts,
        "quality_gates": quality_gates,
        "release_decision": {
            "stage_gate": "PASS" if stage_gate_pass else "FAIL",
            "policy_eligibility": policy_eligibility,
            "production_readiness": str(release["production_readiness"]),
            "blocking_reasons": _strings(blocking_reasons),
        },
        "audit": {
            "canonical_json_sha256": "0" * 64,
            "input_hashes": input_hashes,
            "deterministic_report_id": True,
        },
    }
    pre_integrity = copy.deepcopy(report)
    pre_integrity["audit"]["canonical_json_sha256"] = "0" * 64
    report["audit"]["canonical_json_sha256"] = sha256_document(pre_integrity)
    return report

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from src.intelligence.official_source import canonical_json_bytes


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FEATURE_POLICY = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "decision_feature_policy_v1.yaml"
)
DEFAULT_REASON_REGISTRY = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "decision_feature_reason_codes_v1.yaml"
)


class DecisionFeatureEnvelopeError(RuntimeError):
    """Raised when governed decision features cannot be built safely."""


@dataclass(frozen=True)
class FeatureInputReference:
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


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DecisionFeatureEnvelopeError(f"{label} must be a JSON object.")
    return value


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _strings(values: Iterable[Any]) -> list[str]:
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


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _boolean(value: Any, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def _text(value: Any, default: str = "unknown") -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _parse_time(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DecisionFeatureEnvelopeError(
            "A timezone-aware generated_at timestamp is required."
        )
    text = value.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DecisionFeatureEnvelopeError(
            f"Invalid generated_at timestamp: {value!r}"
        ) from exc
    if moment.tzinfo is None:
        raise DecisionFeatureEnvelopeError(
            "generated_at must include an explicit timezone."
        )
    return moment.astimezone(timezone.utc).isoformat()


def _load_yaml(path: Path | str, label: str) -> tuple[dict[str, Any], str]:
    document_path = Path(path)
    if not document_path.is_file():
        raise FileNotFoundError(f"{label} not found: {document_path}")
    raw = document_path.read_bytes()
    value = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise DecisionFeatureEnvelopeError(f"{label} must be a YAML object.")
    return value, hashlib.sha256(raw).hexdigest()


def _load_policy(path: Path | str) -> tuple[dict[str, Any], str]:
    policy, digest = _load_yaml(path, "Decision-feature policy")
    required = {
        "policy",
        "feature_requirements",
        "severity_order",
        "uncertainty",
        "fail_closed",
        "human_review",
        "prohibited_output_fields",
        "release",
    }
    missing = required - set(policy)
    if missing:
        raise DecisionFeatureEnvelopeError(
            f"Decision-feature policy missing sections: {sorted(missing)}"
        )
    return policy, digest


def _load_reason_registry(
    path: Path | str,
) -> tuple[dict[str, Any], set[str], str]:
    registry, digest = _load_yaml(path, "Reason-code registry")
    meta = _mapping(registry.get("registry"), "registry")
    codes = _list(registry.get("codes"))
    known: set[str] = set()
    for item in codes:
        entry = _mapping(item, "reason-code entry")
        code = _text(entry.get("code"), "")
        if not code:
            raise DecisionFeatureEnvelopeError(
                "Reason-code entries require a non-empty code."
            )
        if code in known:
            raise DecisionFeatureEnvelopeError(
                f"Duplicate reason code in registry: {code}"
            )
        known.add(code)
    if not known:
        raise DecisionFeatureEnvelopeError(
            "Reason-code registry must contain at least one code."
        )
    return dict(meta), known, digest


def _quality_gate(
    gate_id: str,
    metric: str,
    observed: Any,
    expected: Any,
    passed: bool,
    reason_codes: Iterable[str],
) -> dict[str, Any]:
    return {
        "gate_id": gate_id,
        "metric": metric,
        "observed": observed,
        "expected": expected,
        "pass": bool(passed),
        "reason_codes": _strings(reason_codes),
    }


def _normalize_cvss_severity(value: Any, score: float | None) -> str:
    if isinstance(value, str):
        normalized = value.strip().upper().replace("-", "_")
        if normalized in {
            "NONE",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            return normalized
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NOT_APPLICABLE"


def _normalize_impact_severity(value: Any) -> str:
    normalized = _text(value).strip().upper().replace("-", "_")
    aliases = {
        "NONE": "NOT_APPLICABLE",
        "N/A": "NOT_APPLICABLE",
        "NA": "NOT_APPLICABLE",
        "MODERATE": "MEDIUM",
        "VERY_HIGH": "SEVERE",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in {
        "NOT_APPLICABLE",
        "UNKNOWN",
        "LOW",
        "MEDIUM",
        "HIGH",
        "SEVERE",
        "CRITICAL",
    }:
        return "UNKNOWN"
    return normalized


def _source_statuses(checks: list[Any]) -> dict[str, str]:
    required: dict[str, str] = {}
    optional: dict[str, str] = {}
    for raw in checks:
        if not isinstance(raw, Mapping):
            continue
        source = _text(raw.get("source_name"), "")
        status = _text(raw.get("status"), "UNKNOWN").upper()
        if not source:
            continue
        target = required if raw.get("required") is True else optional
        target.setdefault(source, status)
    return dict(sorted({**optional, **required}.items()))


def _ssvc_source_feature(canonical: Mapping[str, Any]) -> dict[str, Any]:
    exploitation = _mapping(canonical.get("exploitation"), "exploitation")
    assertions = _list(exploitation.get("ssvc_assertions"))
    if not assertions:
        return {
            "status": "MISSING",
            "exploitation": None,
            "automatable": None,
            "technical_impact": None,
            "source_role": None,
            "assertion_timestamp": None,
        }
    assertion = _mapping(assertions[0], "ssvc assertion")
    data = _mapping(assertion.get("data"), "ssvc assertion data")
    flattened: dict[str, Any] = {}
    for option in _list(data.get("options")):
        if isinstance(option, Mapping):
            for key, value in option.items():
                flattened[str(key)] = value
    return {
        "status": "PRESENT",
        "exploitation": flattened.get("exploitation"),
        "automatable": flattened.get("automatable"),
        "technical_impact": flattened.get("technicalImpact"),
        "source_role": data.get("role"),
        "assertion_timestamp": data.get("timestamp"),
    }


def _identity_conflicts(
    canonical: Mapping[str, Any],
    affectedness: Mapping[str, Any],
    asset: Mapping[str, Any],
    evidence: Mapping[str, Any],
    runtime: Mapping[str, Any],
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    canonical_target = _mapping(canonical.get("target"), "canonical.target")
    affected_target = _mapping(affectedness.get("target"), "affectedness.target")
    canonical_component = _mapping(
        canonical_target.get("component"),
        "canonical.target.component",
    )
    affected_component = _mapping(
        affected_target.get("component"),
        "affectedness.target.component",
    )
    runtime_component = _mapping(runtime.get("component"), "runtime.component")

    values = {
        "cve_id": [canonical_target.get("cve_id"), affected_target.get("cve_id")],
        "asset_id": [asset.get("asset_id"), affected_target.get("asset_id"), runtime.get("asset_id")],
        "package_name": [
            canonical_component.get("package_name"),
            affected_component.get("package_name"),
            runtime_component.get("package_name"),
        ],
        "ecosystem": [
            canonical_component.get("ecosystem"),
            affected_component.get("ecosystem"),
            runtime_component.get("ecosystem"),
        ],
        "version": [
            canonical_component.get("version"),
            affected_component.get("version"),
            runtime_component.get("version"),
        ],
    }
    for field, raw_values in values.items():
        normalized = {
            _text(value, "").casefold()
            for value in raw_values
            if _text(value, "")
        }
        if len(normalized) != 1:
            conflicts.append(
                {
                    "code": "INPUT_IDENTITY_MISMATCH",
                    "blocking": True,
                    "source": field,
                    "message": f"Input records disagree on {field}: {raw_values!r}",
                }
            )

    asset_id = _text(asset.get("asset_id"), "")
    evidence_assets = {
        _text(item, "")
        for item in _list(evidence.get("asset_references"))
        if _text(item, "")
    }
    if asset_id not in evidence_assets:
        conflicts.append(
            {
                "code": "INPUT_IDENTITY_MISMATCH",
                "blocking": True,
                "source": "component_evidence.asset_references",
                "message": "Component evidence is not explicitly bound to the target asset.",
            }
        )
    return conflicts


def _contains_prohibited_key(value: Any, prohibited: set[str]) -> list[str]:
    findings: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                key_text = str(key)
                child_path = f"{path}/{key_text}"
                if key_text in prohibited:
                    findings.append(child_path)
                walk(child, child_path)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{path}/{index}")

    walk(value, "")
    return findings


def _registered_reason_codes(
    value: Any,
    known_codes: set[str],
) -> tuple[bool, list[str]]:
    observed: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                if key == "reason_codes" and isinstance(child, list):
                    observed.update(
                        item for item in child if isinstance(item, str)
                    )
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    unknown = sorted(observed - known_codes)
    return not unknown, unknown


def build_decision_feature_envelope(
    *,
    canonical_record: Mapping[str, Any],
    affectedness_report: Mapping[str, Any],
    asset_context: Mapping[str, Any],
    component_evidence: Mapping[str, Any],
    runtime_context: Mapping[str, Any],
    input_references: Mapping[str, FeatureInputReference],
    generated_at: str | None = None,
    policy_path: Path | str = DEFAULT_FEATURE_POLICY,
    reason_registry_path: Path | str = DEFAULT_REASON_REGISTRY,
) -> dict[str, Any]:
    """Build a deterministic and decision-neutral Milestone 12D envelope."""

    required_inputs = {
        "canonical_intelligence",
        "affectedness_adjudication",
        "asset_context",
        "component_evidence",
        "runtime_context",
    }
    if set(input_references) != required_inputs:
        raise DecisionFeatureEnvelopeError(
            "input_references must contain exactly: "
            + ", ".join(sorted(required_inputs))
        )

    canonical = dict(_mapping(canonical_record, "canonical_record"))
    affectedness = dict(_mapping(affectedness_report, "affectedness_report"))
    asset = dict(_mapping(asset_context, "asset_context"))
    evidence = dict(_mapping(component_evidence, "component_evidence"))
    runtime = dict(_mapping(runtime_context, "runtime_context"))

    policy, policy_sha256 = _load_policy(policy_path)
    registry_meta, known_reason_codes, registry_sha256 = (
        _load_reason_registry(reason_registry_path)
    )
    policy_meta = _mapping(policy.get("policy"), "policy")
    release_policy = _mapping(policy.get("release"), "release")

    identity_conflicts = _identity_conflicts(
        canonical,
        affectedness,
        asset,
        evidence,
        runtime,
    )
    if identity_conflicts:
        details = "; ".join(item["message"] for item in identity_conflicts)
        raise DecisionFeatureEnvelopeError(
            "Decision-feature identity binding failed: " + details
        )

    generated = _parse_time(
        generated_at
        or affectedness.get("generated_at")
        or canonical.get("generated_at")
    )

    canonical_target = _mapping(canonical.get("target"), "canonical.target")
    affected_target = _mapping(affectedness.get("target"), "affectedness.target")
    affected_component = _mapping(
        affected_target.get("component"),
        "affectedness.target.component",
    )
    target = {
        "cve_id": _text(affected_target.get("cve_id"), ""),
        "asset_id": _text(affected_target.get("asset_id"), ""),
        "component": {
            "component_id": _text(affected_component.get("component_id"), ""),
            "package_name": _text(affected_component.get("package_name"), ""),
            "ecosystem": _text(affected_component.get("ecosystem"), ""),
            "version": _text(affected_component.get("version"), ""),
            "purl": affected_component.get("purl"),
        },
    }

    vulnerability = _mapping(canonical.get("vulnerability"), "vulnerability")
    severity = _mapping(vulnerability.get("severity"), "vulnerability.severity")
    selected = _mapping(severity.get("selected") or {}, "severity.selected")
    base_score = _number(selected.get("base_score"))
    cvss_status = "PRESENT" if base_score is not None else "MISSING"
    technical_reason_codes = [
        "TECHNICAL_SEVERITY_PRESENT"
        if cvss_status == "PRESENT"
        else "TECHNICAL_SEVERITY_MISSING"
    ]
    technical_feature = {
        "status": cvss_status,
        "base_score": base_score,
        "base_severity": _normalize_cvss_severity(
            selected.get("base_severity"),
            base_score,
        ),
        "vector": selected.get("vector"),
        "version": selected.get("version"),
        "source_name": selected.get("source_name"),
        "source_record_id": selected.get("source_record_id"),
        "exploitability_score": _number(selected.get("exploitability_score")),
        "impact_score": _number(selected.get("impact_score")),
        "weaknesses": _strings(_list(vulnerability.get("weaknesses"))),
        "reason_codes": technical_reason_codes,
    }

    exploitation = _mapping(canonical.get("exploitation"), "exploitation")
    kev = _mapping(exploitation.get("kev") or {}, "exploitation.kev")
    epss = _mapping(exploitation.get("epss") or {}, "exploitation.epss")
    ssvc_feature = _ssvc_source_feature(canonical)
    kev_listed = kev.get("listed") if isinstance(kev.get("listed"), bool) else None
    kev_status = _text(kev.get("status"), "UNKNOWN").upper()
    if kev_status not in {"LISTED", "NOT_LISTED", "UNKNOWN"}:
        kev_status = "UNKNOWN"
    epss_probability = _number(epss.get("probability"))
    epss_percentile = _number(epss.get("percentile"))
    epss_status = _text(epss.get("status"), "MISSING").upper()
    if epss_status not in {"PRESENT", "MISSING", "INVALID"}:
        epss_status = "INVALID"
    source_exploitation = _text(
        ssvc_feature.get("exploitation"),
        "",
    ).casefold()
    if source_exploitation == "active":
        known_exploitation = "CONFIRMED_ACTIVE"
    elif kev_listed is True:
        known_exploitation = "KNOWN_CATALOGED"
    elif kev_status == "NOT_LISTED" and ssvc_feature["status"] == "MISSING":
        known_exploitation = "NOT_OBSERVED"
    else:
        known_exploitation = "UNKNOWN"
    exploitation_reasons = [
        {
            "CONFIRMED_ACTIVE": "KNOWN_EXPLOITATION_PRESENT",
            "KNOWN_CATALOGED": "KNOWN_EXPLOITATION_PRESENT",
            "NOT_OBSERVED": "KNOWN_EXPLOITATION_NOT_OBSERVED",
            "UNKNOWN": "KNOWN_EXPLOITATION_UNKNOWN",
        }[known_exploitation],
        "EPSS_PRESENT" if epss_status == "PRESENT" else "EPSS_MISSING",
        (
            "SSVC_SOURCE_ASSERTION_PRESENT"
            if ssvc_feature["status"] == "PRESENT"
            else "SSVC_SOURCE_ASSERTION_MISSING"
        ),
    ]
    exploitation_feature = {
        "known_exploitation_status": known_exploitation,
        "kev": {
            "status": kev_status,
            "listed": kev_listed,
            "date_added": kev.get("date_added"),
            "due_date": kev.get("due_date"),
            "known_ransomware_campaign_use": kev.get(
                "known_ransomware_campaign_use"
            ),
            "required_action_present": bool(
                _text(kev.get("required_action"), "")
            ),
        },
        "epss": {
            "status": epss_status,
            "probability": epss_probability,
            "percentile": epss_percentile,
            "score_date": epss.get("score_date"),
        },
        "ssvc_source_assertion": ssvc_feature,
        "reason_codes": exploitation_reasons,
    }

    adjudication = _mapping(
        affectedness.get("adjudication"),
        "affectedness.adjudication",
    )
    affected_status = _text(adjudication.get("status"), "UNKNOWN").upper()
    affected_reason = {
        "AFFECTED": "AFFECTEDNESS_AFFECTED",
        "PROBABLY_AFFECTED": "AFFECTEDNESS_PROBABLY_AFFECTED",
        "NOT_AFFECTED": "AFFECTEDNESS_NOT_AFFECTED",
        "UNKNOWN": "AFFECTEDNESS_UNKNOWN",
        "CONFLICTED": "AFFECTEDNESS_CONFLICTED",
    }.get(affected_status, "AFFECTEDNESS_UNKNOWN")
    if affected_status not in {
        "AFFECTED",
        "PROBABLY_AFFECTED",
        "NOT_AFFECTED",
        "UNKNOWN",
        "CONFLICTED",
    }:
        affected_status = "UNKNOWN"
    affected_reasons = [affected_reason]
    closure_prohibited = _boolean(adjudication.get("closure_prohibited"), True)
    if closure_prohibited:
        affected_reasons.append("AFFECTEDNESS_CLOSURE_PROHIBITED")
    affectedness_feature = {
        "status": affected_status,
        "technical_status": _text(adjudication.get("technical_status"), "unknown"),
        "confidence": _number(adjudication.get("confidence")),
        "determination_basis": _text(adjudication.get("determination_basis"), "unknown"),
        "human_review_required": _boolean(
            adjudication.get("human_review_required"),
            True,
        ),
        "closure_prohibited": closure_prohibited,
        "supporting_evidence_count": len(
            _list(adjudication.get("supporting_evidence_ids"))
        ),
        "uncertainty_factors": _strings(
            _list(adjudication.get("uncertainty_factors"))
        ),
        "reason_codes": affected_reasons,
    }

    criticality = _mapping(asset.get("criticality"), "asset.criticality")
    mission = _mapping(asset.get("mission"), "asset.mission")
    environment = _mapping(asset.get("environment"), "asset.environment")
    data_profile = _mapping(asset.get("data_profile"), "asset.data_profile")
    provenance = _mapping(asset.get("provenance"), "asset.provenance")
    criticality_level = _text(criticality.get("level"), "unknown").casefold()
    if criticality_level not in {"low", "medium", "high", "very_high"}:
        criticality_level = "unknown"
    approval_status = _text(criticality.get("approval_status"), "unknown")
    synthetic_demo = _text(provenance.get("origin_type"), "").casefold() in {
        "synthetic",
        "synthetic_demo",
        "controlled_demo",
        "controlled_fixture",
    }
    asset_reasons = [
        (
            "ASSET_CRITICALITY_APPROVED"
            if approval_status.casefold() == "approved"
            else "ASSET_CRITICALITY_UNAPPROVED"
        ),
        (
            "MISSION_ESSENTIAL_ASSET"
            if mission.get("mission_essential") is True
            else "NON_MISSION_ESSENTIAL_ASSET"
        ),
    ]
    asset_feature = {
        "level": criticality_level,
        "approval_status": approval_status,
        "mission_essential": _boolean(mission.get("mission_essential")),
        "mission_tier": _text(mission.get("mission_tier")),
        "lifecycle_stage": _text(environment.get("lifecycle_stage")),
        "operational_status": _text(environment.get("operational_status")),
        "highest_data_sensitivity": _text(
            data_profile.get("highest_sensitivity")
        ),
        "contains_personal_data": _boolean(
            data_profile.get("contains_personal_data")
        ),
        "contains_health_data": _boolean(
            data_profile.get("contains_health_data")
        ),
        "synthetic_or_demo_context": synthetic_demo,
        "reason_codes": asset_reasons,
    }

    sector = _mapping(asset.get("sector_context"), "asset.sector_context")
    impact = _mapping(asset.get("impact_assessment"), "asset.impact_assessment")
    resilience = _mapping(asset.get("resilience"), "asset.resilience")
    severity_order = {
        str(key).upper(): int(value)
        for key, value in _mapping(
            policy.get("severity_order"),
            "severity_order",
        ).items()
    }
    impact_dimensions: dict[str, str] = {}
    for name, raw in impact.items():
        if name in {"assessed_by", "assessment_date", "method"}:
            continue
        if isinstance(raw, Mapping):
            impact_dimensions[str(name)] = _normalize_impact_severity(
                raw.get("severity")
            )
    maximum_value = max(
        impact_dimensions.values(),
        key=lambda item: severity_order.get(item, 1),
        default="UNKNOWN",
    )
    maximum_dimensions = sorted(
        name
        for name, value in impact_dimensions.items()
        if value == maximum_value
    )
    mission_feature = {
        "primary_sector": _text(sector.get("primary_sector")),
        "subsector": _text(sector.get("subsector")),
        "jurisdictions": _strings(_list(sector.get("jurisdiction"))),
        "sector_label_is_decision_input": False,
        "maximum_severity": maximum_value,
        "maximum_severity_dimensions": maximum_dimensions,
        "dimensions": dict(sorted(impact_dimensions.items())),
        "manual_alternative_available": _boolean(
            mission.get("manual_alternative_available")
        ),
        "rto_hours": _number(resilience.get("recovery_time_objective_hours")),
        "maximum_tolerable_downtime_hours": _number(
            resilience.get("maximum_tolerable_downtime_hours")
        ),
        "reason_codes": ["SECTOR_CONTEXT_NON_SCORING"],
    }

    exposure = _mapping(asset.get("exposure"), "asset.exposure")
    security_posture = _mapping(
        asset.get("security_posture"),
        "asset.security_posture",
    )
    runtime_reachability = _mapping(
        runtime.get("reachability"),
        "runtime.reachability",
    )
    runtime_presence = _mapping(runtime.get("presence"), "runtime.presence")
    runtime_configuration = _mapping(
        runtime.get("configuration"),
        "runtime.configuration",
    )
    reachability_status = _text(
        runtime_reachability.get("status"),
        "UNKNOWN",
    ).upper()
    if reachability_status not in {"REACHABLE", "NOT_REACHABLE", "UNKNOWN"}:
        reachability_status = "UNKNOWN"
    configuration_status = _text(
        runtime_configuration.get("status"),
        "UNKNOWN",
    ).upper()
    if configuration_status not in {"VULNERABLE", "MITIGATED", "UNKNOWN"}:
        configuration_status = "UNKNOWN"
    presence_status = _text(runtime_presence.get("status"), "UNKNOWN").upper()
    if presence_status not in {"PRESENT", "ABSENT", "UNKNOWN"}:
        presence_status = "UNKNOWN"
    exposure_reasons = [
        "INTERNET_EXPOSED"
        if exposure.get("internet_accessible") is True
        else "NOT_INTERNET_EXPOSED",
        {
            "REACHABLE": "RUNTIME_REACHABILITY_CONFIRMED",
            "NOT_REACHABLE": "RUNTIME_REACHABILITY_NOT_CONFIRMED",
            "UNKNOWN": "RUNTIME_REACHABILITY_UNKNOWN",
        }[reachability_status],
        {
            "VULNERABLE": "RUNTIME_CONFIGURATION_VULNERABLE",
            "MITIGATED": "RUNTIME_CONFIGURATION_MITIGATED",
            "UNKNOWN": "RUNTIME_CONFIGURATION_UNKNOWN",
        }[configuration_status],
    ]
    exposure_feature = {
        "internet_accessible": _boolean(exposure.get("internet_accessible")),
        "externally_accessible": _boolean(exposure.get("externally_accessible")),
        "network_zone": _text(exposure.get("network_zone")),
        "authentication_required": _boolean(
            exposure.get("authentication_required")
        ),
        "privileged_interface_exposed": _boolean(
            exposure.get("privileged_interface_exposed")
        ),
        "exposure_confidence": _number(exposure.get("exposure_confidence")),
        "component_presence": presence_status,
        "runtime_reachability": reachability_status,
        "runtime_reachability_confidence": _number(
            runtime_reachability.get("confidence")
        ),
        "runtime_configuration": configuration_status,
        "compensating_control_count": len(
            _list(security_posture.get("compensating_controls"))
        ),
        "reason_codes": exposure_reasons,
    }

    trust = _mapping(affectedness.get("trust"), "affectedness.trust")
    combined_trust = _mapping(trust.get("combined"), "trust.combined")
    canonical_trust = _mapping(
        trust.get("canonical_intelligence"),
        "trust.canonical_intelligence",
    )
    component_trust = _mapping(
        trust.get("component_evidence"),
        "trust.component_evidence",
    )
    combined_action = _text(combined_trust.get("action"), "REJECT").upper()
    if combined_action not in {
        "ACCEPT",
        "ACCEPT_WITH_WARNINGS",
        "QUARANTINE",
        "REJECT",
    }:
        combined_action = "REJECT"
    trust_reason = {
        "ACCEPT": "EVIDENCE_TRUST_ACCEPTED",
        "ACCEPT_WITH_WARNINGS": "EVIDENCE_TRUST_ACCEPTED_WITH_WARNINGS",
        "QUARANTINE": "EVIDENCE_TRUST_QUARANTINED",
        "REJECT": "EVIDENCE_TRUST_REJECTED",
    }[combined_action]
    component_action = _text(component_trust.get("action"), "REJECT").upper()
    canonical_action = _text(canonical_trust.get("action"), "REJECT").upper()
    for value_name, value in (
        ("component_action", component_action),
        ("canonical_action", canonical_action),
    ):
        if value not in {"ACCEPT", "ACCEPT_WITH_WARNINGS", "QUARANTINE", "REJECT"}:
            raise DecisionFeatureEnvelopeError(
                f"Invalid {value_name}: {value}"
            )
    trust_feature = {
        "combined_action": combined_action,
        "combined_score": _number(combined_trust.get("aggregate_score")),
        "canonical_action": canonical_action,
        "canonical_score": _number(canonical_trust.get("aggregate_score")),
        "component_action": component_action,
        "component_score": _number(component_trust.get("aggregate_score")),
        "component_trust_level": _text(
            component_trust.get("trust_level"),
            "unknown",
        ).casefold(),
        "warning_count": len(_list(component_trust.get("warnings")))
        + len(_list(canonical_trust.get("warnings"))),
        "failed_quality_gate_count": len(
            _list(canonical_trust.get("failed_quality_gates"))
        ),
        "reason_codes": [trust_reason],
    }
    if trust_feature["component_trust_level"] not in {
        "high",
        "medium",
        "low",
        "rejected",
        "unknown",
    }:
        trust_feature["component_trust_level"] = "unknown"

    freshness = _mapping(canonical.get("freshness"), "canonical.freshness")
    freshness_checks = _list(freshness.get("checks"))
    required_checks = [
        item
        for item in freshness_checks
        if isinstance(item, Mapping) and item.get("required") is True
    ]
    required_current = [
        item
        for item in required_checks
        if _text(item.get("status"), "UNKNOWN").upper() == "CURRENT"
    ]
    blocking_freshness = _list(freshness.get("blocking_findings"))
    required_ages = [
        _number(item.get("age_days"))
        for item in required_checks
        if _number(item.get("age_days")) is not None
    ]
    all_required_current = (
        len(required_checks) > 0
        and len(required_checks) == len(required_current)
        and not blocking_freshness
    )
    freshness_feature = {
        "reference_time": _text(freshness.get("reference_time"), generated),
        "required_check_count": len(required_checks),
        "required_current_count": len(required_current),
        "blocking_finding_count": len(blocking_freshness),
        "oldest_required_age_days": max(required_ages) if required_ages else None,
        "all_required_current": all_required_current,
        "source_statuses": _source_statuses(freshness_checks),
        "reason_codes": [
            "REQUIRED_FRESHNESS_CURRENT"
            if all_required_current
            else "BLOCKING_FRESHNESS_FINDING"
        ],
    }

    upstream_release = _mapping(
        affectedness.get("release_decision"),
        "affectedness.release_decision",
    )
    upstream_stage_gate = _text(
        upstream_release.get("stage_gate"),
        "FAIL",
    ).upper()
    upstream_policy_eligibility = _text(
        upstream_release.get("policy_eligibility"),
        "BLOCKED",
    ).upper()
    affected_conflicts = _list(affectedness.get("conflicts"))
    canonical_controls = _mapping(
        canonical.get("correlation_controls"),
        "canonical.correlation_controls",
    )
    canonical_conflicts = _list(canonical_controls.get("conflicts"))
    assertion_differences = _list(
        canonical_controls.get("assertion_differences")
    )
    normalized_conflicts: list[dict[str, Any]] = []
    for source, items in (
        ("affectedness", affected_conflicts),
        ("canonical_intelligence", canonical_conflicts),
    ):
        for raw in items:
            if not isinstance(raw, Mapping):
                continue
            normalized_conflicts.append(
                {
                    "code": _text(raw.get("code"), "UNSPECIFIED_CONFLICT").upper(),
                    "blocking": _boolean(raw.get("blocking")),
                    "source": source,
                    "message": _text(raw.get("message"), "Conflict reported by upstream stage."),
                }
            )
    blocking_conflict_count = sum(
        1 for item in normalized_conflicts if item["blocking"]
    )

    human_review_triggers: list[str] = []
    if affectedness_feature["human_review_required"]:
        human_review_triggers.append("UPSTREAM_HUMAN_REVIEW_REQUIRED")
    if reachability_status == "UNKNOWN":
        human_review_triggers.append("RUNTIME_REACHABILITY_UNKNOWN")
    if configuration_status == "UNKNOWN":
        human_review_triggers.append("RUNTIME_CONFIGURATION_UNKNOWN")
    if asset_feature["mission_essential"]:
        human_review_triggers.append("MISSION_ESSENTIAL_ASSET")
    if asset_feature["lifecycle_stage"].casefold() == "production":
        human_review_triggers.append("PRODUCTION_ASSET")
    if synthetic_demo:
        human_review_triggers.append("NON_OPERATIONAL_CONTEXT")
    if combined_action != "ACCEPT":
        human_review_triggers.append("TRUST_NOT_UNCONDITIONALLY_ACCEPTED")
    if assertion_differences:
        human_review_triggers.append("SOURCE_ASSERTION_DIFFERENCE")

    unknown_feature_count = sum(
        [
            technical_feature["status"] != "PRESENT",
            known_exploitation == "UNKNOWN",
            epss_status != "PRESENT",
            reachability_status == "UNKNOWN",
            configuration_status == "UNKNOWN",
            criticality_level == "unknown",
            maximum_value == "UNKNOWN",
        ]
    )
    uncertainty_rank = 0
    if human_review_triggers or assertion_differences or synthetic_demo:
        uncertainty_rank = max(uncertainty_rank, 1)
    if (
        affected_status in {"PROBABLY_AFFECTED", "UNKNOWN"}
        or approval_status.casefold() != "approved"
        or known_exploitation == "UNKNOWN"
        or unknown_feature_count >= 3
    ):
        uncertainty_rank = max(uncertainty_rank, 2)
    if (
        affected_status == "CONFLICTED"
        or blocking_conflict_count
        or combined_action in {"QUARANTINE", "REJECT"}
        or upstream_stage_gate != "PASS"
        or blocking_freshness
    ):
        uncertainty_rank = 3
    uncertainty_level = ["LOW", "MEDIUM", "HIGH", "CRITICAL"][
        uncertainty_rank
    ]
    uncertainty_reason = {
        "LOW": "UNCERTAINTY_LOW",
        "MEDIUM": "UNCERTAINTY_MEDIUM",
        "HIGH": "UNCERTAINTY_HIGH",
        "CRITICAL": "UNCERTAINTY_CRITICAL",
    }[uncertainty_level]
    uncertainty_reasons = [uncertainty_reason]
    uncertainty_reasons.append(
        "NO_BLOCKING_CONFLICTS"
        if blocking_conflict_count == 0
        else "BLOCKING_CONFLICT_PRESENT"
    )
    if assertion_differences:
        uncertainty_reasons.append("SOURCE_ASSERTION_DIFFERENCE_PRESERVED")
    uncertainty_factors = list(affectedness_feature["uncertainty_factors"])
    if reachability_status == "UNKNOWN":
        uncertainty_factors.append("Runtime reachability is unknown.")
    if configuration_status == "UNKNOWN":
        uncertainty_factors.append("Runtime configuration and mitigation status are unknown.")
    if synthetic_demo:
        uncertainty_factors.append(
            "Asset and component context are controlled demonstration fixtures, not observed production records."
        )
    if assertion_differences:
        uncertainty_factors.append(
            "Official sources differ in field coverage; differences remain preserved with provenance."
        )
    uncertainty_feature = {
        "level": uncertainty_level,
        "unknown_feature_count": unknown_feature_count,
        "blocking_conflict_count": blocking_conflict_count,
        "nonblocking_difference_count": len(assertion_differences),
        "uncertainty_factors": _strings(uncertainty_factors),
        "conflicts": normalized_conflicts,
        "human_review_triggers": _strings(human_review_triggers),
        "reason_codes": uncertainty_reasons,
    }

    ownership = _mapping(asset.get("ownership"), "asset.ownership")

    def owner_reference(key: str) -> str:
        owner = _mapping(ownership.get(key), f"asset.ownership.{key}")
        return _text(owner.get("contact_reference"), "UNASSIGNED")

    human_review_required = bool(human_review_triggers)
    governance_feature = {
        "human_review_required": human_review_required,
        "closure_prohibited": closure_prohibited,
        "upstream_stage_gate": (
            upstream_stage_gate if upstream_stage_gate in {"PASS", "FAIL"} else "FAIL"
        ),
        "upstream_policy_eligibility": (
            upstream_policy_eligibility
            if upstream_policy_eligibility in {"ELIGIBLE", "REVIEW_REQUIRED", "BLOCKED"}
            else "BLOCKED"
        ),
        "production_readiness": "BLOCKED",
        "accountable_owner_reference": owner_reference(
            "accountable_system_owner"
        ),
        "cyber_risk_owner_reference": owner_reference("cyber_risk_owner"),
        "technical_owner_reference": owner_reference("technical_owner"),
        "sector_sme_reference": owner_reference("sector_sme"),
        "decision_output_prohibited": True,
        "reason_codes": [
            "HUMAN_REVIEW_REQUIRED"
            if human_review_required
            else "HUMAN_REVIEW_NOT_REQUIRED",
            "PRODUCTION_BLOCK_PRESERVED",
        ],
    }

    features = {
        "technical_severity": technical_feature,
        "exploitation": exploitation_feature,
        "affectedness": affectedness_feature,
        "asset_criticality": asset_feature,
        "mission_and_sector_impact": mission_feature,
        "exposure_and_reachability": exposure_feature,
        "evidence_trust": trust_feature,
        "freshness": freshness_feature,
        "uncertainty_and_conflicts": uncertainty_feature,
        "governance": governance_feature,
    }

    provenance_entries: list[dict[str, Any]] = []

    def add_provenance(
        feature_path: str,
        input_name: str,
        source_field_paths: Iterable[str],
        extraction_method: str,
    ) -> None:
        reference = input_references[input_name]
        provenance_entries.append(
            {
                "feature_path": feature_path,
                "source_record_id": reference.record_id,
                "source_relative_path": reference.relative_path,
                "source_sha256": reference.sha256,
                "source_field_paths": _strings(source_field_paths),
                "extraction_method": extraction_method,
            }
        )

    for name, source_path in (
        ("status", "/vulnerability/severity/selected"),
        ("base_score", "/vulnerability/severity/selected/base_score"),
        ("base_severity", "/vulnerability/severity/selected/base_severity"),
        ("vector", "/vulnerability/severity/selected/vector"),
        ("weaknesses", "/vulnerability/weaknesses"),
    ):
        add_provenance(
            f"/features/technical_severity/{name}",
            "canonical_intelligence",
            [source_path],
            "deterministic_mapping",
        )
    for name, source_path in (
        ("known_exploitation_status", "/exploitation"),
        ("kev", "/exploitation/kev"),
        ("epss", "/exploitation/epss"),
        ("ssvc_source_assertion", "/exploitation/ssvc_assertions"),
    ):
        add_provenance(
            f"/features/exploitation/{name}",
            "canonical_intelligence",
            [source_path],
            "deterministic_mapping",
        )
    for name, source_path in (
        ("status", "/adjudication/status"),
        ("confidence", "/adjudication/confidence"),
        ("human_review_required", "/adjudication/human_review_required"),
        ("closure_prohibited", "/adjudication/closure_prohibited"),
        ("uncertainty_factors", "/adjudication/uncertainty_factors"),
    ):
        add_provenance(
            f"/features/affectedness/{name}",
            "affectedness_adjudication",
            [source_path],
            "deterministic_copy",
        )
    for name, source_paths in (
        ("level", ["/criticality/level"]),
        ("approval_status", ["/criticality/approval_status"]),
        ("mission_essential", ["/mission/mission_essential"]),
        ("mission_tier", ["/mission/mission_tier"]),
        ("lifecycle_stage", ["/environment/lifecycle_stage"]),
        ("highest_data_sensitivity", ["/data_profile/highest_sensitivity"]),
        ("synthetic_or_demo_context", ["/provenance/origin_type"]),
    ):
        add_provenance(
            f"/features/asset_criticality/{name}",
            "asset_context",
            source_paths,
            "deterministic_mapping",
        )
    for name, source_paths in (
        ("primary_sector", ["/sector_context/primary_sector"]),
        ("maximum_severity", ["/impact_assessment"]),
        ("dimensions", ["/impact_assessment"]),
        ("manual_alternative_available", ["/mission/manual_alternative_available"]),
        ("rto_hours", ["/resilience/recovery_time_objective_hours"]),
    ):
        add_provenance(
            f"/features/mission_and_sector_impact/{name}",
            "asset_context",
            source_paths,
            "deterministic_aggregation",
        )
    for name, input_name, source_paths in (
        ("internet_accessible", "asset_context", ["/exposure/internet_accessible"]),
        ("network_zone", "asset_context", ["/exposure/network_zone"]),
        ("component_presence", "runtime_context", ["/presence/status"]),
        ("runtime_reachability", "runtime_context", ["/reachability/status"]),
        ("runtime_configuration", "runtime_context", ["/configuration/status"]),
        ("compensating_control_count", "asset_context", ["/security_posture/compensating_controls"]),
    ):
        add_provenance(
            f"/features/exposure_and_reachability/{name}",
            input_name,
            source_paths,
            "deterministic_mapping",
        )
    for name, source_path in (
        ("combined_action", "/trust/combined/action"),
        ("combined_score", "/trust/combined/aggregate_score"),
        ("component_action", "/trust/component_evidence/action"),
        ("warning_count", "/trust"),
    ):
        add_provenance(
            f"/features/evidence_trust/{name}",
            "affectedness_adjudication",
            [source_path],
            "deterministic_aggregation",
        )
    for name, source_path in (
        ("reference_time", "/freshness/reference_time"),
        ("all_required_current", "/freshness/checks"),
        ("source_statuses", "/freshness/checks"),
    ):
        add_provenance(
            f"/features/freshness/{name}",
            "canonical_intelligence",
            [source_path],
            "deterministic_aggregation",
        )
    add_provenance(
        "/features/uncertainty_and_conflicts/level",
        "affectedness_adjudication",
        ["/adjudication", "/conflicts", "/trust", "/runtime_context"],
        "policy_derived",
    )
    add_provenance(
        "/features/governance/human_review_required",
        "affectedness_adjudication",
        ["/adjudication/human_review_required", "/release_decision"],
        "policy_derived",
    )
    add_provenance(
        "/features/governance/accountable_owner_reference",
        "asset_context",
        ["/ownership/accountable_system_owner/contact_reference"],
        "deterministic_copy",
    )

    input_hashes = {
        name: reference.sha256
        for name, reference in sorted(input_references.items())
    }
    envelope_id = stable_identifier(
        "AEG-DFE",
        {
            "inputs": input_hashes,
            "policy_sha256": policy_sha256,
            "reason_registry_sha256": registry_sha256,
            "target": target,
        },
    )

    contract = {
        "contract_id": _text(policy_meta.get("contract_id"), ""),
        "contract_version": _text(policy_meta.get("contract_version"), ""),
        "builder_version": _text(policy_meta.get("builder_version"), ""),
        "policy_id": _text(policy_meta.get("policy_id"), ""),
        "policy_version": _text(policy_meta.get("version"), ""),
        "policy_sha256": policy_sha256,
        "reason_registry_id": _text(registry_meta.get("registry_id"), ""),
        "reason_registry_version": _text(registry_meta.get("version"), ""),
        "reason_registry_sha256": registry_sha256,
    }

    prohibited = set(_strings(_list(policy.get("prohibited_output_fields"))))
    prohibited_findings = _contains_prohibited_key(features, prohibited)

    preliminary = {
        "schema_version": "1.0.0",
        "envelope_id": envelope_id,
        "generated_at": generated,
        "contract": contract,
        "inputs": {
            name: reference.to_dict()
            for name, reference in sorted(input_references.items())
        },
        "target": target,
        "features": features,
        "provenance": provenance_entries,
    }
    reasons_valid, unknown_codes = _registered_reason_codes(
        preliminary,
        known_reason_codes,
    )

    trust_accepted = combined_action in {"ACCEPT", "ACCEPT_WITH_WARNINGS"}
    affectedness_resolved = affected_status in {
        "AFFECTED",
        "PROBABLY_AFFECTED",
        "NOT_AFFECTED",
    }
    provenance_complete = len(provenance_entries) >= int(
        _mapping(
            policy.get("feature_requirements"),
            "feature_requirements",
        ).get("minimum_provenance_entries", 24)
    )
    gates = [
        _quality_gate(
            "M12D-INPUT-REFERENCES",
            "required_input_reference_count",
            len(input_references),
            5,
            len(input_references) == 5,
            ["INPUT_IDENTITIES_BOUND"],
        ),
        _quality_gate(
            "M12D-IDENTITY-BINDING",
            "identity_conflict_count",
            0,
            0,
            True,
            ["INPUT_IDENTITIES_BOUND"],
        ),
        _quality_gate(
            "M12D-UPSTREAM-STAGE",
            "affectedness_stage_gate",
            upstream_stage_gate,
            "PASS",
            upstream_stage_gate == "PASS",
            [
                "UPSTREAM_STAGE_GATE_PASSED"
                if upstream_stage_gate == "PASS"
                else "UPSTREAM_STAGE_GATE_FAILED"
            ],
        ),
        _quality_gate(
            "M12D-FEATURE-GROUPS",
            "feature_group_count",
            len(features),
            10,
            len(features) == 10,
            ["FEATURES_EXTRACTED"],
        ),
        _quality_gate(
            "M12D-PROVENANCE",
            "feature_provenance_entry_count",
            len(provenance_entries),
            ">=24",
            provenance_complete,
            [
                "FIELD_PROVENANCE_COMPLETE"
                if provenance_complete
                else "FIELD_PROVENANCE_INCOMPLETE"
            ],
        ),
        _quality_gate(
            "M12D-REASON-REGISTRY",
            "unregistered_reason_codes",
            unknown_codes,
            [],
            reasons_valid,
            [
                "FEATURES_EXTRACTED"
                if reasons_valid
                else "FIELD_PROVENANCE_INCOMPLETE"
            ],
        ),
        _quality_gate(
            "M12D-DECISION-NEUTRALITY",
            "prohibited_decision_output_paths",
            prohibited_findings,
            [],
            not prohibited_findings,
            [
                "DECISION_OUTPUTS_ABSENT"
                if not prohibited_findings
                else "PROHIBITED_DECISION_OUTPUT_PRESENT"
            ],
        ),
        _quality_gate(
            "M12D-TRUST",
            "combined_evidence_trust_action",
            combined_action,
            ["ACCEPT", "ACCEPT_WITH_WARNINGS"],
            trust_accepted,
            [trust_reason],
        ),
        _quality_gate(
            "M12D-FRESHNESS",
            "blocking_freshness_finding_count",
            len(blocking_freshness),
            0,
            not blocking_freshness,
            freshness_feature["reason_codes"],
        ),
        _quality_gate(
            "M12D-AFFECTEDNESS",
            "affectedness_resolved_for_policy_features",
            affected_status,
            ["AFFECTED", "PROBABLY_AFFECTED", "NOT_AFFECTED"],
            affectedness_resolved,
            affectedness_feature["reason_codes"],
        ),
        _quality_gate(
            "M12D-HUMAN-REVIEW",
            "upstream_human_review_preserved",
            governance_feature["human_review_required"],
            affectedness_feature["human_review_required"],
            (
                governance_feature["human_review_required"]
                or not affectedness_feature["human_review_required"]
            ),
            governance_feature["reason_codes"],
        ),
        _quality_gate(
            "M12D-PRODUCTION-BLOCK",
            "production_readiness",
            "BLOCKED",
            "BLOCKED",
            True,
            ["PRODUCTION_BLOCK_PRESERVED"],
        ),
    ]

    stage_gate_pass = all(item["pass"] for item in gates)
    hard_block = (
        not stage_gate_pass
        or affected_status in {"UNKNOWN", "CONFLICTED"}
        or blocking_conflict_count > 0
        or combined_action in {"QUARANTINE", "REJECT"}
        or bool(blocking_freshness)
        or bool(prohibited_findings)
        or not reasons_valid
    )
    if hard_block:
        next_stage = _text(
            release_policy.get("blocked_for_next_stage"),
            "BLOCKED_FOR_12E",
        )
        release_reason = "NEXT_STAGE_BLOCKED"
    elif human_review_required or uncertainty_level in {"HIGH", "CRITICAL"}:
        next_stage = _text(
            release_policy.get("review_required_for_next_stage"),
            "REVIEW_REQUIRED_FOR_12E",
        )
        release_reason = "NEXT_STAGE_REVIEW_REQUIRED"
    else:
        next_stage = _text(
            release_policy.get("eligible_for_next_stage"),
            "ELIGIBLE_FOR_12E",
        )
        release_reason = "NEXT_STAGE_ELIGIBLE"

    blocking_reasons = _strings(_list(release_policy.get("remaining_blockers")))
    if hard_block:
        blocking_reasons.insert(
            0,
            "One or more Milestone 12D fail-closed gates blocked progression to policy execution.",
        )
    elif human_review_required:
        blocking_reasons.append(
            "Accountable human review remains required while downstream policy evaluation proceeds in review-required mode."
        )

    report = {
        **preliminary,
        "quality_gates": gates,
        "release_decision": {
            "stage_gate": "PASS" if stage_gate_pass else "FAIL",
            "next_stage_eligibility": next_stage,
            "production_readiness": "BLOCKED",
            "blocking_reasons": blocking_reasons,
            "reason_codes": [release_reason, "PRODUCTION_BLOCK_PRESERVED"],
        },
        "audit": {
            "canonical_json_sha256": "0" * 64,
            "input_hashes": input_hashes,
            "deterministic_envelope_id": True,
            "prohibited_output_fields_absent": not prohibited_findings,
            "feature_group_count": len(features),
            "provenance_entry_count": len(provenance_entries),
        },
    }

    final_reasons_valid, final_unknown_codes = _registered_reason_codes(
        report,
        known_reason_codes,
    )
    if not final_reasons_valid:
        raise DecisionFeatureEnvelopeError(
            "Unregistered reason codes in decision feature envelope: "
            + ", ".join(final_unknown_codes)
        )
    if prohibited_findings:
        raise DecisionFeatureEnvelopeError(
            "Prohibited decision outputs were emitted: "
            + ", ".join(prohibited_findings)
        )

    pre_integrity = copy.deepcopy(report)
    pre_integrity["audit"]["canonical_json_sha256"] = "0" * 64
    report["audit"]["canonical_json_sha256"] = sha256_document(pre_integrity)
    return report

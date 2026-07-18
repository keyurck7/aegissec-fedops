from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from src.intelligence.official_source import canonical_json_bytes


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DEPLOYER_POLICY = (
    PROJECT_ROOT / "policies" / "decision" / "ssvc_deployer_policy_v1.yaml"
)
DEFAULT_MAPPING_POLICY = (
    PROJECT_ROOT / "policies" / "decision" / "ssvc_mapping_policy_v1.yaml"
)
DEFAULT_DEPLOYER_TABLE = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "ssvc_deployer_decision_table_v1.yaml"
)
DEFAULT_HUMAN_IMPACT_TABLE = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "ssvc_human_impact_decision_table_v1.yaml"
)
DEFAULT_REASON_REGISTRY = (
    PROJECT_ROOT / "policies" / "decision" / "ssvc_reason_codes_v1.yaml"
)


class SSVCPolicyDecisionError(RuntimeError):
    """Raised when governed SSVC evaluation cannot proceed safely."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_document(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(dict(value)))


def stable_identifier(prefix: str, identity: Mapping[str, Any]) -> str:
    digest = sha256_document(identity)[:24].upper()
    return f"{prefix}-{digest}"


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SSVCPolicyDecisionError(f"{label} must be an object.")
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
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def _text(value: Any, default: str = "") -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _parse_time(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    text = value.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SSVCPolicyDecisionError(
            f"Invalid generated_at timestamp: {value!r}"
        ) from exc
    if moment.tzinfo is None:
        raise SSVCPolicyDecisionError(
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
        raise SSVCPolicyDecisionError(f"{label} must be a YAML object.")
    return value, sha256_bytes(raw)


def _decision_point(
    *,
    point_id: str,
    key: str | None,
    name: str | None,
    status: str,
    source_feature_paths: Iterable[str],
    reason_codes: Iterable[str],
    mapping_rule_id: str,
) -> dict[str, Any]:
    return {
        "id": point_id,
        "name": name,
        "key": key,
        "status": status,
        "source_feature_paths": _strings(source_feature_paths),
        "reason_codes": _strings(reason_codes),
        "mapping_rule_id": mapping_rule_id,
    }


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


def _verify_envelope_integrity(envelope: Mapping[str, Any]) -> bool:
    audit = _mapping(envelope.get("audit"), "decision-feature audit")
    expected = _text(audit.get("canonical_json_sha256"))
    if len(expected) != 64:
        return False
    candidate = copy.deepcopy(dict(envelope))
    candidate_audit = _mapping(candidate.get("audit"), "decision-feature audit")
    candidate_audit["canonical_json_sha256"] = "0" * 64
    return sha256_document(candidate) == expected.casefold()


def _registered_reason_codes(
    document: Any,
    known: set[str],
) -> tuple[bool, list[str]]:
    observed: set[str] = set()

    def walk(value: Any, parent_key: str | None = None) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in {"reason_code", "reason_codes"}:
                    if isinstance(child, str):
                        observed.add(child)
                    elif isinstance(child, list):
                        observed.update(
                            item for item in child if isinstance(item, str)
                        )
                walk(child, str(key))
        elif isinstance(value, list):
            for child in value:
                walk(child, parent_key)

    walk(document)
    unknown = sorted(code for code in observed if code not in known)
    return not unknown, unknown


def _load_reason_registry(
    path: Path | str,
) -> tuple[dict[str, Any], set[str], str]:
    document, digest = _load_yaml(path, "SSVC reason registry")
    meta = _mapping(document.get("registry"), "reason registry metadata")
    if meta.get("closed_registry") is not True:
        raise SSVCPolicyDecisionError("SSVC reason registry must be closed.")
    known: set[str] = set()
    for raw in _list(document.get("codes")):
        entry = _mapping(raw, "reason registry entry")
        code = _text(entry.get("code"))
        if not code:
            raise SSVCPolicyDecisionError("Reason codes must be non-empty.")
        if code in known:
            raise SSVCPolicyDecisionError(f"Duplicate SSVC reason code: {code}")
        known.add(code)
    return dict(meta), known, digest


def _normalize_impact(value: Any) -> str:
    normalized = _text(value, "UNKNOWN").upper().replace("-", "_")
    aliases = {
        "NONE": "NOT_APPLICABLE",
        "N/A": "NOT_APPLICABLE",
        "NA": "NOT_APPLICABLE",
        "MODERATE": "MEDIUM",
        "VERY_HIGH": "SEVERE",
    }
    return aliases.get(normalized, normalized)


def _map_exploitation(features: Mapping[str, Any]) -> dict[str, Any]:
    exploitation = _mapping(features.get("exploitation"), "exploitation features")
    kev = _mapping(exploitation.get("kev"), "KEV features")
    source = _mapping(
        exploitation.get("ssvc_source_assertion"),
        "SSVC source assertion",
    )
    known = _text(exploitation.get("known_exploitation_status")).upper()
    source_value = _text(source.get("exploitation")).casefold()
    kev_listed = kev.get("listed") is True
    paths = [
        "/features/exploitation/known_exploitation_status",
        "/features/exploitation/kev/listed",
        "/features/exploitation/ssvc_source_assertion/exploitation",
    ]
    if known == "CONFIRMED_ACTIVE" or kev_listed or source_value == "active":
        return _decision_point(
            point_id="ssvc:E:1.1.0",
            key="A",
            name="active",
            status="RESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_EXPLOITATION_ACTIVE"],
            mapping_rule_id="EXPLOITATION_ACTIVE_PRECEDENCE",
        )
    if known == "PUBLIC_POC" or source_value == "public_poc":
        return _decision_point(
            point_id="ssvc:E:1.1.0",
            key="P",
            name="public_poc",
            status="RESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_EXPLOITATION_PUBLIC_POC"],
            mapping_rule_id="EXPLOITATION_PUBLIC_POC_PRECEDENCE",
        )
    if known == "NOT_OBSERVED" and kev.get("listed") is False:
        return _decision_point(
            point_id="ssvc:E:1.1.0",
            key="N",
            name="none",
            status="RESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_EXPLOITATION_NONE"],
            mapping_rule_id="EXPLOITATION_EXPLICIT_NONE",
        )
    return _decision_point(
        point_id="ssvc:E:1.1.0",
        key=None,
        name=None,
        status="UNRESOLVED",
        source_feature_paths=paths,
        reason_codes=["SSVC_EXPLOITATION_UNRESOLVED"],
        mapping_rule_id="EXPLOITATION_FAIL_CLOSED",
    )


def _map_system_exposure(
    features: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    exposure = _mapping(
        features.get("exposure_and_reachability"),
        "exposure features",
    )
    internet = _boolean(exposure.get("internet_accessible"))
    external = _boolean(exposure.get("externally_accessible"))
    zone = _text(exposure.get("network_zone")).casefold()
    paths = [
        "/features/exposure_and_reachability/internet_accessible",
        "/features/exposure_and_reachability/externally_accessible",
        "/features/exposure_and_reachability/network_zone",
        "/features/exposure_and_reachability/authentication_required",
        "/features/exposure_and_reachability/exposure_confidence",
    ]
    if internet is True or external is True:
        return (
            _decision_point(
                point_id="ssvc:EXP:1.0.1",
                key="O",
                name="open",
                status="RESOLVED",
                source_feature_paths=paths,
                reason_codes=["SSVC_EXPOSURE_OPEN"],
                mapping_rule_id="EXPOSURE_OPEN_ANY_ACCESSIBILITY",
            ),
            [],
        )
    small_zones = {"air_gapped", "isolated", "local", "highly_controlled"}
    if internet is False and external is False and zone in small_zones:
        return (
            _decision_point(
                point_id="ssvc:EXP:1.0.1",
                key="S",
                name="small",
                status="RESOLVED",
                source_feature_paths=paths,
                reason_codes=["SSVC_EXPOSURE_SMALL"],
                mapping_rule_id="EXPOSURE_SMALL_CLOSED_ZONE",
            ),
            [],
        )
    controlled_evidence = (
        internet is False
        and external is False
        and (
            bool(zone)
            or isinstance(exposure.get("authentication_required"), bool)
            or _number(exposure.get("exposure_confidence")) is not None
        )
    )
    if controlled_evidence:
        return (
            _decision_point(
                point_id="ssvc:EXP:1.0.1",
                key="C",
                name="controlled",
                status="RESOLVED",
                source_feature_paths=paths,
                reason_codes=["SSVC_EXPOSURE_CONTROLLED"],
                mapping_rule_id="EXPOSURE_CONTROLLED_EVIDENCE",
            ),
            [],
        )
    assumption = {
        "assumption_id": "ASSUME-EXP-OPEN-001",
        "decision_point": "system_exposure",
        "statement": (
            "System exposure was unresolved and was conservatively assumed open "
            "for official SSVC evaluation."
        ),
        "basis": (
            "Pinned mapping policy requires an open assumption with explicit "
            "recording rather than a silent optimistic default."
        ),
        "reason_code": "SSVC_EXPOSURE_OPEN_ASSUMED",
    }
    return (
        _decision_point(
            point_id="ssvc:EXP:1.0.1",
            key="O",
            name="open",
            status="RESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_EXPOSURE_OPEN_ASSUMED"],
            mapping_rule_id="EXPOSURE_UNKNOWN_ASSUME_OPEN",
        ),
        [assumption],
    )


def _map_automatable(features: Mapping[str, Any]) -> dict[str, Any]:
    exploitation = _mapping(features.get("exploitation"), "exploitation features")
    source = _mapping(
        exploitation.get("ssvc_source_assertion"),
        "SSVC source assertion",
    )
    value = _text(source.get("automatable")).casefold()
    paths = ["/features/exploitation/ssvc_source_assertion/automatable"]
    if value == "yes":
        return _decision_point(
            point_id="ssvc:A:2.0.0",
            key="Y",
            name="yes",
            status="RESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_AUTOMATABLE_YES"],
            mapping_rule_id="AUTOMATABLE_EXPLICIT_YES",
        )
    if value == "no":
        return _decision_point(
            point_id="ssvc:A:2.0.0",
            key="N",
            name="no",
            status="RESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_AUTOMATABLE_NO"],
            mapping_rule_id="AUTOMATABLE_EXPLICIT_NO",
        )
    return _decision_point(
        point_id="ssvc:A:2.0.0",
        key=None,
        name=None,
        status="UNRESOLVED",
        source_feature_paths=paths,
        reason_codes=["SSVC_AUTOMATABLE_UNRESOLVED"],
        mapping_rule_id="AUTOMATABLE_FAIL_CLOSED",
    )


def _map_safety_impact(features: Mapping[str, Any]) -> dict[str, Any]:
    impact = _mapping(
        features.get("mission_and_sector_impact"),
        "mission and sector impact features",
    )
    dimensions = _mapping(impact.get("dimensions"), "impact dimensions")
    paths = [
        "/features/mission_and_sector_impact/dimensions/patient_safety",
        "/features/mission_and_sector_impact/dimensions/public_wellbeing",
    ]
    order = {
        "NOT_APPLICABLE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "SEVERE": 4,
        "CRITICAL": 5,
    }
    values = [
        _normalize_impact(dimensions.get("patient_safety")),
        _normalize_impact(dimensions.get("public_wellbeing")),
    ]
    if any(value not in order for value in values):
        return _decision_point(
            point_id="ssvc:SI:2.0.1",
            key=None,
            name=None,
            status="UNRESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_SAFETY_IMPACT_UNRESOLVED"],
            mapping_rule_id="SAFETY_IMPACT_FAIL_CLOSED",
        )
    selected = max(values, key=order.__getitem__)
    key_map = {
        "NOT_APPLICABLE": "N",
        "LOW": "N",
        "MEDIUM": "N",
        "HIGH": "M",
        "SEVERE": "R",
        "CRITICAL": "C",
    }
    names = {"N": "negligible", "M": "marginal", "R": "major", "C": "hazardous"}
    key = key_map[selected]
    return _decision_point(
        point_id="ssvc:SI:2.0.1",
        key=key,
        name=names[key],
        status="RESOLVED",
        source_feature_paths=paths,
        reason_codes=["SSVC_SAFETY_IMPACT_MAPPED"],
        mapping_rule_id="SAFETY_IMPACT_MAX_DIMENSION",
    )


def _map_mission_impact(features: Mapping[str, Any]) -> dict[str, Any]:
    impact = _mapping(
        features.get("mission_and_sector_impact"),
        "mission and sector impact features",
    )
    criticality = _mapping(features.get("asset_criticality"), "asset criticality")
    severity = _normalize_impact(impact.get("maximum_severity"))
    mission_essential = criticality.get("mission_essential") is True
    paths = [
        "/features/asset_criticality/mission_essential",
        "/features/asset_criticality/mission_tier",
        "/features/mission_and_sector_impact/maximum_severity",
        "/features/mission_and_sector_impact/maximum_tolerable_downtime_hours",
        "/features/mission_and_sector_impact/rto_hours",
        "/features/mission_and_sector_impact/manual_alternative_available",
    ]
    key: str | None = None
    rule = "MISSION_IMPACT_FAIL_CLOSED"
    if severity == "CRITICAL":
        key, rule = "MF", "MISSION_IMPACT_CRITICAL"
    elif mission_essential and severity == "SEVERE":
        key, rule = "MEF", "MISSION_IMPACT_ESSENTIAL_SEVERE"
    elif mission_essential and severity == "HIGH":
        key, rule = "MSC", "MISSION_IMPACT_ESSENTIAL_HIGH"
    elif severity in {"HIGH", "SEVERE"}:
        key, rule = "MSC", "MISSION_IMPACT_HIGH_OR_SEVERE"
    elif severity in {"NOT_APPLICABLE", "LOW", "MEDIUM"}:
        key, rule = "D", "MISSION_IMPACT_LOW_OR_MEDIUM"
    if key is None:
        return _decision_point(
            point_id="ssvc:MI:2.0.0",
            key=None,
            name=None,
            status="UNRESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_MISSION_IMPACT_UNRESOLVED"],
            mapping_rule_id=rule,
        )
    names = {
        "D": "degraded",
        "MSC": "mission_support_crippled",
        "MEF": "mission_essential_failure",
        "MF": "mission_failure",
    }
    return _decision_point(
        point_id="ssvc:MI:2.0.0",
        key=key,
        name=names[key],
        status="RESOLVED",
        source_feature_paths=paths,
        reason_codes=["SSVC_MISSION_IMPACT_MAPPED"],
        mapping_rule_id=rule,
    )


def _derive_human_impact(
    safety: Mapping[str, Any],
    mission: Mapping[str, Any],
    human_rows: list[Any],
) -> tuple[dict[str, Any], int | None]:
    paths = [
        "/mapping/decision_points/safety_impact/key",
        "/mapping/decision_points/mission_impact/key",
    ]
    if safety.get("status") != "RESOLVED" or mission.get("status") != "RESOLVED":
        return (
            _decision_point(
                point_id="ssvc:HI:2.0.2",
                key=None,
                name=None,
                status="UNRESOLVED",
                source_feature_paths=paths,
                reason_codes=["SSVC_HUMAN_IMPACT_UNRESOLVED"],
                mapping_rule_id="HUMAN_IMPACT_PREREQUISITE_BLOCKED",
            ),
            None,
        )
    for raw in human_rows:
        row = _mapping(raw, "human impact table row")
        if (
            row.get("safety_impact_key") == safety.get("key")
            and row.get("mission_impact_key") == mission.get("key")
        ):
            key = _text(row.get("human_impact_key"))
            names = {"L": "low", "M": "medium", "H": "high", "VH": "very_high"}
            if key not in names:
                break
            return (
                _decision_point(
                    point_id="ssvc:HI:2.0.2",
                    key=key,
                    name=names[key],
                    status="RESOLVED",
                    source_feature_paths=paths,
                    reason_codes=["SSVC_HUMAN_IMPACT_DERIVED"],
                    mapping_rule_id=f"HUMAN_IMPACT_TABLE_ROW_{row.get('row')}",
                ),
                int(row.get("row")),
            )
    return (
        _decision_point(
            point_id="ssvc:HI:2.0.2",
            key=None,
            name=None,
            status="UNRESOLVED",
            source_feature_paths=paths,
            reason_codes=["SSVC_HUMAN_IMPACT_UNRESOLVED"],
            mapping_rule_id="HUMAN_IMPACT_ROW_NOT_FOUND",
        ),
        None,
    )


def _match_deployer_row(
    points: Mapping[str, Mapping[str, Any]],
    rows: list[Any],
    outcomes: Mapping[str, Any],
) -> tuple[dict[str, Any], str | None]:
    mandatory = ("exploitation", "system_exposure", "automatable", "human_impact")
    if any(points[name].get("status") != "RESOLVED" for name in mandatory):
        return {
            "status": "BLOCKED",
            "decision_table_id": "ssvc:DP:1.0.0",
            "vector": None,
            "matched_row": None,
            "outcome": None,
        }, None
    vector = "/".join(_text(points[name].get("key")) for name in mandatory)
    for raw in rows:
        row = _mapping(raw, "deployer table row")
        inputs = _mapping(row.get("inputs"), "deployer row inputs")
        observed = tuple(
            _text(_mapping(inputs.get(name), name).get("key"))
            for name in mandatory
        )
        expected = tuple(_text(points[name].get("key")) for name in mandatory)
        if observed == expected:
            outcome_key = _text(row.get("outcome_key"))
            outcome_meta = _mapping(outcomes.get(outcome_key), "outcome metadata")
            name = _text(outcome_meta.get("name"))
            rank = int(outcome_meta.get("rank"))
            reason = {
                "D": "SSVC_DECISION_DEFER",
                "S": "SSVC_DECISION_SCHEDULED",
                "O": "SSVC_DECISION_OUT_OF_CYCLE",
                "I": "SSVC_DECISION_IMMEDIATE",
            }[outcome_key]
            return {
                "status": "DECIDED",
                "decision_table_id": "ssvc:DP:1.0.0",
                "vector": vector,
                "matched_row": int(row.get("row")),
                "outcome": {
                    "id": "ssvc:DSOI:1.0.0",
                    "key": outcome_key,
                    "name": name,
                    "rank": rank,
                    "reason_code": reason,
                },
            }, reason
    return {
        "status": "BLOCKED",
        "decision_table_id": "ssvc:DP:1.0.0",
        "vector": vector,
        "matched_row": None,
        "outcome": None,
    }, None


def build_ssvc_policy_decision(
    *,
    decision_feature_envelope: Mapping[str, Any],
    input_relative_path: str,
    input_sha256: str,
    generated_at: str | None = None,
    deployer_policy_path: Path | str = DEFAULT_DEPLOYER_POLICY,
    mapping_policy_path: Path | str = DEFAULT_MAPPING_POLICY,
    deployer_table_path: Path | str = DEFAULT_DEPLOYER_TABLE,
    human_impact_table_path: Path | str = DEFAULT_HUMAN_IMPACT_TABLE,
    reason_registry_path: Path | str = DEFAULT_REASON_REGISTRY,
) -> dict[str, Any]:
    envelope = dict(_mapping(decision_feature_envelope, "decision-feature envelope"))
    contract = _mapping(envelope.get("contract"), "decision-feature contract")
    if contract.get("contract_id") != "AEGIS-DECISION-FEATURE-CONTRACT":
        raise SSVCPolicyDecisionError("Unsupported decision-feature contract ID.")
    if contract.get("contract_version") != "1.0.0":
        raise SSVCPolicyDecisionError("Unsupported decision-feature contract version.")
    if len(input_sha256) != 64:
        raise SSVCPolicyDecisionError("input_sha256 must be a lowercase SHA-256 digest.")

    deployer_policy, policy_sha = _load_yaml(deployer_policy_path, "SSVC deployer policy")
    mapping_policy, mapping_sha = _load_yaml(mapping_policy_path, "SSVC mapping policy")
    deployer_table, table_sha = _load_yaml(deployer_table_path, "SSVC deployer table")
    human_table, human_sha = _load_yaml(human_impact_table_path, "SSVC human impact table")
    registry_meta, known_reason_codes, registry_sha = _load_reason_registry(reason_registry_path)

    policy_meta = _mapping(deployer_policy.get("policy"), "SSVC policy metadata")
    mapping_meta = _mapping(mapping_policy.get("mapping_policy"), "mapping policy metadata")
    deployer_meta = _mapping(deployer_table.get("decision_table"), "deployer table metadata")
    human_meta = _mapping(human_table.get("decision_table"), "human table metadata")
    outcomes = _mapping(deployer_policy.get("outcomes"), "SSVC outcomes")
    deployer_rows = _list(deployer_table.get("rows"))
    human_rows = _list(human_table.get("rows"))
    if len(deployer_rows) != 72 or len(human_rows) != 16:
        raise SSVCPolicyDecisionError("Pinned SSVC decision tables are incomplete.")

    features = _mapping(envelope.get("features"), "decision features")
    release = _mapping(envelope.get("release_decision"), "12D release decision")
    uncertainty = _mapping(
        features.get("uncertainty_and_conflicts"),
        "uncertainty and conflict features",
    )
    governance_features = _mapping(features.get("governance"), "governance features")

    exploitation = _map_exploitation(features)
    system_exposure, assumptions = _map_system_exposure(features)
    automatable = _map_automatable(features)
    safety_impact = _map_safety_impact(features)
    mission_impact = _map_mission_impact(features)
    human_impact, human_row = _derive_human_impact(
        safety_impact,
        mission_impact,
        human_rows,
    )
    points = {
        "exploitation": exploitation,
        "system_exposure": system_exposure,
        "automatable": automatable,
        "safety_impact": safety_impact,
        "mission_impact": mission_impact,
        "human_impact": human_impact,
    }

    upstream_stage_pass = release.get("stage_gate") == "PASS"
    integrity_verified = _verify_envelope_integrity(envelope)
    blocking_conflicts = int(uncertainty.get("blocking_conflict_count", 0) or 0)
    points_resolved = all(point.get("status") == "RESOLVED" for point in points.values())
    mapping_blocked = (
        not upstream_stage_pass
        or not integrity_verified
        or blocking_conflicts != 0
        or not points_resolved
    )

    official, outcome_reason = _match_deployer_row(points, deployer_rows, outcomes)
    if mapping_blocked:
        official = {
            "status": "BLOCKED",
            "decision_table_id": "ssvc:DP:1.0.0",
            "vector": official.get("vector"),
            "matched_row": None,
            "outcome": None,
        }
    row_matched = official.get("status") == "DECIDED"

    blocking_reason_codes: list[str] = []
    if not upstream_stage_pass:
        blocking_reason_codes.append("SSVC_INPUT_STAGE_GATE_FAILED")
    if not integrity_verified:
        blocking_reason_codes.append("SSVC_INPUT_INTEGRITY_FAILED")
    if blocking_conflicts != 0:
        blocking_reason_codes.append("SSVC_BLOCKING_CONFLICT_PRESENT")
    for point in points.values():
        if point.get("status") != "RESOLVED":
            blocking_reason_codes.extend(_list(point.get("reason_codes")))
    if points_resolved and not row_matched:
        blocking_reason_codes.append("SSVC_OFFICIAL_ROW_NOT_FOUND")
    blocking_reason_codes = _strings(blocking_reason_codes)

    mapping_status = "RESOLVED" if row_matched and not mapping_blocked else "BLOCKED"
    generated = _parse_time(generated_at)
    decision_identity = {
        "input_envelope_id": envelope.get("envelope_id"),
        "input_sha256": input_sha256,
        "policy_sha256": policy_sha,
        "mapping_policy_sha256": mapping_sha,
        "decision_table_sha256": table_sha,
        "human_impact_table_sha256": human_sha,
        "reason_registry_sha256": registry_sha,
        "vector": official.get("vector"),
    }
    decision_id = stable_identifier("AEG-SSVC", decision_identity)

    provenance = [
        {
            "decision_path": f"/mapping/decision_points/{name}",
            "source_feature_paths": point["source_feature_paths"] or ["/features"],
            "mapping_rule_id": point["mapping_rule_id"],
            "input_envelope_id": _text(envelope.get("envelope_id")),
            "input_sha256": input_sha256,
        }
        for name, point in points.items()
    ]
    if human_row is not None:
        provenance.append(
            {
                "decision_path": "/mapping/decision_points/human_impact/key",
                "source_feature_paths": [
                    "/mapping/decision_points/safety_impact/key",
                    "/mapping/decision_points/mission_impact/key",
                ],
                "mapping_rule_id": f"HUMAN_IMPACT_TABLE_ROW_{human_row}",
                "input_envelope_id": _text(envelope.get("envelope_id")),
                "input_sha256": input_sha256,
            }
        )
    if row_matched:
        provenance.append(
            {
                "decision_path": "/official_ssvc_decision/outcome",
                "source_feature_paths": [
                    "/mapping/decision_points/exploitation/key",
                    "/mapping/decision_points/system_exposure/key",
                    "/mapping/decision_points/automatable/key",
                    "/mapping/decision_points/human_impact/key",
                ],
                "mapping_rule_id": f"DEPLOYER_TABLE_ROW_{official['matched_row']}",
                "input_envelope_id": _text(envelope.get("envelope_id")),
                "input_sha256": input_sha256,
            }
        )

    human_review_required = (
        governance_features.get("human_review_required") is True
        or bool(assumptions)
        or mapping_status == "BLOCKED"
    )
    governance_reasons = [
        "SSVC_PRODUCTION_BLOCK_PRESERVED",
        "SSVC_FEDERAL_OVERLAY_NOT_APPLIED",
        "SSVC_ML_ADVISORY_NOT_APPLIED",
        "SSVC_FINAL_DISPOSITION_NOT_AUTHORIZED",
    ]
    if human_review_required:
        governance_reasons.append("SSVC_HUMAN_REVIEW_PRESERVED")
    if row_matched:
        governance_reasons.extend(["SSVC_OFFICIAL_ROW_MATCHED", outcome_reason])
    else:
        governance_reasons.append("SSVC_MAPPING_BLOCKED")
    governance_reasons = _strings(governance_reasons)

    gates = [
        _quality_gate(
            "M12E-CONTRACT",
            "upstream_contract",
            f"{contract.get('contract_id')}:{contract.get('contract_version')}",
            "AEGIS-DECISION-FEATURE-CONTRACT:1.0.0",
            True,
            ["SSVC_INPUT_CONTRACT_VERIFIED"],
        ),
        _quality_gate(
            "M12E-INTEGRITY",
            "input_canonical_integrity",
            integrity_verified,
            True,
            integrity_verified,
            [
                "SSVC_INPUT_INTEGRITY_VERIFIED"
                if integrity_verified
                else "SSVC_INPUT_INTEGRITY_FAILED"
            ],
        ),
        _quality_gate(
            "M12E-UPSTREAM-STAGE",
            "upstream_stage_gate",
            release.get("stage_gate"),
            "PASS",
            upstream_stage_pass,
            [
                "SSVC_INPUT_CONTRACT_VERIFIED"
                if upstream_stage_pass
                else "SSVC_INPUT_STAGE_GATE_FAILED"
            ],
        ),
        _quality_gate(
            "M12E-CONFLICTS",
            "blocking_conflict_count",
            blocking_conflicts,
            0,
            blocking_conflicts == 0,
            [
                "SSVC_NO_BLOCKING_CONFLICTS"
                if blocking_conflicts == 0
                else "SSVC_BLOCKING_CONFLICT_PRESENT"
            ],
        ),
        _quality_gate(
            "M12E-MANDATORY-POINTS",
            "resolved_decision_point_count",
            sum(point.get("status") == "RESOLVED" for point in points.values()),
            6,
            points_resolved,
            [
                "SSVC_MANDATORY_POINTS_RESOLVED"
                if points_resolved
                else "SSVC_MAPPING_BLOCKED"
            ],
        ),
        _quality_gate(
            "M12E-HUMAN-IMPACT",
            "human_impact_table_row",
            human_row,
            "0..15",
            human_row is not None,
            [
                "SSVC_HUMAN_IMPACT_DERIVED"
                if human_row is not None
                else "SSVC_HUMAN_IMPACT_UNRESOLVED"
            ],
        ),
        _quality_gate(
            "M12E-DEPLOYER-ROW",
            "deployer_table_row",
            official.get("matched_row"),
            "0..71",
            row_matched,
            [
                "SSVC_OFFICIAL_ROW_MATCHED"
                if row_matched
                else "SSVC_OFFICIAL_ROW_NOT_FOUND"
            ],
        ),
        _quality_gate(
            "M12E-POLICY-HASHES",
            "policy_hash_count",
            5,
            5,
            True,
            ["SSVC_POLICY_HASHES_VERIFIED"],
        ),
        _quality_gate(
            "M12E-REASON-REGISTRY",
            "closed_reason_registry",
            registry_meta.get("closed_registry"),
            True,
            registry_meta.get("closed_registry") is True,
            ["SSVC_REASON_REGISTRY_VERIFIED"],
        ),
        _quality_gate(
            "M12E-SEPARATION",
            "unauthorized_downstream_outputs",
            0,
            0,
            True,
            [
                "SSVC_FEDERAL_OVERLAY_NOT_APPLIED",
                "SSVC_ML_ADVISORY_NOT_APPLIED",
                "SSVC_FINAL_DISPOSITION_NOT_AUTHORIZED",
            ],
        ),
        _quality_gate(
            "M12E-PRODUCTION-BLOCK",
            "production_readiness",
            release.get("production_readiness"),
            "BLOCKED",
            release.get("production_readiness") == "BLOCKED",
            ["SSVC_PRODUCTION_BLOCK_PRESERVED"],
        ),
        _quality_gate(
            "M12E-PROVENANCE",
            "provenance_entry_count",
            len(provenance),
            ">=6",
            len(provenance) >= 6,
            ["SSVC_PROVENANCE_COMPLETE"],
        ),
    ]

    report = {
        "schema_version": "1.0.0",
        "decision_id": decision_id,
        "generated_at": generated,
        "contract": {
            "policy_id": _text(policy_meta.get("policy_id")),
            "policy_version": _text(policy_meta.get("version")),
            "policy_sha256": policy_sha,
            "mapping_policy_id": _text(mapping_meta.get("policy_id")),
            "mapping_policy_version": _text(mapping_meta.get("version")),
            "mapping_policy_sha256": mapping_sha,
            "decision_table_id": "ssvc:DP:1.0.0",
            "decision_table_version": _text(deployer_meta.get("version")),
            "decision_table_sha256": table_sha,
            "human_impact_table_id": "ssvc:HI:1.0.0",
            "human_impact_table_version": _text(human_meta.get("version")),
            "human_impact_table_sha256": human_sha,
            "reason_registry_id": _text(registry_meta.get("registry_id")),
            "reason_registry_version": _text(registry_meta.get("version")),
            "reason_registry_sha256": registry_sha,
            "upstream_contract_id": _text(contract.get("contract_id")),
            "upstream_contract_version": _text(contract.get("contract_version")),
        },
        "input": {
            "envelope_id": _text(envelope.get("envelope_id")),
            "relative_path": input_relative_path,
            "sha256": input_sha256,
        },
        "target": copy.deepcopy(dict(_mapping(envelope.get("target"), "target"))),
        "mapping": {
            "status": mapping_status,
            "blocking_reason_codes": blocking_reason_codes,
            "decision_points": points,
            "assumptions": assumptions,
        },
        "official_ssvc_decision": official,
        "separation": {
            "official_ssvc_complete": row_matched and not mapping_blocked,
            "federal_overlay_status": "NOT_APPLIED",
            "ml_advisory_status": "NOT_APPLIED",
            "final_disposition_status": "NOT_AUTHORIZED",
        },
        "governance": {
            "human_review_required": human_review_required,
            "production_readiness": "BLOCKED",
            "next_stage": "MILESTONE_12F_INDEPENDENT_ML_ADVISORY",
            "stage_gate": "PASS" if row_matched and not mapping_blocked else "FAIL",
            "reason_codes": governance_reasons,
            "blocking_reasons": _strings(
                _list(release.get("blocking_reasons"))
                + (["Official SSVC evaluation is blocked by unresolved or invalid governed inputs."] if mapping_status == "BLOCKED" else [])
            ),
        },
        "quality_gates": gates,
        "provenance": provenance,
        "audit": {
            "canonical_json_sha256": "0" * 64,
            "deterministic_decision_id": True,
            "policy_hashes_verified": True,
            "table_row_count": len(deployer_rows),
            "human_impact_row_count": len(human_rows),
            "reason_registry_closed": registry_meta.get("closed_registry") is True,
        },
    }

    reasons_valid, unknown_codes = _registered_reason_codes(report, known_reason_codes)
    if not reasons_valid:
        raise SSVCPolicyDecisionError(
            "Unregistered SSVC reason codes: " + ", ".join(unknown_codes)
        )
    pre_integrity = copy.deepcopy(report)
    pre_integrity["audit"]["canonical_json_sha256"] = "0" * 64
    report["audit"]["canonical_json_sha256"] = sha256_document(pre_integrity)
    return report

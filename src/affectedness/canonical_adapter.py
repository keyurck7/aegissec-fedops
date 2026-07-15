from __future__ import annotations

import copy

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping


class CanonicalAffectednessAdapterError(ValueError):
    """Raised when canonical intelligence cannot be adapted safely."""


@dataclass(frozen=True)
class CanonicalTrustView:
    action: str
    aggregate_score: float | None
    reason_codes: tuple[str, ...]
    failed_quality_gates: tuple[str, ...]
    blocking_freshness_findings: tuple[str, ...]
    blocking_conflicts: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "aggregate_score": self.aggregate_score,
            "reason_codes": list(self.reason_codes),
            "failed_quality_gates": list(self.failed_quality_gates),
            "blocking_freshness_findings": list(
                self.blocking_freshness_findings
            ),
            "blocking_conflicts": list(self.blocking_conflicts),
            "warnings": list(self.warnings),
        }


def _as_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CanonicalAffectednessAdapterError(
            f"{label} must be a JSON object."
        )
    return value


def _as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CanonicalAffectednessAdapterError(
            f"{label} must be a JSON array."
        )
    return value


def _unique_strings(values: list[Any]) -> list[str]:
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


def _evidence_id(source_name: str, source_record_id: str) -> str:
    digest = hashlib.sha256(
        f"{source_name}:{source_record_id}".encode("utf-8")
    ).hexdigest()[:20].upper()
    return f"AEG-OFFICIAL-{digest}"


def _component_purl(
    package_name: str,
    ecosystem: str,
    version: str,
    assertions: list[Mapping[str, Any]],
) -> str | None:
    for assertion in assertions:
        if (
            str(assertion.get("package_name", "")).casefold()
            == package_name.casefold()
            and str(assertion.get("ecosystem", "")).casefold()
            == ecosystem.casefold()
        ):
            purl = assertion.get("purl")
            if isinstance(purl, str) and purl.strip():
                base = purl.strip().split("#", 1)[0].split("?", 1)[0]
                last_slash = base.rfind("/")
                last_at = base.rfind("@")
                if last_at > last_slash:
                    return base
                return f"{base}@{version}"
    return None


def component_instance_from_canonical(
    canonical_record: Mapping[str, Any],
    *,
    component_id: str,
    runtime_presence: str,
    evidence_ids: list[str],
) -> dict[str, Any]:
    target = _as_mapping(canonical_record.get("target"), "target")
    component = _as_mapping(target.get("component"), "target.component")
    package_evidence = _as_mapping(
        canonical_record.get("package_evidence"),
        "package_evidence",
    )
    assertions = [
        _as_mapping(item, "package_evidence.assertions[]")
        for item in _as_list(
            package_evidence.get("assertions"),
            "package_evidence.assertions",
        )
    ]

    package_name = str(component.get("package_name", "")).strip()
    ecosystem = str(component.get("ecosystem", "")).strip()
    version = str(component.get("version", "")).strip()
    if not package_name or not ecosystem or not version:
        raise CanonicalAffectednessAdapterError(
            "Canonical target component identity is incomplete."
        )

    presence_map = {
        "ABSENT": "not_present",
        "PRESENT": "present_runtime_unknown",
        "UNKNOWN": "unknown",
    }
    if runtime_presence not in presence_map:
        raise CanonicalAffectednessAdapterError(
            f"Unsupported runtime presence status: {runtime_presence!r}"
        )

    return {
        "component_id": component_id,
        "name": package_name,
        "version": version,
        "ecosystem": ecosystem,
        "purl": _component_purl(
            package_name,
            ecosystem,
            version,
            assertions,
        ),
        "dependency_scope": "observed_or_declared",
        "runtime_status": presence_map[runtime_presence],
        "evidence_ids": _unique_strings(evidence_ids),
    }


def _collapse_same_record_package_assertions(
    packages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse range segments belonging to the same advisory record.

    Multiple range segments from one advisory represent one source opinion.
    They therefore use union semantics:

        affected(segment_1) OR affected(segment_2) OR ...

    Different source_record_id values remain separate so genuinely
    independent and contradictory advisories are still detectable.
    """

    def normalized(value: Any) -> str:
        return str(value or "").strip()

    def stable_union(
        first: list[Any],
        second: list[Any],
    ) -> list[Any]:
        """Merge lists while preserving order and removing duplicates."""
        result: list[Any] = []

        for item in [*first, *second]:
            if item not in result:
                result.append(copy.deepcopy(item))

        return result

    def effective_range_status(
        package: Mapping[str, Any],
    ) -> str:
        """Return the strongest defensible range availability status."""
        declared = normalized(
            package.get("range_status")
        ).lower()

        if declared == "available":
            return "available"

        # A populated independently reconstructed range collection means
        # range evidence is available even if another segment was partial.
        for field_name in (
            "ranges",
            "range_evaluations",
            "affected_ranges",
        ):
            value = package.get(field_name)

            if isinstance(value, list) and value:
                return "available"

        if declared == "partial":
            return "partial"

        if declared == "unavailable":
            return "unavailable"

        return "partial"

    grouped: dict[
        tuple[str, str, str, str],
        dict[str, Any],
    ] = {}

    insertion_order: list[
        tuple[str, str, str, str]
    ] = []

    for package in packages:
        if not isinstance(package, Mapping):
            raise CanonicalAffectednessAdapterError(
                "Canonical affected package entry must be a JSON object."
            )

        source_record_id = normalized(
            package.get("source_record_id")
        )

        if not source_record_id:
            raise CanonicalAffectednessAdapterError(
                "Canonical affected package entry is missing "
                "source_record_id."
            )

        key = (
            normalized(package.get("ecosystem")).lower(),
            normalized(package.get("package_name")).lower(),
            normalized(package.get("purl")).lower(),
            source_record_id,
        )

        incoming = copy.deepcopy(dict(package))
        incoming["source_record_id"] = source_record_id

        if key not in grouped:
            grouped[key] = incoming
            insertion_order.append(key)
            continue

        current = grouped[key]

        # Preserve every independently reconstructed range segment from
        # the same advisory. A nonmatching segment must never erase a
        # matching segment.
        for field_name in (
            "ranges",
            "range_evaluations",
            "affected_ranges",
            "versions",
            "affected_versions",
            "fixed_versions",
            "introduced_versions",
            "last_affected_versions",
            "evidence_ids",
            "reason_codes",
        ):
            current_value = current.get(field_name)
            incoming_value = incoming.get(field_name)

            if not isinstance(current_value, list):
                current_value = []

            if not isinstance(incoming_value, list):
                incoming_value = []

            if current_value or incoming_value:
                current[field_name] = stable_union(
                    current_value,
                    incoming_value,
                )

        # Within one advisory record, affected range segments use OR/union
        # semantics. A nonmatching segment is not an independent denial.
        evidence_statuses = {
            normalized(current.get("evidence_status")).upper(),
            normalized(incoming.get("evidence_status")).upper(),
        }
        evidence_statuses.discard("")

        if "AFFECTED_SUPPORTED" in evidence_statuses:
            current["evidence_status"] = "AFFECTED_SUPPORTED"
        elif evidence_statuses == {"NOT_AFFECTED_SUPPORTED"}:
            current["evidence_status"] = "NOT_AFFECTED_SUPPORTED"
        elif "UNKNOWN" in evidence_statuses:
            current["evidence_status"] = "UNKNOWN"
        elif evidence_statuses:
            current["evidence_status"] = sorted(
                evidence_statuses
            )[0]

        # Availability also follows union semantics. One usable range
        # segment makes the advisory independently evaluable.
        range_statuses = {
            effective_range_status(current),
            effective_range_status(incoming),
        }

        if "available" in range_statuses:
            current["range_status"] = "available"
        elif "partial" in range_statuses:
            current["range_status"] = "partial"
        else:
            current["range_status"] = "unavailable"

        # Explicit positive matches within one advisory also use OR.
        for boolean_field in (
            "explicit_version_match",
            "affected",
        ):
            if (
                boolean_field in current
                or boolean_field in incoming
            ):
                current[boolean_field] = bool(
                    current.get(boolean_field)
                ) or bool(
                    incoming.get(boolean_field)
                )

    collapsed = [
        grouped[key]
        for key in insertion_order
    ]

    # Recalculate once after merging because current may initially have
    # been marked partial before later segments were added.
    for package in collapsed:
        package["range_status"] = effective_range_status(
            package
        )

    return collapsed


def intelligence_record_from_canonical(
    canonical_record: Mapping[str, Any],
) -> dict[str, Any]:
    identifiers = _as_mapping(
        canonical_record.get("identifiers"),
        "identifiers",
    )
    primary_cve = str(identifiers.get("primary_cve", "")).strip()
    if not primary_cve:
        raise CanonicalAffectednessAdapterError(
            "Canonical intelligence is missing identifiers.primary_cve."
        )

    package_evidence = _as_mapping(
        canonical_record.get("package_evidence"),
        "package_evidence",
    )
    aggregate_status = str(
        package_evidence.get("aggregate_status", "")
    ).upper()
    assertions = [
        _as_mapping(item, "package_evidence.assertions[]")
        for item in _as_list(
            package_evidence.get("assertions"),
            "package_evidence.assertions",
        )
    ]

    affected_packages: list[dict[str, Any]] = []
    for assertion in assertions:
        source_record_id = str(
            assertion.get("source_record_id", "UNKNOWN")
        )
        evaluations = [
            _as_mapping(item, "range_evaluations[]")
            for item in _as_list(
                assertion.get("range_evaluations", []),
                "range_evaluations",
            )
        ]
        ranges: list[dict[str, Any]] = []
        any_invalid = False
        for evaluation in evaluations:
            if evaluation.get("valid") is not True:
                any_invalid = True
            range_type = str(evaluation.get("range_type", "")).upper()
            introduced = evaluation.get("introduced")
            fixed = evaluation.get("fixed")
            last_affected = evaluation.get("last_affected")
            if not range_type:
                any_invalid = True
                continue
            ranges.append(
                {
                    "range_type": range_type,
                    "introduced": introduced,
                    "fixed": fixed,
                    "last_affected": last_affected,
                }
            )

        evidence_status = str(
            assertion.get("evidence_status", "SOURCE_QUERY_MATCH_ONLY")
        ).upper()
        if any_invalid:
            range_status = "conflicting"
        elif not ranges:
            range_status = "missing"
        elif aggregate_status in {
            "AFFECTED_SUPPORTED",
            "NOT_AFFECTED_SUPPORTED",
        } and evidence_status in {
            "AFFECTED_SUPPORTED",
            "NOT_AFFECTED_SUPPORTED",
        }:
            range_status = "available"
        else:
            range_status = "partial"

        affected_packages.append(
            {
                "ecosystem": assertion.get("ecosystem"),
                "package_name": assertion.get("package_name"),
                "purl": assertion.get("purl"),
                "range_status": range_status,
                "ranges": ranges,
                "source_record_id": str(
                    assertion.get(
                        "source_record_id"
                    ) or ""
                ).strip(),
                "evidence_ids": [
                    _evidence_id("OSV", source_record_id)
                ],
                "notes": (
                    "Adapted from Milestone 12B canonical OSV package "
                    "evidence. Precomputed range outcomes are not trusted; "
                    "boundaries are independently re-evaluated."
                ),
            }
        )

    affected_packages = _collapse_same_record_package_assertions(
        affected_packages
    )

    return {
        "schema_version": "1.0.0",
        "intelligence_id": str(
            canonical_record.get("record_id", primary_cve)
        ),
        "canonical_id": primary_cve,
        "record_status": "active",
        "aliases": list(identifiers.get("aliases", [])),
        "affected_packages": affected_packages,
        "conflicts": list(
            _as_mapping(
                canonical_record.get("correlation_controls"),
                "correlation_controls",
            ).get("conflicts", [])
        ),
    }


def detect_package_assertion_conflicts(
    canonical_record: Mapping[str, Any],
) -> list[dict[str, Any]]:
    package_evidence = _as_mapping(
        canonical_record.get("package_evidence"),
        "package_evidence",
    )
    assertions = [
        _as_mapping(item, "package_evidence.assertions[]")
        for item in _as_list(
            package_evidence.get("assertions"),
            "package_evidence.assertions",
        )
    ]
    # A single OSV record can contain several affected-range entries.
    # Applicability across those entries follows union semantics:
    #
    #     affected(range_1) OR affected(range_2) OR ...
    #
    # Therefore, mixed AFFECTED_SUPPORTED and NOT_AFFECTED_SUPPORTED
    # assertions from the same source record are not automatically
    # contradictory. We first collapse all assertions belonging to the same
    # normalized package identity and source record. Only independently
    # identified source records may create a cross-record contradiction.
    record_groups: dict[
        tuple[str, str, str, str],
        list[Mapping[str, Any]],
    ] = {}

    for assertion in assertions:
        ecosystem = str(assertion.get("ecosystem") or "").strip().casefold()
        package_name = (
            str(assertion.get("package_name") or "").strip().casefold()
        )
        purl = str(assertion.get("purl") or "").strip().casefold()
        source_record_id = (
            str(assertion.get("source_record_id") or "").strip()
            or "<missing-source-record-id>"
        )

        record_key = (
            ecosystem,
            package_name,
            purl,
            source_record_id,
        )
        record_groups.setdefault(record_key, []).append(assertion)

    package_record_statuses: dict[
        tuple[str, str, str],
        dict[str, str],
    ] = {}

    for record_key, record_assertions in sorted(record_groups.items()):
        identity_key = record_key[:3]
        source_record_id = record_key[3]

        assertion_statuses = {
            str(
                assertion.get(
                    "evidence_status",
                    "SOURCE_QUERY_MATCH_ONLY",
                )
            ).upper()
            for assertion in record_assertions
        }

        # Union semantics within one advisory/source record.
        if "AFFECTED_SUPPORTED" in assertion_statuses:
            record_status = "AFFECTED_SUPPORTED"
        elif assertion_statuses == {"NOT_AFFECTED_SUPPORTED"}:
            record_status = "NOT_AFFECTED_SUPPORTED"
        else:
            record_status = "SOURCE_QUERY_MATCH_ONLY"

        package_record_statuses.setdefault(
            identity_key,
            {},
        )[source_record_id] = record_status

    conflicts: list[dict[str, Any]] = []

    for identity_key, record_statuses in sorted(
        package_record_statuses.items()
    ):
        independent_statuses = set(record_statuses.values())

        if {
            "AFFECTED_SUPPORTED",
            "NOT_AFFECTED_SUPPORTED",
        }.issubset(independent_statuses):
            conflicts.append(
                {
                    "code": "CONTRADICTORY_PACKAGE_AFFECTEDNESS",
                    "blocking": True,
                    "message": (
                        "Independent canonical package records contain "
                        "contradictory affected and not-affected conclusions "
                        "for the same normalized package identity and target "
                        "version."
                    ),
                    "evidence": {
                        "ecosystem": identity_key[0],
                        "package_name": identity_key[1],
                        "purl": identity_key[2],
                        "statuses": sorted(independent_statuses),
                        "source_record_statuses": dict(
                            sorted(record_statuses.items())
                        ),
                    },
                }
            )

    return conflicts


def canonical_intelligence_trust_view(
    canonical_record: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> CanonicalTrustView:
    trust_policy = _as_mapping(
        policy.get("canonical_intelligence_trust"),
        "canonical_intelligence_trust",
    )
    weights = _as_mapping(trust_policy.get("weights"), "weights")

    quality = _as_mapping(canonical_record.get("quality"), "quality")
    gates = [
        _as_mapping(item, "quality.quality_gates[]")
        for item in _as_list(
            quality.get("quality_gates"),
            "quality.quality_gates",
        )
    ]
    failed_gates = tuple(
        str(item.get("gate_id", "UNKNOWN"))
        for item in gates
        if item.get("pass") is not True
    )
    gate_score = (
        sum(item.get("pass") is True for item in gates) / len(gates)
        if gates
        else 0.0
    )

    source_assertions = [
        _as_mapping(item, "source_assertions[]")
        for item in _as_list(
            canonical_record.get("source_assertions"),
            "source_assertions",
        )
    ]
    acceptable = {"accepted", "accepted_with_warnings"}
    source_score = (
        sum(
            str(item.get("validation_status", "")).casefold()
            in acceptable
            for item in source_assertions
        )
        / len(source_assertions)
        if source_assertions
        else 0.0
    )

    freshness = _as_mapping(
        canonical_record.get("freshness"),
        "freshness",
    )
    blocking_freshness = tuple(
        str(value)
        for value in freshness.get("blocking_findings", [])
        if isinstance(value, str)
    )
    freshness_score = 0.0 if blocking_freshness else 1.0

    controls = _as_mapping(
        canonical_record.get("correlation_controls"),
        "correlation_controls",
    )
    blocking_conflicts = tuple(
        str(item.get("field", "UNKNOWN"))
        for item in controls.get("conflicts", [])
        if isinstance(item, Mapping) and item.get("blocking") is True
    )
    control_checks = (
        controls.get("exact_target_correlation_required") is True,
        controls.get("consensus_inference_permitted") is False,
        controls.get("adjacent_record_isolation") is True,
        controls.get("missing_numeric_values_coerced_to_zero") is False,
    )
    controls_score = sum(control_checks) / len(control_checks)

    score = (
        float(weights["quality_gates"]) * gate_score
        + float(weights["source_validation"]) * source_score
        + float(weights["freshness"]) * freshness_score
        + float(weights["correlation_controls"]) * controls_score
    )
    score = round(max(0.0, min(1.0, score)), 4)

    warnings = tuple(
        str(value)
        for value in quality.get("warnings", [])
        if isinstance(value, str) and value.strip()
    )

    quarantine_reasons: list[str] = []
    if quality.get("source_bundle_verification") != "PASS":
        quarantine_reasons.append("SOURCE_BUNDLE_VERIFICATION_FAILURE")
    if failed_gates:
        quarantine_reasons.append("FAILED_QUALITY_GATE")
    if blocking_freshness:
        quarantine_reasons.append("BLOCKING_FRESHNESS_FINDING")
    if blocking_conflicts:
        quarantine_reasons.append("BLOCKING_SOURCE_CONFLICT")
    if controls.get("exact_target_correlation_required") is not True:
        quarantine_reasons.append("EXACT_TARGET_CORRELATION_FAILURE")

    if quarantine_reasons:
        action = "QUARANTINE"
        reason_codes = tuple(quarantine_reasons)
    elif score >= float(trust_policy["accept_threshold"]):
        action = "ACCEPT_WITH_WARNINGS" if warnings else "ACCEPT"
        reason_codes = (
            "CANONICAL_INTELLIGENCE_ACCEPTED_WITH_WARNINGS",
        ) if warnings else ("CANONICAL_INTELLIGENCE_ACCEPTED",)
    elif score >= float(trust_policy["warning_threshold"]):
        action = "ACCEPT_WITH_WARNINGS"
        reason_codes = ("CANONICAL_INTELLIGENCE_BELOW_ACCEPT_THRESHOLD",)
    else:
        action = "QUARANTINE"
        reason_codes = ("CANONICAL_INTELLIGENCE_TRUST_INSUFFICIENT",)

    return CanonicalTrustView(
        action=action,
        aggregate_score=score,
        reason_codes=reason_codes,
        failed_quality_gates=failed_gates,
        blocking_freshness_findings=blocking_freshness,
        blocking_conflicts=blocking_conflicts,
        warnings=warnings,
    )


def stable_document_sha256(document: Mapping[str, Any]) -> str:
    payload = json.dumps(
        dict(document),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

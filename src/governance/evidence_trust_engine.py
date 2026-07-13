from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "trust"
    / "evidence_trust_policy_v1.yaml"
)


DIMENSION_NAMES = (
    "authenticity",
    "integrity",
    "completeness",
    "freshness",
    "consistency",
    "source_authority",
    "parser_confidence",
    "identity_confidence",
)


VALID_ACTIONS = {
    "ACCEPT",
    "ACCEPT_WITH_WARNINGS",
    "QUARANTINE",
    "REJECT",
}


@dataclass(frozen=True)
class TrustDimensionAssessment:
    name: str
    score: float
    status: str
    weight: float
    minimum_score: float
    reason_codes: tuple[str, ...]
    evidence_paths: tuple[str, ...]

    @property
    def below_floor(self) -> bool:
        return self.score < self.minimum_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "status": self.status,
            "weight": self.weight,
            "minimum_score": self.minimum_score,
            "below_floor": self.below_floor,
            "reason_codes": list(self.reason_codes),
            "evidence_paths": list(self.evidence_paths),
        }


@dataclass(frozen=True)
class TrustGateResult:
    code: str
    severity: str
    message: str
    field_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "field_path": self.field_path,
        }


@dataclass
class EvidenceTrustAssessment:
    assessment_id: str
    evidence_id: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    aggregation_method: str
    dimensions: dict[str, TrustDimensionAssessment]
    aggregate_score: float
    trust_level: str
    action: str
    gate_results: list[TrustGateResult] = field(default_factory=list)
    warnings: list[TrustGateResult] = field(default_factory=list)
    assessed_at: str = ""

    @property
    def accepted(self) -> bool:
        return self.action in {
            "ACCEPT",
            "ACCEPT_WITH_WARNINGS",
        }

    @property
    def quarantined(self) -> bool:
        return self.action == "QUARANTINE"

    @property
    def rejected(self) -> bool:
        return self.action == "REJECT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "evidence_id": self.evidence_id,
            "policy": {
                "policy_id": self.policy_id,
                "version": self.policy_version,
                "sha256": self.policy_sha256,
                "aggregation_method": self.aggregation_method,
            },
            "dimensions": {
                name: assessment.to_dict()
                for name, assessment in self.dimensions.items()
            },
            "aggregate_score": self.aggregate_score,
            "trust_level": self.trust_level,
            "action": self.action,
            "accepted": self.accepted,
            "gate_results": [
                result.to_dict()
                for result in self.gate_results
            ],
            "warnings": [
                warning.to_dict()
                for warning in self.warnings
            ],
            "assessed_at": self.assessed_at,
        }

    def to_evidence_trust_block(self) -> dict[str, Any]:
        return {
            name: {
                "score": dimension.score,
                "status": dimension.status,
                "reason_codes": list(dimension.reason_codes),
            }
            for name, dimension in self.dimensions.items()
        } | {
            "overall_score": self.aggregate_score,
            "summary_level": self.trust_level,
            "calculation_policy_id": (
                f"{self.policy_id}:{self.policy_version}"
            ),
        }


class TrustPolicyError(ValueError):
    """Raised when a trust-policy file is invalid."""


class EvidenceTrustEngine:
    """
    Calculate multidimensional evidence trust.

    The aggregate is not the only control. Critical failures and mandatory
    dimension floors can force quarantine or rejection even when the
    aggregate score is otherwise high.
    """

    def __init__(
        self,
        policy_path: Path | str = DEFAULT_POLICY_PATH,
    ) -> None:
        self.policy_path = Path(policy_path)

        if not self.policy_path.exists():
            raise FileNotFoundError(
                f"Trust policy not found: {self.policy_path}"
            )

        raw_policy = self.policy_path.read_bytes()

        self.policy_sha256 = hashlib.sha256(
            raw_policy
        ).hexdigest()

        self.policy_document = yaml.safe_load(
            raw_policy.decode("utf-8")
        )

        if not isinstance(self.policy_document, dict):
            raise TrustPolicyError(
                "Trust policy must be a YAML object."
            )

        self._validate_policy()

        self.policy_metadata = self.policy_document["policy"]
        self.dimension_policy = self.policy_document["dimensions"]
        self.thresholds = self.policy_document["thresholds"]
        self.mappings = self.policy_document["mappings"]

        self.component_evidence_types = set(
            self.policy_document[
                "component_bearing_evidence_types"
            ]
        )

        self.purl_expected_evidence_types = set(
            self.policy_document[
                "purl_expected_evidence_types"
            ]
        )

    def _validate_policy(self) -> None:
        required_sections = {
            "policy",
            "dimensions",
            "thresholds",
            "mappings",
            "component_bearing_evidence_types",
            "purl_expected_evidence_types",
            "hard_rejection_rules",
            "quarantine_rules",
            "warning_rules",
            "output_actions",
        }

        missing_sections = (
            required_sections - set(self.policy_document)
        )

        if missing_sections:
            raise TrustPolicyError(
                f"Trust policy missing sections: "
                f"{sorted(missing_sections)}"
            )

        dimensions = self.policy_document["dimensions"]

        if set(dimensions) != set(DIMENSION_NAMES):
            raise TrustPolicyError(
                "Trust policy dimensions must exactly match "
                f"{list(DIMENSION_NAMES)}."
            )

        weight_total = sum(
            float(configuration["weight"])
            for configuration in dimensions.values()
        )

        if not math.isclose(
            weight_total,
            1.0,
            rel_tol=0,
            abs_tol=1e-9,
        ):
            raise TrustPolicyError(
                f"Trust dimension weights must sum to 1.0, "
                f"but sum to {weight_total}."
            )

        for name, configuration in dimensions.items():
            weight = float(configuration["weight"])
            floor = float(configuration["minimum_score"])

            if weight < 0 or weight > 1:
                raise TrustPolicyError(
                    f"Invalid weight for {name}: {weight}"
                )

            if floor < 0 or floor > 1:
                raise TrustPolicyError(
                    f"Invalid minimum score for {name}: {floor}"
                )

        thresholds = self.policy_document["thresholds"]

        high = float(thresholds["high"])
        medium = float(thresholds["medium"])
        low = float(thresholds["low"])

        if not (1 >= high > medium > low >= 0):
            raise TrustPolicyError(
                "Thresholds must satisfy "
                "1 >= high > medium > low >= 0."
            )

        output_actions = set(
            self.policy_document["output_actions"].values()
        )

        if output_actions != VALID_ACTIONS:
            raise TrustPolicyError(
                "Trust policy output actions must be exactly "
                f"{sorted(VALID_ACTIONS)}."
            )

    def assess(
        self,
        record: dict[str, Any],
        assessed_at: datetime | None = None,
    ) -> EvidenceTrustAssessment:
        evidence_id = str(
            record.get("evidence_id", "AEG-EVD-UNKNOWN")
        )

        assessment_time = assessed_at or datetime.now(
            timezone.utc
        )

        dimensions = {
            "authenticity": self._assess_authenticity(record),
            "integrity": self._assess_integrity(record),
            "completeness": self._assess_completeness(record),
            "freshness": self._assess_freshness(record),
            "consistency": self._assess_consistency(record),
            "source_authority":
                self._assess_source_authority(record),
            "parser_confidence":
                self._assess_parser_confidence(record),
            "identity_confidence":
                self._assess_identity_confidence(record),
        }

        aggregate_score = self._aggregate(dimensions)

        gates, warnings = self._evaluate_gates(
            record=record,
            dimensions=dimensions,
        )

        declared_mismatch_warning = (
            self._compare_declared_trust(
                record=record,
                aggregate_score=aggregate_score,
                dimensions=dimensions,
            )
        )

        if declared_mismatch_warning is not None:
            warnings.append(declared_mismatch_warning)

        action, trust_level = self._determine_action(
            aggregate_score=aggregate_score,
            gates=gates,
            warnings=warnings,
        )

        return EvidenceTrustAssessment(
            assessment_id=self._assessment_id(evidence_id),
            evidence_id=evidence_id,
            policy_id=self.policy_metadata["policy_id"],
            policy_version=str(
                self.policy_metadata["version"]
            ),
            policy_sha256=self.policy_sha256,
            aggregation_method=self.policy_metadata[
                "aggregation_method"
            ],
            dimensions=dimensions,
            aggregate_score=aggregate_score,
            trust_level=trust_level,
            action=action,
            gate_results=gates,
            warnings=warnings,
            assessed_at=assessment_time.isoformat(),
        )

    def apply_assessment_to_record(
        self,
        record: dict[str, Any],
        assessment: EvidenceTrustAssessment,
    ) -> dict[str, Any]:
        """
        Return a copy with its calculated trust and validation decision.

        The input dictionary is never modified in place.
        """
        updated = copy.deepcopy(record)

        updated["trust"] = assessment.to_evidence_trust_block()

        validation = updated.setdefault("validation", {})

        action_to_status = {
            "ACCEPT": "accepted",
            "ACCEPT_WITH_WARNINGS": "accepted_with_warnings",
            "QUARANTINE": "quarantined",
            "REJECT": "rejected",
        }

        validation["business_rules_valid"] = (
            assessment.action
            in {"ACCEPT", "ACCEPT_WITH_WARNINGS"}
        )

        validation["status"] = action_to_status[
            assessment.action
        ]

        validation["validator_version"] = (
            f"{assessment.policy_id}:"
            f"{assessment.policy_version}"
        )

        validation["validated_at"] = assessment.assessed_at

        validation["errors"] = [
            {
                "code": gate.code,
                "message": gate.message,
                "field_path": gate.field_path,
            }
            for gate in assessment.gate_results
            if gate.severity in {"critical", "high"}
        ]

        validation["warnings"] = [
            {
                "code": warning.code,
                "message": warning.message,
                "field_path": warning.field_path,
            }
            for warning in assessment.warnings
        ]

        return updated

    def _dimension_result(
        self,
        name: str,
        score: float,
        status: str,
        reason_codes: list[str],
        evidence_paths: list[str],
    ) -> TrustDimensionAssessment:
        configuration = self.dimension_policy[name]

        return TrustDimensionAssessment(
            name=name,
            score=round(self._clamp(score), 4),
            status=status,
            weight=float(configuration["weight"]),
            minimum_score=float(
                configuration["minimum_score"]
            ),
            reason_codes=tuple(reason_codes),
            evidence_paths=tuple(evidence_paths),
        )

    def _assess_authenticity(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        authorization = record.get("authorization", {})
        source = record.get("source", {})

        status_name = authorization.get(
            "status",
            "authorization_unknown",
        )

        basis_name = authorization.get(
            "collection_basis",
            "unknown",
        )

        category_name = source.get(
            "source_category",
            "unknown",
        )

        status_score = self._mapped_score(
            "authorization_status",
            status_name,
        )

        basis_score = self._mapped_score(
            "collection_basis",
            basis_name,
        )

        category_score = self._mapped_score(
            "source_category",
            category_name,
        )

        score = (
            0.50 * status_score
            + 0.25 * basis_score
            + 0.25 * category_score
        )

        reason_codes = [
            f"AUTHORIZATION_{str(status_name).upper()}",
            f"COLLECTION_BASIS_{str(basis_name).upper()}",
            f"SOURCE_CATEGORY_{str(category_name).upper()}",
        ]

        if authorization.get("approved_use") == "prohibited":
            score = 0.0
            reason_codes.append("APPROVED_USE_PROHIBITED")

        status = (
            "failed"
            if score == 0
            else "estimated"
        )

        return self._dimension_result(
            name="authenticity",
            score=score,
            status=status,
            reason_codes=reason_codes,
            evidence_paths=[
                "authorization.status",
                "authorization.collection_basis",
                "authorization.approved_use",
                "source.source_category",
            ],
        )

    def _assess_integrity(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        integrity = record.get("integrity", {})

        integrity_status = integrity.get(
            "status",
            "not_verified",
        )

        score = self._mapped_score(
            "integrity_status",
            integrity_status,
        )

        reason_codes = [
            f"INTEGRITY_{str(integrity_status).upper()}"
        ]

        hash_algorithm = integrity.get(
            "hash_algorithm",
            "none",
        )

        content_hash = integrity.get("content_hash")
        signature_status = integrity.get(
            "signature_status",
            "unknown",
        )

        if integrity_status == "verified":
            if hash_algorithm == "none" or not content_hash:
                score = min(score, 0.20)
                reason_codes.append(
                    "VERIFIED_WITHOUT_CRYPTOGRAPHIC_HASH"
                )
            else:
                reason_codes.append(
                    "CRYPTOGRAPHIC_HASH_PRESENT"
                )

        if signature_status == "valid":
            score = min(1.0, score + 0.03)
            reason_codes.append("SIGNATURE_VALID")

        elif signature_status == "invalid":
            score = 0.0
            reason_codes.append("SIGNATURE_INVALID")

        elif signature_status in {
            "not_present",
            "not_checked",
            "unknown",
        }:
            reason_codes.append(
                "SIGNATURE_NOT_VERIFIED"
            )

        status = (
            "failed"
            if score == 0
            else (
                "confirmed"
                if integrity_status == "verified"
                else "estimated"
            )
        )

        return self._dimension_result(
            name="integrity",
            score=score,
            status=status,
            reason_codes=reason_codes,
            evidence_paths=[
                "integrity.status",
                "integrity.hash_algorithm",
                "integrity.content_hash",
                "integrity.signature_status",
            ],
        )

    def _assess_completeness(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        evidence_type = record.get(
            "evidence_type",
            "other",
        )

        if evidence_type not in self.component_evidence_types:
            return self._dimension_result(
                name="completeness",
                score=0.90,
                status="estimated",
                reason_codes=[
                    "NON_COMPONENT_EVIDENCE_METADATA_COMPLETE"
                ],
                evidence_paths=[
                    "source",
                    "collection",
                    "artifact",
                ],
            )

        summary = record.get("component_summary")

        if not isinstance(summary, dict):
            return self._dimension_result(
                name="completeness",
                score=0.30,
                status="unknown",
                reason_codes=[
                    "COMPONENT_SUMMARY_MISSING"
                ],
                evidence_paths=[
                    "component_summary"
                ],
            )

        component_count = self._safe_nonnegative_int(
            summary.get("component_count")
        )

        versions_count = self._safe_nonnegative_int(
            summary.get("components_with_versions")
        )

        purl_count = self._safe_nonnegative_int(
            summary.get("components_with_purl")
        )

        if component_count <= 0:
            return self._dimension_result(
                name="completeness",
                score=0.20,
                status="failed",
                reason_codes=[
                    "NO_COMPONENTS_REPORTED"
                ],
                evidence_paths=[
                    "component_summary.component_count"
                ],
            )

        version_ratio = min(
            1.0,
            versions_count / component_count,
        )

        purl_ratio = min(
            1.0,
            purl_count / component_count,
        )

        if evidence_type in self.purl_expected_evidence_types:
            score = (
                0.20
                + 0.45 * version_ratio
                + 0.35 * purl_ratio
            )

            reason_codes = [
                "PURL_EXPECTED_FOR_EVIDENCE_TYPE",
                "COMPONENT_VERSION_COVERAGE_EVALUATED",
                "COMPONENT_PURL_COVERAGE_EVALUATED",
            ]

        else:
            score = 0.30 + 0.70 * version_ratio

            reason_codes = [
                "COMPONENT_VERSION_COVERAGE_EVALUATED",
                "PURL_NOT_MANDATORY_FOR_EVIDENCE_TYPE",
            ]

        return self._dimension_result(
            name="completeness",
            score=score,
            status="estimated",
            reason_codes=reason_codes,
            evidence_paths=[
                "component_summary.component_count",
                "component_summary.components_with_versions",
                "component_summary.components_with_purl",
            ],
        )

    def _assess_freshness(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        freshness = record.get("freshness")

        if not isinstance(freshness, dict):
            return self._dimension_result(
                name="freshness",
                score=self._mapped_score(
                    "freshness_status",
                    "unknown",
                ),
                status="unknown",
                reason_codes=[
                    "FRESHNESS_NOT_EVALUATED"
                ],
                evidence_paths=[
                    "freshness"
                ],
            )

        freshness_status = freshness.get(
            "status",
            "unknown",
        )

        status_score = self._mapped_score(
            "freshness_status",
            freshness_status,
        )

        score = status_score

        reason_codes = [
            f"FRESHNESS_{str(freshness_status).upper()}"
        ]

        age_seconds = freshness.get("age_seconds")
        maximum_age_seconds = freshness.get(
            "maximum_age_seconds"
        )

        if (
            isinstance(age_seconds, int)
            and isinstance(maximum_age_seconds, int)
            and maximum_age_seconds > 0
            and age_seconds >= 0
        ):
            age_ratio = age_seconds / maximum_age_seconds

            if age_ratio <= 0.50:
                ratio_score = 1.00
                reason_codes.append(
                    "AGE_WITHIN_HALF_FRESHNESS_WINDOW"
                )

            elif age_ratio <= 1.00:
                ratio_score = 0.85
                reason_codes.append(
                    "AGE_WITHIN_FRESHNESS_WINDOW"
                )

            elif age_ratio <= 1.50:
                ratio_score = 0.50
                reason_codes.append(
                    "AGE_EXCEEDS_FRESHNESS_WINDOW"
                )

            else:
                ratio_score = 0.25
                reason_codes.append(
                    "AGE_MATERIALLY_EXCEEDS_WINDOW"
                )

            score = min(status_score, ratio_score)

        status = (
            "confirmed"
            if freshness_status == "current"
            else (
                "failed"
                if freshness_status == "expired"
                else "estimated"
            )
        )

        return self._dimension_result(
            name="freshness",
            score=score,
            status=status,
            reason_codes=reason_codes,
            evidence_paths=[
                "freshness.status",
                "freshness.age_seconds",
                "freshness.maximum_age_seconds",
                "freshness.evaluated_at",
            ],
        )

    def _assess_consistency(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        conflicts = record.get("conflicts", [])

        if not conflicts:
            return self._dimension_result(
                name="consistency",
                score=self._mapped_score(
                    "conflict_status",
                    "no_conflicts",
                ),
                status="confirmed",
                reason_codes=[
                    "NO_CONFLICTS_DETECTED"
                ],
                evidence_paths=[
                    "conflicts"
                ],
            )

        scores: list[float] = []
        reason_codes: list[str] = []

        for conflict in conflicts:
            severity = str(
                conflict.get("severity", "medium")
            ).lower()

            resolution_status = str(
                conflict.get(
                    "resolution_status",
                    "open",
                )
            ).lower()

            is_open = resolution_status in {
                "open",
                "under_review",
            }

            prefix = "open" if is_open else "resolved"
            mapping_key = f"{prefix}_{severity}"

            score = self._mapped_score(
                "conflict_status",
                mapping_key,
            )

            scores.append(score)

            reason_codes.append(
                f"CONFLICT_{prefix.upper()}_"
                f"{severity.upper()}"
            )

        final_score = min(scores) if scores else 1.0

        status = (
            "failed"
            if final_score == 0
            else "estimated"
        )

        return self._dimension_result(
            name="consistency",
            score=final_score,
            status=status,
            reason_codes=sorted(set(reason_codes)),
            evidence_paths=[
                "conflicts"
            ],
        )

    def _assess_source_authority(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        authority = record.get(
            "source",
            {},
        ).get(
            "source_authority",
            "unknown",
        )

        score = self._mapped_score(
            "source_authority",
            authority,
        )

        return self._dimension_result(
            name="source_authority",
            score=score,
            status=(
                "confirmed"
                if authority in {
                    "authoritative",
                    "high",
                }
                else "estimated"
            ),
            reason_codes=[
                f"SOURCE_AUTHORITY_{str(authority).upper()}"
            ],
            evidence_paths=[
                "source.source_authority"
            ],
        )

    def _assess_parser_confidence(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        parser = record.get("parser", {})

        parse_status = parser.get(
            "parse_status",
            "failed",
        )

        parser_confidence = parser.get(
            "parser_confidence"
        )

        if not isinstance(
            parser_confidence,
            (int, float),
        ):
            parser_confidence = None

        if parse_status == "success":
            score = (
                float(parser_confidence)
                if parser_confidence is not None
                else 0.80
            )

        elif parse_status == "partial":
            score = min(
                (
                    float(parser_confidence)
                    if parser_confidence is not None
                    else 0.60
                ),
                0.70,
            )

        elif parse_status == "not_required":
            score = 0.90

        else:
            score = 0.0

        return self._dimension_result(
            name="parser_confidence",
            score=score,
            status=(
                "failed"
                if parse_status == "failed"
                else (
                    "confirmed"
                    if parse_status == "success"
                    else "estimated"
                )
            ),
            reason_codes=[
                f"PARSER_STATUS_{str(parse_status).upper()}"
            ],
            evidence_paths=[
                "parser.parse_status",
                "parser.parser_confidence",
                "parser.warnings",
            ],
        )

    def _assess_identity_confidence(
        self,
        record: dict[str, Any],
    ) -> TrustDimensionAssessment:
        evidence_type = record.get(
            "evidence_type",
            "other",
        )

        if evidence_type not in self.component_evidence_types:
            return self._dimension_result(
                name="identity_confidence",
                score=0.80,
                status="estimated",
                reason_codes=[
                    "COMPONENT_IDENTITY_NOT_PRIMARY_PURPOSE"
                ],
                evidence_paths=[
                    "evidence_type"
                ],
            )

        summary = record.get("component_summary")

        if not isinstance(summary, dict):
            return self._dimension_result(
                name="identity_confidence",
                score=0.25,
                status="unknown",
                reason_codes=[
                    "IDENTITY_SUMMARY_MISSING"
                ],
                evidence_paths=[
                    "component_summary"
                ],
            )

        component_count = self._safe_nonnegative_int(
            summary.get("component_count")
        )

        version_count = self._safe_nonnegative_int(
            summary.get("components_with_versions")
        )

        purl_count = self._safe_nonnegative_int(
            summary.get("components_with_purl")
        )

        if component_count <= 0:
            return self._dimension_result(
                name="identity_confidence",
                score=0.15,
                status="failed",
                reason_codes=[
                    "NO_IDENTIFIED_COMPONENTS"
                ],
                evidence_paths=[
                    "component_summary.component_count"
                ],
            )

        version_ratio = min(
            1.0,
            version_count / component_count,
        )

        purl_ratio = min(
            1.0,
            purl_count / component_count,
        )

        if evidence_type in self.purl_expected_evidence_types:
            score = (
                0.15
                + 0.45 * version_ratio
                + 0.40 * purl_ratio
            )

            reason_codes = [
                "VERSION_IDENTITY_COVERAGE_EVALUATED",
                "PURL_IDENTITY_COVERAGE_EVALUATED",
            ]

        else:
            score = 0.25 + 0.75 * version_ratio

            reason_codes = [
                "VERSION_IDENTITY_COVERAGE_EVALUATED",
                "NAME_VERSION_IDENTITY_MODE",
            ]

        return self._dimension_result(
            name="identity_confidence",
            score=score,
            status="estimated",
            reason_codes=reason_codes,
            evidence_paths=[
                "component_summary.component_count",
                "component_summary.components_with_versions",
                "component_summary.components_with_purl",
            ],
        )

    def _aggregate(
        self,
        dimensions: dict[
            str,
            TrustDimensionAssessment,
        ],
    ) -> float:
        method = self.policy_metadata[
            "aggregation_method"
        ]

        if method != "weighted_geometric_mean":
            raise TrustPolicyError(
                f"Unsupported aggregation method: {method}"
            )

        if any(
            dimension.score <= 0
            for dimension in dimensions.values()
        ):
            return 0.0

        weighted_log_sum = sum(
            dimension.weight
            * math.log(dimension.score)
            for dimension in dimensions.values()
        )

        return round(
            math.exp(weighted_log_sum),
            4,
        )

    def _evaluate_gates(
        self,
        record: dict[str, Any],
        dimensions: dict[
            str,
            TrustDimensionAssessment,
        ],
    ) -> tuple[
        list[TrustGateResult],
        list[TrustGateResult],
    ]:
        gates: list[TrustGateResult] = []
        warnings: list[TrustGateResult] = []

        authorization = record.get("authorization", {})
        integrity = record.get("integrity", {})
        parser = record.get("parser", {})
        freshness = record.get("freshness", {})
        provenance = record.get("provenance", {})
        conflicts = record.get("conflicts", [])

        authorization_status = authorization.get("status")
        approved_use = authorization.get("approved_use")

        if authorization_status == "unauthorized":
            gates.append(
                TrustGateResult(
                    code="UNAUTHORIZED_EVIDENCE",
                    severity="critical",
                    message=(
                        "Unauthorized evidence is prohibited from "
                        "entering the decision pipeline."
                    ),
                    field_path="authorization.status",
                )
            )

        if approved_use == "prohibited":
            gates.append(
                TrustGateResult(
                    code="PROHIBITED_EVIDENCE_USE",
                    severity="critical",
                    message=(
                        "Evidence is explicitly prohibited for use."
                    ),
                    field_path="authorization.approved_use",
                )
            )

        if authorization_status == "authorization_unknown":
            gates.append(
                TrustGateResult(
                    code="AUTHORIZATION_REVIEW_REQUIRED",
                    severity="high",
                    message=(
                        "Evidence authorization is unknown and requires "
                        "approval before automated use."
                    ),
                    field_path="authorization.status",
                )
            )

        if authorization_status == "conditionally_authorized":
            gates.append(
                TrustGateResult(
                    code="CONDITIONAL_AUTHORIZATION_REVIEW",
                    severity="high",
                    message=(
                        "Conditionally authorized evidence must be reviewed "
                        "against its usage restrictions."
                    ),
                    field_path="authorization.status",
                )
            )

        if integrity.get("status") == "failed":
            gates.append(
                TrustGateResult(
                    code="INTEGRITY_CHECK_FAILED",
                    severity="critical",
                    message=(
                        "Evidence failed integrity verification."
                    ),
                    field_path="integrity.status",
                )
            )

        if integrity.get("signature_status") == "invalid":
            gates.append(
                TrustGateResult(
                    code="INVALID_DIGITAL_SIGNATURE",
                    severity="critical",
                    message=(
                        "Evidence contains an invalid digital signature."
                    ),
                    field_path="integrity.signature_status",
                )
            )

        if parser.get("parse_status") == "failed":
            gates.append(
                TrustGateResult(
                    code="PARSER_FAILED",
                    severity="critical",
                    message=(
                        "The evidence parser failed and produced no "
                        "trustworthy structured result."
                    ),
                    field_path="parser.parse_status",
                )
            )

        for conflict in conflicts:
            severity = conflict.get("severity")
            status = conflict.get("resolution_status")

            unresolved = status in {
                "open",
                "under_review",
            }

            if unresolved and severity == "critical":
                gates.append(
                    TrustGateResult(
                        code="OPEN_CRITICAL_CONFLICT",
                        severity="critical",
                        message=(
                            "Evidence contains an unresolved critical "
                            "conflict."
                        ),
                        field_path="conflicts",
                    )
                )

            elif unresolved and severity == "high":
                gates.append(
                    TrustGateResult(
                        code="OPEN_HIGH_CONFLICT",
                        severity="high",
                        message=(
                            "Evidence contains an unresolved high-severity "
                            "conflict and must be quarantined."
                        ),
                        field_path="conflicts",
                    )
                )

        if freshness.get("status") in {
            "stale",
            "expired",
        }:
            gates.append(
                TrustGateResult(
                    code="STALE_OR_EXPIRED_EVIDENCE",
                    severity="high",
                    message=(
                        "Stale or expired evidence requires refresh or "
                        "human authorization before automated use."
                    ),
                    field_path="freshness.status",
                )
            )

        if freshness.get("status") == "aging":
            warnings.append(
                TrustGateResult(
                    code="AGING_EVIDENCE",
                    severity="medium",
                    message=(
                        "Evidence is approaching its freshness limit."
                    ),
                    field_path="freshness.status",
                )
            )

        if parser.get("parse_status") == "partial":
            warnings.append(
                TrustGateResult(
                    code="PARTIAL_PARSE",
                    severity="medium",
                    message=(
                        "The evidence parser completed only partially."
                    ),
                    field_path="parser.parse_status",
                )
            )

        if integrity.get("signature_status") in {
            "not_present",
            "not_checked",
            "unknown",
        }:
            warnings.append(
                TrustGateResult(
                    code="SIGNATURE_NOT_VERIFIED",
                    severity="low",
                    message=(
                        "No valid digital signature was verified."
                    ),
                    field_path="integrity.signature_status",
                )
            )

        if provenance.get("origin_type") in {
            "synthetic",
            "model_generated",
        }:
            warnings.append(
                TrustGateResult(
                    code="NON_OPERATIONAL_EVIDENCE_ORIGIN",
                    severity="medium",
                    message=(
                        "Synthetic or model-generated evidence must not be "
                        "represented as observed operational evidence."
                    ),
                    field_path="provenance.origin_type",
                )
            )

        for name, dimension in dimensions.items():
            if dimension.below_floor:
                gates.append(
                    TrustGateResult(
                        code="TRUST_DIMENSION_BELOW_FLOOR",
                        severity="high",
                        message=(
                            f"{name} score {dimension.score:.4f} is below "
                            f"mandatory floor "
                            f"{dimension.minimum_score:.4f}."
                        ),
                        field_path=f"trust.{name}",
                    )
                )

        return gates, warnings

    def _compare_declared_trust(
        self,
        record: dict[str, Any],
        aggregate_score: float,
        dimensions: dict[
            str,
            TrustDimensionAssessment,
        ],
    ) -> TrustGateResult | None:
        declared = record.get("trust")

        if not isinstance(declared, dict):
            return None

        declared_overall = declared.get("overall_score")

        mismatches: list[str] = []

        if isinstance(declared_overall, (int, float)):
            if abs(
                float(declared_overall)
                - aggregate_score
            ) > 0.10:
                mismatches.append(
                    "overall_score"
                )

        for name, assessment in dimensions.items():
            declared_dimension = declared.get(name)

            if not isinstance(declared_dimension, dict):
                continue

            declared_score = declared_dimension.get("score")

            if isinstance(declared_score, (int, float)):
                if abs(
                    float(declared_score)
                    - assessment.score
                ) > 0.15:
                    mismatches.append(name)

        if not mismatches:
            return None

        return TrustGateResult(
            code="DECLARED_TRUST_MISMATCH",
            severity="medium",
            message=(
                "Previously declared trust differs materially from the "
                f"policy-calculated result for: "
                f"{sorted(set(mismatches))}."
            ),
            field_path="trust",
        )

    def _determine_action(
        self,
        aggregate_score: float,
        gates: list[TrustGateResult],
        warnings: list[TrustGateResult],
    ) -> tuple[str, str]:
        has_critical_gate = any(
            gate.severity == "critical"
            for gate in gates
        )

        if has_critical_gate:
            return "REJECT", "rejected"

        high = float(self.thresholds["high"])
        medium = float(self.thresholds["medium"])
        low = float(self.thresholds["low"])

        if aggregate_score < low:
            return "REJECT", "rejected"

        has_high_gate = any(
            gate.severity == "high"
            for gate in gates
        )

        if has_high_gate:
            return "QUARANTINE", "low"

        if aggregate_score >= high:
            trust_level = "high"

        elif aggregate_score >= medium:
            trust_level = "medium"

        else:
            trust_level = "low"

        if trust_level == "low":
            return "QUARANTINE", "low"

        if warnings:
            return "ACCEPT_WITH_WARNINGS", trust_level

        return "ACCEPT", trust_level

    def _mapped_score(
        self,
        mapping_name: str,
        key: Any,
    ) -> float:
        mapping = self.mappings.get(mapping_name)

        if not isinstance(mapping, dict):
            raise TrustPolicyError(
                f"Missing mapping: {mapping_name}"
            )

        normalized_key = str(key)

        value = mapping.get(normalized_key)

        if value is None:
            value = mapping.get("unknown", 0.0)

        return self._clamp(float(value))

    @staticmethod
    def _safe_nonnegative_int(value: Any) -> int:
        if isinstance(value, bool):
            return 0

        if isinstance(value, int) and value >= 0:
            return value

        return 0

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @staticmethod
    def _assessment_id(evidence_id: str) -> str:
        normalized = evidence_id.replace(
            "AEG-EVD-",
            "",
            1,
        )

        return f"AEG-TRUST-{normalized}"

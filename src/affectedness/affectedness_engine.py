from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml

from src.affectedness.versioning import (
    RangeEvaluation,
    evaluate_version_range,
    parse_version,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "affectedness"
    / "affectedness_policy_v1.yaml"
)


VALID_STATUSES = {
    "affected",
    "probably_affected",
    "unknown",
    "probably_not_affected",
    "not_affected",
    "fixed",
}


@dataclass(frozen=True)
class PackageMatch:
    matched: bool
    method: str
    confidence: float
    component_purl: str | None
    intelligence_purl: str | None
    component_name: str
    intelligence_package_name: str | None
    ecosystem: str
    package_index: int | None
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "method": self.method,
            "confidence": self.confidence,
            "component_purl": self.component_purl,
            "intelligence_purl": self.intelligence_purl,
            "component_name": self.component_name,
            "intelligence_package_name": (
                self.intelligence_package_name
            ),
            "ecosystem": self.ecosystem,
            "package_index": self.package_index,
            "reason_codes": list(self.reason_codes),
        }


@dataclass
class AffectednessAssessment:
    assessment_id: str
    status: str
    confidence: float | None
    determination_method: str
    engine_version: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    package_match: PackageMatch | None
    component_version: str | None
    range_status: str | None
    range_evaluations: list[RangeEvaluation]
    reason_codes: list[str]
    supporting_evidence_ids: list[str]
    uncertainty_factors: list[str]
    human_review_required: bool
    determined_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "status": self.status,
            "confidence": self.confidence,
            "determination_method": self.determination_method,
            "engine_version": self.engine_version,
            "policy": {
                "policy_id": self.policy_id,
                "version": self.policy_version,
                "sha256": self.policy_sha256,
            },
            "package_match": (
                self.package_match.to_dict()
                if self.package_match is not None
                else None
            ),
            "component_version": self.component_version,
            "range_status": self.range_status,
            "range_evaluations": [
                evaluation.to_dict()
                for evaluation in self.range_evaluations
            ],
            "reason_codes": self.reason_codes,
            "supporting_evidence_ids": (
                self.supporting_evidence_ids
            ),
            "uncertainty_factors": self.uncertainty_factors,
            "human_review_required": (
                self.human_review_required
            ),
            "determined_at": self.determined_at,
        }

    def to_decision_record_block(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "confidence": self.confidence,
            "determination_method": (
                self.determination_method
            ),
            "engine_version": self.engine_version,
            "reason_codes": self.reason_codes,
            "supporting_evidence_ids": (
                self.supporting_evidence_ids
            ),
            "uncertainty_factors": (
                self.uncertainty_factors
            ),
            "determined_at": self.determined_at,
        }


class AffectednessPolicyError(ValueError):
    """Raised when the affectedness policy is invalid."""


class AffectednessEngine:
    def __init__(
        self,
        policy_path: Path | str = DEFAULT_POLICY_PATH,
    ) -> None:
        self.policy_path = Path(policy_path)

        if not self.policy_path.exists():
            raise FileNotFoundError(
                f"Affectedness policy not found: "
                f"{self.policy_path}"
            )

        raw_policy = self.policy_path.read_bytes()

        self.policy_sha256 = hashlib.sha256(
            raw_policy
        ).hexdigest()

        self.policy = yaml.safe_load(
            raw_policy.decode("utf-8")
        )

        if not isinstance(self.policy, dict):
            raise AffectednessPolicyError(
                "Affectedness policy must be a YAML object."
            )

        self._validate_policy()

        self.metadata = self.policy["policy"]
        self.identity_policy = self.policy["identity"]
        self.trust_policy = self.policy["trust"]
        self.range_policy = self.policy["range_evaluation"]

        self.supported_range_types = {
            str(value).upper()
            for value in self.range_policy[
                "supported_range_types"
            ]
        }

        self.definitive_range_statuses = set(
            self.range_policy[
                "definitive_range_statuses"
            ]
        )

        self.probable_range_statuses = set(
            self.range_policy[
                "probable_range_statuses"
            ]
        )

        self.abstain_range_statuses = set(
            self.range_policy[
                "abstain_range_statuses"
            ]
        )

        self.review_statuses = set(
            self.policy["human_review_required_for"]
        )

        self.confidence_caps = self.policy[
            "confidence_caps"
        ]

    def _validate_policy(self) -> None:
        required_sections = {
            "policy",
            "identity",
            "trust",
            "range_evaluation",
            "state_rules",
            "human_review_required_for",
            "confidence_caps",
        }

        missing = required_sections - set(self.policy)

        if missing:
            raise AffectednessPolicyError(
                f"Affectedness policy missing sections: "
                f"{sorted(missing)}"
            )

        identity = self.policy["identity"]
        trust = self.policy["trust"]

        identity_definitive = float(
            identity["definitive_threshold"]
        )

        identity_probable = float(
            identity["probable_threshold"]
        )

        trust_definitive = float(
            trust["definitive_threshold"]
        )

        trust_probable = float(
            trust["probable_threshold"]
        )

        if not (
            1
            >= identity_definitive
            > identity_probable
            >= 0
        ):
            raise AffectednessPolicyError(
                "Identity thresholds must satisfy "
                "1 >= definitive > probable >= 0."
            )

        if not (
            1
            >= trust_definitive
            > trust_probable
            >= 0
        ):
            raise AffectednessPolicyError(
                "Trust thresholds must satisfy "
                "1 >= definitive > probable >= 0."
            )

        review_statuses = set(
            self.policy["human_review_required_for"]
        )

        if not review_statuses.issubset(VALID_STATUSES):
            raise AffectednessPolicyError(
                "human_review_required_for contains "
                "an invalid affectedness status."
            )

    def assess(
        self,
        component_instance: dict[str, Any],
        intelligence_record: dict[str, Any],
        evidence_trust: Any,
        assessed_at: datetime | None = None,
    ) -> AffectednessAssessment:
        assessment_time = (
            assessed_at
            or datetime.now(timezone.utc)
        )

        component_id = str(
            component_instance.get(
                "component_id",
                "UNKNOWN",
            )
        )

        canonical_id = str(
            intelligence_record.get(
                "canonical_id",
                "UNKNOWN",
            )
        )

        assessment_id = (
            f"AEG-AFF-{component_id}-"
            f"{canonical_id}"
        )

        trust_action, trust_score = (
            self._extract_trust_view(evidence_trust)
        )

        component_evidence_ids = self._unique_strings(
            component_instance.get("evidence_ids", [])
        )

        if trust_action == "REJECT":
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="not_run",
                package_match=None,
                component_version=component_instance.get(
                    "version"
                ),
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "EVIDENCE_TRUST_REJECTED",
                    "AFFECTEDNESS_ABSTAINED",
                ],
                evidence_ids=component_evidence_ids,
                uncertainty=[
                    "Evidence failed mandatory trust controls."
                ],
                determined_at=assessment_time,
            )

        if trust_action == "QUARANTINE":
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="not_run",
                package_match=None,
                component_version=component_instance.get(
                    "version"
                ),
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "EVIDENCE_TRUST_QUARANTINED",
                    "AFFECTEDNESS_ABSTAINED",
                ],
                evidence_ids=component_evidence_ids,
                uncertainty=[
                    "Evidence requires review before affectedness "
                    "may be determined."
                ],
                determined_at=assessment_time,
            )

        if trust_score is None:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="not_run",
                package_match=None,
                component_version=component_instance.get(
                    "version"
                ),
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "EVIDENCE_TRUST_SCORE_MISSING",
                    "AFFECTEDNESS_ABSTAINED",
                ],
                evidence_ids=component_evidence_ids,
                uncertainty=[
                    "No usable evidence-trust score was supplied."
                ],
                determined_at=assessment_time,
            )

        runtime_status = component_instance.get(
            "runtime_status",
            "unknown",
        )

        if runtime_status == "not_present":
            if (
                trust_score
                >= float(
                    self.trust_policy[
                        "definitive_threshold"
                    ]
                )
                and component_evidence_ids
            ):
                return self._result(
                    assessment_id=assessment_id,
                    status="not_affected",
                    confidence=min(trust_score, 0.95),
                    method="runtime_reachability",
                    package_match=None,
                    component_version=component_instance.get(
                        "version"
                    ),
                    range_status=None,
                    evaluations=[],
                    reason_codes=[
                        "COMPONENT_AFFIRMATIVELY_NOT_PRESENT"
                    ],
                    evidence_ids=component_evidence_ids,
                    uncertainty=[],
                    determined_at=assessment_time,
                )

            return self._result(
                assessment_id=assessment_id,
                status="probably_not_affected",
                confidence=min(trust_score, 0.79),
                method="runtime_reachability",
                package_match=None,
                component_version=component_instance.get(
                    "version"
                ),
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "COMPONENT_REPORTED_NOT_PRESENT",
                    "PRESENCE_EVIDENCE_NOT_DEFINITIVE",
                ],
                evidence_ids=component_evidence_ids,
                uncertainty=[
                    "Component absence evidence is not sufficiently "
                    "strong for a definitive conclusion."
                ],
                determined_at=assessment_time,
            )

        component_version_raw = component_instance.get(
            "version"
        )

        if component_version_raw is None or str(
            component_version_raw
        ).strip() == "":
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="not_run",
                package_match=None,
                component_version=None,
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "COMPONENT_VERSION_MISSING"
                ],
                evidence_ids=component_evidence_ids,
                uncertainty=[
                    "Affectedness cannot be evaluated without "
                    "a component version."
                ],
                determined_at=assessment_time,
            )

        component_version = parse_version(
            component_version_raw
        )

        if component_version is None:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="not_run",
                package_match=None,
                component_version=str(
                    component_version_raw
                ),
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "COMPONENT_VERSION_UNPARSABLE"
                ],
                evidence_ids=component_evidence_ids,
                uncertainty=[
                    "The component version uses an unsupported or "
                    "ambiguous format."
                ],
                determined_at=assessment_time,
            )

        package_matches = self._find_package_matches(
            component_instance=component_instance,
            intelligence_record=intelligence_record,
        )

        if not package_matches:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="not_run",
                package_match=None,
                component_version=str(
                    component_version_raw
                ),
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "NO_AFFECTED_PACKAGE_MATCH",
                    "NO_MATCH_IS_NOT_PROOF_OF_SAFETY",
                ],
                evidence_ids=component_evidence_ids,
                uncertainty=[
                    "Package aliases, PURL mapping or source coverage "
                    "may be incomplete."
                ],
                determined_at=assessment_time,
            )

        if len(package_matches) > 1:
            supporting_ids = list(component_evidence_ids)

            for package_match, package in package_matches:
                supporting_ids.extend(
                    package.get("evidence_ids", [])
                )

            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="not_run",
                package_match=None,
                component_version=str(
                    component_version_raw
                ),
                range_status=None,
                evaluations=[],
                reason_codes=[
                    "MULTIPLE_AFFECTED_PACKAGE_MATCHES",
                    "PACKAGE_IDENTITY_AMBIGUOUS",
                ],
                evidence_ids=self._unique_strings(
                    supporting_ids
                ),
                uncertainty=[
                    "Multiple vulnerability package records match "
                    "the component identity."
                ],
                determined_at=assessment_time,
            )

        package_match, affected_package = (
            package_matches[0]
        )

        range_status = affected_package.get(
            "range_status",
            "unknown",
        )

        package_evidence_ids = self._unique_strings(
            affected_package.get("evidence_ids", [])
        )

        supporting_evidence_ids = self._unique_strings(
            component_evidence_ids
            + package_evidence_ids
        )

        if range_status in self.abstain_range_statuses:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=[],
                reason_codes=[
                    "AFFECTED_RANGE_UNAVAILABLE",
                    "AFFECTEDNESS_ABSTAINED",
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=[
                    f"Affected package range status is "
                    f"{range_status!r}."
                ],
                determined_at=assessment_time,
            )

        version_ranges = affected_package.get(
            "ranges",
            [],
        )

        if not version_ranges:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=[],
                reason_codes=[
                    "AFFECTED_VERSION_RANGES_EMPTY"
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=[
                    "The intelligence record contains no usable "
                    "affected-version ranges."
                ],
                determined_at=assessment_time,
            )

        evaluations = [
            evaluate_version_range(
                component_version=component_version,
                version_range=version_range,
                range_index=index,
                supported_range_types=(
                    self.supported_range_types
                ),
            )
            for index, version_range in enumerate(
                version_ranges
            )
        ]

        valid_evaluations = [
            evaluation
            for evaluation in evaluations
            if evaluation.valid
        ]

        invalid_evaluations = [
            evaluation
            for evaluation in evaluations
            if not evaluation.valid
        ]

        # Fail closed when any supplied range cannot be evaluated.
        #
        # Even if another supported range appears to match the component,
        # an unsupported, malformed, ambiguous, or incorrectly ordered range
        # means that the source's complete affected-version statement has not
        # been evaluated. AegisSec must therefore abstain rather than produce
        # an affected or probably-affected conclusion from partial reasoning.
        if invalid_evaluations:
            invalid_reason_codes = [
                "VERSION_RANGE_EVALUATION_INCOMPLETE",
                "AFFECTEDNESS_ABSTAINED",
            ]

            invalid_uncertainty = []

            for evaluation in invalid_evaluations:
                invalid_reason_codes.extend(
                    evaluation.reason_codes
                )

                if evaluation.error:
                    invalid_uncertainty.append(
                        evaluation.error
                    )

            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=invalid_reason_codes,
                evidence_ids=supporting_evidence_ids,
                uncertainty=invalid_uncertainty or [
                    "At least one affected-version range could not "
                    "be evaluated safely."
                ],
                determined_at=assessment_time,
            )

        any_affected = any(
            evaluation.affected is True
            for evaluation in valid_evaluations
        )

        any_fixed_boundary_reached = any(
            evaluation.fixed_boundary_reached
            for evaluation in valid_evaluations
        )

        all_before_introduced = (
            bool(valid_evaluations)
            and all(
                evaluation.before_introduced
                for evaluation in valid_evaluations
            )
        )

        identity_definitive = (
            package_match.confidence
            >= float(
                self.identity_policy[
                    "definitive_threshold"
                ]
            )
        )

        identity_probable = (
            package_match.confidence
            >= float(
                self.identity_policy[
                    "probable_threshold"
                ]
            )
        )

        trust_definitive = (
            trust_score
            >= float(
                self.trust_policy[
                    "definitive_threshold"
                ]
            )
        )

        trust_probable = (
            trust_score
            >= float(
                self.trust_policy[
                    "probable_threshold"
                ]
            )
        )

        definitive_inputs = (
            range_status
            in self.definitive_range_statuses
            and identity_definitive
            and trust_definitive
            and not invalid_evaluations
        )

        probable_inputs = (
            (
                range_status
                in self.probable_range_statuses
            )
            or not identity_definitive
            or not trust_definitive
            or bool(invalid_evaluations)
        ) and identity_probable and trust_probable

        base_confidence = min(
            package_match.confidence,
            trust_score,
        )

        if any_affected:
            if definitive_inputs:
                status = "affected"
                confidence = self._cap_confidence(
                    "affected",
                    base_confidence,
                )

                reason_codes = [
                    "PACKAGE_IDENTITY_MATCHED",
                    "COMPONENT_VERSION_IN_AFFECTED_RANGE",
                    "AFFECTEDNESS_CONFIRMED",
                ]

                uncertainty = []

            else:
                status = "probably_affected"
                confidence = self._cap_confidence(
                    "probably_affected",
                    base_confidence,
                )

                reason_codes = [
                    "PACKAGE_IDENTITY_MATCHED",
                    "COMPONENT_VERSION_IN_KNOWN_AFFECTED_RANGE",
                    "AFFECTEDNESS_NOT_DEFINITIVE",
                ]

                uncertainty = self._uncertainty_reasons(
                    range_status=range_status,
                    identity_definitive=(
                        identity_definitive
                    ),
                    trust_definitive=trust_definitive,
                    invalid_evaluations=(
                        invalid_evaluations
                    ),
                )

            return self._result(
                assessment_id=assessment_id,
                status=status,
                confidence=confidence,
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=reason_codes,
                evidence_ids=supporting_evidence_ids,
                uncertainty=uncertainty,
                determined_at=assessment_time,
            )

        if invalid_evaluations and not probable_inputs:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=[
                    "VERSION_RANGE_EVALUATION_INCOMPLETE",
                    "AFFECTEDNESS_ABSTAINED",
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=[
                    evaluation.error
                    for evaluation in invalid_evaluations
                    if evaluation.error
                ],
                determined_at=assessment_time,
            )

        if not valid_evaluations:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=[
                    "NO_VALID_VERSION_RANGES"
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=[
                    "No version range could be evaluated."
                ],
                determined_at=assessment_time,
            )

        if range_status in self.probable_range_statuses:
            return self._result(
                assessment_id=assessment_id,
                status="probably_not_affected",
                confidence=self._cap_confidence(
                    "probably_not_affected",
                    base_confidence,
                ),
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=[
                    "VERSION_OUTSIDE_KNOWN_AFFECTED_RANGES",
                    "RANGE_COVERAGE_PARTIAL",
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=[
                    "Known ranges are incomplete, so absence from "
                    "those ranges is not definitive."
                ],
                determined_at=assessment_time,
            )

        if invalid_evaluations:
            return self._result(
                assessment_id=assessment_id,
                status="unknown",
                confidence=None,
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=[
                    "VERSION_RANGE_EVALUATION_PARTIAL",
                    "AFFECTEDNESS_ABSTAINED",
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=[
                    evaluation.error
                    for evaluation in invalid_evaluations
                    if evaluation.error
                ],
                determined_at=assessment_time,
            )

        if not definitive_inputs:
            return self._result(
                assessment_id=assessment_id,
                status="probably_not_affected",
                confidence=self._cap_confidence(
                    "probably_not_affected",
                    base_confidence,
                ),
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=[
                    "VERSION_OUTSIDE_AFFECTED_RANGES",
                    "INPUT_CONFIDENCE_NOT_DEFINITIVE",
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=self._uncertainty_reasons(
                    range_status=range_status,
                    identity_definitive=(
                        identity_definitive
                    ),
                    trust_definitive=trust_definitive,
                    invalid_evaluations=[],
                ),
                determined_at=assessment_time,
            )

        if any_fixed_boundary_reached:
            return self._result(
                assessment_id=assessment_id,
                status="fixed",
                confidence=self._cap_confidence(
                    "fixed",
                    base_confidence,
                ),
                method="version_range",
                package_match=package_match,
                component_version=str(
                    component_version_raw
                ),
                range_status=range_status,
                evaluations=evaluations,
                reason_codes=[
                    "VERSION_OUTSIDE_AFFECTED_RANGES",
                    "FIXED_BOUNDARY_REACHED",
                    "FIXED_VERSION_CONFIRMED",
                ],
                evidence_ids=supporting_evidence_ids,
                uncertainty=[],
                determined_at=assessment_time,
            )

        if all_before_introduced:
            reason_codes = [
                "VERSION_PRECEDES_ALL_AFFECTED_RANGES",
                "NOT_AFFECTED_CONFIRMED",
            ]

        else:
            reason_codes = [
                "VERSION_OUTSIDE_ALL_AFFECTED_RANGES",
                "NOT_AFFECTED_CONFIRMED",
            ]

        return self._result(
            assessment_id=assessment_id,
            status="not_affected",
            confidence=self._cap_confidence(
                "not_affected",
                base_confidence,
            ),
            method="version_range",
            package_match=package_match,
            component_version=str(component_version_raw),
            range_status=range_status,
            evaluations=evaluations,
            reason_codes=reason_codes,
            evidence_ids=supporting_evidence_ids,
            uncertainty=[],
            determined_at=assessment_time,
        )

    def _find_package_matches(
        self,
        component_instance: dict[str, Any],
        intelligence_record: dict[str, Any],
    ) -> list[tuple[PackageMatch, dict[str, Any]]]:
        component_purl = component_instance.get("purl")
        component_name = str(
            component_instance.get("name", "")
        ).strip()

        component_ecosystem = str(
            component_instance.get("ecosystem", "Unknown")
        ).strip()

        normalized_component_purl = self._normalize_purl(
            component_purl
        )

        matches = []

        for package_index, package in enumerate(
            intelligence_record.get(
                "affected_packages",
                [],
            )
        ):
            package_purl = package.get("purl")
            package_name = str(
                package.get("package_name", "")
            ).strip()

            package_ecosystem = str(
                package.get("ecosystem", "Unknown")
            ).strip()

            normalized_package_purl = self._normalize_purl(
                package_purl
            )

            if (
                normalized_component_purl
                and normalized_package_purl
                and normalized_component_purl
                == normalized_package_purl
            ):
                match = PackageMatch(
                    matched=True,
                    method="exact_purl",
                    confidence=float(
                        self.identity_policy[
                            "exact_purl_confidence"
                        ]
                    ),
                    component_purl=component_purl,
                    intelligence_purl=package_purl,
                    component_name=component_name,
                    intelligence_package_name=package_name,
                    ecosystem=component_ecosystem,
                    package_index=package_index,
                    reason_codes=(
                        "EXACT_PURL_MATCH",
                    ),
                )

                matches.append((match, package))
                continue

            same_ecosystem = (
                component_ecosystem.casefold()
                == package_ecosystem.casefold()
            )

            same_name = (
                component_name.casefold()
                == package_name.casefold()
            )

            if same_ecosystem and same_name:
                match = PackageMatch(
                    matched=True,
                    method="exact_ecosystem_name",
                    confidence=float(
                        self.identity_policy[
                            "exact_ecosystem_name_confidence"
                        ]
                    ),
                    component_purl=component_purl,
                    intelligence_purl=package_purl,
                    component_name=component_name,
                    intelligence_package_name=package_name,
                    ecosystem=component_ecosystem,
                    package_index=package_index,
                    reason_codes=(
                        "EXACT_ECOSYSTEM_MATCH",
                        "EXACT_PACKAGE_NAME_MATCH",
                    ),
                )

                matches.append((match, package))

        return matches

    def _result(
        self,
        assessment_id: str,
        status: str,
        confidence: float | None,
        method: str,
        package_match: PackageMatch | None,
        component_version: str | None,
        range_status: str | None,
        evaluations: list[RangeEvaluation],
        reason_codes: list[str],
        evidence_ids: list[str],
        uncertainty: list[str],
        determined_at: datetime,
    ) -> AffectednessAssessment:
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid affectedness status: {status}"
            )

        return AffectednessAssessment(
            assessment_id=assessment_id,
            status=status,
            confidence=(
                round(confidence, 4)
                if confidence is not None
                else None
            ),
            determination_method=method,
            engine_version=str(
                self.metadata["engine_version"]
            ),
            policy_id=self.metadata["policy_id"],
            policy_version=str(
                self.metadata["version"]
            ),
            policy_sha256=self.policy_sha256,
            package_match=package_match,
            component_version=component_version,
            range_status=range_status,
            range_evaluations=evaluations,
            reason_codes=self._unique_strings(
                reason_codes
            ),
            supporting_evidence_ids=(
                self._unique_strings(evidence_ids)
            ),
            uncertainty_factors=self._unique_strings(
                uncertainty
            ),
            human_review_required=(
                status in self.review_statuses
            ),
            determined_at=determined_at.isoformat(),
        )

    def _extract_trust_view(
        self,
        evidence_trust: Any,
    ) -> tuple[str | None, float | None]:
        if evidence_trust is None:
            return None, None

        if hasattr(evidence_trust, "action"):
            action = getattr(evidence_trust, "action")
            score = getattr(
                evidence_trust,
                "aggregate_score",
                None,
            )

        elif isinstance(evidence_trust, dict):
            action = evidence_trust.get("action")
            score = evidence_trust.get(
                "aggregate_score"
            )

        else:
            return None, None

        normalized_action = (
            str(action).upper()
            if action is not None
            else None
        )

        if isinstance(score, bool):
            normalized_score = None

        elif isinstance(score, (int, float)):
            normalized_score = float(score)

            if (
                not math.isfinite(normalized_score)
                or normalized_score < 0
                or normalized_score > 1
            ):
                normalized_score = None

        else:
            normalized_score = None

        return normalized_action, normalized_score

    def _cap_confidence(
        self,
        status: str,
        confidence: float,
    ) -> float:
        cap = self.confidence_caps.get(status)

        if cap is None:
            return confidence

        return min(float(cap), confidence)

    def _uncertainty_reasons(
        self,
        range_status: str,
        identity_definitive: bool,
        trust_definitive: bool,
        invalid_evaluations: list[RangeEvaluation],
    ) -> list[str]:
        reasons = []

        if range_status in self.probable_range_statuses:
            reasons.append(
                "Affected-version range coverage is partial."
            )

        if not identity_definitive:
            reasons.append(
                "Package identity confidence is below the "
                "definitive threshold."
            )

        if not trust_definitive:
            reasons.append(
                "Evidence trust is below the definitive threshold."
            )

        for evaluation in invalid_evaluations:
            if evaluation.error:
                reasons.append(evaluation.error)

        return self._unique_strings(reasons)

    @staticmethod
    def _normalize_purl(
        purl: Any,
    ) -> str | None:
        if not isinstance(purl, str):
            return None

        normalized = unquote(purl.strip())

        if not normalized.startswith("pkg:"):
            return None

        normalized = normalized.split("#", 1)[0]
        normalized = normalized.split("?", 1)[0]

        last_slash = normalized.rfind("/")
        last_at = normalized.rfind("@")

        if last_at > last_slash:
            normalized = normalized[:last_at]

        return normalized.casefold()

    @staticmethod
    def _unique_strings(
        values: list[Any],
    ) -> list[str]:
        output = []
        seen = set()

        for value in values:
            if not isinstance(value, str):
                continue

            if value in seen:
                continue

            seen.add(value)
            output.append(value)

        return output

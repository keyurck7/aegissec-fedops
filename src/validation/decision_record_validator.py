from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from src.domain.decision_hashing import (
    sha256_file,
    verify_decision_record_hash,
)
from src.validation.asset_context_validator import AssetContextValidator
from src.validation.evidence_schema_validator import EvidenceSchemaValidator
from src.validation.vulnerability_intelligence_validator import (
    VulnerabilityIntelligenceValidator,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_decision_record.schema.json"
)


PRIORITY_RANK = {
    "UNKNOWN": -1,
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "EMERGENCY": 5,
}


@dataclass(frozen=True)
class DecisionValidationIssue:
    code: str
    message: str
    field_path: str | None = None


@dataclass
class DecisionValidationResult:
    schema_valid: bool
    business_rules_valid: bool
    status: str
    errors: list[DecisionValidationIssue] = field(default_factory=list)
    warnings: list[DecisionValidationIssue] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.schema_valid and self.business_rules_valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_valid": self.schema_valid,
            "business_rules_valid": self.business_rules_valid,
            "status": self.status,
            "errors": [
                {
                    "code": issue.code,
                    "message": issue.message,
                    "field_path": issue.field_path,
                }
                for issue in self.errors
            ],
            "warnings": [
                {
                    "code": issue.code,
                    "message": issue.message,
                    "field_path": issue.field_path,
                }
                for issue in self.warnings
            ],
        }


class DecisionRecordValidator:
    """
    Validate the Decision Record, its referenced inputs and governance rules.
    """

    def __init__(
        self,
        schema_path: Path | str = DEFAULT_SCHEMA_PATH,
        project_root: Path | str = PROJECT_ROOT,
    ) -> None:
        self.schema_path = Path(schema_path)
        self.project_root = Path(project_root).resolve()

        if not self.schema_path.exists():
            raise FileNotFoundError(
                f"Decision Record schema not found: {self.schema_path}"
            )

        with self.schema_path.open("r", encoding="utf-8") as file:
            self.schema = json.load(file)

        Draft202012Validator.check_schema(self.schema)

        self.validator = Draft202012Validator(
            self.schema,
            format_checker=FormatChecker(),
        )

        self.reference_validators = {
            "evidence_record": EvidenceSchemaValidator(),
            "asset_context": AssetContextValidator(),
            "vulnerability_intelligence":
                VulnerabilityIntelligenceValidator(),
        }

        self.reference_id_fields = {
            "evidence_record": "evidence_id",
            "asset_context": "asset_id",
            "vulnerability_intelligence": "intelligence_id",
        }

    def validate(
        self,
        record: dict[str, Any],
    ) -> DecisionValidationResult:
        schema_errors = self._validate_schema(record)

        if schema_errors:
            return DecisionValidationResult(
                schema_valid=False,
                business_rules_valid=False,
                status="rejected",
                errors=schema_errors,
            )

        reference_errors, reference_warnings, loaded_records = (
            self._validate_references(record)
        )

        business_errors, business_warnings = (
            self._validate_business_rules(
                record=record,
                loaded_records=loaded_records,
            )
        )

        errors = reference_errors + business_errors
        warnings = reference_warnings + business_warnings

        if errors:
            return DecisionValidationResult(
                schema_valid=True,
                business_rules_valid=False,
                status="rejected",
                errors=errors,
                warnings=warnings,
            )

        status = "accepted_with_warnings" if warnings else "accepted"

        return DecisionValidationResult(
            schema_valid=True,
            business_rules_valid=True,
            status=status,
            warnings=warnings,
        )

    def validate_file(
        self,
        record_path: Path | str,
    ) -> DecisionValidationResult:
        path = Path(record_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Decision Record not found: {path}"
            )

        with path.open("r", encoding="utf-8") as file:
            record = json.load(file)

        if not isinstance(record, dict):
            return DecisionValidationResult(
                schema_valid=False,
                business_rules_valid=False,
                status="rejected",
                errors=[
                    DecisionValidationIssue(
                        code="RECORD_NOT_OBJECT",
                        message=(
                            "Decision Record must be a JSON object."
                        ),
                    )
                ],
            )

        return self.validate(record)

    def _validate_schema(
        self,
        record: dict[str, Any],
    ) -> list[DecisionValidationIssue]:
        issues: list[DecisionValidationIssue] = []

        sorted_errors = sorted(
            self.validator.iter_errors(record),
            key=lambda error: list(error.absolute_path),
        )

        for error in sorted_errors:
            field_path = ".".join(
                str(part) for part in error.absolute_path
            )

            issues.append(
                DecisionValidationIssue(
                    code="SCHEMA_VALIDATION_ERROR",
                    message=error.message,
                    field_path=field_path or None,
                )
            )

        return issues

    def _all_references(
        self,
        record: dict[str, Any],
    ) -> list[dict[str, Any]]:
        inputs = record["input_records"]

        return [
            inputs["asset_context"],
            inputs["vulnerability_intelligence"],
            *inputs["evidence_records"],
        ]

    def _resolve_safe_path(
        self,
        relative_path: str,
    ) -> Path | None:
        supplied_path = Path(relative_path)

        if supplied_path.is_absolute():
            return None

        resolved = (self.project_root / supplied_path).resolve()

        if (
            resolved != self.project_root
            and self.project_root not in resolved.parents
        ):
            return None

        return resolved

    def _validate_references(
        self,
        record: dict[str, Any],
    ) -> tuple[
        list[DecisionValidationIssue],
        list[DecisionValidationIssue],
        dict[str, dict[str, Any]],
    ]:
        errors: list[DecisionValidationIssue] = []
        warnings: list[DecisionValidationIssue] = []
        loaded_records: dict[str, dict[str, Any]] = {}

        seen_references: set[tuple[str, str]] = set()

        for index, reference in enumerate(self._all_references(record)):
            field_path = f"input_records.reference.{index}"
            record_type = reference["record_type"]
            record_id = reference["record_id"]

            reference_key = (record_type, record_id)

            if reference_key in seen_references:
                errors.append(
                    DecisionValidationIssue(
                        code="DUPLICATE_INPUT_REFERENCE",
                        message=(
                            f"Duplicate input reference: {reference_key}"
                        ),
                        field_path=field_path,
                    )
                )
                continue

            seen_references.add(reference_key)

            resolved_path = self._resolve_safe_path(
                reference["relative_path"]
            )

            if resolved_path is None:
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_PATH_ESCAPE",
                        message=(
                            "Input reference resolves outside the "
                            "AegisSec project root."
                        ),
                        field_path=f"{field_path}.relative_path",
                    )
                )
                continue

            if not resolved_path.exists():
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_RECORD_NOT_FOUND",
                        message=(
                            f"Referenced record not found: "
                            f"{reference['relative_path']}"
                        ),
                        field_path=f"{field_path}.relative_path",
                    )
                )
                continue

            actual_hash = sha256_file(resolved_path)

            if actual_hash != reference["sha256"]:
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_RECORD_HASH_MISMATCH",
                        message=(
                            "Referenced input hash does not match the "
                            "current file contents."
                        ),
                        field_path=f"{field_path}.sha256",
                    )
                )

            try:
                with resolved_path.open("r", encoding="utf-8") as file:
                    referenced_record = json.load(file)
            except json.JSONDecodeError as exc:
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_RECORD_INVALID_JSON",
                        message=str(exc),
                        field_path=f"{field_path}.relative_path",
                    )
                )
                continue

            if not isinstance(referenced_record, dict):
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_RECORD_NOT_OBJECT",
                        message=(
                            "Referenced input must be a JSON object."
                        ),
                        field_path=f"{field_path}.relative_path",
                    )
                )
                continue

            expected_id_field = self.reference_id_fields[record_type]
            actual_record_id = referenced_record.get(expected_id_field)

            if actual_record_id != record_id:
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_RECORD_ID_MISMATCH",
                        message=(
                            f"Reference expects {record_id}, but file "
                            f"contains {actual_record_id}."
                        ),
                        field_path=f"{field_path}.record_id",
                    )
                )

            actual_schema_version = referenced_record.get(
                "schema_version"
            )

            if actual_schema_version != reference["schema_version"]:
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_SCHEMA_VERSION_MISMATCH",
                        message=(
                            "Referenced input schema version does not "
                            "match the Decision Record."
                        ),
                        field_path=f"{field_path}.schema_version",
                    )
                )

            validator = self.reference_validators[record_type]
            validation_result = validator.validate(referenced_record)

            if not validation_result.valid:
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_RECORD_VALIDATION_FAILED",
                        message=(
                            f"Referenced {record_type} did not pass "
                            "validation."
                        ),
                        field_path=field_path,
                    )
                )

            if validation_result.status != reference["validation_status"]:
                errors.append(
                    DecisionValidationIssue(
                        code="INPUT_VALIDATION_STATUS_MISMATCH",
                        message=(
                            f"Reference declares "
                            f"{reference['validation_status']}, but "
                            f"validator returned "
                            f"{validation_result.status}."
                        ),
                        field_path=(
                            f"{field_path}.validation_status"
                        ),
                    )
                )

            loaded_records[record_type] = referenced_record

            if validation_result.warnings:
                warnings.append(
                    DecisionValidationIssue(
                        code="INPUT_ACCEPTED_WITH_WARNINGS",
                        message=(
                            f"Referenced {record_type} contains "
                            f"{len(validation_result.warnings)} warning(s)."
                        ),
                        field_path=field_path,
                    )
                )

        return errors, warnings, loaded_records

    def _known_evidence_ids(
        self,
        loaded_records: dict[str, dict[str, Any]],
    ) -> set[str]:
        evidence_ids: set[str] = set()

        evidence_record = loaded_records.get("evidence_record")

        if evidence_record:
            evidence_id = evidence_record.get("evidence_id")

            if isinstance(evidence_id, str):
                evidence_ids.add(evidence_id)

        asset = loaded_records.get("asset_context")

        if asset:
            evidence_ids.update(
                asset.get("provenance", {}).get(
                    "source_evidence_ids",
                    [],
                )
            )

        intelligence = loaded_records.get(
            "vulnerability_intelligence"
        )

        if intelligence:
            evidence_ids.update(
                intelligence.get("provenance", {}).get(
                    "source_evidence_ids",
                    [],
                )
            )

        return evidence_ids

    def _validate_business_rules(
        self,
        record: dict[str, Any],
        loaded_records: dict[str, dict[str, Any]],
    ) -> tuple[
        list[DecisionValidationIssue],
        list[DecisionValidationIssue],
    ]:
        errors: list[DecisionValidationIssue] = []
        warnings: list[DecisionValidationIssue] = []

        affectedness = record["affectedness"]
        policy = record["policy_decision"]
        ml = record["ml_advisory"]
        arbitration = record["arbitration"]
        human = record["human_disposition"]
        provenance = record["provenance"]

        known_evidence_ids = self._known_evidence_ids(
            loaded_records
        )

        # Rule 1: Decision Record hash must verify.
        if not verify_decision_record_hash(record):
            errors.append(
                DecisionValidationIssue(
                    code="DECISION_RECORD_HASH_MISMATCH",
                    message=(
                        "Decision Record contents do not match the "
                        "stored audit hash."
                    ),
                    field_path="audit.record_hash",
                )
            )

        # Rule 2: Component evidence must be traceable.
        for evidence_id in record["component_instance"]["evidence_ids"]:
            if evidence_id not in known_evidence_ids:
                errors.append(
                    DecisionValidationIssue(
                        code="COMPONENT_EVIDENCE_NOT_FOUND",
                        message=(
                            f"Component evidence {evidence_id} is not "
                            "present in the validated input lineage."
                        ),
                        field_path=(
                            "component_instance.evidence_ids"
                        ),
                    )
                )

        # Rule 3: Affectedness evidence must be traceable.
        for evidence_id in affectedness["supporting_evidence_ids"]:
            if evidence_id not in known_evidence_ids:
                errors.append(
                    DecisionValidationIssue(
                        code="AFFECTEDNESS_EVIDENCE_NOT_FOUND",
                        message=(
                            f"Affectedness evidence {evidence_id} is not "
                            "present in the validated input lineage."
                        ),
                        field_path=(
                            "affectedness.supporting_evidence_ids"
                        ),
                    )
                )

        # Rule 4: Policy-rule evidence must be traceable.
        for rule_index, rule in enumerate(policy["triggered_rules"]):
            for evidence_id in rule["supporting_evidence_ids"]:
                if evidence_id not in known_evidence_ids:
                    errors.append(
                        DecisionValidationIssue(
                            code="POLICY_EVIDENCE_NOT_FOUND",
                            message=(
                                f"Policy evidence {evidence_id} is not "
                                "present in the validated input lineage."
                            ),
                            field_path=(
                                "policy_decision.triggered_rules."
                                f"{rule_index}.supporting_evidence_ids"
                            ),
                        )
                    )

        # Rule 5: Unknown affectedness requires human review.
        if affectedness["status"] in {
            "unknown",
            "probably_affected",
        }:
            if not arbitration["human_review_required"]:
                errors.append(
                    DecisionValidationIssue(
                        code="UNCERTAIN_AFFECTEDNESS_REQUIRES_REVIEW",
                        message=(
                            "Unknown or probably-affected findings "
                            "require human review."
                        ),
                        field_path=(
                            "arbitration.human_review_required"
                        ),
                    )
                )

        # Rule 6: Not-affected and fixed decisions need affirmative proof.
        if affectedness["status"] in {
            "not_affected",
            "fixed",
        }:
            if not affectedness["supporting_evidence_ids"]:
                errors.append(
                    DecisionValidationIssue(
                        code="NEGATIVE_AFFECTEDNESS_WITHOUT_EVIDENCE",
                        message=(
                            "Not-affected or fixed determinations require "
                            "affirmative supporting evidence."
                        ),
                        field_path=(
                            "affectedness.supporting_evidence_ids"
                        ),
                    )
                )

            confidence = affectedness["confidence"]

            if confidence is None or confidence < 0.8:
                errors.append(
                    DecisionValidationIssue(
                        code="NEGATIVE_AFFECTEDNESS_LOW_CONFIDENCE",
                        message=(
                            "Not-affected or fixed determinations require "
                            "confidence of at least 0.8."
                        ),
                        field_path="affectedness.confidence",
                    )
                )

        # Rule 7: Completed policy decisions require complete metadata.
        if policy["status"] == "completed":
            required_policy_values = {
                "policy_id": policy["policy_id"],
                "policy_version": policy["policy_version"],
                "evaluated_at": policy["evaluated_at"],
            }

            for field_name, value in required_policy_values.items():
                if value is None or value == "":
                    errors.append(
                        DecisionValidationIssue(
                            code="COMPLETED_POLICY_FIELD_MISSING",
                            message=(
                                "Completed policy decision requires "
                                f"{field_name}."
                            ),
                            field_path=(
                                f"policy_decision.{field_name}"
                            ),
                        )
                    )

            if policy["action"] == "UNKNOWN":
                errors.append(
                    DecisionValidationIssue(
                        code="COMPLETED_POLICY_ACTION_UNKNOWN",
                        message=(
                            "Completed policy decision cannot use an "
                            "UNKNOWN action."
                        ),
                        field_path="policy_decision.action",
                    )
                )

            if policy["minimum_priority"] == "UNKNOWN":
                errors.append(
                    DecisionValidationIssue(
                        code="COMPLETED_POLICY_PRIORITY_UNKNOWN",
                        message=(
                            "Completed policy decision cannot use an "
                            "UNKNOWN minimum priority."
                        ),
                        field_path=(
                            "policy_decision.minimum_priority"
                        ),
                    )
                )

        # Rule 8: Final system priority may never fall below policy floor.
        floor = policy["minimum_priority"]
        system_priority = arbitration["final_system_priority"]

        if (
            floor != "UNKNOWN"
            and system_priority != "UNKNOWN"
            and PRIORITY_RANK[system_priority]
            < PRIORITY_RANK[floor]
        ):
            errors.append(
                DecisionValidationIssue(
                    code="POLICY_FLOOR_VIOLATION",
                    message=(
                        "Final system priority is lower than the "
                        "policy-mandated minimum."
                    ),
                    field_path=(
                        "arbitration.final_system_priority"
                    ),
                )
            )

        # Rule 9: Completed ML requires complete, calibrated metadata.
        if ml["status"] == "completed":
            required_ml_values = {
                "model_id": ml["model_id"],
                "model_version": ml["model_version"],
                "predicted_priority": ml["predicted_priority"],
                "confidence": ml["confidence"],
                "calibrated": ml["calibrated"],
                "evaluated_at": ml["evaluated_at"],
            }

            for field_name, value in required_ml_values.items():
                if value is None:
                    errors.append(
                        DecisionValidationIssue(
                            code="COMPLETED_ML_FIELD_MISSING",
                            message=(
                                "Completed ML advisory requires "
                                f"{field_name}."
                            ),
                            field_path=f"ml_advisory.{field_name}",
                        )
                    )

            probabilities = ml["probabilities"]

            if probabilities:
                probability_sum = sum(probabilities.values())

                if abs(probability_sum - 1.0) > 0.02:
                    errors.append(
                        DecisionValidationIssue(
                            code="ML_PROBABILITIES_NOT_NORMALIZED",
                            message=(
                                "ML class probabilities must sum to "
                                "approximately 1.0."
                            ),
                            field_path="ml_advisory.probabilities",
                        )
                    )
            else:
                errors.append(
                    DecisionValidationIssue(
                        code="COMPLETED_ML_PROBABILITIES_MISSING",
                        message=(
                            "Completed ML advisory requires class "
                            "probabilities."
                        ),
                        field_path="ml_advisory.probabilities",
                    )
                )

        if ml["status"] == "not_run":
            warnings.append(
                DecisionValidationIssue(
                    code="ML_ADVISORY_NOT_RUN",
                    message=(
                        "The ML advisory model has not been run. "
                        "The Decision Record currently relies on policy."
                    ),
                    field_path="ml_advisory.status",
                )
            )

        # Rule 10: KEV + affected requires ACT and Critical-or-higher.
        intelligence = loaded_records.get(
            "vulnerability_intelligence"
        )

        if intelligence:
            kev_status = intelligence["kev"]["status"]

            if (
                kev_status == "listed"
                and affectedness["status"] in {
                    "affected",
                    "probably_affected",
                }
            ):
                if policy["action"] != "ACT":
                    errors.append(
                        DecisionValidationIssue(
                            code="KEV_AFFECTED_REQUIRES_ACT",
                            message=(
                                "A KEV-listed affected vulnerability "
                                "requires ACT."
                            ),
                            field_path="policy_decision.action",
                        )
                    )

                if (
                    PRIORITY_RANK[policy["minimum_priority"]]
                    < PRIORITY_RANK["CRITICAL"]
                ):
                    errors.append(
                        DecisionValidationIssue(
                            code="KEV_AFFECTED_PRIORITY_TOO_LOW",
                            message=(
                                "A KEV-listed affected vulnerability "
                                "requires at least a Critical policy floor."
                            ),
                            field_path=(
                                "policy_decision.minimum_priority"
                            ),
                        )
                    )

                if not arbitration["human_review_required"]:
                    errors.append(
                        DecisionValidationIssue(
                            code="KEV_AFFECTED_REQUIRES_REVIEW",
                            message=(
                                "A KEV-listed affected vulnerability "
                                "requires accountable human review."
                            ),
                            field_path=(
                                "arbitration.human_review_required"
                            ),
                        )
                    )

        # Rule 11: Pending review status must actually require review.
        if (
            record["decision_status"] == "pending_human_review"
            and not arbitration["human_review_required"]
        ):
            errors.append(
                DecisionValidationIssue(
                    code="PENDING_STATUS_WITHOUT_REVIEW",
                    message=(
                        "pending_human_review requires "
                        "human_review_required=true."
                    ),
                    field_path="decision_status",
                )
            )

        # Rule 12: Completed human decisions require accountable details.
        if human["status"] != "pending":
            required_human_values = {
                "analyst": human["analyst"],
                "final_priority": human["final_priority"],
                "final_action": human["final_action"],
                "justification": human["justification"],
                "decided_at": human["decided_at"],
            }

            for field_name, value in required_human_values.items():
                if value is None or value == "":
                    errors.append(
                        DecisionValidationIssue(
                            code="HUMAN_DISPOSITION_FIELD_MISSING",
                            message=(
                                "Completed human disposition requires "
                                f"{field_name}."
                            ),
                            field_path=(
                                f"human_disposition.{field_name}"
                            ),
                        )
                    )

        if human["status"] == "pending":
            warnings.append(
                DecisionValidationIssue(
                    code="HUMAN_DISPOSITION_PENDING",
                    message=(
                        "The Decision Record is awaiting accountable "
                        "human disposition."
                    ),
                    field_path="human_disposition.status",
                )
            )

        # Rule 13: Overrides require reason, approval and expiry.
        if human["override"]:
            override_requirements = {
                "override_reason": human["override_reason"],
                "approved_by": human["approved_by"],
                "expires_at": human["expires_at"],
            }

            for field_name, value in override_requirements.items():
                if value is None or value == "":
                    errors.append(
                        DecisionValidationIssue(
                            code="OVERRIDE_GOVERNANCE_FIELD_MISSING",
                            message=(
                                "Human override requires "
                                f"{field_name}."
                            ),
                            field_path=(
                                f"human_disposition.{field_name}"
                            ),
                        )
                    )

        # Rule 14: Non-overridable policy floors cannot be reduced.
        non_overridable_floor = any(
            rule["non_overridable"]
            and rule["effect"] == "set_priority_floor"
            for rule in policy["triggered_rules"]
        )

        if (
            non_overridable_floor
            and human["final_priority"] is not None
            and PRIORITY_RANK[human["final_priority"]]
            < PRIORITY_RANK[policy["minimum_priority"]]
        ):
            errors.append(
                DecisionValidationIssue(
                    code="NON_OVERRIDABLE_POLICY_FLOOR_VIOLATION",
                    message=(
                        "Human disposition cannot reduce a "
                        "non-overridable policy floor."
                    ),
                    field_path="human_disposition.final_priority",
                )
            )

        # Rule 15: Controlled fixtures must remain explicitly disclosed.
        if provenance["origin_type"] == "controlled_fixture":
            warnings.append(
                DecisionValidationIssue(
                    code="CONTROLLED_DECISION_FIXTURE",
                    message=(
                        "This Decision Record is a controlled fixture "
                        "and must not be presented as an operational case."
                    ),
                    field_path="provenance.origin_type",
                )
            )

        return errors, warnings

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "aegis_evidence_record.schema.json"
)


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    field_path: str | None = None


@dataclass
class EvidenceValidationResult:
    schema_valid: bool
    business_rules_valid: bool
    status: str
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)

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


class EvidenceSchemaValidator:
    """Validates AegisSec evidence records against schema and core invariants."""

    def __init__(self, schema_path: Path | str = DEFAULT_SCHEMA_PATH) -> None:
        self.schema_path = Path(schema_path)

        if not self.schema_path.exists():
            raise FileNotFoundError(
                f"Evidence schema not found: {self.schema_path}"
            )

        with self.schema_path.open("r", encoding="utf-8") as file:
            self.schema = json.load(file)

        Draft202012Validator.check_schema(self.schema)

        self.validator = Draft202012Validator(
            self.schema,
            format_checker=FormatChecker(),
        )

    def validate(self, record: dict[str, Any]) -> EvidenceValidationResult:
        schema_errors = self._validate_schema(record)

        if schema_errors:
            return EvidenceValidationResult(
                schema_valid=False,
                business_rules_valid=False,
                status="rejected",
                errors=schema_errors,
            )

        business_errors, warnings = self._validate_business_rules(record)

        if business_errors:
            return EvidenceValidationResult(
                schema_valid=True,
                business_rules_valid=False,
                status="rejected",
                errors=business_errors,
                warnings=warnings,
            )

        status = "accepted_with_warnings" if warnings else "accepted"

        return EvidenceValidationResult(
            schema_valid=True,
            business_rules_valid=True,
            status=status,
            warnings=warnings,
        )

    def validate_file(self, record_path: Path | str) -> EvidenceValidationResult:
        path = Path(record_path)

        if not path.exists():
            raise FileNotFoundError(f"Evidence record not found: {path}")

        with path.open("r", encoding="utf-8") as file:
            record = json.load(file)

        if not isinstance(record, dict):
            return EvidenceValidationResult(
                schema_valid=False,
                business_rules_valid=False,
                status="rejected",
                errors=[
                    ValidationIssue(
                        code="RECORD_NOT_OBJECT",
                        message="Evidence record must be a JSON object.",
                        field_path=None,
                    )
                ],
            )

        return self.validate(record)

    def _validate_schema(
        self,
        record: dict[str, Any],
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []

        sorted_errors = sorted(
            self.validator.iter_errors(record),
            key=lambda error: list(error.absolute_path),
        )

        for error in sorted_errors:
            field_path = ".".join(str(part) for part in error.absolute_path)

            issues.append(
                ValidationIssue(
                    code="SCHEMA_VALIDATION_ERROR",
                    message=error.message,
                    field_path=field_path or None,
                )
            )

        return issues

    def _validate_business_rules(
        self,
        record: dict[str, Any],
    ) -> tuple[list[ValidationIssue], list[ValidationIssue]]:
        errors: list[ValidationIssue] = []
        warnings: list[ValidationIssue] = []

        authorization = record["authorization"]
        integrity = record["integrity"]
        freshness = record.get("freshness")
        parser = record["parser"]
        trust = record["trust"]
        validation = record["validation"]

        # Rule 1: Unauthorized evidence must never be accepted.
        if authorization["status"] == "unauthorized":
            errors.append(
                ValidationIssue(
                    code="UNAUTHORIZED_EVIDENCE",
                    message=(
                        "Unauthorized evidence cannot enter the AegisSec "
                        "decision pipeline."
                    ),
                    field_path="authorization.status",
                )
            )

        # Rule 2: Prohibited-use evidence must never be accepted.
        if authorization["approved_use"] == "prohibited":
            errors.append(
                ValidationIssue(
                    code="PROHIBITED_EVIDENCE_USE",
                    message="Evidence is marked as prohibited for use.",
                    field_path="authorization.approved_use",
                )
            )

        # Rule 3: Verified integrity requires a cryptographic hash.
        if integrity["status"] == "verified":
            if integrity["hash_algorithm"] == "none":
                errors.append(
                    ValidationIssue(
                        code="VERIFIED_WITHOUT_HASH_ALGORITHM",
                        message=(
                            "Integrity cannot be verified when the hash "
                            "algorithm is 'none'."
                        ),
                        field_path="integrity.hash_algorithm",
                    )
                )

            if not integrity.get("content_hash"):
                errors.append(
                    ValidationIssue(
                        code="VERIFIED_WITHOUT_CONTENT_HASH",
                        message=(
                            "Verified integrity requires a cryptographic "
                            "content hash."
                        ),
                        field_path="integrity.content_hash",
                    )
                )

        # Rule 4: Failed integrity forces rejection.
        if integrity["status"] == "failed":
            errors.append(
                ValidationIssue(
                    code="INTEGRITY_CHECK_FAILED",
                    message="Evidence failed its integrity check.",
                    field_path="integrity.status",
                )
            )

        # Rule 5: Failed parsing forces rejection.
        if parser["parse_status"] == "failed":
            errors.append(
                ValidationIssue(
                    code="PARSER_FAILED",
                    message="The evidence parser failed.",
                    field_path="parser.parse_status",
                )
            )

        # Rule 6: Stale or expired evidence cannot be high trust.
        if freshness and freshness["status"] in {"stale", "expired"}:
            if trust["summary_level"] == "high":
                errors.append(
                    ValidationIssue(
                        code="STALE_EVIDENCE_HIGH_TRUST",
                        message=(
                            "Stale or expired evidence cannot receive a "
                            "high trust classification."
                        ),
                        field_path="trust.summary_level",
                    )
                )

            warnings.append(
                ValidationIssue(
                    code="EVIDENCE_NOT_CURRENT",
                    message=(
                        "The evidence is stale or expired and may require "
                        "refresh or human review."
                    ),
                    field_path="freshness.status",
                )
            )

        # Rule 7: Low or rejected trust cannot be silently accepted.
        if trust["summary_level"] == "rejected":
            errors.append(
                ValidationIssue(
                    code="TRUST_ENGINE_REJECTED_EVIDENCE",
                    message="The trust engine rejected this evidence.",
                    field_path="trust.summary_level",
                )
            )

        if (
            trust["summary_level"] == "low"
            and validation["status"] == "accepted"
        ):
            errors.append(
                ValidationIssue(
                    code="LOW_TRUST_SILENT_ACCEPTANCE",
                    message=(
                        "Low-trust evidence cannot be accepted without "
                        "warnings, quarantine, or human review."
                    ),
                    field_path="validation.status",
                )
            )

        # Rule 8: Open high or critical conflicts require quarantine.
        unresolved_conflicts = [
            conflict
            for conflict in record.get("conflicts", [])
            if conflict["severity"] in {"critical", "high"}
            and conflict["resolution_status"] in {"open", "under_review"}
        ]

        if unresolved_conflicts:
            errors.append(
                ValidationIssue(
                    code="UNRESOLVED_HIGH_SEVERITY_CONFLICT",
                    message=(
                        "Evidence contains unresolved high or critical "
                        "conflicts and must be quarantined."
                    ),
                    field_path="conflicts",
                )
            )

        # Rule 9: Unknown authorization requires warning/review.
        if authorization["status"] == "authorization_unknown":
            warnings.append(
                ValidationIssue(
                    code="AUTHORIZATION_REVIEW_REQUIRED",
                    message=(
                        "Authorization is unknown. Evidence must not be used "
                        "for automated decision-making before approval."
                    ),
                    field_path="authorization.status",
                )
            )

        # Rule 10: Synthetic or model-generated evidence must be disclosed.
        origin_type = record["provenance"]["origin_type"]

        if origin_type in {"synthetic", "model_generated"}:
            warnings.append(
                ValidationIssue(
                    code="NON_OBSERVED_EVIDENCE",
                    message=(
                        f"Evidence origin is '{origin_type}'. It must not be "
                        "presented as observed operational evidence."
                    ),
                    field_path="provenance.origin_type",
                )
            )

        return errors, warnings

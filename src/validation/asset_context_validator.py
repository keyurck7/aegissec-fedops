from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "aegis_asset_context.schema.json"
)


@dataclass(frozen=True)
class AssetValidationIssue:
    code: str
    message: str
    field_path: str | None = None


@dataclass
class AssetValidationResult:
    schema_valid: bool
    business_rules_valid: bool
    status: str
    errors: list[AssetValidationIssue] = field(default_factory=list)
    warnings: list[AssetValidationIssue] = field(default_factory=list)

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


class AssetContextValidator:
    """Validates AegisSec asset context records and mission-context invariants."""

    HIGH_IMPACTS = {"severe", "catastrophic"}

    def __init__(self, schema_path: Path | str = DEFAULT_SCHEMA_PATH) -> None:
        self.schema_path = Path(schema_path)

        if not self.schema_path.exists():
            raise FileNotFoundError(
                f"Asset context schema not found: {self.schema_path}"
            )

        with self.schema_path.open("r", encoding="utf-8") as file:
            self.schema = json.load(file)

        Draft202012Validator.check_schema(self.schema)

        self.validator = Draft202012Validator(
            self.schema,
            format_checker=FormatChecker(),
        )

    def validate(self, record: dict[str, Any]) -> AssetValidationResult:
        schema_errors = self._validate_schema(record)

        if schema_errors:
            return AssetValidationResult(
                schema_valid=False,
                business_rules_valid=False,
                status="rejected",
                errors=schema_errors,
            )

        business_errors, warnings = self._validate_business_rules(record)

        if business_errors:
            return AssetValidationResult(
                schema_valid=True,
                business_rules_valid=False,
                status="rejected",
                errors=business_errors,
                warnings=warnings,
            )

        status = "accepted_with_warnings" if warnings else "accepted"

        return AssetValidationResult(
            schema_valid=True,
            business_rules_valid=True,
            status=status,
            warnings=warnings,
        )

    def validate_file(
        self,
        record_path: Path | str,
    ) -> AssetValidationResult:
        path = Path(record_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Asset context record not found: {path}"
            )

        with path.open("r", encoding="utf-8") as file:
            record = json.load(file)

        if not isinstance(record, dict):
            return AssetValidationResult(
                schema_valid=False,
                business_rules_valid=False,
                status="rejected",
                errors=[
                    AssetValidationIssue(
                        code="RECORD_NOT_OBJECT",
                        message="Asset context record must be a JSON object.",
                    )
                ],
            )

        return self.validate(record)

    def _validate_schema(
        self,
        record: dict[str, Any],
    ) -> list[AssetValidationIssue]:
        issues: list[AssetValidationIssue] = []

        sorted_errors = sorted(
            self.validator.iter_errors(record),
            key=lambda error: list(error.absolute_path),
        )

        for error in sorted_errors:
            field_path = ".".join(str(part) for part in error.absolute_path)

            issues.append(
                AssetValidationIssue(
                    code="SCHEMA_VALIDATION_ERROR",
                    message=error.message,
                    field_path=field_path or None,
                )
            )

        return issues

    def _validate_business_rules(
        self,
        record: dict[str, Any],
    ) -> tuple[list[AssetValidationIssue], list[AssetValidationIssue]]:
        errors: list[AssetValidationIssue] = []
        warnings: list[AssetValidationIssue] = []

        sector = record["sector_context"]
        mission = record["mission"]
        criticality = record["criticality"]
        environment = record["environment"]
        exposure = record["exposure"]
        impacts = record["impact_assessment"]
        data_profile = record["data_profile"]
        resilience = record["resilience"]
        provenance = record["provenance"]

        # Invariant 1: Sector name cannot be used directly as a priority input.
        if sector["sector_label_is_decision_input"] is not False:
            errors.append(
                AssetValidationIssue(
                    code="SECTOR_LABEL_PRIORITY_BIAS",
                    message=(
                        "Sector labels must not directly determine "
                        "vulnerability priority. Use documented consequences."
                    ),
                    field_path=(
                        "sector_context.sector_label_is_decision_input"
                    ),
                )
            )

        # Invariant 2: Mission-essential assets cannot be classified as low.
        if (
            mission["mission_essential"]
            and criticality["level"] in {"low", "unknown"}
        ):
            errors.append(
                AssetValidationIssue(
                    code="MISSION_CRITICALITY_CONFLICT",
                    message=(
                        "A mission-essential asset cannot have low or "
                        "unknown criticality."
                    ),
                    field_path="criticality.level",
                )
            )

        # Invariant 3: Essential mission tier must be high or very high.
        if (
            mission["mission_tier"] == "essential"
            and criticality["level"] not in {"high", "very_high"}
        ):
            errors.append(
                AssetValidationIssue(
                    code="ESSENTIAL_TIER_UNDERRATED",
                    message=(
                        "An essential mission-tier asset must have high or "
                        "very-high criticality."
                    ),
                    field_path="criticality.level",
                )
            )

        # Invariant 4: High-criticality production assets require resilience.
        if (
            environment["lifecycle_stage"] == "production"
            and criticality["level"] in {"high", "very_high"}
        ):
            required_resilience = {
                "recovery_time_objective_hours":
                    resilience["recovery_time_objective_hours"],
                "maximum_tolerable_downtime_hours":
                    resilience["maximum_tolerable_downtime_hours"],
            }

            for field_name, value in required_resilience.items():
                if value is None:
                    errors.append(
                        AssetValidationIssue(
                            code="MISSING_RESILIENCE_OBJECTIVE",
                            message=(
                                "High-criticality production assets require "
                                f"a defined {field_name}."
                            ),
                            field_path=f"resilience.{field_name}",
                        )
                    )

        # Invariant 5: RTO must not exceed maximum tolerable downtime.
        rto = resilience["recovery_time_objective_hours"]
        mtd = resilience["maximum_tolerable_downtime_hours"]

        if rto is not None and mtd is not None and rto > mtd:
            errors.append(
                AssetValidationIssue(
                    code="RTO_EXCEEDS_TOLERABLE_DOWNTIME",
                    message=(
                        "Recovery time objective cannot exceed maximum "
                        "tolerable downtime."
                    ),
                    field_path="resilience.recovery_time_objective_hours",
                )
            )

        # Invariant 6: Severe impact claims require supporting evidence.
        impact_fields = [
            "confidentiality",
            "integrity",
            "availability",
            "public_service",
            "public_wellbeing",
            "patient_safety",
            "mission_readiness",
            "legal_regulatory",
        ]

        for impact_name in impact_fields:
            impact = impacts[impact_name]

            if (
                impact["severity"] in self.HIGH_IMPACTS
                and not impact["evidence_ids"]
            ):
                errors.append(
                    AssetValidationIssue(
                        code="SEVERE_IMPACT_WITHOUT_EVIDENCE",
                        message=(
                            f"Severe or catastrophic {impact_name} impact "
                            "requires supporting evidence."
                        ),
                        field_path=(
                            f"impact_assessment.{impact_name}.evidence_ids"
                        ),
                    )
                )

        # Invariant 7: Unknown exposure on production assets requires review.
        exposure_unknown = any(
            exposure[field] is None
            for field in [
                "internet_accessible",
                "externally_accessible",
                "authentication_required",
            ]
        ) or exposure["network_zone"] == "unknown"

        if (
            environment["lifecycle_stage"] == "production"
            and exposure_unknown
        ):
            warnings.append(
                AssetValidationIssue(
                    code="PRODUCTION_EXPOSURE_UNKNOWN",
                    message=(
                        "Production exposure is incomplete. Automated "
                        "prioritization must use caution or request review."
                    ),
                    field_path="exposure",
                )
            )

        # Invariant 8: Publicly accessible assets without authentication warn.
        if (
            exposure["internet_accessible"] is True
            and exposure["authentication_required"] is False
        ):
            warnings.append(
                AssetValidationIssue(
                    code="PUBLIC_ACCESS_WITHOUT_AUTHENTICATION",
                    message=(
                        "The asset is internet accessible without required "
                        "authentication. Confirm that this is intentional."
                    ),
                    field_path="exposure.authentication_required",
                )
            )

        # Invariant 9: Sensitive-data booleans require matching categories.
        category_set = set(data_profile["data_categories"])

        if (
            data_profile["contains_personal_data"]
            and "personal_data" not in category_set
        ):
            errors.append(
                AssetValidationIssue(
                    code="PERSONAL_DATA_CATEGORY_MISSING",
                    message=(
                        "contains_personal_data is true but personal_data "
                        "is absent from data_categories."
                    ),
                    field_path="data_profile.data_categories",
                )
            )

        if (
            data_profile["contains_health_data"]
            and "health_data" not in category_set
        ):
            errors.append(
                AssetValidationIssue(
                    code="HEALTH_DATA_CATEGORY_MISSING",
                    message=(
                        "contains_health_data is true but health_data is "
                        "absent from data_categories."
                    ),
                    field_path="data_profile.data_categories",
                )
            )

        if (
            data_profile["contains_defence_sensitive_data"]
            and "defence_logistics_data" not in category_set
            and "classified_data" not in category_set
        ):
            errors.append(
                AssetValidationIssue(
                    code="DEFENCE_DATA_CATEGORY_MISSING",
                    message=(
                        "Defence-sensitive data is declared but no matching "
                        "data category is present."
                    ),
                    field_path="data_profile.data_categories",
                )
            )

        # Invariant 10: Synthetic demo assets must be explicitly disclosed.
        if provenance["origin_type"] == "synthetic_demo":
            warnings.append(
                AssetValidationIssue(
                    code="SYNTHETIC_DEMO_CONTEXT",
                    message=(
                        "This asset is a controlled demonstration fixture "
                        "and must not be presented as a live operational asset."
                    ),
                    field_path="provenance.origin_type",
                )
            )

        # Invariant 11: Pending or expired criticality needs review.
        if criticality["approval_status"] in {
            "pending_review",
            "expired",
        }:
            warnings.append(
                AssetValidationIssue(
                    code="CRITICALITY_APPROVAL_REVIEW_REQUIRED",
                    message=(
                        "Asset criticality is pending or expired and "
                        "requires accountable-owner review."
                    ),
                    field_path="criticality.approval_status",
                )
            )

        return errors, warnings

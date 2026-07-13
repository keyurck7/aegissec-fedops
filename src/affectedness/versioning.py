from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version


_PRERELEASE_PATTERNS = (
    (re.compile(r"(?i)-alpha([0-9]+)"), r"a\1"),
    (re.compile(r"(?i)-beta([0-9]+)"), r"b\1"),
    (re.compile(r"(?i)-rc([0-9]+)"), r"rc\1"),
)


@dataclass(frozen=True)
class ParsedVersion:
    raw_value: str
    normalized_value: str
    value: Version


@dataclass(frozen=True)
class RangeEvaluation:
    range_index: int
    range_type: str
    introduced: str | None
    fixed: str | None
    last_affected: str | None
    valid: bool
    affected: bool | None
    fixed_boundary_reached: bool
    before_introduced: bool
    reason_codes: tuple[str, ...]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "range_index": self.range_index,
            "range_type": self.range_type,
            "introduced": self.introduced,
            "fixed": self.fixed,
            "last_affected": self.last_affected,
            "valid": self.valid,
            "affected": self.affected,
            "fixed_boundary_reached": (
                self.fixed_boundary_reached
            ),
            "before_introduced": self.before_introduced,
            "reason_codes": list(self.reason_codes),
            "error": self.error,
        }


def normalize_version_text(value: str) -> str:
    """
    Normalize a limited set of common version forms.

    Unsupported or ambiguous formats are not guessed. They are rejected by
    packaging.version.Version and lead to an Unknown determination.
    """
    normalized = value.strip()

    if normalized.lower().startswith("v") and len(normalized) > 1:
        if normalized[1].isdigit():
            normalized = normalized[1:]

    for pattern, replacement in _PRERELEASE_PATTERNS:
        normalized = pattern.sub(replacement, normalized)

    return normalized


def parse_version(value: Any) -> ParsedVersion | None:
    if value is None:
        return None

    if not isinstance(value, str):
        value = str(value)

    normalized = normalize_version_text(value)

    if not normalized:
        return None

    try:
        parsed = Version(normalized)
    except InvalidVersion:
        return None

    return ParsedVersion(
        raw_value=value,
        normalized_value=normalized,
        value=parsed,
    )


def evaluate_version_range(
    component_version: ParsedVersion,
    version_range: dict[str, Any],
    range_index: int,
    supported_range_types: set[str],
) -> RangeEvaluation:
    range_type = str(
        version_range.get("range_type", "")
    ).upper()

    introduced_raw = version_range.get("introduced")
    fixed_raw = version_range.get("fixed")
    last_affected_raw = version_range.get("last_affected")

    if range_type not in supported_range_types:
        return RangeEvaluation(
            range_index=range_index,
            range_type=range_type,
            introduced=introduced_raw,
            fixed=fixed_raw,
            last_affected=last_affected_raw,
            valid=False,
            affected=None,
            fixed_boundary_reached=False,
            before_introduced=False,
            reason_codes=("UNSUPPORTED_RANGE_TYPE",),
            error=(
                f"Range type {range_type!r} is not supported by "
                "this engine version."
            ),
        )

    if (
        introduced_raw is None
        and fixed_raw is None
        and last_affected_raw is None
    ):
        return RangeEvaluation(
            range_index=range_index,
            range_type=range_type,
            introduced=None,
            fixed=None,
            last_affected=None,
            valid=False,
            affected=None,
            fixed_boundary_reached=False,
            before_introduced=False,
            reason_codes=("EMPTY_VERSION_RANGE",),
            error="Version range contains no boundaries.",
        )

    if fixed_raw is not None and last_affected_raw is not None:
        return RangeEvaluation(
            range_index=range_index,
            range_type=range_type,
            introduced=introduced_raw,
            fixed=fixed_raw,
            last_affected=last_affected_raw,
            valid=False,
            affected=None,
            fixed_boundary_reached=False,
            before_introduced=False,
            reason_codes=("AMBIGUOUS_UPPER_BOUND",),
            error=(
                "A range cannot contain both fixed and "
                "last_affected boundaries."
            ),
        )

    introduced = (
        parse_version(introduced_raw)
        if introduced_raw is not None
        else None
    )

    fixed = (
        parse_version(fixed_raw)
        if fixed_raw is not None
        else None
    )

    last_affected = (
        parse_version(last_affected_raw)
        if last_affected_raw is not None
        else None
    )

    invalid_boundaries = []

    if introduced_raw is not None and introduced is None:
        invalid_boundaries.append("introduced")

    if fixed_raw is not None and fixed is None:
        invalid_boundaries.append("fixed")

    if (
        last_affected_raw is not None
        and last_affected is None
    ):
        invalid_boundaries.append("last_affected")

    if invalid_boundaries:
        return RangeEvaluation(
            range_index=range_index,
            range_type=range_type,
            introduced=introduced_raw,
            fixed=fixed_raw,
            last_affected=last_affected_raw,
            valid=False,
            affected=None,
            fixed_boundary_reached=False,
            before_introduced=False,
            reason_codes=("INVALID_RANGE_BOUNDARY",),
            error=(
                "Unable to parse range boundaries: "
                f"{invalid_boundaries}"
            ),
        )

    if (
        introduced is not None
        and fixed is not None
        and fixed.value <= introduced.value
    ):
        return RangeEvaluation(
            range_index=range_index,
            range_type=range_type,
            introduced=introduced_raw,
            fixed=fixed_raw,
            last_affected=last_affected_raw,
            valid=False,
            affected=None,
            fixed_boundary_reached=False,
            before_introduced=False,
            reason_codes=("INVALID_RANGE_ORDER",),
            error=(
                "Fixed boundary must be greater than "
                "the introduced boundary."
            ),
        )

    if (
        introduced is not None
        and last_affected is not None
        and last_affected.value < introduced.value
    ):
        return RangeEvaluation(
            range_index=range_index,
            range_type=range_type,
            introduced=introduced_raw,
            fixed=fixed_raw,
            last_affected=last_affected_raw,
            valid=False,
            affected=None,
            fixed_boundary_reached=False,
            before_introduced=False,
            reason_codes=("INVALID_RANGE_ORDER",),
            error=(
                "last_affected must not precede introduced."
            ),
        )

    lower_bound_satisfied = (
        introduced is None
        or component_version.value >= introduced.value
    )

    before_introduced = (
        introduced is not None
        and component_version.value < introduced.value
    )

    if fixed is not None:
        upper_bound_satisfied = (
            component_version.value < fixed.value
        )

        fixed_boundary_reached = (
            component_version.value >= fixed.value
        )

    elif last_affected is not None:
        upper_bound_satisfied = (
            component_version.value <= last_affected.value
        )

        fixed_boundary_reached = False

    else:
        upper_bound_satisfied = True
        fixed_boundary_reached = False

    affected = (
        lower_bound_satisfied
        and upper_bound_satisfied
    )

    reason_codes = []

    if affected:
        reason_codes.append(
            "VERSION_WITHIN_AFFECTED_RANGE"
        )

    if before_introduced:
        reason_codes.append(
            "VERSION_PRECEDES_INTRODUCTION"
        )

    if fixed_boundary_reached:
        reason_codes.append(
            "FIXED_BOUNDARY_REACHED"
        )

    if not reason_codes:
        reason_codes.append(
            "VERSION_OUTSIDE_THIS_RANGE"
        )

    return RangeEvaluation(
        range_index=range_index,
        range_type=range_type,
        introduced=introduced_raw,
        fixed=fixed_raw,
        last_affected=last_affected_raw,
        valid=True,
        affected=affected,
        fixed_boundary_reached=fixed_boundary_reached,
        before_introduced=before_introduced,
        reason_codes=tuple(reason_codes),
        error=None,
    )

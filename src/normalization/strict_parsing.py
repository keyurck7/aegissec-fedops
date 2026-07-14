from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Generic, Iterable, Pattern, TypeVar
from urllib.parse import unquote


T = TypeVar("T")


class ParseStatus(str, Enum):
    PARSED = "parsed"
    MISSING = "missing"
    INVALID = "invalid"


DEFAULT_MISSING_TOKENS = frozenset(
    {
        "",
        "na",
        "n/a",
        "null",
        "none",
        "missing",
        "unknown",
        "not available",
        "not_available",
        "-",
        "--",
    }
)


TRUE_TOKENS = frozenset(
    {
        "true",
        "1",
        "yes",
        "y",
    }
)


FALSE_TOKENS = frozenset(
    {
        "false",
        "0",
        "no",
        "n",
    }
)


CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
PURL_PATTERN = re.compile(
    r"^pkg:(?P<type>[a-z0-9][a-z0-9.+-]*)/"
    r"(?P<path>[^@?#]+)"
    r"(?:@(?P<version>[^?#]+))?"
    r"(?:\?(?P<qualifiers>[^#]+))?"
    r"(?:#(?P<subpath>.+))?$"
)
MAX_RAW_TOKEN_LENGTH = 10_000
_FORMULA_PREFIXES = ("=", "+", "-", "@")


@dataclass(frozen=True)
class ParseOutcome(Generic[T]):
    field_name: str
    raw_value: Any
    normalized_text: str | None
    status: ParseStatus
    value: T | None
    code: str
    message: str

    @property
    def valid(self) -> bool:
        return self.status != ParseStatus.INVALID

    @property
    def missing(self) -> bool:
        return self.status == ParseStatus.MISSING

    @property
    def parsed(self) -> bool:
        return self.status == ParseStatus.PARSED

    def to_dict(self) -> dict[str, Any]:
        value = self.value

        if isinstance(value, (date, datetime)):
            serialized_value: Any = value.isoformat()
        else:
            serialized_value = value

        return {
            "field_name": self.field_name,
            "raw_value": self.raw_value,
            "normalized_text": self.normalized_text,
            "status": self.status.value,
            "value": serialized_value,
            "code": self.code,
            "message": self.message,
        }


def _normalized_text(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, str):
        return value.strip()

    return str(value).strip()


def _text_security_issue(
    value: Any,
    maximum_raw_length: int = MAX_RAW_TOKEN_LENGTH,
) -> tuple[str, str] | None:
    """Return a fail-closed security finding for hostile text tokens."""
    if not isinstance(value, str):
        return None

    if len(value) > maximum_raw_length:
        return (
            "RAW_TEXT_ABOVE_SECURITY_LIMIT",
            f"Input exceeds the {maximum_raw_length}-character security limit.",
        )

    for character in value:
        category = unicodedata.category(character)
        if category == "Cs":
            return (
                "UNICODE_SURROGATE_NOT_ALLOWED",
                "Unicode surrogate code points are not allowed.",
            )
        if category == "Cf":
            return (
                "UNICODE_FORMAT_CONTROL_NOT_ALLOWED",
                "Unicode format, bidi, and zero-width controls are not allowed.",
            )
        if category == "Cc":
            return (
                "CONTROL_CHARACTER_NOT_ALLOWED",
                "Control characters, including embedded line breaks and NUL bytes, are not allowed.",
            )

    return None


def _guard_text_value(
    value: Any,
    field_name: str,
    maximum_raw_length: int = MAX_RAW_TOKEN_LENGTH,
) -> ParseOutcome[Any] | None:
    issue = _text_security_issue(
        value,
        maximum_raw_length=maximum_raw_length,
    )
    if issue is None:
        return None
    code, message = issue
    return _invalid_outcome(
        field_name=field_name,
        raw_value=value,
        code=code,
        message=f"{field_name}: {message}",
    )


def _is_missing(
    value: Any,
    missing_tokens: Iterable[str] = DEFAULT_MISSING_TOKENS,
) -> bool:
    if value is None:
        return True

    if isinstance(value, str):
        normalized = value.strip().casefold()

        normalized_missing_tokens = {
            token.casefold()
            for token in missing_tokens
        }

        return normalized in normalized_missing_tokens

    return False


def _missing_outcome(
    field_name: str,
    raw_value: Any,
) -> ParseOutcome[Any]:
    return ParseOutcome(
        field_name=field_name,
        raw_value=raw_value,
        normalized_text=_normalized_text(raw_value),
        status=ParseStatus.MISSING,
        value=None,
        code="VALUE_MISSING",
        message=(
            f"{field_name} is missing. No replacement value was invented."
        ),
    )


def _invalid_outcome(
    field_name: str,
    raw_value: Any,
    code: str,
    message: str,
) -> ParseOutcome[Any]:
    return ParseOutcome(
        field_name=field_name,
        raw_value=raw_value,
        normalized_text=_normalized_text(raw_value),
        status=ParseStatus.INVALID,
        value=None,
        code=code,
        message=message,
    )


def _parsed_outcome(
    field_name: str,
    raw_value: Any,
    value: T,
    code: str = "VALUE_PARSED",
    message: str | None = None,
) -> ParseOutcome[T]:
    return ParseOutcome(
        field_name=field_name,
        raw_value=raw_value,
        normalized_text=_normalized_text(raw_value),
        status=ParseStatus.PARSED,
        value=value,
        code=code,
        message=message or f"{field_name} parsed successfully.",
    )


def parse_optional_boolean(
    value: Any,
    field_name: str,
) -> ParseOutcome[bool]:
    """
    Parse a nullable Boolean without using Python's bool(value) coercion.

    Accepted true tokens:
        true, 1, yes, y

    Accepted false tokens:
        false, 0, no, n

    Missing tokens become MISSING, not False.
    """

    if _is_missing(value):
        return _missing_outcome(field_name, value)

    text_guard = _guard_text_value(value, field_name)
    if text_guard is not None:
        return text_guard

    if isinstance(value, bool):
        return _parsed_outcome(
            field_name=field_name,
            raw_value=value,
            value=value,
            code="BOOLEAN_PARSED",
        )

    if isinstance(value, int) and not isinstance(value, bool):
        if value == 1:
            return _parsed_outcome(
                field_name=field_name,
                raw_value=value,
                value=True,
                code="BOOLEAN_PARSED",
            )

        if value == 0:
            return _parsed_outcome(
                field_name=field_name,
                raw_value=value,
                value=False,
                code="BOOLEAN_PARSED",
            )

        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_BOOLEAN_INTEGER",
            message=(
                f"{field_name} received integer {value}. "
                "Only 0 and 1 are valid Boolean integers."
            ),
        )

    if not isinstance(value, str):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_BOOLEAN_TYPE",
            message=(
                f"{field_name} must be a Boolean or recognized Boolean "
                f"token, not {type(value).__name__}."
            ),
        )

    normalized = value.strip().casefold()

    if normalized in TRUE_TOKENS:
        return _parsed_outcome(
            field_name=field_name,
            raw_value=value,
            value=True,
            code="BOOLEAN_PARSED",
        )

    if normalized in FALSE_TOKENS:
        return _parsed_outcome(
            field_name=field_name,
            raw_value=value,
            value=False,
            code="BOOLEAN_PARSED",
        )

    return _invalid_outcome(
        field_name=field_name,
        raw_value=value,
        code="UNRECOGNIZED_BOOLEAN_TOKEN",
        message=(
            f"{field_name} contains unrecognized Boolean token "
            f"{value!r}."
        ),
    )


def parse_required_boolean(
    value: Any,
    field_name: str,
) -> ParseOutcome[bool]:
    result = parse_optional_boolean(
        value=value,
        field_name=field_name,
    )

    if result.status == ParseStatus.MISSING:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="REQUIRED_BOOLEAN_MISSING",
            message=f"{field_name} is a required Boolean field.",
        )

    return result


def parse_optional_float(
    value: Any,
    field_name: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> ParseOutcome[float]:
    """
    Parse a finite floating-point number.

    Missing values remain None.
    Boolean values are rejected because bool is a subclass of int.
    NaN and infinity are rejected.
    Comma decimal notation is rejected as ambiguous.
    """

    if _is_missing(value):
        return _missing_outcome(field_name, value)

    text_guard = _guard_text_value(value, field_name)
    if text_guard is not None:
        return text_guard

    if isinstance(value, bool):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="BOOLEAN_NOT_ALLOWED_AS_NUMBER",
            message=(
                f"{field_name} cannot use a Boolean as a numeric value."
            ),
        )

    normalized = _normalized_text(value)

    if normalized is None:
        return _missing_outcome(field_name, value)

    if "," in normalized:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="AMBIGUOUS_NUMERIC_FORMAT",
            message=(
                f"{field_name} contains a comma. Use a period as the "
                "decimal separator and do not use thousands separators."
            ),
        )

    try:
        decimal_value = Decimal(normalized)
    except (InvalidOperation, ValueError):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_NUMERIC_VALUE",
            message=(
                f"{field_name} contains invalid numeric value "
                f"{value!r}."
            ),
        )

    if not decimal_value.is_finite():
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NON_FINITE_NUMERIC_VALUE",
            message=(
                f"{field_name} cannot contain NaN or infinity."
            ),
        )

    try:
        parsed_value = float(decimal_value)
    except (OverflowError, ValueError):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NUMERIC_CONVERSION_OVERFLOW",
            message=f"{field_name} cannot be represented as a finite float.",
        )

    if not math.isfinite(parsed_value):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NUMERIC_CONVERSION_OVERFLOW",
            message=f"{field_name} cannot be represented as a finite float.",
        )

    if minimum is not None and parsed_value < minimum:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NUMERIC_VALUE_BELOW_MINIMUM",
            message=(
                f"{field_name} must be at least {minimum}, "
                f"but received {parsed_value}."
            ),
        )

    if maximum is not None and parsed_value > maximum:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NUMERIC_VALUE_ABOVE_MAXIMUM",
            message=(
                f"{field_name} must be no greater than {maximum}, "
                f"but received {parsed_value}."
            ),
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=parsed_value,
        code="FLOAT_PARSED",
    )


def parse_required_float(
    value: Any,
    field_name: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> ParseOutcome[float]:
    result = parse_optional_float(
        value=value,
        field_name=field_name,
        minimum=minimum,
        maximum=maximum,
    )

    if result.status == ParseStatus.MISSING:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="REQUIRED_NUMBER_MISSING",
            message=f"{field_name} is a required numeric field.",
        )

    return result


def parse_optional_integer(
    value: Any,
    field_name: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> ParseOutcome[int]:
    if _is_missing(value):
        return _missing_outcome(field_name, value)

    text_guard = _guard_text_value(value, field_name)
    if text_guard is not None:
        return text_guard

    if isinstance(value, bool):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="BOOLEAN_NOT_ALLOWED_AS_INTEGER",
            message=(
                f"{field_name} cannot use a Boolean as an integer."
            ),
        )

    normalized = _normalized_text(value)

    if normalized is None:
        return _missing_outcome(field_name, value)

    if "," in normalized:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="AMBIGUOUS_INTEGER_FORMAT",
            message=(
                f"{field_name} contains a comma and cannot be parsed "
                "unambiguously."
            ),
        )

    try:
        decimal_value = Decimal(normalized)
    except (InvalidOperation, ValueError):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_INTEGER_VALUE",
            message=(
                f"{field_name} contains invalid integer value "
                f"{value!r}."
            ),
        )

    if not decimal_value.is_finite():
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NON_FINITE_INTEGER_VALUE",
            message=(
                f"{field_name} cannot contain NaN or infinity."
            ),
        )

    if decimal_value != decimal_value.to_integral_value():
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="FRACTIONAL_VALUE_NOT_INTEGER",
            message=(
                f"{field_name} requires an integer but received "
                f"{value!r}."
            ),
        )

    try:
        parsed_value = int(decimal_value)
    except (OverflowError, ValueError):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INTEGER_CONVERSION_OVERFLOW",
            message=f"{field_name} cannot be represented as an integer.",
        )

    if minimum is not None and parsed_value < minimum:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INTEGER_BELOW_MINIMUM",
            message=(
                f"{field_name} must be at least {minimum}, "
                f"but received {parsed_value}."
            ),
        )

    if maximum is not None and parsed_value > maximum:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INTEGER_ABOVE_MAXIMUM",
            message=(
                f"{field_name} must be no greater than {maximum}, "
                f"but received {parsed_value}."
            ),
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=parsed_value,
        code="INTEGER_PARSED",
    )


def parse_probability(
    value: Any,
    field_name: str,
) -> ParseOutcome[float]:
    return parse_optional_float(
        value=value,
        field_name=field_name,
        minimum=0.0,
        maximum=1.0,
    )


def parse_cvss_score(
    value: Any,
    field_name: str = "cvss_score",
) -> ParseOutcome[float]:
    return parse_optional_float(
        value=value,
        field_name=field_name,
        minimum=0.0,
        maximum=10.0,
    )


def parse_optional_date(
    value: Any,
    field_name: str,
) -> ParseOutcome[date]:
    """
    Accept only ISO 8601 calendar dates: YYYY-MM-DD.

    Ambiguous values such as 07/08/2026 are rejected.
    """

    if _is_missing(value):
        return _missing_outcome(field_name, value)

    text_guard = _guard_text_value(value, field_name)
    if text_guard is not None:
        return text_guard

    if isinstance(value, datetime):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="DATETIME_NOT_ALLOWED_AS_DATE",
            message=(
                f"{field_name} requires a date without a time value."
            ),
        )

    if isinstance(value, date):
        return _parsed_outcome(
            field_name=field_name,
            raw_value=value,
            value=value,
            code="DATE_PARSED",
        )

    if not isinstance(value, str):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_DATE_TYPE",
            message=(
                f"{field_name} must be an ISO date string."
            ),
        )

    normalized = value.strip()

    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", normalized):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NON_ISO_DATE_FORMAT",
            message=(
                f"{field_name} must use YYYY-MM-DD format."
            ),
        )

    try:
        parsed_value = date.fromisoformat(normalized)
    except ValueError:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_CALENDAR_DATE",
            message=(
                f"{field_name} contains an invalid calendar date."
            ),
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=parsed_value,
        code="DATE_PARSED",
    )


def parse_optional_datetime(
    value: Any,
    field_name: str,
    require_timezone: bool = True,
) -> ParseOutcome[datetime]:
    """
    Parse an ISO 8601 datetime.

    By default, timezone information is mandatory.
    """

    if _is_missing(value):
        return _missing_outcome(field_name, value)

    text_guard = _guard_text_value(value, field_name)
    if text_guard is not None:
        return text_guard

    if isinstance(value, datetime):
        parsed_value = value
    elif isinstance(value, str):
        normalized = value.strip()

        if normalized.endswith("Z"):
            normalized = f"{normalized[:-1]}+00:00"

        try:
            parsed_value = datetime.fromisoformat(normalized)
        except ValueError:
            return _invalid_outcome(
                field_name=field_name,
                raw_value=value,
                code="INVALID_ISO_DATETIME",
                message=(
                    f"{field_name} must be a valid ISO 8601 datetime."
                ),
            )
    else:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_DATETIME_TYPE",
            message=(
                f"{field_name} must be an ISO datetime string."
            ),
        )

    if require_timezone and parsed_value.tzinfo is None:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="DATETIME_TIMEZONE_MISSING",
            message=(
                f"{field_name} requires an explicit timezone."
            ),
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=parsed_value,
        code="DATETIME_PARSED",
    )


def parse_optional_string(
    value: Any,
    field_name: str,
    minimum_length: int = 1,
    maximum_length: int | None = None,
    require_ascii: bool = False,
    reject_formula_prefix: bool = False,
) -> ParseOutcome[str]:
    if _is_missing(value):
        return _missing_outcome(field_name, value)

    if not isinstance(value, str):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_STRING_TYPE",
            message=(
                f"{field_name} must be a string, not "
                f"{type(value).__name__}."
            ),
        )

    text_guard = _guard_text_value(
        value,
        field_name,
        maximum_raw_length=(maximum_length or MAX_RAW_TOKEN_LENGTH),
    )
    if text_guard is not None:
        return text_guard

    normalized = value.strip()

    if require_ascii and not normalized.isascii():
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NON_ASCII_SECURITY_IDENTIFIER",
            message=f"{field_name} must use canonical ASCII characters.",
        )

    if reject_formula_prefix and normalized.startswith(_FORMULA_PREFIXES):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="SPREADSHEET_FORMULA_PREFIX_NOT_ALLOWED",
            message=(
                f"{field_name} begins with a spreadsheet formula prefix and "
                "cannot be exported safely without explicit escaping."
            ),
        )

    if len(normalized) < minimum_length:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="STRING_BELOW_MINIMUM_LENGTH",
            message=(
                f"{field_name} must contain at least "
                f"{minimum_length} character(s)."
            ),
        )

    if (
        maximum_length is not None
        and len(normalized) > maximum_length
    ):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="STRING_ABOVE_MAXIMUM_LENGTH",
            message=(
                f"{field_name} cannot exceed "
                f"{maximum_length} characters."
            ),
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=normalized,
        code="STRING_PARSED",
    )


def parse_required_string(
    value: Any,
    field_name: str,
    minimum_length: int = 1,
    maximum_length: int | None = None,
    require_ascii: bool = False,
    reject_formula_prefix: bool = False,
) -> ParseOutcome[str]:
    result = parse_optional_string(
        value=value,
        field_name=field_name,
        minimum_length=minimum_length,
        maximum_length=maximum_length,
        require_ascii=require_ascii,
        reject_formula_prefix=reject_formula_prefix,
    )

    if result.status == ParseStatus.MISSING:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="REQUIRED_STRING_MISSING",
            message=f"{field_name} is a required string field.",
        )

    return result


def parse_optional_enum(
    value: Any,
    field_name: str,
    allowed_values: Iterable[str],
) -> ParseOutcome[str]:
    allowed = list(allowed_values)
    canonical_by_normalized = {
        candidate.strip().casefold(): candidate
        for candidate in allowed
    }

    if _is_missing(value):
        return _missing_outcome(field_name, value)

    if not isinstance(value, str):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_ENUM_TYPE",
            message=(
                f"{field_name} must be one of {allowed}."
            ),
        )

    text_guard = _guard_text_value(value, field_name)
    if text_guard is not None:
        return text_guard

    normalized = value.strip().casefold()
    canonical_value = canonical_by_normalized.get(normalized)

    if canonical_value is None:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="ENUM_VALUE_NOT_ALLOWED",
            message=(
                f"{field_name} value {value!r} is not allowed. "
                f"Expected one of {allowed}."
            ),
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=canonical_value,
        code="ENUM_PARSED",
    )


def parse_cve_id(
    value: Any,
    field_name: str = "canonical_id",
) -> ParseOutcome[str]:
    result = parse_required_string(
        value=value,
        field_name=field_name,
        minimum_length=13,
        maximum_length=30,
    )

    if not result.parsed:
        return result

    canonical_value = result.value.upper()

    if not CVE_PATTERN.fullmatch(canonical_value):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_CVE_IDENTIFIER",
            message=(
                f"{field_name} must match CVE-YYYY-NNNN or a longer "
                "numeric suffix."
            ),
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=canonical_value,
        code="CVE_ID_PARSED",
    )



def parse_ascii_identifier(
    value: Any,
    field_name: str,
    pattern: str | Pattern[str],
    minimum_length: int = 1,
    maximum_length: int = 150,
) -> ParseOutcome[str]:
    """Parse a canonical ASCII security identifier against an allowlist."""
    result = parse_required_string(
        value=value,
        field_name=field_name,
        minimum_length=minimum_length,
        maximum_length=maximum_length,
        require_ascii=True,
        reject_formula_prefix=True,
    )
    if not result.parsed:
        return result

    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    assert result.value is not None
    if compiled.fullmatch(result.value) is None:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="SECURITY_IDENTIFIER_PATTERN_MISMATCH",
            message=f"{field_name} does not match its approved identifier grammar.",
        )
    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=result.value,
        code="SECURITY_IDENTIFIER_PARSED",
    )


def parse_optional_purl(
    value: Any,
    field_name: str = "purl",
) -> ParseOutcome[str]:
    """Parse a bounded, traversal-resistant Package URL token."""
    if _is_missing(value):
        return _missing_outcome(field_name, value)
    if not isinstance(value, str):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_PURL_TYPE",
            message=f"{field_name} must be a Package URL string.",
        )

    text_guard = _guard_text_value(value, field_name, maximum_raw_length=2048)
    if text_guard is not None:
        return text_guard

    normalized = value.strip()
    if not normalized.isascii():
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="NON_ASCII_PURL_NOT_ALLOWED",
            message=f"{field_name} must use ASCII or valid percent encoding.",
        )
    if any(character.isspace() for character in normalized):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="PURL_WHITESPACE_NOT_ALLOWED",
            message=f"{field_name} cannot contain whitespace.",
        )
    if "\\" in normalized:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="PURL_BACKSLASH_NOT_ALLOWED",
            message=f"{field_name} cannot contain backslashes.",
        )
    if re.search(r"%(?![0-9A-Fa-f]{2})", normalized):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_PURL_PERCENT_ENCODING",
            message=f"{field_name} contains malformed percent encoding.",
        )

    match = PURL_PATTERN.fullmatch(normalized)
    if match is None:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="INVALID_PURL",
            message=f"{field_name} does not match the Package URL grammar.",
        )

    decoded_path = unquote(match.group("path"))
    path_segments = decoded_path.split("/")
    if any(segment in {"", ".", ".."} for segment in path_segments):
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="PURL_PATH_TRAVERSAL_OR_EMPTY_SEGMENT",
            message=f"{field_name} contains an unsafe or empty path segment.",
        )
    if "\\" in decoded_path:
        return _invalid_outcome(
            field_name=field_name,
            raw_value=value,
            code="PURL_DECODED_BACKSLASH_NOT_ALLOWED",
            message=f"{field_name} decodes to an unsafe backslash path.",
        )

    return _parsed_outcome(
        field_name=field_name,
        raw_value=value,
        value=normalized,
        code="PURL_PARSED",
    )

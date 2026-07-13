from __future__ import annotations

from datetime import timezone

from src.normalization.strict_parsing import (
    ParseStatus,
    parse_cvss_score,
    parse_optional_boolean,
    parse_optional_date,
    parse_optional_datetime,
    parse_optional_enum,
    parse_optional_float,
    parse_optional_integer,
    parse_probability,
)


def test_false_string_is_parsed_as_false() -> None:
    result = parse_optional_boolean(
        "False",
        field_name="kev_flag",
    )

    assert result.status == ParseStatus.PARSED
    assert result.value is False


def test_true_string_is_parsed_as_true() -> None:
    result = parse_optional_boolean(
        "TRUE",
        field_name="kev_flag",
    )

    assert result.status == ParseStatus.PARSED
    assert result.value is True


def test_zero_string_is_parsed_as_false_boolean() -> None:
    result = parse_optional_boolean(
        "0",
        field_name="kev_flag",
    )

    assert result.status == ParseStatus.PARSED
    assert result.value is False


def test_missing_boolean_remains_missing() -> None:
    result = parse_optional_boolean(
        "",
        field_name="kev_flag",
    )

    assert result.status == ParseStatus.MISSING
    assert result.value is None


def test_unrecognized_boolean_is_invalid() -> None:
    result = parse_optional_boolean(
        "maybe",
        field_name="kev_flag",
    )

    assert result.status == ParseStatus.INVALID
    assert result.code == "UNRECOGNIZED_BOOLEAN_TOKEN"


def test_blank_probability_remains_missing() -> None:
    result = parse_probability(
        "",
        field_name="epss_probability",
    )

    assert result.status == ParseStatus.MISSING
    assert result.value is None


def test_zero_probability_is_valid_real_zero() -> None:
    result = parse_probability(
        "0",
        field_name="epss_probability",
    )

    assert result.status == ParseStatus.PARSED
    assert result.value == 0.0


def test_nan_string_is_invalid_not_missing() -> None:
    result = parse_probability(
        "NaN",
        field_name="epss_probability",
    )

    assert result.status == ParseStatus.INVALID
    assert result.code == "NON_FINITE_NUMERIC_VALUE"


def test_infinite_numeric_value_is_invalid() -> None:
    result = parse_optional_float(
        float("inf"),
        field_name="numeric_value",
    )

    assert result.status == ParseStatus.INVALID
    assert result.code == "NON_FINITE_NUMERIC_VALUE"


def test_cvss_boundary_value_is_valid() -> None:
    result = parse_cvss_score("10.0")

    assert result.status == ParseStatus.PARSED
    assert result.value == 10.0


def test_cvss_above_ten_is_invalid() -> None:
    result = parse_cvss_score("10.1")

    assert result.status == ParseStatus.INVALID
    assert result.code == "NUMERIC_VALUE_ABOVE_MAXIMUM"


def test_fractional_number_is_not_integer() -> None:
    result = parse_optional_integer(
        "3.5",
        field_name="source_count",
    )

    assert result.status == ParseStatus.INVALID
    assert result.code == "FRACTIONAL_VALUE_NOT_INTEGER"


def test_iso_date_is_valid() -> None:
    result = parse_optional_date(
        "2026-07-13",
        field_name="score_date",
    )

    assert result.status == ParseStatus.PARSED
    assert result.value.isoformat() == "2026-07-13"


def test_ambiguous_date_is_invalid() -> None:
    result = parse_optional_date(
        "07/08/2026",
        field_name="score_date",
    )

    assert result.status == ParseStatus.INVALID
    assert result.code == "NON_ISO_DATE_FORMAT"


def test_utc_datetime_is_valid() -> None:
    result = parse_optional_datetime(
        "2026-07-13T17:00:00Z",
        field_name="retrieved_at",
    )

    assert result.status == ParseStatus.PARSED
    assert result.value.tzinfo == timezone.utc


def test_naive_datetime_is_invalid_by_default() -> None:
    result = parse_optional_datetime(
        "2026-07-13T17:00:00",
        field_name="retrieved_at",
    )

    assert result.status == ParseStatus.INVALID
    assert result.code == "DATETIME_TIMEZONE_MISSING"


def test_enum_is_normalized_to_canonical_value() -> None:
    result = parse_optional_enum(
        " HIGH ",
        field_name="criticality",
        allowed_values=(
            "very_high",
            "high",
            "medium",
            "low",
        ),
    )

    assert result.status == ParseStatus.PARSED
    assert result.value == "high"


def test_unknown_enum_value_is_invalid() -> None:
    result = parse_optional_enum(
        "critical",
        field_name="criticality",
        allowed_values=(
            "very_high",
            "high",
            "medium",
            "low",
        ),
    )

    assert result.status == ParseStatus.INVALID
    assert result.code == "ENUM_VALUE_NOT_ALLOWED"

from __future__ import annotations

import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Sequence

from src.intelligence.official_source import (
    OfficialSourceFetchResult,
    OfficialSourceValidationError,
    fetch_official_json,
)


EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def normalize_epss_cve_ids(cve_ids: Sequence[str]) -> list[str]:
    normalized = sorted({str(value).strip().upper() for value in cve_ids})
    if not normalized:
        raise ValueError("At least one CVE identifier is required.")
    if len(normalized) > 100:
        raise ValueError("AegisSec EPSS batch requests are limited to 100 CVEs.")
    invalid = [value for value in normalized if not CVE_PATTERN.fullmatch(value)]
    if invalid:
        raise ValueError(f"Invalid CVE identifiers: {invalid}")
    return normalized


def _probability(value: Any, field_name: str) -> float:
    try:
        number = float(Decimal(str(value)))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise OfficialSourceValidationError(
            f"FIRST EPSS field {field_name} must be numeric."
        ) from exc
    if number < 0 or number > 1:
        raise OfficialSourceValidationError(
            f"FIRST EPSS field {field_name} must be within [0, 1]."
        )
    return number


def validate_epss_response(
    payload: Any,
    *,
    requested_cve_ids: Sequence[str],
) -> list[str]:
    if not isinstance(payload, dict):
        raise OfficialSourceValidationError(
            "FIRST EPSS response must be a JSON object."
        )
    data = payload.get("data")
    if not isinstance(data, list):
        raise OfficialSourceValidationError(
            "FIRST EPSS response field 'data' must be a list."
        )
    requested = set(normalize_epss_cve_ids(requested_cve_ids))
    returned: list[str] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise OfficialSourceValidationError(
                f"FIRST EPSS item at index {index} must be an object."
            )
        cve_id = str(item.get("cve", "")).upper()
        if not CVE_PATTERN.fullmatch(cve_id):
            raise OfficialSourceValidationError(
                f"FIRST EPSS item at index {index} has an invalid CVE ID."
            )
        if cve_id not in requested:
            raise OfficialSourceValidationError(
                f"FIRST EPSS returned an unrequested CVE: {cve_id}"
            )
        _probability(item.get("epss"), "epss")
        _probability(item.get("percentile"), "percentile")
        score_date = item.get("date")
        if not isinstance(score_date, str):
            raise OfficialSourceValidationError(
                f"FIRST EPSS item at index {index} lacks score date."
            )
        try:
            date.fromisoformat(score_date)
        except ValueError as exc:
            raise OfficialSourceValidationError(
                f"FIRST EPSS item at index {index} has an invalid score date."
            ) from exc
        returned.append(cve_id)
    if len(returned) != len(set(returned)):
        raise OfficialSourceValidationError(
            "FIRST EPSS response contains duplicate CVE identifiers."
        )
    return sorted(returned)


def query_epss_scores(
    cve_ids: Sequence[str],
    *,
    score_date: str | None = None,
    timeout_seconds: float = 20.0,
    max_attempts: int = 3,
    session: Any | None = None,
    evaluated_at: datetime | None = None,
    sleep_function=None,
) -> OfficialSourceFetchResult:
    normalized = normalize_epss_cve_ids(cve_ids)
    params: dict[str, Any] = {"cve": ",".join(normalized)}
    if score_date is not None:
        date.fromisoformat(score_date)
        params["date"] = score_date
    kwargs: dict[str, Any] = {}
    if sleep_function is not None:
        kwargs["sleep_function"] = sleep_function
    result = fetch_official_json(
        source_name="FIRST_EPSS",
        source_category="official_public_service",
        source_authority="high",
        method="GET",
        endpoint=EPSS_URL,
        allowed_hosts=("api.first.org",),
        params=params,
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
        session=session,
        evaluated_at=evaluated_at,
        **kwargs,
    )
    validate_epss_response(result.payload, requested_cve_ids=normalized)
    return result


def epss_record_ids(
    fetch_result: OfficialSourceFetchResult,
    *,
    requested_cve_ids: Sequence[str],
) -> list[str]:
    return validate_epss_response(
        fetch_result.payload,
        requested_cve_ids=requested_cve_ids,
    )

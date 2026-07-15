from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Sequence

from src.intelligence.official_source import (
    OfficialSourceFetchResult,
    OfficialSourceValidationError,
    fetch_official_json,
)


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def _parse_iso_date(value: Any, field_name: str) -> None:
    if not isinstance(value, str):
        raise OfficialSourceValidationError(
            f"CISA KEV field {field_name} must be an ISO date string."
        )
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise OfficialSourceValidationError(
            f"CISA KEV field {field_name} is not a valid ISO date."
        ) from exc


def validate_cisa_kev_response(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        raise OfficialSourceValidationError(
            "CISA KEV response must be a JSON object."
        )
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise OfficialSourceValidationError(
            "CISA KEV response field 'vulnerabilities' must be a list."
        )
    if "catalogVersion" in payload and not isinstance(payload["catalogVersion"], str):
        raise OfficialSourceValidationError(
            "CISA KEV catalogVersion must be a string when present."
        )
    returned: list[str] = []
    for index, item in enumerate(vulnerabilities):
        if not isinstance(item, dict):
            raise OfficialSourceValidationError(
                f"CISA KEV item at index {index} must be an object."
            )
        cve_id = str(item.get("cveID", "")).upper()
        if not CVE_PATTERN.fullmatch(cve_id):
            raise OfficialSourceValidationError(
                f"CISA KEV item at index {index} has an invalid cveID."
            )
        _parse_iso_date(item.get("dateAdded"), "dateAdded")
        _parse_iso_date(item.get("dueDate"), "dueDate")
        if not isinstance(item.get("requiredAction"), str):
            raise OfficialSourceValidationError(
                f"CISA KEV item at index {index} lacks requiredAction."
            )
        returned.append(cve_id)
    if len(returned) != len(set(returned)):
        raise OfficialSourceValidationError(
            "CISA KEV response contains duplicate CVE identifiers."
        )
    return sorted(returned)


def query_cisa_kev_catalog(
    *,
    timeout_seconds: float = 30.0,
    max_attempts: int = 3,
    session: Any | None = None,
    evaluated_at: datetime | None = None,
    sleep_function=None,
) -> OfficialSourceFetchResult:
    kwargs: dict[str, Any] = {}
    if sleep_function is not None:
        kwargs["sleep_function"] = sleep_function
    result = fetch_official_json(
        source_name="CISA_KEV",
        source_category="official_government",
        source_authority="authoritative",
        method="GET",
        endpoint=CISA_KEV_URL,
        allowed_hosts=("www.cisa.gov",),
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
        session=session,
        evaluated_at=evaluated_at,
        **kwargs,
    )
    validate_cisa_kev_response(result.payload)
    return result


def find_cisa_kev_records(
    payload: Any,
    cve_ids: Sequence[str],
) -> list[dict[str, Any]]:
    validate_cisa_kev_response(payload)
    requested = {str(value).strip().upper() for value in cve_ids}
    invalid = sorted(value for value in requested if not CVE_PATTERN.fullmatch(value))
    if invalid:
        raise ValueError(f"Invalid CVE identifiers: {invalid}")
    return [
        item
        for item in payload["vulnerabilities"]
        if str(item["cveID"]).upper() in requested
    ]

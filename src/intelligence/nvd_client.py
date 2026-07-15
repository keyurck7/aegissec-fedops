from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Sequence

from src.intelligence.official_source import (
    OfficialSourceFetchResult,
    OfficialSourceValidationError,
    fetch_official_json,
)


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def normalize_cve_ids(cve_ids: Sequence[str]) -> list[str]:
    normalized = sorted({str(value).strip().upper() for value in cve_ids})
    if not normalized:
        raise ValueError("At least one CVE identifier is required.")
    if len(normalized) > 100:
        raise ValueError("NVD cveIds requests are limited to 100 identifiers.")
    invalid = [value for value in normalized if not CVE_PATTERN.fullmatch(value)]
    if invalid:
        raise ValueError(f"Invalid CVE identifiers: {invalid}")
    return normalized


def validate_nvd_response(
    payload: Any,
    *,
    requested_cve_ids: Sequence[str],
) -> list[str]:
    if not isinstance(payload, dict):
        raise OfficialSourceValidationError("NVD response must be a JSON object.")
    vulnerabilities = payload.get("vulnerabilities")
    total_results = payload.get("totalResults")
    if not isinstance(vulnerabilities, list):
        raise OfficialSourceValidationError(
            "NVD response field 'vulnerabilities' must be a list."
        )
    if not isinstance(total_results, int) or total_results < 0:
        raise OfficialSourceValidationError(
            "NVD response field 'totalResults' must be a non-negative integer."
        )
    if total_results != len(vulnerabilities):
        raise OfficialSourceValidationError(
            "NVD exact-ID response count does not match vulnerabilities length."
        )

    requested = set(normalize_cve_ids(requested_cve_ids))
    returned: list[str] = []
    for index, item in enumerate(vulnerabilities):
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            raise OfficialSourceValidationError(
                f"NVD vulnerability at index {index} lacks a CVE object."
            )
        cve_id = str(item["cve"].get("id", "")).upper()
        if not CVE_PATTERN.fullmatch(cve_id):
            raise OfficialSourceValidationError(
                f"NVD vulnerability at index {index} has an invalid CVE ID."
            )
        if cve_id not in requested:
            raise OfficialSourceValidationError(
                f"NVD returned an unrequested CVE identifier: {cve_id}"
            )
        returned.append(cve_id)
    if len(returned) != len(set(returned)):
        raise OfficialSourceValidationError("NVD response contains duplicate CVE IDs.")
    return sorted(returned)


def query_nvd_cves(
    cve_ids: Sequence[str],
    *,
    api_key: str | None = None,
    timeout_seconds: float = 30.0,
    max_attempts: int = 3,
    session: Any | None = None,
    evaluated_at: datetime | None = None,
    sleep_function=None,
) -> OfficialSourceFetchResult:
    normalized = normalize_cve_ids(cve_ids)
    key = api_key if api_key is not None else os.getenv("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    kwargs: dict[str, Any] = {}
    if sleep_function is not None:
        kwargs["sleep_function"] = sleep_function
    result = fetch_official_json(
        source_name="NVD",
        source_category="official_government",
        source_authority="authoritative",
        method="GET",
        endpoint=NVD_CVE_URL,
        allowed_hosts=("services.nvd.nist.gov",),
        params={"cveIds": ",".join(normalized)},
        headers=headers,
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
        session=session,
        evaluated_at=evaluated_at,
        **kwargs,
    )
    validate_nvd_response(result.payload, requested_cve_ids=normalized)
    return result


def nvd_record_ids(
    fetch_result: OfficialSourceFetchResult,
    *,
    requested_cve_ids: Sequence[str],
) -> list[str]:
    return validate_nvd_response(
        fetch_result.payload,
        requested_cve_ids=requested_cve_ids,
    )

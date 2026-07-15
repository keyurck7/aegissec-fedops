from __future__ import annotations

from datetime import datetime
from typing import Any

from src.intelligence.official_source import (
    OfficialSourceFetchResult,
    OfficialSourceValidationError,
    fetch_official_json,
)
from src.intelligence.osv_client import OSV_QUERY_URL


def validate_osv_response(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        raise OfficialSourceValidationError("OSV response must be a JSON object.")
    vulnerabilities = payload.get("vulns", [])
    if not isinstance(vulnerabilities, list):
        raise OfficialSourceValidationError("OSV response field 'vulns' must be a list.")
    record_ids: list[str] = []
    for index, item in enumerate(vulnerabilities):
        if not isinstance(item, dict):
            raise OfficialSourceValidationError(
                f"OSV vulnerability at index {index} must be an object."
            )
        record_id = item.get("id")
        if not isinstance(record_id, str) or len(record_id) < 3:
            raise OfficialSourceValidationError(
                f"OSV vulnerability at index {index} lacks a valid ID."
            )
        record_ids.append(record_id)
    if len(record_ids) != len(set(record_ids)):
        raise OfficialSourceValidationError("OSV response contains duplicate IDs.")
    return sorted(record_ids)


def query_osv_component(
    *,
    package_name: str,
    ecosystem: str,
    version: str | None,
    timeout_seconds: float = 20.0,
    max_attempts: int = 3,
    session: Any | None = None,
    evaluated_at: datetime | None = None,
    sleep_function=None,
) -> OfficialSourceFetchResult:
    name = package_name.strip()
    normalized_ecosystem = ecosystem.strip()
    normalized_version = version.strip() if isinstance(version, str) else None
    if not name or not normalized_ecosystem:
        raise ValueError("OSV package name and ecosystem are required.")
    body: dict[str, Any] = {
        "package": {"name": name, "ecosystem": normalized_ecosystem}
    }
    if normalized_version:
        body["version"] = normalized_version
    kwargs: dict[str, Any] = {}
    if sleep_function is not None:
        kwargs["sleep_function"] = sleep_function
    result = fetch_official_json(
        source_name="OSV",
        source_category="open_source_project",
        source_authority="high",
        method="POST",
        endpoint=OSV_QUERY_URL,
        allowed_hosts=("api.osv.dev",),
        json_body=body,
        timeout_seconds=timeout_seconds,
        max_attempts=max_attempts,
        session=session,
        evaluated_at=evaluated_at,
        **kwargs,
    )
    validate_osv_response(result.payload)
    return result


def osv_record_ids(fetch_result: OfficialSourceFetchResult) -> list[str]:
    return validate_osv_response(fetch_result.payload)

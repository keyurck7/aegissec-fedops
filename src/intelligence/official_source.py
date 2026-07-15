from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

import requests
from jsonschema import Draft202012Validator, FormatChecker

from src.governance.recovery_checkpoint import atomic_write_bundle


DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "aegis_official_source_envelope.schema.json"
)

SENSITIVE_FIELD_NAMES = frozenset(
    {
        "apikey",
        "api_key",
        "authorization",
        "cookie",
        "password",
        "private_key",
        "secret",
        "token",
        "x-api-key",
    }
)

RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "date",
        "etag",
        "last-modified",
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    }
)


class OfficialSourceError(RuntimeError):
    """Base error for official-source retrieval and evidence handling."""


class OfficialSourceHTTPError(OfficialSourceError):
    """Raised when a bounded official-source request cannot complete safely."""


class OfficialSourceValidationError(OfficialSourceError):
    """Raised when an official source returns an invalid or unexpected document."""


class OfficialSourceIntegrityError(OfficialSourceError):
    """Raised when a persisted source-evidence bundle fails verification."""


@dataclass(frozen=True)
class OfficialSourceFetchResult:
    source_name: str
    source_category: str
    source_authority: str
    endpoint: str
    method: str
    request_parameters: Mapping[str, Any]
    request_body: Any
    request_headers: Mapping[str, Any]
    retrieved_at: str
    status_code: int
    attempt_count: int
    timeout_seconds: float
    max_attempts: int
    response_headers: Mapping[str, str]
    payload: Any

    @property
    def payload_bytes(self) -> bytes:
        return canonical_json_bytes(self.payload)

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload_bytes).hexdigest()

    @property
    def payload_size_bytes(self) -> int:
        return len(self.payload_bytes)


@dataclass(frozen=True)
class OfficialSourceBundlePaths:
    envelope_path: Path
    payload_path: Path
    integrity_path: Path


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _utc_iso(value: datetime | None = None) -> str:
    moment = value or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("Official-source timestamps must be timezone-aware.")
    return moment.astimezone(timezone.utc).isoformat()


def _redact(value: Any, *, field_name: str | None = None) -> Any:
    normalized_name = (field_name or "").strip().casefold().replace("-", "_")
    sensitive_names = {item.replace("-", "_") for item in SENSITIVE_FIELD_NAMES}
    if normalized_name in sensitive_names:
        return "<redacted>"
    if isinstance(value, Mapping):
        return {
            str(key): _redact(child, field_name=str(key))
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_redact(child) for child in value]
    return value


def _safe_response_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        return {}
    result: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).casefold()
        if lowered in SAFE_RESPONSE_HEADERS:
            result[lowered] = str(value)
    return dict(sorted(result.items()))


def _validate_endpoint(url: str, allowed_hosts: Sequence[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Official-source endpoints must use HTTPS.")
    host = (parsed.hostname or "").casefold()
    normalized_hosts = {item.casefold() for item in allowed_hosts}
    if not host or host not in normalized_hosts:
        raise ValueError(f"Official-source host is not allow-listed: {host or '<empty>'}")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are prohibited in official-source URLs.")


def _response_json(response: Any, max_response_bytes: int) -> Any:
    headers = getattr(response, "headers", {})
    if isinstance(headers, Mapping):
        content_length = headers.get("Content-Length") or headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > max_response_bytes:
                    raise OfficialSourceHTTPError(
                        "Official-source response exceeds the configured size limit."
                    )
            except ValueError as exc:
                raise OfficialSourceHTTPError(
                    "Official-source Content-Length is malformed."
                ) from exc
    try:
        document = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise OfficialSourceHTTPError(
            "Official source returned malformed JSON."
        ) from exc
    try:
        size = len(canonical_json_bytes(document))
    except (TypeError, ValueError) as exc:
        raise OfficialSourceHTTPError(
            "Official source returned non-canonical JSON values."
        ) from exc
    if size > max_response_bytes:
        raise OfficialSourceHTTPError(
            "Official-source JSON exceeds the configured size limit."
        )
    return document


def _retry_delay_seconds(response: Any, attempt: int) -> float:
    headers = getattr(response, "headers", {})
    if isinstance(headers, Mapping):
        value = headers.get("Retry-After") or headers.get("retry-after")
        if value is not None:
            try:
                return min(max(float(value), 0.0), 30.0)
            except (TypeError, ValueError):
                pass
    return min(0.5 * (2 ** max(attempt - 1, 0)), 8.0)


def fetch_official_json(
    *,
    source_name: str,
    source_category: str,
    source_authority: str,
    method: str,
    endpoint: str,
    allowed_hosts: Sequence[str],
    params: Mapping[str, Any] | None = None,
    json_body: Any = None,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = 20.0,
    max_attempts: int = 3,
    max_response_bytes: int = 32 * 1024 * 1024,
    session: Any | None = None,
    evaluated_at: datetime | None = None,
    sleep_function: Callable[[float], None] = time.sleep,
) -> OfficialSourceFetchResult:
    """Perform a bounded, allow-listed JSON request and preserve safe metadata."""

    _validate_endpoint(endpoint, allowed_hosts)
    normalized_method = method.strip().upper()
    if normalized_method not in {"GET", "POST"}:
        raise ValueError("Official-source method must be GET or POST.")
    if not source_name.strip():
        raise ValueError("Official-source name is required.")
    if timeout_seconds <= 0 or timeout_seconds > 120:
        raise ValueError("timeout_seconds must be within (0, 120].")
    if max_attempts < 1 or max_attempts > 5:
        raise ValueError("max_attempts must be within [1, 5].")
    if max_response_bytes < 1024:
        raise ValueError("max_response_bytes must be at least 1024 bytes.")

    request_headers = {
        "Accept": "application/json",
        "User-Agent": "AegisSec-FedOps/0.1 official-intelligence",
    }
    if headers:
        request_headers.update({str(key): str(value) for key, value in headers.items()})

    requester = session or requests
    last_error: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            request_callable = getattr(requester, normalized_method.casefold(), None)
            if request_callable is None:
                request_callable = getattr(requester, "request", None)
            if request_callable is None:
                raise OfficialSourceHTTPError(
                    "HTTP session does not expose the requested method."
                )

            kwargs = {
                "params": dict(params or {}),
                "headers": request_headers,
                "timeout": timeout_seconds,
            }
            if normalized_method == "POST":
                kwargs["json"] = json_body

            if getattr(requester, normalized_method.casefold(), None) is None:
                response = request_callable(normalized_method, endpoint, **kwargs)
            else:
                response = request_callable(endpoint, **kwargs)

            status_code = int(getattr(response, "status_code"))
            if status_code in RETRYABLE_STATUS_CODES:
                last_error = OfficialSourceHTTPError(
                    f"{source_name} returned retryable HTTP status {status_code}."
                )
                if attempt < max_attempts:
                    sleep_function(_retry_delay_seconds(response, attempt))
                    continue
                raise last_error

            try:
                response.raise_for_status()
            except requests.HTTPError as exc:
                raise OfficialSourceHTTPError(
                    f"{source_name} returned non-success HTTP status {status_code}."
                ) from exc

            payload = _response_json(response, max_response_bytes)
            return OfficialSourceFetchResult(
                source_name=source_name,
                source_category=source_category,
                source_authority=source_authority,
                endpoint=endpoint,
                method=normalized_method,
                request_parameters=dict(params or {}),
                request_body=json_body,
                request_headers=request_headers,
                retrieved_at=_utc_iso(evaluated_at),
                status_code=status_code,
                attempt_count=attempt,
                timeout_seconds=float(timeout_seconds),
                max_attempts=max_attempts,
                response_headers=_safe_response_headers(
                    getattr(response, "headers", {})
                ),
                payload=payload,
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = exc
            if attempt < max_attempts:
                sleep_function(min(0.5 * (2 ** (attempt - 1)), 8.0))
                continue
            raise OfficialSourceHTTPError(
                f"{source_name} request failed after {max_attempts} bounded attempts."
            ) from exc

    raise OfficialSourceHTTPError(
        f"{source_name} request did not complete."
    ) from last_error


def build_official_source_envelope(
    fetch_result: OfficialSourceFetchResult,
    *,
    source_record_ids: Sequence[str],
    validation_status: str = "accepted",
    validation_errors: Sequence[str] = (),
    validation_warnings: Sequence[str] = (),
    collector: str = "AegisSec Official Intelligence Collector",
    collector_version: str = "0.1.0",
) -> dict[str, Any]:
    if validation_status not in {"accepted", "accepted_with_warnings", "rejected"}:
        raise ValueError("Unsupported official-source validation status.")
    unique_record_ids = sorted({str(value) for value in source_record_ids if str(value)})
    identity = {
        "source_name": fetch_result.source_name,
        "endpoint": fetch_result.endpoint,
        "retrieved_at": fetch_result.retrieved_at,
        "payload_sha256": fetch_result.payload_sha256,
    }
    envelope_id = "AEG-OSI-" + hashlib.sha256(
        canonical_json_bytes(identity)
    ).hexdigest()[:24].upper()
    return {
        "schema_version": "1.0.0",
        "envelope_id": envelope_id,
        "source": {
            "source_name": fetch_result.source_name,
            "source_category": fetch_result.source_category,
            "source_authority": fetch_result.source_authority,
            "endpoint": fetch_result.endpoint,
        },
        "request": {
            "method": fetch_result.method,
            "parameters": _redact(fetch_result.request_parameters),
            "body": _redact(fetch_result.request_body),
            "headers": _redact(fetch_result.request_headers),
            "timeout_seconds": fetch_result.timeout_seconds,
            "max_attempts": fetch_result.max_attempts,
        },
        "retrieval": {
            "mode": "live",
            "status": "success",
            "retrieved_at": fetch_result.retrieved_at,
            "http_status": fetch_result.status_code,
            "attempt_count": fetch_result.attempt_count,
            "response_headers": dict(fetch_result.response_headers),
        },
        "artifact": {
            "media_type": "application/json",
            "size_bytes": fetch_result.payload_size_bytes,
            "sha256": fetch_result.payload_sha256,
            "payload_filename": None,
        },
        "records": {
            "record_count": len(unique_record_ids),
            "record_ids": unique_record_ids,
        },
        "validation": {
            "status": validation_status,
            "errors": list(validation_errors),
            "warnings": list(validation_warnings),
        },
        "provenance": {
            "collector": collector,
            "collector_version": collector_version,
            "network_used": True,
            "credential_material_persisted": False,
        },
    }


def _load_schema(schema_path: Path | str = DEFAULT_SCHEMA_PATH) -> dict[str, Any]:
    path = Path(schema_path)
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def validate_official_source_envelope(
    envelope: Mapping[str, Any],
    schema_path: Path | str = DEFAULT_SCHEMA_PATH,
) -> None:
    schema = _load_schema(schema_path)
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(dict(envelope)),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        messages = []
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path)
            messages.append(f"{location or '<root>'}: {error.message}")
        raise OfficialSourceValidationError(
            "Official-source envelope schema validation failed: "
            + "; ".join(messages)
        )


def write_official_source_bundle(
    output_dir: Path | str,
    fetch_result: OfficialSourceFetchResult,
    *,
    source_record_ids: Sequence[str],
    validation_status: str = "accepted",
    validation_errors: Sequence[str] = (),
    validation_warnings: Sequence[str] = (),
) -> OfficialSourceBundlePaths:
    envelope = build_official_source_envelope(
        fetch_result,
        source_record_ids=source_record_ids,
        validation_status=validation_status,
        validation_errors=validation_errors,
        validation_warnings=validation_warnings,
    )
    stem = envelope["envelope_id"].casefold()
    root = Path(output_dir)
    payload_path = root / f"{stem}.payload.json"
    envelope_path = root / f"{stem}.envelope.json"
    integrity_path = root / f"{stem}.integrity.sha256"
    envelope["artifact"]["payload_filename"] = payload_path.name
    validate_official_source_envelope(envelope)

    envelope_bytes = canonical_json_bytes(envelope)
    payload_bytes = fetch_result.payload_bytes
    manifest = (
        f"{hashlib.sha256(payload_bytes).hexdigest()}  {payload_path.name}\n"
        f"{hashlib.sha256(envelope_bytes).hexdigest()}  {envelope_path.name}\n"
    ).encode("utf-8")
    atomic_write_bundle(
        {
            payload_path: payload_bytes,
            envelope_path: envelope_bytes,
            integrity_path: manifest,
        }
    )
    return OfficialSourceBundlePaths(
        envelope_path=envelope_path,
        payload_path=payload_path,
        integrity_path=integrity_path,
    )


def verify_official_source_bundle(
    envelope_path: Path | str,
) -> dict[str, Any]:
    path = Path(envelope_path)
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OfficialSourceIntegrityError(
            f"Official-source envelope is unreadable: {path}"
        ) from exc
    validate_official_source_envelope(envelope)
    payload_name = envelope["artifact"]["payload_filename"]
    payload_path = path.parent / payload_name
    integrity_path = path.with_name(
        path.name.replace(".envelope.json", ".integrity.sha256")
    )
    if not payload_path.is_file() or not integrity_path.is_file():
        raise OfficialSourceIntegrityError(
            "Official-source bundle is incomplete."
        )
    payload_bytes = payload_path.read_bytes()
    actual_payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if actual_payload_sha256 != envelope["artifact"]["sha256"]:
        raise OfficialSourceIntegrityError(
            "Official-source payload hash does not match its envelope."
        )
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfficialSourceIntegrityError(
            "Official-source payload is malformed."
        ) from exc
    if canonical_json_bytes(payload) != payload_bytes:
        raise OfficialSourceIntegrityError(
            "Official-source payload is not canonically serialized."
        )
    expected_manifest = {
        line.split(maxsplit=1)[1].strip(): line.split(maxsplit=1)[0]
        for line in integrity_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    for target in (payload_path, path):
        expected = expected_manifest.get(target.name)
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if expected != actual:
            raise OfficialSourceIntegrityError(
                f"Official-source integrity manifest mismatch: {target.name}"
            )
    return envelope

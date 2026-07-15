from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List

import requests

from src.governance.recovery_checkpoint import atomic_write_bundle, atomic_write_json


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OSVClientError(RuntimeError):
    """Raised when OSV cannot be queried or safely recovered from cache."""


class OSVCacheIntegrityError(OSVClientError):
    """Raised when an OSV cache entry fails its integrity contract."""


def _validate_response_document(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise OSVClientError("OSV response must be a JSON object.")
    vulnerabilities = value.get("vulns", [])
    if not isinstance(vulnerabilities, list):
        raise OSVClientError("OSV response field 'vulns' must be a list.")
    return value


def query_osv_package(
    name: str,
    ecosystem: str,
    version: str | None = None,
    timeout: int = 20,
    *,
    max_attempts: int = 3,
    session: Any | None = None,
) -> Dict[str, Any]:
    """Query OSV with a bounded attempt budget and no sleep-based retries."""

    if not name or not ecosystem:
        raise ValueError("OSV package name and ecosystem are required.")
    if timeout <= 0:
        raise ValueError("OSV timeout must be positive.")
    if max_attempts < 1:
        raise ValueError("OSV max_attempts must be at least one.")

    payload: Dict[str, Any] = {
        "package": {
            "name": name,
            "ecosystem": ecosystem,
        }
    }
    if version:
        payload["version"] = version

    requester = session or requests
    last_error: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = requester.post(
                OSV_QUERY_URL,
                json=payload,
                timeout=timeout,
                headers={"Accept": "application/json"},
            )
            status_code = int(response.status_code)
            if status_code == 429 or status_code >= 500:
                last_error = OSVClientError(
                    f"OSV transient HTTP status {status_code} on attempt {attempt}."
                )
                if attempt < max_attempts:
                    continue
                raise last_error
            response.raise_for_status()
            return _validate_response_document(response.json())
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = exc
            if attempt < max_attempts:
                continue
            raise OSVClientError(
                f"OSV request failed after {max_attempts} bounded attempts."
            ) from exc
        except (ValueError, json.JSONDecodeError) as exc:
            raise OSVClientError("OSV returned malformed JSON.") from exc

    raise OSVClientError("OSV query failed.") from last_error


def _cache_hash_path(cache_file: Path) -> Path:
    return cache_file.with_suffix(cache_file.suffix + ".sha256")


def _canonical_json_bytes(value: Any) -> bytes:
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


def _write_verified_cache(
    cache_file: Path,
    data: Dict[str, Any],
    *,
    written_at: datetime | None = None,
) -> None:
    payload = _canonical_json_bytes(data)
    digest = hashlib.sha256(payload).hexdigest()
    timestamp = written_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("written_at must be timezone-aware.")
    metadata = (
        json.dumps(
            {
                "algorithm": "sha256",
                "payload_sha256": digest,
                "written_at": timestamp.astimezone(timezone.utc).isoformat(),
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    atomic_write_bundle(
        {
            cache_file: payload,
            _cache_hash_path(cache_file): metadata,
        }
    )


def _read_verified_cache(
    cache_file: Path,
    *,
    max_cache_age_seconds: int | None = None,
    evaluated_at: datetime | None = None,
) -> Dict[str, Any]:
    hash_path = _cache_hash_path(cache_file)
    if not cache_file.is_file() or not hash_path.is_file():
        raise FileNotFoundError(cache_file)
    raw = cache_file.read_bytes()
    try:
        metadata = json.loads(hash_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OSVCacheIntegrityError("OSV cache metadata is unreadable.") from exc
    expected = metadata.get("payload_sha256")
    actual = hashlib.sha256(raw).hexdigest()
    if expected != actual:
        raise OSVCacheIntegrityError("OSV cache payload hash mismatch.")
    if max_cache_age_seconds is not None:
        if max_cache_age_seconds < 0:
            raise ValueError("max_cache_age_seconds must be non-negative.")
        now = evaluated_at or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("evaluated_at must be timezone-aware.")
        written_at_value = metadata.get("written_at")
        if not isinstance(written_at_value, str):
            raise OSVCacheIntegrityError("OSV cache written_at is missing.")
        normalized = (
            written_at_value[:-1] + "+00:00"
            if written_at_value.endswith("Z")
            else written_at_value
        )
        written_at = datetime.fromisoformat(normalized)
        if written_at.tzinfo is None:
            raise OSVCacheIntegrityError("OSV cache written_at lacks timezone.")
        age = (now.astimezone(timezone.utc) - written_at).total_seconds()
        if age > max_cache_age_seconds:
            raise OSVCacheIntegrityError("OSV cache entry is stale.")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OSVCacheIntegrityError("OSV cache payload is malformed.") from exc
    return _validate_response_document(document)


def load_or_query_osv(
    component: Dict[str, Any],
    cache_dir: str = "data/cache/osv",
    *,
    max_cache_age_seconds: int | None = None,
    evaluated_at: datetime | None = None,
    query_function: Callable[..., Dict[str, Any]] = query_osv_package,
) -> Dict[str, Any]:
    """Load an integrity-verified cache entry or query and atomically persist it."""

    cache_root = Path(cache_dir)
    cache_root.mkdir(parents=True, exist_ok=True)

    name = str(component["component_name"])
    ecosystem = str(component["ecosystem"])
    version = str(component.get("version") or "unknown")
    safe_name = "_".join(part for part in name.replace("/", "_").split() if part)
    safe_ecosystem = "_".join(
        part for part in ecosystem.replace("/", "_").split() if part
    )
    cache_file = cache_root / f"{safe_ecosystem}_{safe_name}_{version}.json"

    if cache_file.exists() or _cache_hash_path(cache_file).exists():
        try:
            return _read_verified_cache(
                cache_file,
                max_cache_age_seconds=max_cache_age_seconds,
                evaluated_at=evaluated_at,
            )
        except (FileNotFoundError, OSVCacheIntegrityError):
            pass

    data = query_function(
        name=name,
        ecosystem=ecosystem,
        version=component.get("version"),
    )
    validated = _validate_response_document(data)
    _write_verified_cache(cache_file, validated, written_at=evaluated_at)
    return validated


def flatten_osv_results(
    component: Dict[str, Any],
    osv_response: Dict[str, Any],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for vulnerability in osv_response.get("vulns", []):
        aliases = vulnerability.get("aliases", [])
        cve_aliases = [
            alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-")
        ]
        findings.append(
            {
                "asset_id": component["asset_id"],
                "component_name": component["component_name"],
                "version": component.get("version"),
                "ecosystem": component["ecosystem"],
                "source": "OSV",
                "vulnerability_id": vulnerability.get("id"),
                "cve_ids": cve_aliases,
                "summary": vulnerability.get("summary"),
                "details": vulnerability.get("details"),
                "modified": vulnerability.get("modified"),
                "published": vulnerability.get("published"),
                "aliases": aliases,
            }
        )

    return findings

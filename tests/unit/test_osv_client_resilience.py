from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from src.intelligence.osv_client import (
    OSVCacheIntegrityError,
    OSVClientError,
    _cache_hash_path,
    _read_verified_cache,
    load_or_query_osv,
    query_osv_package,
)


class Response:
    def __init__(self, status_code=200, document=None):
        self.status_code = status_code
        self._document = document if document is not None else {"vulns": []}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return self._document


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def post(self, *args, **kwargs):
        value = self.responses[self.calls]
        self.calls += 1
        if isinstance(value, BaseException):
            raise value
        return value


def test_osv_query_retries_transient_status_without_sleep() -> None:
    session = Session([Response(503), Response(200, {"vulns": []})])
    result = query_osv_package("log4j-core", "Maven", session=session)
    assert result == {"vulns": []}
    assert session.calls == 2


def test_osv_query_stops_at_attempt_budget() -> None:
    session = Session([Response(503), Response(503)])
    with pytest.raises(OSVClientError):
        query_osv_package(
            "log4j-core", "Maven", session=session, max_attempts=2
        )
    assert session.calls == 2


def test_osv_cache_is_integrity_verified(tmp_path: Path) -> None:
    component = {
        "component_name": "log4j-core", "ecosystem": "Maven",
        "version": "2.17.1"
    }
    first = load_or_query_osv(
        component,
        str(tmp_path),
        query_function=lambda **kwargs: {"vulns": [{"id": "X"}]},
    )
    assert first["vulns"][0]["id"] == "X"
    cache_file = next(path for path in tmp_path.glob("*.json") if not path.name.endswith(".sha256"))
    cache_file.write_text('{"vulns":[]}\n', encoding="utf-8")
    with pytest.raises(OSVCacheIntegrityError):
        _read_verified_cache(cache_file)


def test_osv_stale_cache_is_rejected(tmp_path: Path) -> None:
    component = {
        "component_name": "log4j-core", "ecosystem": "Maven",
        "version": "2.17.1"
    }
    load_or_query_osv(
        component,
        str(tmp_path),
        query_function=lambda **kwargs: {"vulns": []},
    )
    cache_file = next(path for path in tmp_path.glob("*.json") if not path.name.endswith(".sha256"))
    metadata = _cache_hash_path(cache_file)
    text = metadata.read_text(encoding="utf-8").replace(
        "2026", "2020", 1
    )
    metadata.write_text(text, encoding="utf-8")
    with pytest.raises(OSVCacheIntegrityError):
        _read_verified_cache(
            cache_file,
            max_cache_age_seconds=60,
            evaluated_at=datetime(2026, 7, 15, tzinfo=timezone.utc),
        )


def test_osv_response_shape_is_validated() -> None:
    session = Session([Response(200, {"vulns": "not-a-list"})])
    with pytest.raises(OSVClientError):
        query_osv_package("log4j-core", "Maven", session=session)

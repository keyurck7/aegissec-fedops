from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from src.intelligence.official_source import (
    OfficialSourceHTTPError,
    OfficialSourceIntegrityError,
    build_official_source_envelope,
    fetch_official_json,
    verify_official_source_bundle,
    write_official_source_bundle,
)


class Response:
    def __init__(self, status_code=200, document=None, headers=None):
        self.status_code = status_code
        self._document = {} if document is None else document
        self.headers = headers or {"Content-Type": "application/json"}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return self._document


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        value = self.responses[len(self.calls) - 1]
        if isinstance(value, BaseException):
            raise value
        return value


def fetch(session: Session, **overrides):
    values = {
        "source_name": "NVD",
        "source_category": "official_government",
        "source_authority": "authoritative",
        "method": "GET",
        "endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "allowed_hosts": ("services.nvd.nist.gov",),
        "params": {"cveIds": "CVE-2021-44228"},
        "headers": {"apiKey": "secret-value"},
        "session": session,
        "evaluated_at": datetime(2026, 7, 15, tzinfo=timezone.utc),
        "sleep_function": lambda _: None,
    }
    values.update(overrides)
    return fetch_official_json(**values)


def test_official_fetch_is_allow_listed_and_https_only() -> None:
    session = Session([Response()])
    with pytest.raises(ValueError):
        fetch(session, endpoint="http://services.nvd.nist.gov/x")
    with pytest.raises(ValueError):
        fetch(session, endpoint="https://example.com/x")


def test_official_fetch_retries_with_bounded_attempts() -> None:
    session = Session([Response(503), Response(200, {"ok": True})])
    result = fetch(session)
    assert result.attempt_count == 2
    assert result.payload == {"ok": True}


def test_official_fetch_stops_after_attempt_budget() -> None:
    session = Session([Response(503), Response(503)])
    with pytest.raises(OfficialSourceHTTPError):
        fetch(session, max_attempts=2)
    assert len(session.calls) == 2


def test_api_key_is_redacted_from_envelope() -> None:
    result = fetch(Session([Response(200, {"ok": True})]))
    envelope = build_official_source_envelope(
        result,
        source_record_ids=("CVE-2021-44228",),
    )
    serialized = json.dumps(envelope)
    assert "secret-value" not in serialized
    assert envelope["request"]["headers"]["apiKey"] == "<redacted>"
    assert envelope["provenance"]["credential_material_persisted"] is False


def test_bundle_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    result = fetch(Session([Response(200, {"ok": True})]))
    paths = write_official_source_bundle(
        tmp_path,
        result,
        source_record_ids=("CVE-2021-44228",),
    )
    envelope = verify_official_source_bundle(paths.envelope_path)
    assert envelope["records"]["record_count"] == 1
    paths.payload_path.write_text('{"ok":false}\n', encoding="utf-8")
    with pytest.raises(OfficialSourceIntegrityError):
        verify_official_source_bundle(paths.envelope_path)

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import requests

from src.intelligence.nvd_client import (
    normalize_cve_ids,
    query_nvd_cves,
)
from src.intelligence.official_source import OfficialSourceValidationError


class Response:
    status_code = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, document):
        self.document = document

    def raise_for_status(self):
        return None

    def json(self):
        return self.document


class Session:
    def __init__(self, document):
        self.document = document
        self.kwargs = None

    def get(self, *args, **kwargs):
        self.kwargs = kwargs
        return Response(self.document)


def valid_document(cve_id="CVE-2021-44228"):
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-07-15T00:00:00.000",
        "vulnerabilities": [{"cve": {"id": cve_id}}],
    }


def test_nvd_query_uses_cve_ids_and_api_key_header() -> None:
    session = Session(valid_document())
    result = query_nvd_cves(
        ["cve-2021-44228"],
        api_key="top-secret",
        session=session,
        evaluated_at=datetime(2026, 7, 15, tzinfo=timezone.utc),
        sleep_function=lambda _: None,
    )
    assert result.payload["totalResults"] == 1
    assert session.kwargs["params"]["cveIds"] == "CVE-2021-44228"
    assert session.kwargs["headers"]["apiKey"] == "top-secret"


def test_nvd_rejects_unrequested_cve() -> None:
    with pytest.raises(OfficialSourceValidationError):
        query_nvd_cves(
            ["CVE-2021-44228"],
            session=Session(valid_document("CVE-2022-0001")),
            sleep_function=lambda _: None,
        )


def test_nvd_rejects_malformed_response() -> None:
    with pytest.raises(OfficialSourceValidationError):
        query_nvd_cves(
            ["CVE-2021-44228"],
            session=Session({"totalResults": 1, "vulnerabilities": "bad"}),
            sleep_function=lambda _: None,
        )


def test_nvd_cve_normalization_is_strict() -> None:
    assert normalize_cve_ids(["cve-2021-44228"]) == ["CVE-2021-44228"]
    with pytest.raises(ValueError):
        normalize_cve_ids(["not-a-cve"])

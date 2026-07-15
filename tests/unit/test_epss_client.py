from __future__ import annotations

import pytest

from src.intelligence.epss_client import query_epss_scores
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


def test_epss_query_preserves_probability_strings() -> None:
    session = Session(
        {
            "status": "OK",
            "status-code": 200,
            "version": "1.0",
            "access": "public",
            "total": 1,
            "offset": 0,
            "limit": 100,
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.943580000",
                    "percentile": "0.999990000",
                    "date": "2026-07-15",
                }
            ],
        }
    )
    result = query_epss_scores(
        ["CVE-2021-44228"],
        session=session,
        sleep_function=lambda _: None,
    )
    assert result.payload["data"][0]["epss"] == "0.943580000"
    assert session.kwargs["params"]["cve"] == "CVE-2021-44228"


def test_epss_rejects_probability_above_one() -> None:
    document = {
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "1.2",
                "percentile": "0.9",
                "date": "2026-07-15",
            }
        ]
    }
    with pytest.raises(OfficialSourceValidationError):
        query_epss_scores(
            ["CVE-2021-44228"],
            session=Session(document),
            sleep_function=lambda _: None,
        )

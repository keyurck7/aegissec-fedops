from __future__ import annotations

import pytest

from src.intelligence.cisa_kev_client import (
    find_cisa_kev_records,
    query_cisa_kev_catalog,
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

    def get(self, *args, **kwargs):
        return Response(self.document)


def valid_document():
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.07.15",
        "dateReleased": "2026-07-15T00:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "Controlled shape fixture.",
                "requiredAction": "Apply mitigations per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            }
        ],
    }


def test_cisa_catalog_and_requested_match() -> None:
    result = query_cisa_kev_catalog(
        session=Session(valid_document()),
        sleep_function=lambda _: None,
    )
    matches = find_cisa_kev_records(result.payload, ["CVE-2021-44228"])
    assert len(matches) == 1
    assert matches[0]["cveID"] == "CVE-2021-44228"


def test_cisa_catalog_rejects_invalid_dates() -> None:
    document = valid_document()
    document["vulnerabilities"][0]["dueDate"] = "not-a-date"
    with pytest.raises(OfficialSourceValidationError):
        query_cisa_kev_catalog(
            session=Session(document),
            sleep_function=lambda _: None,
        )

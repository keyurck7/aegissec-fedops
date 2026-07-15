from __future__ import annotations

import pytest

from src.intelligence.official_source import OfficialSourceValidationError
from src.intelligence.osv_official_client import query_osv_component


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

    def post(self, *args, **kwargs):
        self.kwargs = kwargs
        return Response(self.document)


def test_osv_official_query_uses_component_version() -> None:
    session = Session({"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]})
    result = query_osv_component(
        package_name="org.apache.logging.log4j:log4j-core",
        ecosystem="Maven",
        version="2.14.1",
        session=session,
        sleep_function=lambda _: None,
    )
    assert result.payload["vulns"][0]["id"].startswith("GHSA-")
    assert session.kwargs["json"]["version"] == "2.14.1"


def test_osv_official_query_rejects_duplicate_ids() -> None:
    document = {"vulns": [{"id": "X-1"}, {"id": "X-1"}]}
    with pytest.raises(OfficialSourceValidationError):
        query_osv_component(
            package_name="log4j-core",
            ecosystem="Maven",
            version="2.14.1",
            session=Session(document),
            sleep_function=lambda _: None,
        )

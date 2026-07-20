from __future__ import annotations

import json

import pytest

from src.presentation_demo import live_intelligence


def sample_inventory():
    return {
        "inventory_id": "AEG-TEST-INVENTORY",
        "authorized_demo": True,
        "production_eligible": False,
        "components": [
            {
                "component_id": "AEG-CMP-TEST-1",
                "sector": "HEALTHCARE",
                "criticality": "CRITICAL",
                "mission_essential": True,
                "internet_exposed": True,
                "package": {
                    "ecosystem": "PyPI",
                    "name": "Django",
                    "version": "2.2.0",
                },
            }
        ],
    }


def test_normalize_component():
    component = (
        live_intelligence.normalize_component(
            sample_inventory()["components"][0]
        )
    )

    assert component["component_id"] == (
        "AEG-CMP-TEST-1"
    )
    assert component["package"]["ecosystem"] == "PyPI"
    assert component["package"]["name"] == "Django"
    assert component["package"]["version"] == "2.2.0"


def test_batch_payload_preserves_component_order():
    components = [
        live_intelligence.normalize_component(
            sample_inventory()["components"][0]
        )
    ]

    payload = (
        live_intelligence.build_batch_payload(
            components
        )
    )

    assert payload == {
        "queries": [
            {
                "version": "2.2.0",
                "package": {
                    "name": "Django",
                    "ecosystem": "PyPI",
                },
            }
        ]
    }


def test_ingestion_creates_governed_report(
    tmp_path,
    monkeypatch,
):
    inventory_path = tmp_path / "inventory.json"
    output_path = tmp_path / "report.json"

    inventory_path.write_text(
        json.dumps(sample_inventory()),
        encoding="utf-8",
    )

    def fake_request(
        url,
        *,
        payload=None,
        timeout=25.0,
        attempts=3,
    ):
        del timeout, attempts

        if url.endswith("/v1/querybatch"):
            assert payload is not None
            return {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-TEST-0001"
                            }
                        ]
                    }
                ]
            }

        assert url.endswith(
            "/v1/vulns/GHSA-TEST-0001"
        )

        return {
            "id": "GHSA-TEST-0001",
            "aliases": ["CVE-2026-0001"],
            "summary": "Controlled test vulnerability",
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-01-02T00:00:00Z",
            "severity": [],
            "database_specific": {
                "severity": "HIGH"
            },
        }

    monkeypatch.setattr(
        live_intelligence,
        "request_json",
        fake_request,
    )

    report = live_intelligence.ingest_osv(
        inventory_path,
        output_path,
    )

    assert report["summary"][
        "components_assessed"
    ] == 1

    assert report["summary"][
        "vulnerable_components"
    ] == 1

    assert report["components"][0][
        "cve_aliases"
    ] == ["CVE-2026-0001"]

    assert report["governance"][
        "production_readiness"
    ] == "BLOCKED"

    assert output_path.exists()
    assert output_path.with_suffix(
        ".json.sha256"
    ).exists()


def test_response_count_mismatch_fails_closed(
    tmp_path,
    monkeypatch,
):
    inventory_path = tmp_path / "inventory.json"

    inventory_path.write_text(
        json.dumps(sample_inventory()),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        live_intelligence,
        "request_json",
        lambda *args, **kwargs: {"results": []},
    )

    with pytest.raises(
        live_intelligence.LiveIntelligenceError,
        match="response count",
    ):
        live_intelligence.ingest_osv(
            inventory_path,
            tmp_path / "output.json",
        )


def test_unsupported_ecosystem_is_rejected():
    component = sample_inventory()["components"][0]
    component["package"]["ecosystem"] = "Unknown"

    with pytest.raises(
        live_intelligence.LiveIntelligenceError,
        match="Unsupported OSV ecosystem",
    ):
        live_intelligence.normalize_component(component)

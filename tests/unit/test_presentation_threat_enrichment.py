from __future__ import annotations

import json

import pytest

from src.presentation_demo import threat_enrichment


def source_report():
    return {
        "report_id": "AEG-LIVE-TEST",
        "source": {
            "name": "OSV",
            "mode": "LIVE_API",
        },
        "summary": {
            "components_assessed": 2,
        },
        "governance": {
            "live_source_claim": "VERIFIED",
            "production_readiness": "BLOCKED",
        },
        "components": [
            {
                "component_id": "AEG-CMP-1",
                "sector": "HEALTHCARE",
                "criticality": "CRITICAL",
                "mission_essential": True,
                "internet_exposed": True,
                "package": {
                    "ecosystem": "Maven",
                    "name": "example:critical",
                    "version": "1.0.0",
                },
                "cve_aliases": [
                    "CVE-2021-44228",
                ],
            },
            {
                "component_id": "AEG-CMP-2",
                "sector": "EDUCATION",
                "criticality": "MEDIUM",
                "mission_essential": False,
                "internet_exposed": False,
                "package": {
                    "ecosystem": "PyPI",
                    "name": "example-low",
                    "version": "1.0.0",
                },
                "cve_aliases": [
                    "CVE-2024-0001",
                ],
            },
        ],
    }


def test_chunk_cves_respects_character_limit():
    cves = [
        "CVE-2021-0001",
        "CVE-2021-0002",
        "CVE-2021-0003",
    ]

    chunks = threat_enrichment.chunk_cves(
        cves,
        maximum_query_characters=28,
    )

    assert chunks == [
        ["CVE-2021-0001", "CVE-2021-0002"],
        ["CVE-2021-0003"],
    ]


def test_invalid_cve_is_ignored():
    assert (
        threat_enrichment.normalize_cve(
            "GHSA-example"
        )
        is None
    )

    assert (
        threat_enrichment.normalize_cve(
            "cve-2021-44228"
        )
        == "CVE-2021-44228"
    )


def test_attention_signal_prioritizes_kev():
    signal, reasons = (
        threat_enrichment.attention_signal(
            kev_count=1,
            maximum_epss=0.95,
            criticality="CRITICAL",
            mission_essential=True,
            internet_exposed=True,
        )
    )

    assert signal == "IMMEDIATE_REVIEW"
    assert "CISA_KEV_CONFIRMED" in reasons


def test_enriched_report_is_governed(
    tmp_path,
    monkeypatch,
):
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"

    input_path.write_text(
        json.dumps(source_report()),
        encoding="utf-8",
    )

    def fake_request(
        url,
        *,
        payload=None,
        timeout=30.0,
        attempts=3,
    ):
        del payload, timeout, attempts

        if "known_exploited_vulnerabilities" in url:
            return {
                "catalogVersion": "test-1",
                "dateReleased": (
                    "2026-07-20T00:00:00Z"
                ),
                "count": 1,
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "vulnerabilityName": (
                            "Controlled test vulnerability"
                        ),
                        "dateAdded": "2021-12-10",
                        "dueDate": "2021-12-24",
                        "knownRansomwareCampaignUse": (
                            "Known"
                        ),
                        "requiredAction": (
                            "Apply vendor mitigations"
                        ),
                        "shortDescription": (
                            "Controlled test record"
                        ),
                        "notes": "",
                        "cwes": ["CWE-502"],
                    }
                ],
            }

        if "api.first.org" in url:
            return {
                "status": "OK",
                "status-code": 200,
                "version": "1.0",
                "total": 2,
                "data": [
                    {
                        "cve": "CVE-2021-44228",
                        "epss": "0.975",
                        "percentile": "0.999",
                        "date": "2026-07-20",
                    },
                    {
                        "cve": "CVE-2024-0001",
                        "epss": "0.020",
                        "percentile": "0.300",
                        "date": "2026-07-20",
                    },
                ],
            }

        raise AssertionError(
            f"Unexpected URL: {url}"
        )

    monkeypatch.setattr(
        threat_enrichment,
        "request_json",
        fake_request,
    )

    report = (
        threat_enrichment.build_enriched_report(
            input_path,
            output_path,
        )
    )

    assert report["summary"][
        "components_assessed"
    ] == 2

    assert report["summary"][
        "kev_confirmed_cves"
    ] == 1

    first = report["components"][0][
        "threat_enrichment"
    ]

    assert first["attention_signal"] == (
        "IMMEDIATE_REVIEW"
    )

    assert first["kev_confirmed_cves"] == 1
    assert first["maximum_epss"] == 0.975

    assert report["governance"][
        "authoritative_policy_engine"
    ] == "SSVC"

    assert report["governance"][
        "production_readiness"
    ] == "BLOCKED"

    assert output_path.exists()
    assert output_path.with_suffix(
        ".json.sha256"
    ).exists()


def test_unverified_osv_source_fails_closed(
    tmp_path,
):
    report = source_report()
    report["governance"][
        "live_source_claim"
    ] = "UNVERIFIED"

    input_path = tmp_path / "input.json"

    input_path.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    with pytest.raises(
        threat_enrichment.ThreatEnrichmentError,
        match="not verified",
    ):
        threat_enrichment.build_enriched_report(
            input_path,
            tmp_path / "output.json",
        )

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.intelligence.official_source import (
    OfficialSourceFetchResult,
    canonical_json_bytes,
    write_official_source_bundle,
)
from src.intelligence.source_correlation import (
    SourceCorrelationError,
    correlate_official_run,
    load_verified_official_run,
)


NOW = datetime(2026, 7, 15, 14, 9, 14, tzinfo=timezone.utc)
TARGET = "CVE-2021-44228"


def payloads(*, epss_present: bool = True) -> dict[str, object]:
    osv = {
        "vulns": [
            {
                "id": "GHSA-jfh8-c2jp-5v3q",
                "aliases": [TARGET],
                "summary": "Remote code injection in Log4j",
                "published": "2021-12-10T00:40:56Z",
                "modified": "2025-10-22T19:37:02Z",
                "database_specific": {
                    "severity": "CRITICAL",
                    "cwe_ids": ["CWE-20", "CWE-502"],
                },
                "affected": [
                    {
                        "package": {
                            "ecosystem": "Maven",
                            "name": "org.apache.logging.log4j:log4j-core",
                            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "2.13.0"},
                                    {"fixed": "2.15.0"},
                                ],
                            }
                        ],
                        "versions": ["2.13.0", "2.14.1"],
                    },
                    {
                        "package": {
                            "ecosystem": "Maven",
                            "name": "unrelated:package",
                        },
                        "versions": ["2.14.1"],
                    },
                ],
                "references": [{"url": "https://example.invalid/advisory"}],
            },
            {
                "id": "GHSA-adjacent-0000",
                "aliases": ["CVE-2021-45046"],
                "summary": "Adjacent vulnerability",
                "published": "2021-12-15T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "affected": [],
            },
        ]
    }
    nvd = {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": TARGET,
                    "sourceIdentifier": "security@apache.org",
                    "vulnStatus": "Analyzed",
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2026-06-17T04:12:05.460",
                    "descriptions": [{"lang": "en", "value": "NVD description"}],
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-20"},
                                {"lang": "en", "value": "CWE-400"},
                            ]
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 6.0,
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                            }
                        ],
                        "ssvcV203": [
                            {
                                "source": "cisa",
                                "ssvcData": {
                                    "id": TARGET,
                                    "options": [{"exploitation": "active"}],
                                },
                            }
                        ],
                    },
                }
            }
        ],
    }
    kev = {
        "catalogVersion": "2026.07.14",
        "dateReleased": "2026-07-14T19:00:56Z",
        "vulnerabilities": [
            {
                "cveID": TARGET,
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "shortDescription": "CISA description",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "requiredAction": "Apply updates or remove affected assets.",
                "knownRansomwareCampaignUse": "Known",
                "cwes": ["CWE-20", "CWE-400", "CWE-502"],
            }
        ],
    }
    epss = {
        "data": (
            [
                {
                    "cve": TARGET,
                    "epss": "0.99999",
                    "percentile": "1.0",
                    "date": "2026-07-15",
                }
            ]
            if epss_present
            else []
        )
    }
    return {"OSV": osv, "NVD": nvd, "CISA_KEV": kev, "FIRST_EPSS": epss}


def build_run(tmp_path: Path, *, epss_present: bool = True):
    source_meta = {
        "OSV": ("open_source_project", "high", "https://api.osv.dev/v1/query"),
        "NVD": (
            "official_government",
            "authoritative",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        ),
        "CISA_KEV": (
            "official_government",
            "authoritative",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ),
        "FIRST_EPSS": (
            "official_public_service",
            "high",
            "https://api.first.org/data/v1/epss",
        ),
    }
    output = tmp_path / "data" / "raw" / "official_sources" / "run"
    bundles = {}
    for source_name, payload in payloads(epss_present=epss_present).items():
        category, authority, endpoint = source_meta[source_name]
        result = OfficialSourceFetchResult(
            source_name=source_name,
            source_category=category,
            source_authority=authority,
            endpoint=endpoint,
            method="GET" if source_name != "OSV" else "POST",
            request_parameters={},
            request_body=None,
            request_headers={"Accept": "application/json"},
            retrieved_at=NOW.isoformat(),
            status_code=200,
            attempt_count=1,
            timeout_seconds=30.0,
            max_attempts=3,
            response_headers={"content-type": "application/json"},
            payload=payload,
        )
        record_ids = {
            "OSV": ["GHSA-adjacent-0000", "GHSA-jfh8-c2jp-5v3q"],
            "NVD": [TARGET],
            "CISA_KEV": [TARGET],
            "FIRST_EPSS": [TARGET] if epss_present else [],
        }[source_name]
        paths = write_official_source_bundle(
            output,
            result,
            source_record_ids=record_ids,
            validation_status="accepted" if record_ids else "accepted_with_warnings",
            validation_warnings=() if record_ids else ("No requested source record was present.",),
        )
        bundles[source_name] = {
            "envelope": str(paths.envelope_path.relative_to(tmp_path)),
            "payload": str(paths.payload_path.relative_to(tmp_path)),
            "integrity": str(paths.integrity_path.relative_to(tmp_path)),
            "record_ids": record_ids,
        }
    summary = {
        "schema_version": "1.0.0",
        "run_id": "AEG-M12-OFFICIAL-20260715T140914Z",
        "retrieved_at": NOW.isoformat(),
        "component": {
            "package_name": "org.apache.logging.log4j:log4j-core",
            "ecosystem": "Maven",
            "version": "2.14.1",
        },
        "requested_cve_ids": [TARGET],
        "sources": bundles,
        "network_used": True,
        "production_readiness": "BLOCKED",
        "limitations": [],
    }
    summary_path = output / "milestone12_official_source_summary.json"
    summary_path.write_bytes(canonical_json_bytes(summary))
    return load_verified_official_run(summary_path, project_root=tmp_path)


def test_exact_osv_alias_is_correlated_and_adjacent_record_isolated(tmp_path: Path) -> None:
    correlation = correlate_official_run(build_run(tmp_path), TARGET)
    assert correlation["exact_target_matches"]["OSV"] == ["GHSA-jfh8-c2jp-5v3q"]
    assert [item["record_id"] for item in correlation["osv"]["adjacent_records"]] == [
        "GHSA-adjacent-0000"
    ]


def test_osv_package_filter_excludes_unrelated_package(tmp_path: Path) -> None:
    correlation = correlate_official_run(build_run(tmp_path), TARGET)
    assertions = correlation["osv"]["package_evidence"]["assertions"]
    assert len(assertions) == 1
    assert assertions[0]["package_name"] == "org.apache.logging.log4j:log4j-core"
    assert assertions[0]["explicit_version_match"] is True
    assert assertions[0]["evidence_status"] == "AFFECTED_SUPPORTED"


def test_source_count_is_never_interpreted_as_consensus(tmp_path: Path) -> None:
    correlation = correlate_official_run(build_run(tmp_path), TARGET)
    assert correlation["controls"]["source_count_is_consensus"] is False
    assert correlation["controls"]["consensus_inference_permitted"] is False


def test_missing_epss_remains_missing_and_not_zero(tmp_path: Path) -> None:
    correlation = correlate_official_run(build_run(tmp_path, epss_present=False), TARGET)
    record = correlation["first_epss"]["record"]
    assert record["status"] == "MISSING"
    assert record["probability"] is None
    assert record["percentile"] is None


def test_nvd_selected_cvss_prefers_primary_nvd_metric(tmp_path: Path) -> None:
    correlation = correlate_official_run(build_run(tmp_path), TARGET)
    selected = correlation["nvd"]["record"]["selected_cvss"]
    assert selected["version"] == "3.1"
    assert selected["base_score"] == 10.0
    assert selected["source"] == "nvd@nist.gov"


def test_cwe_coverage_difference_is_preserved_not_flattened(tmp_path: Path) -> None:
    correlation = correlate_official_run(build_run(tmp_path), TARGET)
    assert correlation["assertion_differences"]
    assert correlation["assertion_differences"][0]["classification"] == "SOURCE_COVERAGE_DIFFERENCE"


def test_target_must_have_been_requested(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    with pytest.raises(SourceCorrelationError):
        correlate_official_run(run, "CVE-2022-0001")


def test_tampered_payload_fails_before_correlation(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    source = run.sources["NVD"]
    source.payload_path.write_text('{"tampered":true}\n', encoding="utf-8")
    with pytest.raises(SourceCorrelationError):
        load_verified_official_run(run.summary_path, project_root=tmp_path)

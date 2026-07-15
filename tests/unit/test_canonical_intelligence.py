from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.intelligence.canonical_intelligence import (
    CanonicalIntelligenceError,
    build_canonical_intelligence,
    verify_canonical_intelligence_bundle,
    write_canonical_intelligence_bundle,
)
from tests.unit.test_source_correlation import TARGET, build_run


def test_canonical_record_preserves_source_ownership(tmp_path: Path) -> None:
    record, _ = build_canonical_intelligence(build_run(tmp_path), target_cve=TARGET)
    ownership = {
        item["source_name"]: item["claim_ownership"]
        for item in record["source_assertions"]
    }
    assert "cvss" in ownership["NVD"]
    assert "known_exploitation" in ownership["CISA_KEV"]
    assert "exploit_probability" in ownership["FIRST_EPSS"]
    assert "affected_ranges" in ownership["OSV"]


def test_adjacent_osv_cve_cannot_contaminate_target_aliases(tmp_path: Path) -> None:
    record, _ = build_canonical_intelligence(build_run(tmp_path), target_cve=TARGET)
    assert "CVE-2021-45046" not in record["identifiers"]["aliases"]
    assert record["adjacent_vulnerabilities"][0]["aliases"] == ["CVE-2021-45046"]


def test_canonical_field_provenance_covers_decision_inputs(tmp_path: Path) -> None:
    record, _ = build_canonical_intelligence(build_run(tmp_path), target_cve=TARGET)
    paths = {item["field_path"] for item in record["field_provenance"]}
    assert "/vulnerability/severity/selected" in paths
    assert "/exploitation/kev" in paths
    assert "/exploitation/epss" in paths
    assert "/package_evidence" in paths


def test_canonical_stage_does_not_claim_affectedness(tmp_path: Path) -> None:
    record, report = build_canonical_intelligence(build_run(tmp_path), target_cve=TARGET)
    assert record["affectedness_decision"]["status"] == "NOT_EVALUATED"
    assert record["production_readiness"] == "BLOCKED"
    assert report["release_decision"]["production_readiness"] == "BLOCKED"


def test_live_log4shell_style_fixture_has_expected_canonical_fields(tmp_path: Path) -> None:
    record, report = build_canonical_intelligence(build_run(tmp_path), target_cve=TARGET)
    assert record["vulnerability"]["severity"]["selected"]["base_score"] == 10.0
    assert record["exploitation"]["kev"]["status"] == "LISTED"
    assert record["exploitation"]["epss"]["probability"] == pytest.approx(0.99999)
    assert record["package_evidence"]["aggregate_status"] == "AFFECTED_SUPPORTED"
    assert report["release_decision"]["stage_gate"] == "PASS"


def test_missing_epss_stays_null_in_canonical_record(tmp_path: Path) -> None:
    record, _ = build_canonical_intelligence(
        build_run(tmp_path, epss_present=False),
        target_cve=TARGET,
    )
    assert record["exploitation"]["epss"]["status"] == "MISSING"
    assert record["exploitation"]["epss"]["probability"] is None


def test_canonical_build_is_deterministic(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    first_record, first_report = build_canonical_intelligence(run, target_cve=TARGET)
    second_record, second_report = build_canonical_intelligence(run, target_cve=TARGET)
    assert first_record == second_record
    assert first_report == second_report


def test_canonical_bundle_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    output = tmp_path / "data" / "processed" / "canonical"
    paths = write_canonical_intelligence_bundle(
        summary_path=run.summary_path,
        target_cve=TARGET,
        output_dir=output,
        project_root=tmp_path,
    )
    canonical, report = verify_canonical_intelligence_bundle(paths.canonical_path)
    assert canonical["record_id"].startswith("AEG-CVI-")
    assert report["canonical_record"]["record_id"] == canonical["record_id"]

    document = json.loads(paths.correlation_path.read_text(encoding="utf-8"))
    document["release_decision"]["stage_gate"] = "FAIL"
    paths.correlation_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(CanonicalIntelligenceError):
        verify_canonical_intelligence_bundle(paths.canonical_path)

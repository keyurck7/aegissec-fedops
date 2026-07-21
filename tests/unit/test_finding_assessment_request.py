from __future__ import annotations

import copy
import json

from pathlib import Path

import pandas as pd
from jsonschema import Draft202012Validator

from src.intake.unified_gateway import (
    ingest_bytes,
)
from src.orchestration.finding_assessment_request import (
    build_finding_assessment_request,
    build_requests_from_workbench,
    verify_finding_assessment_request,
)
from src.presentation_demo.unified_scan_workbench import (
    run_unified_scan,
)


ROOT = Path(__file__).resolve().parents[2]


def envelope():
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": (
                    "pkg:maven/"
                    "org.apache.logging.log4j/"
                    "log4j-core@2.14.1"
                ),
            }
        ],
    }

    return ingest_bytes(
        json.dumps(document).encode(),
        filename="demo.cdx.json",
    )


def asset():
    return {
        "asset_id": (
            "AEG-AST-HOSP-SCHED-001"
        ),
        "criticality": {
            "level": "high"
        },
        "exposure": {
            "internet_accessible": True
        },
        "impact_assessment": {
            "availability": "SEVERE"
        },
    }


def finding():
    return {
        "cve_id": "CVE-2021-44228",
        "package_name": "log4j-core",
        "package_version": "2.14.1",
        "purl": (
            "pkg:maven/"
            "org.apache.logging.log4j/"
            "log4j-core@2.14.1"
        ),
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "epss_score": 0.99999,
        "epss_percentile": 1.0,
        "kev_flag": True,
    }


def test_ready_request_validates_schema():
    request = (
        build_finding_assessment_request(
            input_envelope=envelope(),
            asset_context=asset(),
            component=(
                envelope()["components"][0]
            ),
            finding_row=finding(),
            historical_snapshot={
                "cve_id": (
                    "CVE-2021-44228"
                ),
                "snapshot_kev": True,
            },
        )
    )

    assert (
        request["status"]
        == "READY_FOR_AFFECTEDNESS"
    )

    assert (
        request[
            "unit_of_assessment"
        ]["cve_id"]
        == "CVE-2021-44228"
    )

    assert (
        verify_finding_assessment_request(
            request
        )
    )

    schema = json.loads(
        (
            ROOT
            / "schemas"
            / "aegis_finding_assessment_request.schema.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    errors = list(
        Draft202012Validator(
            schema
        ).iter_errors(request)
    )

    assert errors == []


def test_missing_version_blocks_request():
    component = dict(
        envelope()["components"][0]
    )

    component["version"] = None

    request = (
        build_finding_assessment_request(
            input_envelope=envelope(),
            asset_context=asset(),
            component=component,
            finding_row=finding(),
        )
    )

    assert request["status"] == "BLOCKED"

    assert (
        "EXACT_COMPONENT_VERSION_MISSING"
        in request["readiness"][
            "blocking_reason_codes"
        ]
    )


def test_runtime_unknown_is_preserved():
    request = (
        build_finding_assessment_request(
            input_envelope=envelope(),
            asset_context=asset(),
            component=(
                envelope()["components"][0]
            ),
            finding_row=finding(),
        )
    )

    assert (
        request["runtime_context"][
            "presence"
        ]
        == "PRESENT"
    )

    assert (
        request["runtime_context"][
            "reachability"
        ]
        == "UNKNOWN"
    )

    assert (
        "RUNTIME_REACHABILITY_UNKNOWN"
        in request["readiness"][
            "warnings"
        ]
    )


def test_request_tampering_is_detected():
    request = (
        build_finding_assessment_request(
            input_envelope=envelope(),
            asset_context=asset(),
            component=(
                envelope()["components"][0]
            ),
            finding_row=finding(),
        )
    )

    tampered = copy.deepcopy(
        request
    )

    tampered[
        "unit_of_assessment"
    ]["component"]["version"] = (
        "9.9.9"
    )

    assert not (
        verify_finding_assessment_request(
            tampered
        )
    )


def test_manifest_deduplicates_same_unit():
    input_envelope = envelope()

    workbench = {
        "envelope": input_envelope,
        "scan": {
            "vulnerability_findings": (
                pd.DataFrame(
                    [
                        finding(),
                        finding(),
                    ]
                )
            )
        },
        "snapshot_evidence": (
            pd.DataFrame()
        ),
    }

    manifest = build_requests_from_workbench(
        workbench_result=workbench,
        asset_context=asset(),
    )

    assert (
        manifest["statistics"][
            "source_finding_rows"
        ]
        == 2
    )

    assert (
        manifest["statistics"][
            "request_count"
        ]
        == 1
    )

    assert (
        manifest["statistics"][
            "duplicate_request_count"
        ]
        == 1
    )


def test_real_demo_contains_ready_log4shell_request():
    sbom = (
        ROOT
        / "data"
        / "demo"
        / "aegissec_demo_project.cdx.json"
    )

    asset_path = (
        ROOT
        / "data"
        / "sample_inputs"
        / "assets"
        / "valid_healthcare_asset.json"
    )

    workbench = run_unified_scan(
        sbom.read_bytes(),
        filename=sbom.name,
        authorized=True,
    )

    asset_context = json.loads(
        asset_path.read_text(
            encoding="utf-8"
        )
    )

    manifest = build_requests_from_workbench(
        workbench_result=workbench,
        asset_context=asset_context,
    )

    matches = [
        request
        for request
        in manifest["requests"]
        if request[
            "unit_of_assessment"
        ]["cve_id"]
        == "CVE-2021-44228"
        and "log4j"
        in str(
            request[
                "unit_of_assessment"
            ]["component"].get(
                "name"
            )
        ).lower()
    ]

    assert matches

    assert any(
        request["status"]
        == "READY_FOR_AFFECTEDNESS"
        for request in matches
    )

    selected = next(
        request
        for request in matches
        if request["status"]
        == "READY_FOR_AFFECTEDNESS"
    )

    assert (
        selected[
            "unit_of_assessment"
        ]["component"]["version"]
        == "2.14.1"
    )

    assert (
        selected["governance"][
            "final_disposition_authority"
        ]
        == "HUMAN"
    )

    assert (
        selected["governance"][
            "production_readiness"
        ]
        == "BLOCKED"
    )



def test_risk_mart_component_id_bridges_through_bom_ref():
    input_envelope = envelope()

    canonical_component = (
        input_envelope[
            "components"
        ][0]
    )

    workbench = {
        "envelope": input_envelope,
        "scan": {
            "matched_components": (
                pd.DataFrame(
                    [
                        {
                            "component_id": (
                                "AEG-RISK-CMP-0001"
                            ),
                            "bom_ref": (
                                canonical_component[
                                    "component_id"
                                ]
                            ),
                            "ecosystem": "Maven",
                            "package_name": (
                                "org.apache.logging.log4j:"
                                "log4j-core"
                            ),
                            "version": "2.14.1",
                            "purl": (
                                canonical_component[
                                    "purl"
                                ]
                            ),
                        }
                    ]
                )
            ),
            "vulnerability_findings": (
                pd.DataFrame(
                    [
                        {
                            "component_id": (
                                "AEG-RISK-CMP-0001"
                            ),
                            "vulnerability_id": (
                                "CVE-2021-44228"
                            ),
                            "epss_score": (
                                0.99999
                            ),
                            "kev": 1,
                        }
                    ]
                )
            ),
        },
        "snapshot_evidence": (
            pd.DataFrame()
        ),
    }

    manifest = build_requests_from_workbench(
        workbench_result=workbench,
        asset_context=asset(),
    )

    assert (
        manifest["statistics"][
            "request_count"
        ]
        == 1
    )

    request = manifest[
        "requests"
    ][0]

    resolved = request[
        "unit_of_assessment"
    ]["component"]

    assert (
        request["status"]
        == "READY_FOR_AFFECTEDNESS"
    )

    assert (
        resolved["component_id"]
        == canonical_component[
            "component_id"
        ]
    )

    assert (
        resolved["name"]
        == "log4j-core"
    )

    assert (
        resolved["version"]
        == "2.14.1"
    )

    assert (
        resolved["purl"]
        == canonical_component[
            "purl"
        ]
    )

    assert (
        request[
            "evidence_snapshot"
        ]["exploitation"][
            "kev_flag"
        ]
        is True
    )

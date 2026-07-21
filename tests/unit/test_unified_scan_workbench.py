from __future__ import annotations

import json

from pathlib import Path

import pandas as pd
import pytest

from src.intake.unified_gateway import (
    InputGatewayError,
    ingest_bytes,
)
from src.presentation_demo import (
    unified_scan_workbench as workbench,
)


def fake_scan(
    payload: bytes,
    *,
    filename: str,
):
    document = json.loads(
        payload.decode("utf-8")
    )

    return {
        "summary": {
            "uploaded_components": len(
                document["components"]
            ),
            "matched_components": 1,
            "unmatched_components": 0,
            "vulnerable_matched_components": 1,
            "components_with_kev": 0,
            "operational_status": (
                "REVIEW_REQUIRED"
            ),
        },
        "document": {
            "filename": filename,
            "sha256": "0" * 64,
            "spec_version": "1.6",
        },
        "matched_components": (
            pd.DataFrame(
                [
                    {
                        "package_name": (
                            "requests"
                        ),
                        "package_version": (
                            "2.31.0"
                        ),
                    }
                ]
            )
        ),
        "unmatched_components": (
            pd.DataFrame()
        ),
        "vulnerability_findings": (
            pd.DataFrame(
                [
                    {
                        "cve": (
                            "CVE-2024-10000"
                        )
                    }
                ]
            )
        ),
    }


def test_synthetic_cyclonedx_uses_only_exact_versions():
    envelope = ingest_bytes(
        (
            b"requests==2.31.0\n"
            b"django>=4.2\n"
        ),
        filename="requirements.txt",
    )

    document = (
        workbench
        .build_synthetic_cyclonedx(
            envelope
        )
    )

    assert document[
        "bomFormat"
    ] == "CycloneDX"

    assert len(
        document["components"]
    ) == 1

    assert document[
        "components"
    ][0]["name"] == "requests"


def test_generated_python_purl():
    purl = workbench.generated_purl(
        {
            "name": "requests",
            "version": "2.31.0",
            "ecosystem": "PyPI",
            "purl": None,
        }
    )

    assert (
        purl
        == "pkg:pypi/requests@2.31.0"
    )


def test_run_workbench_with_stubbed_scan(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        workbench,
        "scan_cyclonedx_bytes",
        fake_scan,
    )

    result = workbench.run_unified_scan(
        b"requests==2.31.0\n",
        filename="requirements.txt",
        authorized=True,
        database_path=(
            tmp_path
            / "missing.sqlite"
        ),
    )

    assert (
        result["envelope"][
            "detection"
        ]["format"]
        == "REQUIREMENTS_TXT"
    )

    assert (
        result[
            "exact_scan_components"
        ]
        == 1
    )

    assert (
        result["cve_ids"]
        == ["CVE-2024-10000"]
    )

    assert (
        result["governance"][
            "ssvc_authority"
        ]
        == "PRESERVED"
    )

    assert (
        result["governance"][
            "final_disposition"
        ]
        == "HUMAN"
    )

    assert (
        result["governance"][
            "production_readiness"
        ]
        == "BLOCKED"
    )


def test_trivy_cve_hint_is_collected(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        workbench,
        "scan_cyclonedx_bytes",
        fake_scan,
    )

    document = {
        "Results": [
            {
                "Type": "python",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": (
                            "CVE-2021-44228"
                        ),
                        "PkgName": "example",
                        "InstalledVersion": (
                            "1.0.0"
                        ),
                    }
                ],
            }
        ]
    }

    result = workbench.run_unified_scan(
        json.dumps(document).encode(),
        filename="trivy.json",
        authorized=True,
        database_path=(
            tmp_path
            / "missing.sqlite"
        ),
    )

    assert (
        "CVE-2021-44228"
        in result["cve_ids"]
    )


def test_unauthorized_input_is_rejected():
    with pytest.raises(
        InputGatewayError,
        match="authorized",
    ):
        workbench.run_unified_scan(
            b"requests==2.31.0",
            filename="requirements.txt",
            authorized=False,
        )


def test_dashboard_has_unified_scan_page():
    text = Path(
        "app/aegissec_command_center.py"
    ).read_text(
        encoding="utf-8"
    )

    assert (
        '"Scan a System"'
        in text
    )

    assert (
        'elif page == "Scan a System":'
        in text
    )

    assert (
        'elif page == "SBOM Ingestion":'
        not in text
    )

    assert (
        "run_unified_scan"
        in text
    )

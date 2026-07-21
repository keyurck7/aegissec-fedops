from __future__ import annotations

import json

import pytest

from jsonschema import Draft202012Validator

from src.intake.unified_gateway import (
    InputGatewayError,
    ingest_bytes,
    serialize_envelope,
    verify_envelope_integrity,
)


def load_schema():
    with open(
        "schemas/"
        "aegis_unified_input_envelope.schema.json",
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def assert_valid_envelope(envelope):
    validator = Draft202012Validator(
        load_schema()
    )

    errors = sorted(
        validator.iter_errors(envelope),
        key=lambda error: list(
            error.absolute_path
        ),
    )

    assert errors == []
    assert verify_envelope_integrity(
        envelope
    )
    assert serialize_envelope(envelope)


def test_cyclonedx_json() -> None:
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

    envelope = ingest_bytes(
        json.dumps(document).encode(),
        filename="demo.cdx.json",
    )

    assert (
        envelope["detection"]["format"]
        == "CYCLONEDX_JSON"
    )
    assert (
        envelope["statistics"][
            "component_count"
        ]
        == 1
    )
    assert (
        envelope["components"][0][
            "identity_status"
        ]
        == "EXACT"
    )

    assert_valid_envelope(envelope)


def test_spdx_json() -> None:
    document = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": (
                            "pkg:pypi/"
                            "requests@2.31.0"
                        ),
                    }
                ],
            }
        ],
    }

    envelope = ingest_bytes(
        json.dumps(document).encode(),
        filename="software.spdx.json",
    )

    assert (
        envelope["detection"]["format"]
        == "SPDX_JSON"
    )
    assert (
        envelope["components"][0][
            "ecosystem"
        ]
        == "PyPI"
    )

    assert_valid_envelope(envelope)


def test_requirements_unknown_version() -> None:
    payload = (
        b"requests==2.31.0\n"
        b"django>=4.2\n"
    )

    envelope = ingest_bytes(
        payload,
        filename="requirements.txt",
    )

    assert (
        envelope["detection"]["format"]
        == "REQUIREMENTS_TXT"
    )
    assert (
        envelope["statistics"][
            "unknown_version_count"
        ]
        == 1
    )
    assert (
        envelope["trust"][
            "human_review_required"
        ]
        is True
    )

    assert_valid_envelope(envelope)


def test_package_json_ranges_remain_unknown() -> None:
    document = {
        "name": "portal",
        "dependencies": {
            "lodash": "^4.17.20",
            "axios": "0.21.1",
        },
    }

    envelope = ingest_bytes(
        json.dumps(document).encode(),
        filename="package.json",
    )

    assert (
        envelope["detection"]["format"]
        == "PACKAGE_JSON"
    )
    assert (
        envelope["statistics"][
            "unknown_version_count"
        ]
        == 1
    )

    assert_valid_envelope(envelope)


def test_package_lock_json() -> None:
    document = {
        "name": "portal",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "portal",
                "version": "1.0.0"
            },
            "node_modules/axios": {
                "version": "0.21.1"
            }
        },
    }

    envelope = ingest_bytes(
        json.dumps(document).encode(),
        filename="package-lock.json",
    )

    assert (
        envelope["detection"]["format"]
        == "PACKAGE_LOCK_JSON"
    )
    assert (
        envelope["components"][0][
            "name"
        ]
        == "axios"
    )

    assert_valid_envelope(envelope)


def test_component_csv() -> None:
    payload = (
        b"name,version,ecosystem,purl\n"
        b"django,3.2.10,PyPI,"
        b"pkg:pypi/django@3.2.10\n"
    )

    envelope = ingest_bytes(
        payload,
        filename="inventory.csv",
    )

    assert (
        envelope["detection"]["format"]
        == "COMPONENT_CSV"
    )
    assert (
        envelope["components"][0][
            "identity_status"
        ]
        == "EXACT"
    )

    assert_valid_envelope(envelope)


def test_syft_json() -> None:
    document = {
        "artifacts": [
            {
                "name": "urllib3",
                "version": "1.26.5",
                "type": "python",
                "purl": (
                    "pkg:pypi/"
                    "urllib3@1.26.5"
                ),
                "locations": [
                    {
                        "path": (
                            "/usr/lib/python/"
                            "urllib3"
                        )
                    }
                ],
            }
        ]
    }

    envelope = ingest_bytes(
        json.dumps(document).encode(),
        filename="syft.json",
    )

    assert (
        envelope["detection"]["format"]
        == "SYFT_JSON"
    )
    assert (
        envelope["components"][0][
            "ecosystem"
        ]
        == "PyPI"
    )

    assert_valid_envelope(envelope)


def test_trivy_is_advisory_only() -> None:
    document = {
        "Results": [
            {
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": (
                            "CVE-2021-44228"
                        ),
                        "PkgName": "example",
                        "InstalledVersion": "1.0.0",
                        "Severity": "CRITICAL",
                    }
                ],
            }
        ]
    }

    envelope = ingest_bytes(
        json.dumps(document).encode(),
        filename="trivy.json",
    )

    assert (
        envelope["detection"]["format"]
        == "TRIVY_JSON"
    )
    assert (
        envelope["vulnerability_hints"][0][
            "authority"
        ]
        == "ADVISORY_ONLY"
    )
    assert (
        envelope["governance"][
            "may_determine_affectedness_alone"
        ]
        is False
    )

    assert_valid_envelope(envelope)


def test_archive_is_rejected() -> None:
    with pytest.raises(
        InputGatewayError,
        match="Archive",
    ) as error:
        ingest_bytes(
            b"PK\x03\x04fake",
            filename="input.zip",
        )

    assert (
        error.value.reason_code
        == "INPUT_ARCHIVE_PROHIBITED"
    )


def test_executable_is_rejected() -> None:
    with pytest.raises(
        InputGatewayError,
        match="Executable",
    ) as error:
        ingest_bytes(
            b"\x7fELFfake",
            filename="scanner",
        )

    assert (
        error.value.reason_code
        == "INPUT_EXECUTABLE_PROHIBITED"
    )


def test_unauthorized_input_is_rejected() -> None:
    with pytest.raises(
        InputGatewayError,
        match="authorized",
    ) as error:
        ingest_bytes(
            b"requests==2.31.0",
            filename="requirements.txt",
            authorized=False,
        )

    assert (
        error.value.reason_code
        == "INPUT_AUTHORIZATION_REQUIRED"
    )


def test_integrity_detects_tampering() -> None:
    envelope = ingest_bytes(
        b"requests==2.31.0",
        filename="requirements.txt",
    )

    assert verify_envelope_integrity(
        envelope
    )

    envelope["components"][0][
        "version"
    ] = "999.0.0"

    assert not verify_envelope_integrity(
        envelope
    )

from __future__ import annotations

import pytest

from src.intelligence.field_provenance import (
    ProvenanceContext,
    assert_provenance_coverage,
    build_field_provenance,
    stable_digest,
    stable_identifier,
)


def context() -> ProvenanceContext:
    return ProvenanceContext(
        source_name="NVD",
        source_record_id="CVE-2021-44228",
        source_authority="authoritative",
        retrieved_at="2026-07-15T14:09:14+00:00",
        artifact_sha256="a" * 64,
        envelope_id="AEG-OSI-" + "A" * 24,
    )


def test_stable_digest_is_order_independent_for_mappings() -> None:
    assert stable_digest({"b": 2, "a": 1}) == stable_digest({"a": 1, "b": 2})


def test_stable_identifier_is_deterministic() -> None:
    first = stable_identifier("AEG-CVI", {"cve": "CVE-2021-44228"})
    second = stable_identifier("AEG-CVI", {"cve": "CVE-2021-44228"})
    assert first == second
    assert first.startswith("AEG-CVI-")
    assert len(first.rsplit("-", 1)[1]) == 24


def test_field_provenance_hashes_the_selected_value() -> None:
    item = build_field_provenance(
        field_path="/vulnerability/status",
        value="Analyzed",
        context=context(),
        extraction_method="exact_field",
        source_pointer="/vulnerabilities/0/cve/vulnStatus",
    )
    assert item["source_name"] == "NVD"
    assert item["value_sha256"] == stable_digest("Analyzed")
    assert item["source_artifact_sha256"] == "a" * 64


def test_field_provenance_requires_absolute_json_pointers() -> None:
    with pytest.raises(ValueError):
        build_field_provenance(
            field_path="vulnerability/status",
            value="Analyzed",
            context=context(),
            extraction_method="exact_field",
            source_pointer="/vulnerabilities/0/cve/vulnStatus",
        )


def test_provenance_coverage_fails_closed() -> None:
    record = {
        "field_provenance": [
            {
                "field_path": "/target/cve_id",
            }
        ]
    }
    with pytest.raises(ValueError):
        assert_provenance_coverage(
            record,
            required_field_paths={"/target/cve_id", "/target/component"},
        )

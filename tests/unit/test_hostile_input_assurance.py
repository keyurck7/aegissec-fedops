from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from src.affectedness.versioning import parse_version
from src.ingestion.vulnerability_feature_parser import (
    parse_vulnerability_feature_row,
)
from src.normalization.strict_parsing import (
    ParseStatus,
    parse_optional_float,
    parse_optional_purl,
    parse_probability,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "hostile_input_catalog_v1.yaml"
)
REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_hostile_input_report.json"
)
RESULTS_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_hostile_input_results.csv"
)
UNDETECTED_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_undetected_inputs.json"
)
INTEGRITY_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation_reports"
    / "hostile_inputs"
    / "step11d_trusted_baseline_integrity.sha256"
)
SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_hostile_input_assurance_report.schema.json"
)
EXPECTED_BLOCKERS = [
    "Real operational validation has not yet been completed.",
    "Independent security review has not yet been completed.",
]


def load_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def load_catalog() -> dict:
    payload = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def valid_row() -> dict[str, object]:
    return {
        "finding_id": "FND-STRICT-001",
        "asset_id": "AEG-AST-HOSP-SCHED-001",
        "component_name": "log4j-core",
        "component_version": "2.14.1",
        "canonical_id": "CVE-2021-44228",
        "kev_flag": "False",
        "epss_probability": "",
        "epss_percentile": "0.999",
        "cvss_score": "10.0",
        "internet_accessible": "true",
        "asset_criticality": "high",
        "affectedness": "affected",
        "input_trust": "high",
        "patient_safety_impact": "high",
        "mission_readiness_impact": "not_applicable",
    }


def test_catalog_contains_50_unique_critical_scenarios() -> None:
    scenarios = load_catalog()["scenarios"]
    scenario_ids = [item["scenario_id"] for item in scenarios]

    assert len(scenarios) == 50
    assert len(set(scenario_ids)) == 50
    assert all(item["severity"] == "critical" for item in scenarios)
    assert all(item["handler"] for item in scenarios)
    assert all(item["expected_outcomes"] for item in scenarios)
    assert all(item["expected_oracles"] for item in scenarios)


def test_required_hostile_input_families_are_present() -> None:
    families = {item["family"] for item in load_catalog()["scenarios"]}
    required = {
        "boolean_deception",
        "numeric_poisoning",
        "boundary_violation",
        "date_ambiguity",
        "timestamp_manipulation",
        "unicode_deception",
        "control_character_injection",
        "purl_corruption",
        "oversized_input",
        "parser_exhaustion",
        "type_confusion",
        "cve_corruption",
        "duplicate_identity",
        "enum_poisoning",
        "formula_injection",
        "version_ambiguity",
        "unsupported_version_scheme",
        "missing_value_confusion",
    }
    assert required.issubset(families)


def test_native_nan_is_invalid_not_missing() -> None:
    result = parse_probability(float("nan"), "epss_probability")

    assert result.status == ParseStatus.INVALID
    assert result.code == "NON_FINITE_NUMERIC_VALUE"


def test_float_conversion_overflow_is_rejected() -> None:
    result = parse_optional_float("1e1000000", "score")

    assert result.status == ParseStatus.INVALID
    assert result.code == "NUMERIC_CONVERSION_OVERFLOW"


def test_zero_width_and_bidi_controls_are_rejected() -> None:
    zero_width = parse_optional_purl(
        "pkg:maven/org.example/log\u200b4j"
    )
    bidi = parse_optional_purl(
        "pkg:maven/org.example/log4j\u202e"
    )

    assert zero_width.status == ParseStatus.INVALID
    assert zero_width.code == "UNICODE_FORMAT_CONTROL_NOT_ALLOWED"
    assert bidi.status == ParseStatus.INVALID
    assert bidi.code == "UNICODE_FORMAT_CONTROL_NOT_ALLOWED"


def test_purl_percent_and_traversal_attacks_are_rejected() -> None:
    malformed = parse_optional_purl("pkg:maven/org.example/log%ZZ")
    traversal = parse_optional_purl(
        "pkg:maven/org.example/%2e%2e/secret"
    )

    assert malformed.status == ParseStatus.INVALID
    assert malformed.code == "INVALID_PURL_PERCENT_ENCODING"
    assert traversal.status == ParseStatus.INVALID
    assert traversal.code == "PURL_PATH_TRAVERSAL_OR_EMPTY_SEGMENT"


def test_formula_and_object_component_names_reject_feature_row() -> None:
    formula_row = valid_row()
    formula_row["component_name"] = "=HYPERLINK(\"x\")"
    object_row = valid_row()
    object_row["component_name"] = {"name": "log4j-core"}

    formula_report = parse_vulnerability_feature_row(formula_row)
    object_report = parse_vulnerability_feature_row(object_row)

    assert formula_report.accepted is False
    assert {
        error.code for error in formula_report.errors
    } >= {"SPREADSHEET_FORMULA_PREFIX_NOT_ALLOWED"}
    assert object_report.accepted is False
    assert {
        error.code for error in object_report.errors
    } >= {"INVALID_STRING_TYPE"}


def test_ambiguous_version_expressions_are_not_guessed() -> None:
    assert parse_version("2.x") is None
    assert parse_version(">=2.0,<3.0") is None
    assert parse_version("1" * 151) is None


def test_generated_report_validates_against_schema() -> None:
    schema = load_json(SCHEMA_PATH)
    report = load_json(REPORT_PATH)

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )
    assert errors == []


def test_all_critical_inputs_are_defended() -> None:
    report = load_json(REPORT_PATH)
    summary = report["summary"]

    assert summary["scenario_count"] == 50
    assert summary["critical_scenario_count"] == 50
    assert summary["rejected_count"] == 42
    assert summary["quarantined_count"] == 2
    assert summary["normalized_safe_count"] == 6
    assert summary["accepted_with_warning_count"] == 0
    assert summary["undetected_count"] == 0
    assert summary["harness_error_count"] == 0
    assert summary["defended_critical_count"] == 50
    assert summary["critical_hostile_input_defence_rate"] == 1.0
    assert summary["overall_passed"] is True

    for result in report["results"]:
        assert result["outcome"] in {
            "REJECTED",
            "QUARANTINED",
            "NORMALIZED_SAFE",
        }
        assert result["defended"] is True
        assert result["expectation_met"] is True
        assert result["ephemeral_only"] is True
        assert result["detection_oracles"]
        assert result["findings"]
        assert result["error"] is None


def test_subgroup_quality_gates_are_100_percent() -> None:
    summary = load_json(REPORT_PATH)["summary"]

    assert summary["nonfinite_numeric_scenario_count"] > 0
    assert summary["nonfinite_numeric_defence_rate"] == 1.0
    assert summary["unicode_deception_scenario_count"] > 0
    assert summary["unicode_deception_defence_rate"] == 1.0
    assert summary["oversized_payload_scenario_count"] > 0
    assert summary["oversized_payload_defence_rate"] == 1.0
    assert summary["malformed_identifier_scenario_count"] > 0
    assert summary["malformed_identifier_defence_rate"] == 1.0
    assert summary["missing_value_semantics_scenario_count"] > 0
    assert summary["missing_value_semantics_defence_rate"] == 1.0
    assert summary["type_confusion_scenario_count"] > 0
    assert summary["type_confusion_defence_rate"] == 1.0


def test_trusted_inputs_remain_unchanged() -> None:
    report = load_json(REPORT_PATH)
    assert report["summary"]["trusted_input_integrity_passed"] is True

    before = report["input_integrity_checks_before"]
    after = report["input_integrity_checks_after"]
    assert set(before) == set(after)
    for name in before:
        assert before[name]["passed"] is True
        assert after[name]["passed"] is True
        assert before[name]["actual_sha256"] == after[name]["actual_sha256"]


def test_release_decision_preserves_honest_blockers() -> None:
    release = load_json(REPORT_PATH)["release_decision"]

    assert release["stage_gate_status"] == "PASS"
    assert release["production_readiness_status"] == "BLOCKED"
    assert release["blocking_reasons"] == EXPECTED_BLOCKERS


def test_csv_and_undetected_artifacts_are_consistent() -> None:
    with RESULTS_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        rows = list(csv.DictReader(handle))

    undetected = load_json(UNDETECTED_PATH)

    assert len(rows) == 50
    assert undetected["undetected_input_ids"] == []
    assert undetected["undetected_inputs"] == []
    assert undetected["harness_error_input_ids"] == []
    assert INTEGRITY_PATH.is_file()
    assert len(INTEGRITY_PATH.read_text(encoding="utf-8").splitlines()) == 8


def test_cli_runner_imports_project_from_any_working_directory(
    tmp_path: Path,
) -> None:
    runner = (
        PROJECT_ROOT
        / "scripts"
        / "run_step11d_hostile_input_assurance.py"
    )

    result = subprocess.run(
        [sys.executable, str(runner), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (
        "Run Step 11D hostile and malformed input assurance."
        in result.stdout
    )

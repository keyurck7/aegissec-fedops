from __future__ import annotations

import copy
import csv
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from src.affectedness.versioning import evaluate_version_range, parse_version
from src.ingestion.vulnerability_feature_parser import (
    parse_vulnerability_feature_row,
)
from src.normalization.strict_parsing import (
    ParseOutcome,
    ParseStatus,
    parse_cve_id,
    parse_cvss_score,
    parse_optional_boolean,
    parse_optional_date,
    parse_optional_datetime,
    parse_optional_enum,
    parse_optional_float,
    parse_optional_integer,
    parse_optional_purl,
    parse_probability,
)
from src.validation.vulnerability_intelligence_validator import (
    VulnerabilityIntelligenceValidator,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "hostile_input_catalog_v1.yaml"
)

DEFENDED_OUTCOMES = {
    "REJECTED",
    "QUARANTINED",
    "NORMALIZED_SAFE",
    "ACCEPTED_WITH_WARNING",
}


@dataclass(frozen=True)
class HostileInputFinding:
    code: str
    oracle: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "oracle": self.oracle,
            "message": self.message,
        }


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def write_json(path: Path | str, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def write_results_csv(
    path: Path | str,
    results: list[dict[str, Any]],
) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "scenario_id",
        "family",
        "severity",
        "outcome",
        "defended",
        "expectation_met",
        "detection_oracles",
        "finding_codes",
        "observed_status",
        "observed_code",
        "error",
    ]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            observed = result.get("observed") or {}
            writer.writerow(
                {
                    "scenario_id": result["scenario_id"],
                    "family": result["family"],
                    "severity": result["severity"],
                    "outcome": result["outcome"],
                    "defended": result["defended"],
                    "expectation_met": result["expectation_met"],
                    "detection_oracles": ";".join(
                        result["detection_oracles"]
                    ),
                    "finding_codes": ";".join(
                        finding["code"] for finding in result["findings"]
                    ),
                    "observed_status": observed.get("status", ""),
                    "observed_code": observed.get("code", ""),
                    "error": result.get("error") or "",
                }
            )


def _safe_scalar(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _parse_observation(outcome: ParseOutcome[Any]) -> dict[str, Any]:
    return {
        "status": outcome.status.value,
        "code": outcome.code,
        "value": _safe_scalar(outcome.value),
        "normalized_text": outcome.normalized_text,
    }


def _finding(code: str, oracle: str, message: str) -> HostileInputFinding:
    return HostileInputFinding(code=code, oracle=oracle, message=message)


class HostileInputAssuranceHarness:
    def __init__(
        self,
        catalog_path: Path | str = DEFAULT_CATALOG_PATH,
        project_root: Path | str = PROJECT_ROOT,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.catalog_path = Path(catalog_path).resolve()
        self.catalog = yaml.safe_load(
            self.catalog_path.read_text(encoding="utf-8")
        )
        if not isinstance(self.catalog, dict):
            raise ValueError("Hostile-input catalog must be a YAML object.")
        self.trusted_paths = {
            name: self.project_root / item["relative_path"]
            for name, item in self.catalog["trusted_inputs"].items()
        }
        self.handlers: dict[str, Callable[[], dict[str, Any]]] = {
            name.removeprefix("_scenario_"): method
            for name in dir(self)
            if name.startswith("_scenario_")
            and callable(method := getattr(self, name))
        }

    def _input_integrity_checks(self) -> dict[str, dict[str, Any]]:
        checks: dict[str, dict[str, Any]] = {}
        for name, definition in self.catalog["trusted_inputs"].items():
            path = self.project_root / definition["relative_path"]
            actual = sha256_file(path) if path.is_file() else "0" * 64
            checks[name] = {
                "relative_path": definition["relative_path"],
                "expected_sha256": definition["expected_sha256"],
                "actual_sha256": actual,
                "passed": path.is_file()
                and actual == definition["expected_sha256"],
            }
        return checks

    @staticmethod
    def _execution(
        outcome: str,
        findings: list[HostileInputFinding],
        observed: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "outcome": outcome,
            "findings": findings,
            "observed": observed or {},
        }

    @staticmethod
    def _from_invalid_parse(
        outcome: ParseOutcome[Any],
        oracle: str = "STRICT_PARSER",
    ) -> dict[str, Any]:
        findings = []
        if outcome.status == ParseStatus.INVALID:
            findings.append(_finding(outcome.code, oracle, outcome.message))
        return HostileInputAssuranceHarness._execution(
            "REJECTED" if findings else "UNDETECTED",
            findings,
            _parse_observation(outcome),
        )

    @staticmethod
    def _from_safe_parse(
        outcome: ParseOutcome[Any],
        code: str,
        message: str,
        oracle: str = "STRICT_PARSER",
    ) -> dict[str, Any]:
        if outcome.status not in {ParseStatus.PARSED, ParseStatus.MISSING}:
            return HostileInputAssuranceHarness._execution(
                "UNDETECTED",
                [],
                _parse_observation(outcome),
            )
        return HostileInputAssuranceHarness._execution(
            "NORMALIZED_SAFE",
            [_finding(code, oracle, message)],
            _parse_observation(outcome),
        )

    @staticmethod
    def _base_row() -> dict[str, Any]:
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

    def _feature_rejection(
        self,
        field_name: str,
        value: Any,
    ) -> dict[str, Any]:
        row = self._base_row()
        row[field_name] = value
        report = parse_vulnerability_feature_row(row)
        findings = [
            _finding(issue.code, "FEATURE_ROW_PARSER", issue.message)
            for issue in report.errors
        ]
        observed = {
            "status": "accepted" if report.accepted else "rejected",
            "code": findings[0].code if findings else "ROW_ACCEPTED",
            "value": _safe_scalar(report.values.get(field_name)),
        }
        return self._execution(
            "REJECTED" if findings else "UNDETECTED",
            findings,
            observed,
        )

    def _intelligence_rejection(
        self,
        mutate: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        record = load_json(self.trusted_paths["intelligence_fixture"])
        mutate(record)
        validation = VulnerabilityIntelligenceValidator().validate(record)
        findings = [
            _finding(issue.code, "INTELLIGENCE_VALIDATOR", issue.message)
            for issue in validation.errors
        ]
        observed = {
            "status": validation.status,
            "code": findings[0].code if findings else "RECORD_ACCEPTED",
            "value": None,
        }
        return self._execution(
            "REJECTED" if findings else "UNDETECTED",
            findings,
            observed,
        )

    # Boolean and number scenarios.
    def _scenario_boolean_false_string(self) -> dict[str, Any]:
        result = parse_optional_boolean("False", "kev_flag")
        if result.parsed and result.value is False:
            return self._from_safe_parse(
                result,
                "FALSE_TOKEN_PRESERVED",
                "The string False was parsed as Boolean false.",
            )
        return self._execution("UNDETECTED", [], _parse_observation(result))

    def _scenario_boolean_true_whitespace(self) -> dict[str, Any]:
        result = parse_optional_boolean(" true ", "kev_flag")
        if result.parsed and result.value is True:
            return self._from_safe_parse(
                result,
                "TRUE_TOKEN_CANONICALIZED",
                "Whitespace was removed and true remained Boolean true.",
            )
        return self._execution("UNDETECTED", [], _parse_observation(result))

    def _scenario_boolean_unknown_token(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_boolean("maybe", "kev_flag")
        )

    def _scenario_boolean_list_type(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_boolean(["false"], "kev_flag")
        )

    def _scenario_nan_string(self) -> dict[str, Any]:
        return self._from_invalid_parse(parse_probability("NaN", "epss"))

    def _scenario_nan_float(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_probability(float("nan"), "epss")
        )

    def _scenario_positive_infinity(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_float(float("inf"), "score")
        )

    def _scenario_overflow_exponent(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_float("1e1000000", "score")
        )

    def _scenario_comma_number(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_float("1,000", "score")
        )

    def _scenario_probability_negative(self) -> dict[str, Any]:
        return self._from_invalid_parse(parse_probability("-0.01", "epss"))

    def _scenario_probability_above_one(self) -> dict[str, Any]:
        return self._from_invalid_parse(parse_probability("1.01", "epss"))

    def _scenario_number_boolean(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_float(True, "score")
        )

    def _scenario_huge_numeric_token(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_float("9" * 10001, "score")
        )

    def _scenario_cvss_negative(self) -> dict[str, Any]:
        return self._from_invalid_parse(parse_cvss_score("-0.1"))

    def _scenario_cvss_above_ten(self) -> dict[str, Any]:
        return self._from_invalid_parse(parse_cvss_score("10.1"))

    def _scenario_cvss_boundary_ten(self) -> dict[str, Any]:
        result = parse_cvss_score("10.0")
        if result.parsed and result.value == 10.0:
            return self._from_safe_parse(
                result,
                "CVSS_BOUNDARY_PRESERVED",
                "The valid maximum CVSS score remained 10.0.",
            )
        return self._execution("UNDETECTED", [], _parse_observation(result))

    # Date and Unicode scenarios.
    def _scenario_ambiguous_date(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_date("07/08/2026", "score_date")
        )

    def _scenario_invalid_leap_date(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_date("2025-02-29", "score_date")
        )

    def _scenario_naive_datetime(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_datetime("2026-07-13T17:00:00", "retrieved_at")
        )

    def _scenario_future_datetime(self) -> dict[str, Any]:
        result = parse_optional_datetime(
            "2099-01-01T00:00:00Z", "retrieved_at"
        )
        findings: list[HostileInputFinding] = []
        if result.parsed and result.value is not None:
            reference = datetime(2030, 1, 1, tzinfo=timezone.utc)
            if result.value > reference:
                findings.append(
                    _finding(
                        "IMPLAUSIBLE_FUTURE_TIMESTAMP",
                        "TIMESTAMP_CONSISTENCY",
                        "Timestamp is beyond the approved evaluation horizon.",
                    )
                )
        return self._execution(
            "QUARANTINED" if findings else "UNDETECTED",
            findings,
            _parse_observation(result),
        )

    def _scenario_bidi_datetime(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_datetime(
                "2026-07-13T17:00:00Z\u202e", "retrieved_at"
            )
        )

    def _scenario_cyrillic_cve(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_cve_id("СVE-2021-44228")
        )

    def _scenario_zero_width_cve(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_cve_id("CVE-2021-44\u200b228")
        )

    def _scenario_bidi_asset_id(self) -> dict[str, Any]:
        return self._feature_rejection(
            "asset_id", "AEG-AST-\u202eHOSP-001"
        )

    def _scenario_nul_component(self) -> dict[str, Any]:
        return self._feature_rejection(
            "component_name", "log4j\x00-core"
        )

    def _scenario_newline_component(self) -> dict[str, Any]:
        return self._feature_rejection(
            "component_name", "log4j\n-core"
        )

    # PURL and size scenarios.
    def _scenario_non_ascii_purl(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_purl("pkg:maven/оrg.example/component")
        )

    def _scenario_invalid_percent_purl(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_purl("pkg:maven/org.example/log%ZZ")
        )

    def _scenario_traversal_purl(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_purl("pkg:maven/org.example/%2e%2e/secret")
        )

    def _scenario_oversized_component(self) -> dict[str, Any]:
        return self._feature_rejection("component_name", "a" * 501)

    def _scenario_oversized_version(self) -> dict[str, Any]:
        parsed = parse_version("1" * 151)
        findings = []
        if parsed is None:
            findings.append(
                _finding(
                    "VERSION_TOKEN_ABOVE_SECURITY_LIMIT",
                    "VERSION_PARSER",
                    "Version token exceeded the 150-character limit.",
                )
            )
        return self._execution(
            "REJECTED" if findings else "UNDETECTED",
            findings,
            {"status": "invalid" if parsed is None else "parsed", "code": findings[0].code if findings else "VERSION_PARSED", "value": None},
        )

    def _scenario_excessive_aliases(self) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            record["aliases"] = [f"GHSA-aaaa-bbbb-{i:04d}" for i in range(101)]
        return self._intelligence_rejection(mutate)

    def _scenario_excessive_observations(self) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            base = record["observations"][0]
            record["observations"] = []
            for index in range(501):
                item = copy.deepcopy(base)
                item["observation_id"] = f"OBS-NVD-LARGE-{index:04d}"
                record["observations"].append(item)
            record["source_assessment"]["source_count"] = 501
        return self._intelligence_rejection(mutate)

    def _scenario_canonical_object(self) -> dict[str, Any]:
        return self._intelligence_rejection(
            lambda record: record.__setitem__("canonical_id", {"cve": "CVE-2021-44228"})
        )

    def _scenario_giant_integer(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_integer("9" * 10001, "source_count")
        )

    # Identity, enum, formula, type and version scenarios.
    def _scenario_malformed_cve_prefix(self) -> dict[str, Any]:
        return self._from_invalid_parse(parse_cve_id("CVE_2021_44228"))

    def _scenario_short_cve_suffix(self) -> dict[str, Any]:
        return self._from_invalid_parse(parse_cve_id("CVE-2021-123"))

    def _scenario_duplicate_aliases_normalized(self) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            record["aliases"] = ["GHSA-jfh8-c2jp-5v3q", "ghsa-jfh8-c2jp-5v3q"]
        return self._intelligence_rejection(mutate)

    def _scenario_canonical_duplicate_alias(self) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            record["aliases"].append(record["canonical_id"].lower())
        return self._intelligence_rejection(mutate)

    def _scenario_duplicate_purl(self) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            record["affected_packages"].append(
                copy.deepcopy(record["affected_packages"][0])
            )
        return self._intelligence_rejection(mutate)

    def _scenario_unknown_enum(self) -> dict[str, Any]:
        return self._from_invalid_parse(
            parse_optional_enum(
                "ultra", "criticality", ("high", "medium", "low")
            )
        )

    def _scenario_enum_whitespace(self) -> dict[str, Any]:
        result = parse_optional_enum(
            " HIGH ", "criticality", ("high", "medium", "low")
        )
        if result.parsed and result.value == "high":
            return self._from_safe_parse(
                result,
                "ENUM_CANONICALIZED",
                "Whitespace and case were normalized to the canonical enum.",
            )
        return self._execution("UNDETECTED", [], _parse_observation(result))

    def _scenario_formula_component(self) -> dict[str, Any]:
        return self._feature_rejection(
            "component_name", "=HYPERLINK(\"https://attacker.invalid\")"
        )

    def _scenario_object_component(self) -> dict[str, Any]:
        return self._feature_rejection(
            "component_name", {"name": "log4j-core"}
        )

    def _version_rejection(self, raw: str, code: str) -> dict[str, Any]:
        parsed = parse_version(raw)
        findings = []
        if parsed is None:
            findings.append(
                _finding(
                    code,
                    "VERSION_PARSER",
                    "Ambiguous or unsupported version token was not guessed.",
                )
            )
        return self._execution(
            "REJECTED" if findings else "UNDETECTED",
            findings,
            {"status": "invalid" if parsed is None else "parsed", "code": findings[0].code if findings else "VERSION_PARSED", "value": None if parsed is None else parsed.normalized_value},
        )

    def _scenario_wildcard_version(self) -> dict[str, Any]:
        return self._version_rejection("2.x", "WILDCARD_VERSION_NOT_ALLOWED")

    def _scenario_comparison_version(self) -> dict[str, Any]:
        return self._version_rejection(">=2.0,<3.0", "VERSION_EXPRESSION_NOT_ALLOWED")

    def _scenario_conflicting_range(self) -> dict[str, Any]:
        def mutate(record: dict[str, Any]) -> None:
            record["affected_packages"][0]["ranges"][0]["last_affected"] = "2.3.0"
        return self._intelligence_rejection(mutate)

    def _scenario_unsupported_range_type(self) -> dict[str, Any]:
        component = parse_version("2.14.1")
        if component is None:
            raise ValueError("Baseline version unexpectedly failed parsing.")
        evaluation = evaluate_version_range(
            component,
            {
                "range_type": "GIT",
                "introduced": "2.0",
                "fixed": "2.15.0",
                "last_affected": None,
            },
            range_index=0,
            supported_range_types={"ECOSYSTEM", "SEMVER"},
        )
        findings = []
        if not evaluation.valid and "UNSUPPORTED_RANGE_TYPE" in evaluation.reason_codes:
            findings.append(
                _finding(
                    "UNSUPPORTED_RANGE_TYPE",
                    "VERSION_RANGE_ENGINE",
                    "Unsupported range type forced an abstaining result.",
                )
            )
        return self._execution(
            "QUARANTINED" if findings else "UNDETECTED",
            findings,
            {"status": "invalid" if not evaluation.valid else "parsed", "code": evaluation.reason_codes[0], "value": evaluation.affected},
        )

    def _scenario_missing_probability(self) -> dict[str, Any]:
        result = parse_probability("", "epss_probability")
        if result.missing and result.value is None:
            return self._from_safe_parse(
                result,
                "MISSING_VALUE_PRESERVED",
                "Blank EPSS remained missing and no score was invented.",
            )
        return self._execution("UNDETECTED", [], _parse_observation(result))

    def _scenario_zero_probability(self) -> dict[str, Any]:
        result = parse_probability("0", "epss_probability")
        if result.parsed and result.value == 0.0:
            return self._from_safe_parse(
                result,
                "REAL_ZERO_PRESERVED",
                "A real zero EPSS score remained zero rather than missing.",
            )
        return self._execution("UNDETECTED", [], _parse_observation(result))

    def execute_scenario(self, scenario: dict[str, Any]) -> dict[str, Any]:
        base = {
            "scenario_id": scenario["scenario_id"],
            "title": scenario["title"],
            "family": scenario["family"],
            "severity": scenario["severity"],
            "handler": scenario["handler"],
            "control_tags": list(scenario.get("control_tags", [])),
            "expected_outcomes": list(scenario["expected_outcomes"]),
            "expected_oracles": list(scenario["expected_oracles"]),
            "ephemeral_only": True,
        }
        try:
            handler = self.handlers.get(scenario["handler"])
            if handler is None:
                raise KeyError(f"Unknown scenario handler: {scenario['handler']}")
            execution = handler()
            findings: list[HostileInputFinding] = execution["findings"]
            outcome = execution["outcome"]
            oracles = sorted({finding.oracle for finding in findings})
            expectation_met = (
                outcome in set(scenario["expected_outcomes"])
                and set(scenario["expected_oracles"]).issubset(oracles)
            )
            defended = (
                outcome in DEFENDED_OUTCOMES
                and bool(findings)
                and expectation_met
            )
            if not defended:
                outcome = "UNDETECTED"
            base.update(
                {
                    "outcome": outcome,
                    "defended": defended,
                    "expectation_met": expectation_met,
                    "detection_oracles": oracles,
                    "findings": [finding.to_dict() for finding in findings],
                    "observed": execution.get("observed", {}),
                    "error": None,
                }
            )
        except Exception as exc:
            base.update(
                {
                    "outcome": "HARNESS_ERROR",
                    "defended": False,
                    "expectation_met": False,
                    "detection_oracles": [],
                    "findings": [],
                    "observed": {},
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
        return base

    @staticmethod
    def _control_rate(
        results: list[dict[str, Any]],
        tag: str,
    ) -> tuple[int, int, float]:
        applicable = [r for r in results if tag in r["control_tags"]]
        defended = [r for r in applicable if r["defended"]]
        rate = len(defended) / len(applicable) if applicable else 1.0
        return len(applicable), len(defended), rate

    def run(self) -> dict[str, Any]:
        before = self._input_integrity_checks()
        if not all(item["passed"] for item in before.values()):
            failed = [name for name, item in before.items() if not item["passed"]]
            raise ValueError(f"Trusted input integrity failed: {failed}")

        baseline_row = parse_vulnerability_feature_row(self._base_row())
        baseline_intelligence = VulnerabilityIntelligenceValidator().validate(
            load_json(self.trusted_paths["intelligence_fixture"])
        )
        baseline_purl = parse_optional_purl(
            "pkg:maven/org.apache.logging.log4j/log4j-core"
        )
        baseline_version = parse_version("2.14.1")
        if not baseline_row.accepted:
            raise ValueError("Baseline vulnerability row is invalid.")
        if not baseline_intelligence.valid:
            raise ValueError("Baseline intelligence record is invalid.")
        if not baseline_purl.parsed or baseline_version is None:
            raise ValueError("Baseline PURL or version is invalid.")

        results = [self.execute_scenario(s) for s in self.catalog["scenarios"]]
        after = self._input_integrity_checks()
        unchanged = all(
            item["passed"]
            and item["actual_sha256"] == before[name]["actual_sha256"]
            for name, item in after.items()
        )

        critical = [r for r in results if r["severity"] == "critical"]
        defended = [r for r in critical if r["defended"]]
        undetected = [r for r in results if r["outcome"] == "UNDETECTED"]
        errors = [r for r in results if r["outcome"] == "HARNESS_ERROR"]
        rejected = [r for r in results if r["outcome"] == "REJECTED"]
        quarantined = [r for r in results if r["outcome"] == "QUARANTINED"]
        normalized = [r for r in results if r["outcome"] == "NORMALIZED_SAFE"]
        warnings = [r for r in results if r["outcome"] == "ACCEPTED_WITH_WARNING"]

        controls = {}
        for tag in (
            "nonfinite_numeric",
            "unicode_deception",
            "oversized_payload",
            "malformed_identifier",
            "missing_value_semantics",
            "type_confusion",
        ):
            controls[tag] = self._control_rate(results, tag)

        defence_rate = len(defended) / len(critical) if critical else 1.0
        gates = self.catalog["release_gates"]
        gate_specs = [
            ("GATE-CRITICAL-HOSTILE-INPUT-DEFENCE", defence_rate, "gte", gates["critical_hostile_input_defence_rate_minimum"]),
            ("GATE-UNDETECTED-CRITICAL-INPUTS", len(undetected), "lte", gates["undetected_critical_inputs_maximum"]),
            ("GATE-HARNESS-ERRORS", len(errors), "lte", gates["harness_errors_maximum"]),
            ("GATE-NONFINITE-NUMERIC", controls["nonfinite_numeric"][2], "gte", gates["nonfinite_rejection_rate_minimum"]),
            ("GATE-UNICODE-DECEPTION", controls["unicode_deception"][2], "gte", gates["unicode_deception_detection_rate_minimum"]),
            ("GATE-OVERSIZED-PAYLOAD", controls["oversized_payload"][2], "gte", gates["oversized_payload_defence_rate_minimum"]),
            ("GATE-MALFORMED-IDENTIFIER", controls["malformed_identifier"][2], "gte", gates["malformed_identifier_defence_rate_minimum"]),
            ("GATE-MISSING-VALUE-SEMANTICS", controls["missing_value_semantics"][2], "gte", gates["missing_value_semantic_accuracy_minimum"]),
            ("GATE-TYPE-CONFUSION", controls["type_confusion"][2], "gte", gates["type_confusion_defence_rate_minimum"]),
            ("GATE-TRUSTED-INPUT-INTEGRITY", unchanged, "eq", gates["require_trusted_inputs_unchanged"]),
        ]
        quality_gates = []
        for gate_id, observed, operator, threshold in gate_specs:
            if operator == "gte":
                passed = observed >= threshold
            elif operator == "lte":
                passed = observed <= threshold
            else:
                passed = observed == threshold
            quality_gates.append(
                {
                    "gate_id": gate_id,
                    "observed": observed,
                    "operator": operator,
                    "threshold": threshold,
                    "passed": passed,
                }
            )
        overall = all(gate["passed"] for gate in quality_gates)

        def control_summary(tag: str, prefix: str) -> dict[str, Any]:
            total, defended_count, rate = controls[tag]
            return {
                f"{prefix}_scenario_count": total,
                f"{prefix}_defended_count": defended_count,
                f"{prefix}_defence_rate": rate,
            }

        summary = {
            "scenario_count": len(results),
            "critical_scenario_count": len(critical),
            "rejected_count": len(rejected),
            "quarantined_count": len(quarantined),
            "normalized_safe_count": len(normalized),
            "accepted_with_warning_count": len(warnings),
            "undetected_count": len(undetected),
            "harness_error_count": len(errors),
            "defended_critical_count": len(defended),
            "critical_hostile_input_defence_rate": defence_rate,
            **control_summary("nonfinite_numeric", "nonfinite_numeric"),
            **control_summary("unicode_deception", "unicode_deception"),
            **control_summary("oversized_payload", "oversized_payload"),
            **control_summary("malformed_identifier", "malformed_identifier"),
            **control_summary("missing_value_semantics", "missing_value_semantics"),
            **control_summary("type_confusion", "type_confusion"),
            "trusted_input_integrity_passed": unchanged,
            "overall_passed": overall,
        }
        blockers = gates["approved_remaining_production_blockers"]
        return {
            "schema_version": "1.0.0",
            "report_id": "AEG-HOSTILE-INPUT-STEP11D-001",
            "catalog": {
                "catalog_id": self.catalog["policy"]["catalog_id"],
                "version": self.catalog["policy"]["version"],
                "harness_version": self.catalog["policy"]["harness_version"],
                "relative_path": self.catalog_path.relative_to(self.project_root).as_posix(),
                "sha256": sha256_file(self.catalog_path),
            },
            "input_integrity_checks_before": before,
            "input_integrity_checks_after": after,
            "baseline_validation": {
                "feature_row_accepted": baseline_row.accepted,
                "intelligence_record_status": baseline_intelligence.status,
                "intelligence_record_valid": baseline_intelligence.valid,
                "purl_parsed": baseline_purl.parsed,
                "version_parsed": baseline_version is not None,
            },
            "summary": summary,
            "quality_gates": quality_gates,
            "results": results,
            "undetected_input_ids": [r["scenario_id"] for r in undetected],
            "harness_error_input_ids": [r["scenario_id"] for r in errors],
            "release_decision": {
                "stage_gate_status": "PASS" if overall else "FAIL",
                "production_readiness_status": "BLOCKED",
                "blocking_reasons": blockers,
            },
            "limitations": [
                "The campaign uses controlled repository fixtures and does not replace live operational testing.",
                "Resource-exhaustion scenarios use bounded representative payloads rather than destructive denial-of-service loads.",
                "PURL validation implements a strict security profile and is not a complete conformance certification for every Package URL extension.",
                "Passing Step 11D does not replace independent security assessment or authorization to operate.",
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

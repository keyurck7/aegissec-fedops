from __future__ import annotations

import copy
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.assurance.policy_assurance import apply_overrides, load_json, load_jsonl
from src.policy.policy_floor_engine import PolicyFloorEngine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "metamorphic_relation_catalog_v1.yaml"
)


class MetamorphicAssuranceError(ValueError):
    """Raised when a metamorphic catalog or execution is invalid."""


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return float(numerator) / float(denominator)


def write_json(path: Path | str, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def write_results_csv(path: Path | str, results: list[dict[str, Any]]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "relation_id",
        "family",
        "severity",
        "mode",
        "baseline_case_id",
        "transformed_case_id",
        "outcome",
        "passed",
        "change_scope_valid",
        "changed_paths",
        "violations",
        "check_codes",
        "error",
    ]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "relation_id": result["relation_id"],
                    "family": result["family"],
                    "severity": result["severity"],
                    "mode": result["mode"],
                    "baseline_case_id": result["baseline_case_id"],
                    "transformed_case_id": result["transformed_case_id"],
                    "outcome": result["outcome"],
                    "passed": result["passed"],
                    "change_scope_valid": result["change_scope_valid"],
                    "changed_paths": ";".join(result["changed_paths"]),
                    "violations": ";".join(result["violations"]),
                    "check_codes": ";".join(
                        check["code"] for check in result["checks"]
                    ),
                    "error": result.get("error") or "",
                }
            )


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(_flatten(child, child_path))
        return flattened
    if isinstance(value, list):
        flattened[prefix] = copy.deepcopy(value)
        return flattened
    flattened[prefix] = value
    return flattened


def _changed_paths(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    left = _flatten(before)
    right = _flatten(after)
    missing = object()
    return sorted(
        path
        for path in set(left) | set(right)
        if left.get(path, missing) != right.get(path, missing)
    )


def _deep_set(payload: dict[str, Any], dotted_path: str, value: Any) -> None:
    parts = dotted_path.split(".")
    current: Any = payload
    for part in parts[:-1]:
        if not isinstance(current, dict):
            raise MetamorphicAssuranceError(
                f"Cannot traverse transformation path {dotted_path!r}."
            )
        if part not in current:
            current[part] = {}
        current = current[part]
    if not isinstance(current, dict):
        raise MetamorphicAssuranceError(
            f"Cannot assign transformation path {dotted_path!r}."
        )
    current[parts[-1]] = copy.deepcopy(value)


def _unique_evidence_count(case: dict[str, Any]) -> int:
    scenario = case["scenario"]
    evidence: set[str] = set()
    for value in scenario.get("affectedness", {}).get(
        "supporting_evidence_ids", []
    ):
        if isinstance(value, str) and value:
            evidence.add(value)
    return len(evidence)


class MetamorphicAssuranceHarness:
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
            raise MetamorphicAssuranceError(
                "Metamorphic catalog must be a YAML object."
            )
        self._validate_catalog()
        self.trusted_inputs = self.catalog["trusted_inputs"]
        self.corpus_path = self.project_root / self.trusted_inputs[
            "assurance_corpus"
        ]["relative_path"]
        self.manifest_path = self.project_root / self.trusted_inputs[
            "assurance_manifest"
        ]["relative_path"]
        self.policy_path = self.project_root / self.trusted_inputs[
            "decision_policy"
        ]["relative_path"]
        self.manifest = load_json(self.manifest_path)
        self.cases = {
            case["case_id"]: case for case in load_jsonl(self.corpus_path)
        }
        self.engine = PolicyFloorEngine(policy_path=self.policy_path)
        self.action_ranks = dict(self.engine.action_ranks)
        self.priority_ranks = dict(self.engine.priority_ranks)
        base_fixtures = self.manifest["base_fixtures"]
        self.base_asset = load_json(
            self.project_root
            / base_fixtures["asset_context"]["relative_path"]
        )
        self.base_intelligence = load_json(
            self.project_root
            / base_fixtures["vulnerability_intelligence"]["relative_path"]
        )
        component_source = load_json(
            self.project_root
            / base_fixtures["component_source"]["relative_path"]
        )
        self.base_component = component_source["component_instance"]

    def _validate_catalog(self) -> None:
        required = {
            "policy",
            "trusted_inputs",
            "quality_gates",
            "production_readiness",
            "limitations",
            "relations",
        }
        missing = required - set(self.catalog)
        if missing:
            raise MetamorphicAssuranceError(
                f"Metamorphic catalog missing sections: {sorted(missing)}"
            )
        relations = self.catalog["relations"]
        if not isinstance(relations, list) or not relations:
            raise MetamorphicAssuranceError(
                "Metamorphic catalog must contain relations."
            )
        ids = [item.get("relation_id") for item in relations]
        if any(not isinstance(item, str) or not item for item in ids):
            raise MetamorphicAssuranceError("Every relation requires an ID.")
        if len(ids) != len(set(ids)):
            raise MetamorphicAssuranceError("Relation IDs must be unique.")
        allowed_modes = {
            "EXACT_EQUALITY",
            "NON_DECREASING",
            "FAIL_CLOSED",
            "NO_AUTOMATION_GAIN",
            "EVIDENCE_REMOVAL",
        }
        for relation in relations:
            if relation.get("severity") != "critical":
                raise MetamorphicAssuranceError(
                    "Every Step 11E relation must be critical."
                )
            if relation.get("mode") not in allowed_modes:
                raise MetamorphicAssuranceError(
                    f"Unsupported relation mode: {relation.get('mode')!r}"
                )
            has_comparison = bool(relation.get("comparison_case_id"))
            has_transformations = bool(relation.get("transformations"))
            if has_comparison == has_transformations:
                raise MetamorphicAssuranceError(
                    f"{relation['relation_id']} must define exactly one "
                    "comparison source."
                )

    def input_integrity_checks(self) -> dict[str, dict[str, Any]]:
        checks: dict[str, dict[str, Any]] = {}
        for name, definition in self.trusted_inputs.items():
            relative_path = definition["relative_path"]
            candidate = Path(relative_path)
            resolved = (self.project_root / candidate).resolve()
            safe = (
                not candidate.is_absolute()
                and (
                    resolved == self.project_root
                    or self.project_root in resolved.parents
                )
            )
            exists = safe and resolved.is_file()
            actual = sha256_file(resolved) if exists else None
            checks[name] = {
                "relative_path": relative_path,
                "expected_sha256": definition["expected_sha256"],
                "actual_sha256": actual,
                "safe_path": safe,
                "exists": exists,
                "passed": bool(
                    safe
                    and exists
                    and actual == definition["expected_sha256"]
                ),
            }
        return checks

    def _evaluate_case(
        self,
        case: dict[str, Any],
        evaluated_at: datetime,
    ) -> dict[str, Any]:
        scenario = case["scenario"]
        asset = apply_overrides(
            self.base_asset, scenario["asset_overrides"]
        )
        intelligence = apply_overrides(
            self.base_intelligence, scenario["intelligence_overrides"]
        )
        component = apply_overrides(
            self.base_component, scenario["component_overrides"]
        )
        assessment = self.engine.evaluate(
            asset_context=asset,
            intelligence_record=intelligence,
            component_instance=component,
            affectedness_assessment=scenario["affectedness"],
            evidence_trust=scenario["trust"],
            evaluated_at=evaluated_at,
        )
        supporting_ids = sorted(
            {
                evidence_id
                for rule in assessment.matched_rules
                for evidence_id in rule.supporting_evidence_ids
            }
        )
        return {
            "action": assessment.action,
            "priority": assessment.minimum_priority,
            "deadline_hours": assessment.response_deadline_hours,
            "human_review_required": assessment.human_review_required,
            "containment_required": assessment.containment_required,
            "prohibit_closure": assessment.prohibit_closure,
            "invariants_passed": assessment.invariants_passed,
            "matched_rule_ids": [
                rule.rule_id for rule in assessment.matched_rules
            ],
            "supporting_evidence_ids": supporting_ids,
            "input_affectedness_evidence_count": _unique_evidence_count(case),
        }

    def _transformed_case(
        self, relation: dict[str, Any]
    ) -> tuple[dict[str, Any], str]:
        if relation.get("comparison_case_id"):
            case_id = relation["comparison_case_id"]
            if case_id not in self.cases:
                raise MetamorphicAssuranceError(
                    f"Unknown comparison case: {case_id}"
                )
            return copy.deepcopy(self.cases[case_id]), case_id
        base = copy.deepcopy(self.cases[relation["baseline_case_id"]])
        for transformation in relation["transformations"]:
            _deep_set(
                base["scenario"],
                transformation["path"],
                transformation.get("value"),
            )
        transformed_id = f"{relation['baseline_case_id']}::{relation['relation_id']}"
        return base, transformed_id

    def _monotonic_checks(
        self,
        baseline: dict[str, Any],
        transformed: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return [
            {
                "code": "ACTION_NOT_DECREASED",
                "passed": self.action_ranks[transformed["action"]]
                >= self.action_ranks[baseline["action"]],
                "message": "Action rank must not decrease.",
            },
            {
                "code": "PRIORITY_NOT_DECREASED",
                "passed": self.priority_ranks[transformed["priority"]]
                >= self.priority_ranks[baseline["priority"]],
                "message": "Priority rank must not decrease.",
            },
            {
                "code": "DEADLINE_NOT_LENGTHENED",
                "passed": float(transformed["deadline_hours"])
                <= float(baseline["deadline_hours"]) + 1e-9,
                "message": "Response deadline must not lengthen.",
            },
            {
                "code": "REVIEW_NOT_REMOVED",
                "passed": not baseline["human_review_required"]
                or transformed["human_review_required"],
                "message": "Existing human review must not be removed.",
            },
            {
                "code": "CONTAINMENT_NOT_REMOVED",
                "passed": not baseline["containment_required"]
                or transformed["containment_required"],
                "message": "Existing containment must not be removed.",
            },
            {
                "code": "CLOSURE_PROHIBITION_NOT_REMOVED",
                "passed": not baseline["prohibit_closure"]
                or transformed["prohibit_closure"],
                "message": "Existing closure prohibition must not be removed.",
            },
        ]

    def _relation_checks(
        self,
        relation: dict[str, Any],
        baseline: dict[str, Any],
        transformed: dict[str, Any],
        changed_paths: list[str],
    ) -> list[dict[str, Any]]:
        expected_paths = sorted(relation["expected_changed_paths"])
        checks: list[dict[str, Any]] = [
            {
                "code": "TRANSFORMATION_SCOPE_EXACT",
                "passed": changed_paths == expected_paths,
                "message": (
                    f"Expected changed paths {expected_paths}; "
                    f"received {changed_paths}."
                ),
            },
            {
                "code": "BASELINE_INVARIANTS_PASS",
                "passed": baseline["invariants_passed"] is True,
                "message": "Baseline policy invariants must pass.",
            },
            {
                "code": "TRANSFORMED_INVARIANTS_PASS",
                "passed": transformed["invariants_passed"] is True,
                "message": "Transformed policy invariants must pass.",
            },
            {
                "code": "EXPECTED_RULES_TRIGGERED",
                "passed": set(relation["expected_transformed_rule_ids"])
                .issubset(set(transformed["matched_rule_ids"])),
                "message": "Expected transformed policy rules must trigger.",
            },
        ]
        mode = relation["mode"]
        if mode == "EXACT_EQUALITY":
            for field in (
                "action",
                "priority",
                "deadline_hours",
                "human_review_required",
                "containment_required",
                "prohibit_closure",
            ):
                checks.append(
                    {
                        "code": f"{field.upper()}_EQUAL",
                        "passed": baseline[field] == transformed[field],
                        "message": f"{field} must remain equal.",
                    }
                )
            checks.append(
                {
                    "code": "MATCHED_RULES_EQUAL",
                    "passed": baseline["matched_rule_ids"]
                    == transformed["matched_rule_ids"],
                    "message": "Sector-only changes must not alter matched rules.",
                }
            )
        else:
            checks.extend(self._monotonic_checks(baseline, transformed))
        if mode == "FAIL_CLOSED":
            checks.extend(
                [
                    {
                        "code": "FAIL_CLOSED_HOLD",
                        "passed": transformed["action"] == "HOLD",
                        "message": "Rejected or quarantined trust must force HOLD.",
                    },
                    {
                        "code": "FAIL_CLOSED_HIGH_PRIORITY",
                        "passed": self.priority_ranks[transformed["priority"]]
                        >= self.priority_ranks["HIGH"],
                        "message": "Fail-closed handling requires at least High priority.",
                    },
                    {
                        "code": "FAIL_CLOSED_DEADLINE",
                        "passed": float(transformed["deadline_hours"]) <= 4.0,
                        "message": "Fail-closed handling requires a four-hour deadline or shorter.",
                    },
                    {
                        "code": "FAIL_CLOSED_REVIEW",
                        "passed": transformed["human_review_required"] is True,
                        "message": "Fail-closed handling requires human review.",
                    },
                    {
                        "code": "FAIL_CLOSED_NO_CLOSURE",
                        "passed": transformed["prohibit_closure"] is True,
                        "message": "Fail-closed handling must prohibit closure.",
                    },
                ]
            )
        if mode == "EVIDENCE_REMOVAL":
            checks.append(
                {
                    "code": "EVIDENCE_REFERENCE_COUNT_NOT_INCREASED",
                    "passed": transformed["input_affectedness_evidence_count"]
                    < baseline["input_affectedness_evidence_count"],
                    "message": "The transformation must remove affectedness evidence.",
                }
            )
        return checks

    def run(self) -> dict[str, Any]:
        evaluated_at = datetime.fromisoformat(
            self.catalog["policy"]["evaluated_at"]
        )
        before = self.input_integrity_checks()
        if not all(item["passed"] for item in before.values()):
            raise MetamorphicAssuranceError(
                "Trusted baseline verification failed before execution."
            )
        results: list[dict[str, Any]] = []
        for relation in self.catalog["relations"]:
            try:
                base_id = relation["baseline_case_id"]
                if base_id not in self.cases:
                    raise MetamorphicAssuranceError(
                        f"Unknown baseline case: {base_id}"
                    )
                baseline_case = copy.deepcopy(self.cases[base_id])
                transformed_case, transformed_id = self._transformed_case(relation)
                changed_paths = _changed_paths(
                    baseline_case["scenario"], transformed_case["scenario"]
                )
                baseline_decision = self._evaluate_case(
                    baseline_case, evaluated_at
                )
                transformed_decision = self._evaluate_case(
                    transformed_case, evaluated_at
                )
                checks = self._relation_checks(
                    relation,
                    baseline_decision,
                    transformed_decision,
                    changed_paths,
                )
                violations = [
                    check["code"] for check in checks if not check["passed"]
                ]
                passed = not violations
                results.append(
                    {
                        "relation_id": relation["relation_id"],
                        "property": relation["property"],
                        "family": relation["family"],
                        "severity": relation["severity"],
                        "mode": relation["mode"],
                        "control_tags": relation["control_tags"],
                        "baseline_case_id": base_id,
                        "transformed_case_id": transformed_id,
                        "expected_changed_paths": sorted(
                            relation["expected_changed_paths"]
                        ),
                        "changed_paths": changed_paths,
                        "change_scope_valid": changed_paths
                        == sorted(relation["expected_changed_paths"]),
                        "baseline": baseline_decision,
                        "transformed": transformed_decision,
                        "checks": checks,
                        "violations": violations,
                        "passed": passed,
                        "outcome": "PASSED" if passed else "VIOLATED",
                        "error": None,
                        "ephemeral_only": True,
                    }
                )
            except Exception as exc:  # pragma: no cover - fail-safe reporting
                results.append(
                    {
                        "relation_id": relation.get("relation_id", "UNKNOWN"),
                        "property": relation.get("property", ""),
                        "family": relation.get("family", ""),
                        "severity": relation.get("severity", "critical"),
                        "mode": relation.get("mode", ""),
                        "control_tags": relation.get("control_tags", []),
                        "baseline_case_id": relation.get("baseline_case_id", ""),
                        "transformed_case_id": relation.get(
                            "comparison_case_id", ""
                        ),
                        "expected_changed_paths": relation.get(
                            "expected_changed_paths", []
                        ),
                        "changed_paths": [],
                        "change_scope_valid": False,
                        "baseline": {},
                        "transformed": {},
                        "checks": [],
                        "violations": [],
                        "passed": False,
                        "outcome": "HARNESS_ERROR",
                        "error": f"{type(exc).__name__}: {exc}",
                        "ephemeral_only": True,
                    }
                )
        after = self.input_integrity_checks()
        trusted_integrity = all(
            before[name]["passed"]
            and after[name]["passed"]
            and before[name]["actual_sha256"] == after[name]["actual_sha256"]
            for name in before
        )
        relation_count = len(results)
        critical_count = sum(item["severity"] == "critical" for item in results)
        passed_count = sum(item["outcome"] == "PASSED" for item in results)
        violation_count = sum(item["outcome"] == "VIOLATED" for item in results)
        blocked_count = sum(
            item["outcome"] == "BLOCKED_INVALID_TRANSFORMATION"
            for item in results
        )
        harness_error_count = sum(
            item["outcome"] == "HARNESS_ERROR" for item in results
        )

        def tag_rate(tag: str) -> float:
            group = [item for item in results if tag in item["control_tags"]]
            return safe_rate(sum(item["passed"] for item in group), len(group))

        def check_rate(code: str) -> float:
            checks = [
                check
                for item in results
                for check in item["checks"]
                if check["code"] == code
            ]
            return safe_rate(sum(check["passed"] for check in checks), len(checks))

        summary = {
            "relation_count": relation_count,
            "critical_relation_count": critical_count,
            "passed_count": passed_count,
            "violated_count": violation_count,
            "blocked_invalid_transformation_count": blocked_count,
            "harness_error_count": harness_error_count,
            "critical_relation_pass_rate": safe_rate(passed_count, critical_count),
            "sector_neutrality_consistency_rate": tag_rate("sector_neutrality"),
            "danger_escalation_monotonicity_rate": tag_rate("danger_escalation"),
            "trust_degradation_fail_closed_rate": tag_rate("trust_fail_closed"),
            "deadline_monotonicity_rate": check_rate("DEADLINE_NOT_LENGTHENED"),
            "review_monotonicity_rate": check_rate("REVIEW_NOT_REMOVED"),
            "containment_monotonicity_rate": check_rate("CONTAINMENT_NOT_REMOVED"),
            "closure_monotonicity_rate": check_rate(
                "CLOSURE_PROHIBITION_NOT_REMOVED"
            ),
            "evidence_removal_no_confidence_gain_rate": tag_rate(
                "evidence_removal"
            ),
            "trusted_input_integrity_passed": trusted_integrity,
        }
        gates = self.catalog["quality_gates"]
        quality_gates = [
            {
                "gate_id": "META-CRITICAL-PASS-RATE",
                "metric": "critical_relation_pass_rate",
                "operator": "gte",
                "threshold": gates["critical_relation_pass_rate_minimum"],
                "observed": summary["critical_relation_pass_rate"],
                "passed": summary["critical_relation_pass_rate"]
                >= gates["critical_relation_pass_rate_minimum"],
            },
            {
                "gate_id": "META-SECTOR-NEUTRALITY",
                "metric": "sector_neutrality_consistency_rate",
                "operator": "gte",
                "threshold": gates[
                    "sector_neutrality_consistency_rate_minimum"
                ],
                "observed": summary["sector_neutrality_consistency_rate"],
                "passed": summary["sector_neutrality_consistency_rate"]
                >= gates["sector_neutrality_consistency_rate_minimum"],
            },
            {
                "gate_id": "META-DANGER-MONOTONICITY",
                "metric": "danger_escalation_monotonicity_rate",
                "operator": "gte",
                "threshold": gates[
                    "danger_escalation_monotonicity_rate_minimum"
                ],
                "observed": summary["danger_escalation_monotonicity_rate"],
                "passed": summary["danger_escalation_monotonicity_rate"]
                >= gates["danger_escalation_monotonicity_rate_minimum"],
            },
            {
                "gate_id": "META-TRUST-FAIL-CLOSED",
                "metric": "trust_degradation_fail_closed_rate",
                "operator": "gte",
                "threshold": gates[
                    "trust_degradation_fail_closed_rate_minimum"
                ],
                "observed": summary["trust_degradation_fail_closed_rate"],
                "passed": summary["trust_degradation_fail_closed_rate"]
                >= gates["trust_degradation_fail_closed_rate_minimum"],
            },
        ]
        for metric in (
            "deadline_monotonicity_rate",
            "review_monotonicity_rate",
            "containment_monotonicity_rate",
            "closure_monotonicity_rate",
            "evidence_removal_no_confidence_gain_rate",
        ):
            quality_gates.append(
                {
                    "gate_id": "META-" + metric.upper().replace("_", "-"),
                    "metric": metric,
                    "operator": "gte",
                    "threshold": gates[f"{metric}_minimum"],
                    "observed": summary[metric],
                    "passed": summary[metric] >= gates[f"{metric}_minimum"],
                }
            )
        quality_gates.extend(
            [
                {
                    "gate_id": "META-NO-VIOLATIONS",
                    "metric": "violated_count",
                    "operator": "lte",
                    "threshold": gates["violation_count_maximum"],
                    "observed": violation_count,
                    "passed": violation_count <= gates["violation_count_maximum"],
                },
                {
                    "gate_id": "META-NO-HARNESS-ERRORS",
                    "metric": "harness_error_count",
                    "operator": "lte",
                    "threshold": gates["harness_error_count_maximum"],
                    "observed": harness_error_count,
                    "passed": harness_error_count
                    <= gates["harness_error_count_maximum"],
                },
                {
                    "gate_id": "META-TRUSTED-INTEGRITY",
                    "metric": "trusted_input_integrity_passed",
                    "operator": "eq",
                    "threshold": gates["trusted_input_integrity_required"],
                    "observed": trusted_integrity,
                    "passed": trusted_integrity
                    is gates["trusted_input_integrity_required"],
                },
            ]
        )
        overall_passed = all(item["passed"] for item in quality_gates)
        summary["overall_passed"] = overall_passed
        blocking_reasons = list(
            self.catalog["production_readiness"]["blocking_reasons"]
        )
        report = {
            "report_id": "AEG-METAMORPHIC-STEP11E-001",
            "schema_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "catalog": {
                "catalog_id": self.catalog["policy"]["catalog_id"],
                "version": self.catalog["policy"]["version"],
                "relative_path": str(
                    self.catalog_path.relative_to(self.project_root)
                ),
                "sha256": sha256_file(self.catalog_path),
            },
            "decision_policy": {
                "relative_path": self.trusted_inputs["decision_policy"][
                    "relative_path"
                ],
                "sha256": sha256_file(self.policy_path),
            },
            "assurance_corpus": {
                "relative_path": self.trusted_inputs["assurance_corpus"][
                    "relative_path"
                ],
                "sha256": sha256_file(self.corpus_path),
                "case_count": len(self.cases),
            },
            "input_integrity_checks_before": before,
            "input_integrity_checks_after": after,
            "summary": summary,
            "quality_gates": quality_gates,
            "results": results,
            "violation_relation_ids": [
                item["relation_id"] for item in results if item["outcome"] == "VIOLATED"
            ],
            "harness_error_relation_ids": [
                item["relation_id"]
                for item in results
                if item["outcome"] == "HARNESS_ERROR"
            ],
            "release_decision": {
                "stage_gate_status": "PASS" if overall_passed else "FAIL",
                "production_readiness_status": "BLOCKED",
                "blocking_reasons": blocking_reasons,
            },
            "limitations": list(self.catalog["limitations"]),
        }
        return report


def save_metamorphic_artifacts(
    report: dict[str, Any],
    output_dir: Path | str,
) -> dict[str, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    report_path = directory / "step11e_metamorphic_assurance_report.json"
    csv_path = directory / "step11e_relation_results.csv"
    violations_path = directory / "step11e_violations.json"
    integrity_path = directory / "step11e_trusted_baseline_integrity.sha256"
    write_json(report_path, report)
    write_results_csv(csv_path, report["results"])
    violations = [item for item in report["results"] if item["outcome"] != "PASSED"]
    write_json(
        violations_path,
        {
            "report_id": report["report_id"],
            "schema_version": report["schema_version"],
            "violation_relation_ids": report["violation_relation_ids"],
            "harness_error_relation_ids": report["harness_error_relation_ids"],
            "violations": violations,
        },
    )
    integrity_lines = [
        f"{item['actual_sha256']}  {item['relative_path']}"
        for item in report["input_integrity_checks_after"].values()
        if item["passed"]
    ]
    integrity_path.write_text("\n".join(integrity_lines) + "\n", encoding="utf-8")
    return {
        "report": report_path,
        "csv": csv_path,
        "violations": violations_path,
        "integrity": integrity_path,
    }

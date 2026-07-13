from __future__ import annotations

import copy
import csv
import hashlib
import json
import math
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.assurance.fairness_robustness import (
    FairnessEvaluationError,
    FairnessRobustnessEvaluator,
)
from src.assurance.policy_assurance import apply_overrides
from src.policy.policy_floor_engine import (
    PolicyConfigurationError,
    PolicyFloorEngine,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "policy_mutation_catalog_v1.yaml"
)

FIXED_EVALUATION_TIME = datetime(
    2026,
    7,
    13,
    21,
    15,
    tzinfo=timezone.utc,
)

VALID_OUTCOMES = {
    "BLOCKED_AT_LOAD",
    "KILLED_BY_ASSURANCE",
    "SURVIVED",
    "HARNESS_ERROR",
}


class PolicyMutationError(ValueError):
    """Raised when the mutation catalog or harness inputs are invalid."""


@dataclass(frozen=True)
class MutationExecution:
    mutation_id: str
    status: str
    executable: bool
    result: dict[str, Any]



def sha256_file(path: Path | str) -> str:
    file_path = Path(path)
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()



def load_json(path: Path | str) -> dict[str, Any]:
    file_path = Path(path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))

    if not isinstance(payload, dict):
        raise PolicyMutationError(
            f"Expected a JSON object: {file_path}"
        )

    return payload



def load_jsonl(path: Path | str) -> list[dict[str, Any]]:
    file_path = Path(path)
    records: list[dict[str, Any]] = []

    for line_number, line in enumerate(
        file_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        payload = json.loads(line)

        if not isinstance(payload, dict):
            raise PolicyMutationError(
                f"JSONL line {line_number} is not an object: {file_path}"
            )

        records.append(payload)

    if not records:
        raise PolicyMutationError(
            f"Mutation corpus is empty: {file_path}"
        )

    return records



def write_json(path: Path | str, payload: Any) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )



def write_results_csv(
    path: Path | str,
    results: list[dict[str, Any]],
) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "mutation_id",
        "family",
        "severity",
        "status",
        "executable",
        "failed_case_count",
        "under_triage_count",
        "invariant_failure_case_count",
        "stage_gate_status",
        "static_contract_failure_count",
        "detection_oracles",
        "mutated_policy_sha256",
    ]

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            writer.writerow(
                {
                    "mutation_id": result["mutation_id"],
                    "family": result["family"],
                    "severity": result["severity"],
                    "status": result["status"],
                    "executable": result["executable"],
                    "failed_case_count": result[
                        "assurance"
                    ]["failed_case_count"],
                    "under_triage_count": result[
                        "release_evaluation"
                    ]["under_triage_count"],
                    "invariant_failure_case_count": result[
                        "assurance"
                    ]["invariant_failure_case_count"],
                    "stage_gate_status": result[
                        "release_evaluation"
                    ]["stage_gate_status"],
                    "static_contract_failure_count": len(
                        result["static_contract_failures"]
                    ),
                    "detection_oracles": "|".join(
                        result["detection_oracles"]
                    ),
                    "mutated_policy_sha256": result[
                        "mutated_policy_sha256"
                    ],
                }
            )



def _deep_set(
    payload: dict[str, Any],
    dotted_path: str,
    value: Any,
) -> None:
    parts = dotted_path.split(".")
    current: Any = payload

    for index, part in enumerate(parts[:-1]):
        next_part = parts[index + 1]

        if isinstance(current, list):
            try:
                list_index = int(part)
            except ValueError as exc:
                raise PolicyMutationError(
                    f"Expected list index in path {dotted_path!r}."
                ) from exc

            if list_index < 0 or list_index >= len(current):
                raise PolicyMutationError(
                    f"List index outside range in path {dotted_path!r}."
                )

            current = current[list_index]
            continue

        if not isinstance(current, dict):
            raise PolicyMutationError(
                f"Cannot traverse mutation path {dotted_path!r}."
            )

        if part not in current:
            current[part] = [] if next_part.isdigit() else {}

        current = current[part]

    final_part = parts[-1]

    if isinstance(current, list):
        try:
            list_index = int(final_part)
        except ValueError as exc:
            raise PolicyMutationError(
                f"Expected final list index in path {dotted_path!r}."
            ) from exc

        if list_index < 0 or list_index >= len(current):
            raise PolicyMutationError(
                f"List index outside range in path {dotted_path!r}."
            )

        current[list_index] = copy.deepcopy(value)
        return

    if not isinstance(current, dict):
        raise PolicyMutationError(
            f"Cannot assign mutation path {dotted_path!r}."
        )

    current[final_part] = copy.deepcopy(value)



def _deep_get(payload: dict[str, Any], dotted_path: str) -> Any:
    current: Any = payload

    for part in dotted_path.split("."):
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]

    return current



def _rule_by_id(
    policy: dict[str, Any],
    rule_id: str,
) -> dict[str, Any]:
    matches = [
        rule
        for rule in policy.get("rules", [])
        if rule.get("rule_id") == rule_id
    ]

    if len(matches) != 1:
        raise PolicyMutationError(
            f"Expected exactly one policy rule {rule_id!r}; "
            f"found {len(matches)}."
        )

    return matches[0]



def apply_mutation_operations(
    trusted_policy: dict[str, Any],
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    mutated = copy.deepcopy(trusted_policy)

    for operation in operations:
        op = operation.get("op")

        if op == "set_rule_field":
            rule = _rule_by_id(mutated, str(operation["rule_id"]))
            _deep_set(
                rule,
                str(operation["field_path"]),
                operation.get("value"),
            )

        elif op == "set_policy_field":
            _deep_set(
                mutated,
                str(operation["field_path"]),
                operation.get("value"),
            )

        elif op == "append_policy_list":
            target = _deep_get(
                mutated,
                str(operation["field_path"]),
            )

            if not isinstance(target, list):
                raise PolicyMutationError(
                    "append_policy_list requires a list target."
                )

            target.append(copy.deepcopy(operation.get("value")))

        elif op == "append_rule_condition":
            rule = _rule_by_id(mutated, str(operation["rule_id"]))
            conditions = rule.setdefault("when", {}).setdefault("all", [])

            if not isinstance(conditions, list):
                raise PolicyMutationError(
                    "Rule condition collection must be a list."
                )

            conditions.append(copy.deepcopy(operation["condition"]))

        elif op == "remove_rule":
            rule_id = str(operation["rule_id"])
            before = len(mutated.get("rules", []))
            mutated["rules"] = [
                rule
                for rule in mutated.get("rules", [])
                if rule.get("rule_id") != rule_id
            ]

            if len(mutated["rules"]) != before - 1:
                raise PolicyMutationError(
                    f"Could not remove exactly one rule {rule_id!r}."
                )

        else:
            raise PolicyMutationError(
                f"Unsupported mutation operation: {op!r}"
            )

    return mutated



def _minimal_policy_fixtures() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    impact_names = (
        "availability",
        "confidentiality",
        "integrity",
        "legal_regulatory",
        "mission_readiness",
        "patient_safety",
        "public_service",
        "public_wellbeing",
    )

    asset = {
        "criticality": {"level": "moderate"},
        "exposure": {
            "internet_accessible": False,
            "externally_accessible": False,
            "network_zone": "internal",
            "exposure_evidence_ids": [
                "AEG-EVD-EXPOSURE-BASELINE"
            ],
        },
        "mission": {"mission_essential": False},
        "impact_assessment": {
            name: {
                "severity": "low",
                "evidence_ids": ["AEG-EVD-IMPACT-BASELINE"],
            }
            for name in impact_names
        },
        "provenance": {
            "source_evidence_ids": ["AEG-EVD-ASSET-BASELINE"]
        },
        "sector_context": {"primary_sector": "healthcare"},
    }

    intelligence = {
        "canonical_id": "CVE-2021-44228",
        "record_status": "validated",
        "cvss": {
            "selected_metric_id": "CVSS-METRIC-BASELINE",
            "metrics": [
                {
                    "metric_id": "CVSS-METRIC-BASELINE",
                    "base_score": 5.0,
                    "base_severity": "MEDIUM",
                    "evidence_id": "AEG-EVD-CVSS-BASELINE",
                }
            ],
        },
        "epss": {
            "status": "available",
            "probability": 0.01,
            "percentile": 0.1,
            "model_version": "baseline",
            "score_date": "2026-07-13",
            "retrieved_at": "2026-07-13T00:00:00+00:00",
            "missing_reason": None,
            "evidence_id": "AEG-EVD-EPSS-BASELINE",
        },
        "kev": {
            "status": "not_listed",
            "catalog_version": "2026.07",
            "date_added": None,
            "due_date": None,
            "required_action": None,
            "evidence_id": "AEG-EVD-KEV-BASELINE",
        },
        "exploitation": {
            "status": "none",
            "confidence": "low",
            "last_observed_at": None,
            "evidence_ids": ["AEG-EVD-EXPLOIT-BASELINE"],
        },
        "remediation": {
            "status": "fix_available",
            "evidence_ids": ["AEG-EVD-REMEDIATION-BASELINE"],
        },
        "provenance": {
            "source_evidence_ids": ["AEG-EVD-INTEL-BASELINE"]
        },
    }

    component = {
        "component_id": "COMP-LOG4J-BASELINE",
        "runtime_status": "not_loaded",
        "evidence_ids": ["AEG-EVD-COMPONENT-BASELINE"],
    }

    return asset, intelligence, component



def _decision_signature(assessment: Any) -> dict[str, Any]:
    return {
        "action": assessment.action,
        "priority": assessment.minimum_priority,
        "deadline_hours": assessment.response_deadline_hours,
        "human_review_required": assessment.human_review_required,
        "containment_required": assessment.containment_required,
        "prohibit_closure": assessment.prohibit_closure,
        "invariants_passed": assessment.invariants_passed,
    }



def _expected_signature(case: dict[str, Any]) -> dict[str, Any]:
    expected = case["expected"]
    return {
        "action": expected["action"],
        "priority": expected["priority"],
        "deadline_hours": float(expected["deadline_hours"]),
        "human_review_required": expected["human_review_required"],
        "containment_required": expected["containment_required"],
        "prohibit_closure": expected["prohibit_closure"],
        "invariants_passed": expected["invariants_must_pass"],
    }



def _case_checks(
    actual: dict[str, Any],
    expected: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {
            "code": "ACTION_MATCHES_ORACLE",
            "passed": actual["action"] == expected["action"],
        },
        {
            "code": "PRIORITY_MATCHES_ORACLE",
            "passed": actual["priority"] == expected["priority"],
        },
        {
            "code": "DEADLINE_MATCHES_ORACLE",
            "passed": math.isclose(
                float(actual["deadline_hours"]),
                float(expected["deadline_hours"]),
                rel_tol=0,
                abs_tol=1e-9,
            ),
        },
        {
            "code": "REVIEW_MATCHES_ORACLE",
            "passed": (
                actual["human_review_required"]
                is expected["human_review_required"]
            ),
        },
        {
            "code": "CONTAINMENT_MATCHES_ORACLE",
            "passed": (
                actual["containment_required"]
                is expected["containment_required"]
            ),
        },
        {
            "code": "CLOSURE_MATCHES_ORACLE",
            "passed": (
                actual["prohibit_closure"]
                is expected["prohibit_closure"]
            ),
        },
        {
            "code": "POLICY_INVARIANTS_PASS",
            "passed": (
                actual["invariants_passed"]
                is expected["invariants_passed"]
            ),
        },
    ]



def run_policy_against_corpus(
    policy_path: Path | str,
    cases: list[dict[str, Any]],
    evaluated_at: datetime = FIXED_EVALUATION_TIME,
) -> dict[str, Any]:
    engine = PolicyFloorEngine(policy_path=policy_path)
    base_asset, base_intelligence, base_component = (
        _minimal_policy_fixtures()
    )

    case_results: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for case in cases:
        scenario = case["scenario"]
        asset = apply_overrides(
            base_asset,
            scenario["asset_overrides"],
        )
        intelligence = apply_overrides(
            base_intelligence,
            scenario["intelligence_overrides"],
        )
        component = apply_overrides(
            base_component,
            scenario["component_overrides"],
        )

        assessment = engine.evaluate(
            asset_context=asset,
            intelligence_record=intelligence,
            component_instance=component,
            affectedness_assessment=scenario["affectedness"],
            evidence_trust=scenario["trust"],
            evaluated_at=evaluated_at,
        )

        actual = _decision_signature(assessment)
        expected = _expected_signature(case)
        checks = _case_checks(actual, expected)
        passed = all(check["passed"] for check in checks)

        result = {
            "case_id": case["case_id"],
            "pair_id": case["pair_id"],
            "sector_label": case["sector_label"],
            "counterfactual_key": case["counterfactual_key"],
            "affectedness_profile": scenario[
                "affectedness_profile"
            ],
            "operational_profile": scenario[
                "operational_profile"
            ],
            "passed": passed,
            "expected": expected,
            "actual": actual,
            "checks": checks,
            "matched_rule_ids": [
                rule.rule_id for rule in assessment.matched_rules
            ],
            "invariant_results": [
                invariant.to_dict()
                for invariant in assessment.invariant_results
            ],
        }

        case_results.append(result)
        grouped[case["pair_id"]].append(result)

    pair_results: list[dict[str, Any]] = []

    for pair_id in sorted(grouped):
        pair = grouped[pair_id]
        decision_signatures = {
            json.dumps(
                result["actual"],
                sort_keys=True,
                separators=(",", ":"),
            )
            for result in pair
        }
        rule_signatures = {
            json.dumps(
                result["matched_rule_ids"],
                sort_keys=True,
                separators=(",", ":"),
            )
            for result in pair
        }
        sectors = sorted(result["sector_label"] for result in pair)
        passed = (
            len(pair) == 2
            and sectors == ["defence_logistics", "healthcare"]
            and len(decision_signatures) == 1
            and len(rule_signatures) == 1
        )

        pair_results.append(
            {
                "pair_id": pair_id,
                "case_ids": [result["case_id"] for result in pair],
                "sectors": sectors,
                "decision_equal": len(decision_signatures) == 1,
                "matched_rules_equal": len(rule_signatures) == 1,
                "counterfactual_key_equal": len(
                    {result["counterfactual_key"] for result in pair}
                )
                == 1,
                "differing_fields": [
                    "sector_context.primary_sector"
                ],
                "passed": passed,
            }
        )

    passed_cases = sum(result["passed"] for result in case_results)
    passed_pairs = sum(result["passed"] for result in pair_results)
    invariant_pass_cases = sum(
        result["actual"]["invariants_passed"]
        for result in case_results
    )
    rule_coverage = Counter(
        rule_id
        for result in case_results
        for rule_id in result["matched_rule_ids"]
    )

    return {
        "summary": {
            "case_count": len(case_results),
            "passed_cases": passed_cases,
            "failed_cases": len(case_results) - passed_cases,
            "pair_count": len(pair_results),
            "passed_pairs": passed_pairs,
            "failed_pairs": len(pair_results) - passed_pairs,
            "invariant_pass_cases": invariant_pass_cases,
            "sector_disparity_count": len(pair_results) - passed_pairs,
            "overall_passed": (
                passed_cases == len(case_results)
                and passed_pairs == len(pair_results)
                and invariant_pass_cases == len(case_results)
            ),
        },
        "policy": {
            "policy_id": engine.metadata["policy_id"],
            "version": str(engine.metadata["version"]),
            "sha256": engine.policy_sha256,
        },
        "coverage": {
            "triggered_rule_coverage": dict(sorted(rule_coverage.items()))
        },
        "case_results": case_results,
        "counterfactual_results": pair_results,
        "generated_at": evaluated_at.isoformat(),
    }



def evaluate_static_security_contract(
    policy: dict[str, Any],
    contract: dict[str, Any],
) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []

    if policy.get("action_ranks") != contract.get("action_ranks"):
        failures.append(
            {
                "code": "ACTION_RANKS_CHANGED",
                "message": "Action rank ordering differs from the approved contract.",
            }
        )

    if policy.get("priority_ranks") != contract.get("priority_ranks"):
        failures.append(
            {
                "code": "PRIORITY_RANKS_CHANGED",
                "message": "Priority rank ordering differs from the approved contract.",
            }
        )

    fixed_fragments = {
        str(fragment).casefold()
        for fragment in contract.get("forbidden_field_fragments", [])
    }
    policy_fragments = {
        str(fragment).casefold()
        for fragment in policy.get("forbidden_field_fragments", [])
    }

    missing_fragments = sorted(fixed_fragments - policy_fragments)

    if missing_fragments:
        failures.append(
            {
                "code": "FORBIDDEN_LABEL_GUARD_REMOVED",
                "message": (
                    "Required forbidden field fragments are missing: "
                    + ", ".join(missing_fragments)
                ),
            }
        )

    for field_name in policy.get("allowed_context_fields", []):
        lowered = str(field_name).casefold()

        if any(fragment in lowered for fragment in fixed_fragments):
            failures.append(
                {
                    "code": "PROHIBITED_CONTEXT_FIELD_ALLOWED",
                    "message": f"Prohibited context field allowed: {field_name}",
                }
            )

    rules = {
        str(rule.get("rule_id")): rule
        for rule in policy.get("rules", [])
    }
    required_rule_ids = set(contract.get("required_rule_ids", []))
    missing_rules = sorted(required_rule_ids - set(rules))

    if missing_rules:
        failures.append(
            {
                "code": "REQUIRED_RULE_REMOVED",
                "message": "Required policy rules are missing: " + ", ".join(missing_rules),
            }
        )

    for rule_id, rule in rules.items():
        for condition in rule.get("when", {}).get("all", []):
            field_name = str(condition.get("field", ""))
            lowered = field_name.casefold()

            if any(fragment in lowered for fragment in fixed_fragments):
                failures.append(
                    {
                        "code": "PROHIBITED_RULE_INPUT",
                        "message": (
                            f"Rule {rule_id} directly uses prohibited field "
                            f"{field_name}."
                        ),
                    }
                )

    action_ranks = contract.get("action_ranks", {})
    priority_ranks = contract.get("priority_ranks", {})

    for rule_id, minimum in contract.get(
        "critical_rule_minima",
        {},
    ).items():
        rule = rules.get(rule_id)

        if rule is None:
            continue

        setting = rule.get("set", {})
        actual_action = setting.get("action_floor")
        required_action = minimum.get("action_floor")

        if (
            actual_action not in action_ranks
            or action_ranks[actual_action]
            < action_ranks[required_action]
        ):
            failures.append(
                {
                    "code": "CRITICAL_ACTION_FLOOR_WEAKENED",
                    "message": f"{rule_id} action floor is below {required_action}.",
                }
            )

        actual_priority = setting.get("priority_floor")
        required_priority = minimum.get("priority_floor")

        if (
            actual_priority not in priority_ranks
            or priority_ranks[actual_priority]
            < priority_ranks[required_priority]
        ):
            failures.append(
                {
                    "code": "CRITICAL_PRIORITY_FLOOR_WEAKENED",
                    "message": f"{rule_id} priority floor is below {required_priority}.",
                }
            )

        deadline_maximum = float(minimum["deadline_hours_maximum"])
        actual_deadline = setting.get("deadline_hours")

        if (
            not isinstance(actual_deadline, (int, float))
            or isinstance(actual_deadline, bool)
            or float(actual_deadline) > deadline_maximum
        ):
            failures.append(
                {
                    "code": "CRITICAL_DEADLINE_EXTENDED",
                    "message": (
                        f"{rule_id} deadline exceeds {deadline_maximum} hours."
                    ),
                }
            )

        for boolean_field in (
            "human_review_required",
            "containment_required",
            "prohibit_closure",
        ):
            if minimum.get(boolean_field) is True and setting.get(
                boolean_field
            ) is not True:
                failures.append(
                    {
                        "code": f"CRITICAL_{boolean_field.upper()}_REMOVED",
                        "message": f"{rule_id} removed {boolean_field}.",
                    }
                )

        if minimum.get("non_overridable") is True and rule.get(
            "non_overridable"
        ) is not True:
            failures.append(
                {
                    "code": "CRITICAL_RULE_MADE_OVERRIDABLE",
                    "message": f"{rule_id} is no longer non-overridable.",
                }
            )

    return failures



def _validate_catalog(catalog: dict[str, Any]) -> None:
    required_sections = {
        "policy",
        "trusted_policy",
        "assurance_inputs",
        "release_gates",
        "security_contract",
        "mutations",
    }
    missing = required_sections - set(catalog)

    if missing:
        raise PolicyMutationError(
            f"Mutation catalog missing sections: {sorted(missing)}"
        )

    mutations = catalog["mutations"]

    if not isinstance(mutations, list) or not mutations:
        raise PolicyMutationError(
            "Mutation catalog requires a non-empty mutation list."
        )

    ids = [mutation.get("mutation_id") for mutation in mutations]

    if any(not mutation_id for mutation_id in ids):
        raise PolicyMutationError("Every mutation requires a mutation_id.")

    if len(ids) != len(set(ids)):
        raise PolicyMutationError("Mutation IDs must be unique.")

    for mutation in mutations:
        if mutation.get("severity") != "critical":
            raise PolicyMutationError(
                "Step 11B currently permits critical mutations only."
            )

        if not mutation.get("operations"):
            raise PolicyMutationError(
                f"Mutation {mutation['mutation_id']} has no operations."
            )



def _load_catalog(path: Path | str) -> dict[str, Any]:
    catalog_path = Path(path)
    payload = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))

    if not isinstance(payload, dict):
        raise PolicyMutationError(
            "Mutation catalog must be a YAML object."
        )

    _validate_catalog(payload)
    return payload



def _artifact_path(
    project_root: Path,
    metadata: dict[str, Any],
) -> Path:
    relative_path = metadata.get("relative_path")

    if not isinstance(relative_path, str) or not relative_path:
        raise PolicyMutationError("Artifact relative_path is required.")

    resolved = (project_root / relative_path).resolve()

    if project_root != resolved and project_root not in resolved.parents:
        raise PolicyMutationError(
            f"Artifact path escapes project root: {relative_path}"
        )

    return resolved



def _check_input_hashes(
    project_root: Path,
    catalog: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    checks: dict[str, dict[str, Any]] = {}

    trusted_metadata = catalog["trusted_policy"]
    trusted_path = _artifact_path(project_root, trusted_metadata)
    trusted_actual = sha256_file(trusted_path)
    trusted_expected = trusted_metadata["expected_sha256"]
    checks["trusted_policy"] = {
        "relative_path": trusted_metadata["relative_path"],
        "expected_sha256": trusted_expected,
        "actual_sha256": trusted_actual,
        "passed": trusted_actual == trusted_expected,
    }

    for name, metadata in catalog["assurance_inputs"].items():
        if "expected_sha256" not in metadata:
            continue

        path = _artifact_path(project_root, metadata)
        actual = sha256_file(path)
        expected = metadata["expected_sha256"]
        checks[name] = {
            "relative_path": metadata["relative_path"],
            "expected_sha256": expected,
            "actual_sha256": actual,
            "passed": actual == expected,
        }

    failed = [name for name, check in checks.items() if not check["passed"]]

    if failed:
        raise PolicyMutationError(
            "Mutation input integrity checks failed: " + ", ".join(failed)
        )

    return checks



def _oracle_summary(
    assurance_report: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    failed_cases = [
        result
        for result in assurance_report["case_results"]
        if not result["passed"]
    ]
    invariant_failure_cases = [
        result
        for result in assurance_report["case_results"]
        if not result["actual"]["invariants_passed"]
    ]
    failed_check_codes = Counter(
        check["code"]
        for result in failed_cases
        for check in result["checks"]
        if not check["passed"]
    )
    failed_pairs = [
        result
        for result in assurance_report["counterfactual_results"]
        if not result["passed"]
    ]

    oracles: list[str] = []

    if any(
        code != "POLICY_INVARIANTS_PASS"
        for code in failed_check_codes
    ):
        oracles.append("CASE_ORACLE")

    if invariant_failure_cases:
        oracles.append("POLICY_INVARIANT")

    if failed_pairs:
        oracles.append("COUNTERFACTUAL_CONSISTENCY")

    summary = {
        "case_count": len(assurance_report["case_results"]),
        "passed_case_count": (
            len(assurance_report["case_results"]) - len(failed_cases)
        ),
        "failed_case_count": len(failed_cases),
        "failed_case_ids": [result["case_id"] for result in failed_cases],
        "failed_check_codes": dict(sorted(failed_check_codes.items())),
        "invariant_failure_case_count": len(invariant_failure_cases),
        "invariant_failure_case_ids": [
            result["case_id"] for result in invariant_failure_cases
        ],
        "failed_pair_count": len(failed_pairs),
        "failed_pair_ids": [result["pair_id"] for result in failed_pairs],
    }

    return summary, oracles



def _release_summary(
    evaluation_report: dict[str, Any] | None,
    consistency_error: str | None,
) -> tuple[dict[str, Any], list[str]]:
    if evaluation_report is None:
        return (
            {
                "stage_gate_status": "NOT_EVALUATED",
                "under_triage_count": 0,
                "safety_recall": None,
                "full_rule_coverage_rate": None,
                "uncovered_policy_rules": [],
                "failed_quality_gate_ids": [],
                "policy_consistency_error": consistency_error,
            },
            ["POLICY_CONSISTENCY"] if consistency_error else [],
        )

    release = evaluation_report["release_decision"]
    safety = evaluation_report["safety_metrics"]
    coverage = evaluation_report["rule_coverage"]
    failed_gate_ids = [
        gate["gate_id"]
        for gate in evaluation_report["quality_gates"]
        if gate["release_blocking"] and not gate["passed"]
    ]

    oracles: list[str] = []

    if release["stage_gate_status"] == "FAIL":
        oracles.append("RELEASE_GATE")

    if safety["under_triage_count"] > 0:
        oracles.append("UNDER_TRIAGE_DETECTION")

    if coverage["full_rule_coverage_rate"] < 1.0:
        oracles.append("RULE_COVERAGE")

    return (
        {
            "stage_gate_status": release["stage_gate_status"],
            "under_triage_count": safety["under_triage_count"],
            "safety_recall": safety["safety_recall"],
            "full_rule_coverage_rate": coverage[
                "full_rule_coverage_rate"
            ],
            "uncovered_policy_rules": coverage[
                "uncovered_policy_rules"
            ],
            "failed_quality_gate_ids": failed_gate_ids,
            "policy_consistency_error": None,
        },
        oracles,
    )



class PolicyMutationHarness:
    def __init__(
        self,
        project_root: Path | str = PROJECT_ROOT,
        catalog_path: Path | str = DEFAULT_CATALOG_PATH,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.catalog_path = Path(catalog_path).resolve()
        self.catalog = _load_catalog(self.catalog_path)
        self.catalog_sha256 = sha256_file(self.catalog_path)
        self.input_integrity_checks = _check_input_hashes(
            self.project_root,
            self.catalog,
        )

        self.trusted_policy_path = _artifact_path(
            self.project_root,
            self.catalog["trusted_policy"],
        )
        self.trusted_policy_sha256 = sha256_file(
            self.trusted_policy_path
        )
        trusted_payload = yaml.safe_load(
            self.trusted_policy_path.read_text(encoding="utf-8")
        )

        if not isinstance(trusted_payload, dict):
            raise PolicyMutationError(
                "Trusted policy must be a YAML object."
            )

        self.trusted_policy = trusted_payload

        corpus_metadata = self.catalog["assurance_inputs"]["corpus"]
        self.corpus_path = _artifact_path(
            self.project_root,
            corpus_metadata,
        )
        self.cases = load_jsonl(self.corpus_path)

        gate_metadata = self.catalog["assurance_inputs"][
            "release_gate_policy"
        ]
        self.release_gate_policy_path = _artifact_path(
            self.project_root,
            gate_metadata,
        )

    def calibrate_trusted_policy(self) -> dict[str, Any]:
        report = run_policy_against_corpus(
            self.trusted_policy_path,
            self.cases,
        )
        summary = report["summary"]

        if not summary["overall_passed"]:
            raise PolicyMutationError(
                "Trusted-policy calibration failed against the Step 11A corpus."
            )

        if sha256_file(self.trusted_policy_path) != self.trusted_policy_sha256:
            raise PolicyMutationError(
                "Trusted policy changed during calibration."
            )

        return {
            "case_count": summary["case_count"],
            "passed_case_count": summary["passed_cases"],
            "pair_count": summary["pair_count"],
            "passed_pair_count": summary["passed_pairs"],
            "invariant_pass_case_count": summary[
                "invariant_pass_cases"
            ],
            "passed": True,
        }

    def execute_mutation(
        self,
        mutation: dict[str, Any],
    ) -> MutationExecution:
        mutation_id = str(mutation["mutation_id"])
        base_result = {
            "mutation_id": mutation_id,
            "title": mutation["title"],
            "family": mutation["family"],
            "severity": mutation["severity"],
            "description": mutation["description"],
            "expected_detection": mutation.get(
                "expected_detection",
                [],
            ),
            "operations": mutation["operations"],
            "status": "HARNESS_ERROR",
            "executable": False,
            "trusted_policy_sha256": self.trusted_policy_sha256,
            "mutated_policy_sha256": "",
            "load_error": None,
            "static_contract_failures": [],
            "assurance": {
                "case_count": len(self.cases),
                "passed_case_count": 0,
                "failed_case_count": 0,
                "failed_case_ids": [],
                "failed_check_codes": {},
                "invariant_failure_case_count": 0,
                "invariant_failure_case_ids": [],
                "failed_pair_count": 0,
                "failed_pair_ids": [],
            },
            "release_evaluation": {
                "stage_gate_status": "NOT_EVALUATED",
                "under_triage_count": 0,
                "safety_recall": None,
                "full_rule_coverage_rate": None,
                "uncovered_policy_rules": [],
                "failed_quality_gate_ids": [],
                "policy_consistency_error": None,
            },
            "detection_oracles": [],
            "error": None,
        }

        try:
            mutated_policy = apply_mutation_operations(
                self.trusted_policy,
                mutation["operations"],
            )
            static_failures = evaluate_static_security_contract(
                mutated_policy,
                self.catalog["security_contract"],
            )
            base_result["static_contract_failures"] = static_failures

            with tempfile.TemporaryDirectory(
                prefix="aegissec-step11b-"
            ) as temporary_directory:
                temp_root = Path(temporary_directory)
                policy_path = temp_root / "mutated_policy.yaml"
                policy_path.write_text(
                    yaml.safe_dump(
                        mutated_policy,
                        sort_keys=False,
                        allow_unicode=True,
                    ),
                    encoding="utf-8",
                )
                base_result["mutated_policy_sha256"] = sha256_file(
                    policy_path
                )

                try:
                    PolicyFloorEngine(policy_path=policy_path)
                except (PolicyConfigurationError, KeyError, TypeError, ValueError) as exc:
                    base_result["status"] = "BLOCKED_AT_LOAD"
                    base_result["load_error"] = (
                        f"{type(exc).__name__}: {exc}"
                    )
                    base_result["detection_oracles"] = [
                        "POLICY_LOADER"
                    ]
                    return MutationExecution(
                        mutation_id=mutation_id,
                        status="BLOCKED_AT_LOAD",
                        executable=False,
                        result=base_result,
                    )

                base_result["executable"] = True
                assurance_report = run_policy_against_corpus(
                    policy_path,
                    self.cases,
                )
                assurance_summary, assurance_oracles = _oracle_summary(
                    assurance_report
                )
                base_result["assurance"] = assurance_summary

                assurance_path = temp_root / "mutation_assurance_report.json"
                write_json(assurance_path, assurance_report)

                evaluation_report: dict[str, Any] | None = None
                consistency_error: str | None = None

                try:
                    evaluator = FairnessRobustnessEvaluator(
                        gate_policy_path=self.release_gate_policy_path,
                        decision_policy_path=policy_path,
                    )
                    evaluation_report = evaluator.evaluate(
                        assurance_report=assurance_report,
                        source_report_path=assurance_path,
                        evaluated_at=FIXED_EVALUATION_TIME,
                    )
                except (
                    FairnessEvaluationError,
                    PolicyConfigurationError,
                    KeyError,
                    TypeError,
                    ValueError,
                ) as exc:
                    consistency_error = f"{type(exc).__name__}: {exc}"

                release_summary, release_oracles = _release_summary(
                    evaluation_report,
                    consistency_error,
                )
                base_result["release_evaluation"] = release_summary

                detection_oracles = []

                if static_failures:
                    detection_oracles.append(
                        "STATIC_SECURITY_CONTRACT"
                    )

                detection_oracles.extend(assurance_oracles)
                detection_oracles.extend(release_oracles)
                detection_oracles = sorted(set(detection_oracles))
                base_result["detection_oracles"] = detection_oracles

                if detection_oracles:
                    status = "KILLED_BY_ASSURANCE"
                else:
                    status = "SURVIVED"

                base_result["status"] = status

                return MutationExecution(
                    mutation_id=mutation_id,
                    status=status,
                    executable=True,
                    result=base_result,
                )

        except Exception as exc:  # pragma: no cover - safety net
            base_result["status"] = "HARNESS_ERROR"
            base_result["error"] = f"{type(exc).__name__}: {exc}"

            return MutationExecution(
                mutation_id=mutation_id,
                status="HARNESS_ERROR",
                executable=False,
                result=base_result,
            )

    def run(self) -> dict[str, Any]:
        trusted_before = sha256_file(self.trusted_policy_path)
        calibration = self.calibrate_trusted_policy()
        executions = [
            self.execute_mutation(mutation)
            for mutation in self.catalog["mutations"]
        ]
        results = [execution.result for execution in executions]
        trusted_after = sha256_file(self.trusted_policy_path)

        status_counts = Counter(result["status"] for result in results)
        critical_results = [
            result for result in results if result["severity"] == "critical"
        ]
        defended_critical = [
            result
            for result in critical_results
            if result["status"]
            in {"BLOCKED_AT_LOAD", "KILLED_BY_ASSURANCE"}
        ]
        executable_critical = [
            result for result in critical_results if result["executable"]
        ]
        killed_executable_critical = [
            result
            for result in executable_critical
            if result["status"] == "KILLED_BY_ASSURANCE"
        ]
        surviving_critical = [
            result
            for result in critical_results
            if result["status"] == "SURVIVED"
        ]
        harness_errors = [
            result
            for result in results
            if result["status"] == "HARNESS_ERROR"
        ]

        defence_rate = (
            len(defended_critical) / len(critical_results)
            if critical_results
            else 1.0
        )
        executable_kill_rate = (
            len(killed_executable_critical) / len(executable_critical)
            if executable_critical
            else 1.0
        )
        trusted_integrity_passed = trusted_before == trusted_after

        gates = self.catalog["release_gates"]
        quality_gates = [
            {
                "gate_id": "MUTATION-CRITICAL-DEFENCE-RATE",
                "observed": defence_rate,
                "operator": "gte",
                "threshold": gates[
                    "critical_mutation_defence_rate_minimum"
                ],
                "passed": defence_rate
                >= gates["critical_mutation_defence_rate_minimum"],
            },
            {
                "gate_id": "MUTATION-EXECUTABLE-KILL-RATE",
                "observed": executable_kill_rate,
                "operator": "gte",
                "threshold": gates[
                    "executable_critical_mutation_kill_rate_minimum"
                ],
                "passed": executable_kill_rate
                >= gates[
                    "executable_critical_mutation_kill_rate_minimum"
                ],
            },
            {
                "gate_id": "MUTATION-SURVIVORS",
                "observed": len(surviving_critical),
                "operator": "lte",
                "threshold": gates[
                    "surviving_critical_mutations_maximum"
                ],
                "passed": len(surviving_critical)
                <= gates["surviving_critical_mutations_maximum"],
            },
            {
                "gate_id": "MUTATION-HARNESS-ERRORS",
                "observed": len(harness_errors),
                "operator": "lte",
                "threshold": gates["harness_errors_maximum"],
                "passed": len(harness_errors)
                <= gates["harness_errors_maximum"],
            },
            {
                "gate_id": "TRUSTED-POLICY-INTEGRITY",
                "observed": trusted_integrity_passed,
                "operator": "eq",
                "threshold": True,
                "passed": trusted_integrity_passed,
            },
        ]
        overall_passed = all(gate["passed"] for gate in quality_gates)

        return {
            "schema_version": "1.0.0",
            "report_id": "AEG-MUTATION-STEP11B-001",
            "catalog": {
                "catalog_id": self.catalog["policy"]["catalog_id"],
                "version": str(self.catalog["policy"]["version"]),
                "harness_version": str(
                    self.catalog["policy"]["harness_version"]
                ),
                "relative_path": self.catalog_path.relative_to(
                    self.project_root
                ).as_posix(),
                "sha256": self.catalog_sha256,
            },
            "trusted_policy": {
                "relative_path": self.trusted_policy_path.relative_to(
                    self.project_root
                ).as_posix(),
                "sha256_before": trusted_before,
                "sha256_after": trusted_after,
                "unchanged": trusted_integrity_passed,
            },
            "input_integrity_checks": self.input_integrity_checks,
            "baseline_calibration": calibration,
            "summary": {
                "mutation_count": len(results),
                "critical_mutation_count": len(critical_results),
                "blocked_at_load_count": status_counts[
                    "BLOCKED_AT_LOAD"
                ],
                "killed_by_assurance_count": status_counts[
                    "KILLED_BY_ASSURANCE"
                ],
                "survived_count": status_counts["SURVIVED"],
                "harness_error_count": status_counts[
                    "HARNESS_ERROR"
                ],
                "critical_mutation_defence_rate": defence_rate,
                "executable_critical_mutation_count": len(
                    executable_critical
                ),
                "executable_critical_killed_count": len(
                    killed_executable_critical
                ),
                "executable_critical_mutation_kill_rate": (
                    executable_kill_rate
                ),
                "trusted_policy_integrity_passed": (
                    trusted_integrity_passed
                ),
                "overall_passed": overall_passed,
            },
            "quality_gates": quality_gates,
            "results": results,
            "surviving_mutation_ids": [
                result["mutation_id"] for result in surviving_critical
            ],
            "harness_error_mutation_ids": [
                result["mutation_id"] for result in harness_errors
            ],
            "release_decision": {
                "stage_gate_status": "PASS" if overall_passed else "FAIL",
                "production_readiness_status": "BLOCKED",
                "blocking_reasons": gates[
                    "approved_remaining_production_blockers"
                ],
            },
            "limitations": [
                "Mutations execute only against ephemeral policy copies.",
                "The suite evaluates deterministic policy logic and does not replace independent penetration testing.",
                "The controlled corpus is not operational incident data.",
                "A killed mutation proves detection by this harness, not complete absence of policy defects.",
            ],
            "generated_at": FIXED_EVALUATION_TIME.isoformat(),
        }

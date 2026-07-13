from __future__ import annotations

import copy
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker

from src.policy.policy_floor_engine import PolicyFloorEngine


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_policy_assurance_case.schema.json"
)

DEFAULT_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "federal_base_policy_v1.yaml"
)


ACTION_RANKS = {
    "TRACK": 0,
    "TRACK_STAR": 1,
    "ATTEND": 2,
    "ACT": 3,
    "HOLD": 4,
}


PRIORITY_RANKS = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "EMERGENCY": 5,
}


AFFECTEDNESS_PROFILES = (
    {
        "name": "affected",
        "confidence": 0.95,
    },
    {
        "name": "probably_affected",
        "confidence": 0.75,
    },
    {
        "name": "unknown",
        "confidence": None,
    },
    {
        "name": "probably_not_affected",
        "confidence": 0.70,
    },
    {
        "name": "fixed",
        "confidence": 0.95,
    },
)


OPERATIONAL_PROFILES = (
    "baseline",
    "kev_listed",
    "active_exploitation",
    "internet_exposed",
    "exposure_unknown",
    "catastrophic_impact",
    "severe_impact",
    "mission_essential",
    "high_criticality",
    "critical_cvss",
    "no_fix_available",
    "trust_blocked",
)


SECTOR_LABELS = (
    {
        "label": "healthcare",
        "suffix": "HC",
    },
    {
        "label": "defence_logistics",
        "suffix": "DL",
    },
)


def sha256_file(path: Path | str) -> str:
    file_path = Path(path)
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def canonical_json_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def load_json(path: Path | str) -> dict[str, Any]:
    file_path = Path(path)

    with file_path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(
            f"Expected JSON object: {file_path}"
        )

    return payload


def load_jsonl(
    path: Path | str,
) -> list[dict[str, Any]]:
    file_path = Path(path)
    records: list[dict[str, Any]] = []

    with file_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            payload = json.loads(stripped)

            if not isinstance(payload, dict):
                raise ValueError(
                    "JSONL item must be an object at "
                    f"line {line_number}."
                )

            records.append(payload)

    return records


def write_json(
    path: Path | str,
    payload: dict[str, Any],
) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False,
            sort_keys=False,
        )
        file.write("\n")


def write_jsonl(
    path: Path | str,
    records: Iterable[dict[str, Any]],
) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with file_path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(
                json.dumps(
                    record,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
            file.write("\n")


def deep_set(
    payload: dict[str, Any],
    dotted_path: str,
    value: Any,
) -> None:
    """
    Set values using paths such as:

        exposure.internet_accessible
        cvss.metrics.0.base_score
    """
    parts = dotted_path.split(".")
    current: Any = payload

    for index, part in enumerate(parts[:-1]):
        next_part = parts[index + 1]

        if isinstance(current, list):
            try:
                list_index = int(part)
            except ValueError as exc:
                raise ValueError(
                    f"Expected list index in path "
                    f"{dotted_path!r}, received {part!r}."
                ) from exc

            if (
                list_index < 0
                or list_index >= len(current)
            ):
                raise IndexError(
                    f"List index outside range in "
                    f"path {dotted_path!r}."
                )

            current = current[list_index]
            continue

        if not isinstance(current, dict):
            raise TypeError(
                f"Cannot traverse path {dotted_path!r}."
            )

        if part not in current:
            current[part] = (
                []
                if next_part.isdigit()
                else {}
            )

        current = current[part]

    final_part = parts[-1]

    if isinstance(current, list):
        try:
            list_index = int(final_part)
        except ValueError as exc:
            raise ValueError(
                f"Expected final list index in "
                f"path {dotted_path!r}."
            ) from exc

        if (
            list_index < 0
            or list_index >= len(current)
        ):
            raise IndexError(
                f"List index outside range in "
                f"path {dotted_path!r}."
            )

        current[list_index] = copy.deepcopy(value)
        return

    if not isinstance(current, dict):
        raise TypeError(
            f"Cannot assign path {dotted_path!r}."
        )

    current[final_part] = copy.deepcopy(value)


def apply_overrides(
    payload: dict[str, Any],
    overrides: dict[str, Any],
) -> dict[str, Any]:
    updated = copy.deepcopy(payload)

    for field_path, value in overrides.items():
        deep_set(
            updated,
            field_path,
            value,
        )

    return updated


def higher_action(
    current: str,
    candidate: str,
) -> str:
    if (
        ACTION_RANKS[candidate]
        > ACTION_RANKS[current]
    ):
        return candidate

    return current


def higher_priority(
    current: str,
    candidate: str,
) -> str:
    if (
        PRIORITY_RANKS[candidate]
        > PRIORITY_RANKS[current]
    ):
        return candidate

    return current


def build_expected_decision(
    affectedness_status: str,
    operational_profile: str,
) -> dict[str, Any]:
    """
    Independent declarative oracle for the assurance corpus.

    This function does not call PolicyFloorEngine. It represents the
    expected safety contract against which the engine is evaluated.
    """
    base_expectations = {
        "affected": {
            "action": "ATTEND",
            "priority": "HIGH",
            "deadline_hours": 168.0,
            "human_review_required": False,
            "containment_required": False,
            "prohibit_closure": False,
        },
        "probably_affected": {
            "action": "ATTEND",
            "priority": "HIGH",
            "deadline_hours": 72.0,
            "human_review_required": True,
            "containment_required": False,
            "prohibit_closure": True,
        },
        "unknown": {
            "action": "HOLD",
            "priority": "HIGH",
            "deadline_hours": 24.0,
            "human_review_required": True,
            "containment_required": False,
            "prohibit_closure": True,
        },
        "probably_not_affected": {
            "action": "HOLD",
            "priority": "MEDIUM",
            "deadline_hours": 72.0,
            "human_review_required": True,
            "containment_required": False,
            "prohibit_closure": True,
        },
        "fixed": {
            "action": "TRACK",
            "priority": "INFORMATIONAL",
            "deadline_hours": 720.0,
            "human_review_required": False,
            "containment_required": False,
            "prohibit_closure": False,
        },
    }

    if affectedness_status not in base_expectations:
        raise ValueError(
            f"Unsupported affectedness status: "
            f"{affectedness_status}"
        )

    expectation = copy.deepcopy(
        base_expectations[affectedness_status]
    )

    vulnerable_states = {
        "affected",
        "probably_affected",
    }

    uncertain_states = {
        "unknown",
        "probably_not_affected",
    }

    def escalate(
        action: str,
        priority: str,
        deadline_hours: float,
        human_review_required: bool = False,
        containment_required: bool = False,
        prohibit_closure: bool = False,
    ) -> None:
        expectation["action"] = higher_action(
            expectation["action"],
            action,
        )

        expectation["priority"] = higher_priority(
            expectation["priority"],
            priority,
        )

        expectation["deadline_hours"] = min(
            float(expectation["deadline_hours"]),
            float(deadline_hours),
        )

        expectation["human_review_required"] = (
            expectation["human_review_required"]
            or human_review_required
        )

        expectation["containment_required"] = (
            expectation["containment_required"]
            or containment_required
        )

        expectation["prohibit_closure"] = (
            expectation["prohibit_closure"]
            or prohibit_closure
        )

    if operational_profile == "baseline":
        pass

    elif operational_profile == "kev_listed":
        if affectedness_status in vulnerable_states:
            escalate(
                action="ACT",
                priority="CRITICAL",
                deadline_hours=24,
                human_review_required=True,
                prohibit_closure=True,
            )

        elif affectedness_status in uncertain_states:
            escalate(
                action="HOLD",
                priority="CRITICAL",
                deadline_hours=24,
                human_review_required=True,
                prohibit_closure=True,
            )

    elif operational_profile == "active_exploitation":
        if affectedness_status in vulnerable_states:
            escalate(
                action="ACT",
                priority="EMERGENCY",
                deadline_hours=4,
                human_review_required=True,
                containment_required=True,
                prohibit_closure=True,
            )

    elif operational_profile == "internet_exposed":
        if affectedness_status in vulnerable_states:
            escalate(
                action="ACT",
                priority="CRITICAL",
                deadline_hours=24,
                human_review_required=True,
                prohibit_closure=True,
            )

    elif operational_profile == "exposure_unknown":
        if affectedness_status in vulnerable_states:
            escalate(
                action="ATTEND",
                priority="HIGH",
                deadline_hours=72,
                human_review_required=True,
                prohibit_closure=True,
            )

    elif operational_profile == "catastrophic_impact":
        if affectedness_status in vulnerable_states:
            escalate(
                action="ACT",
                priority="EMERGENCY",
                deadline_hours=4,
                human_review_required=True,
                containment_required=True,
                prohibit_closure=True,
            )

    elif operational_profile == "severe_impact":
        if affectedness_status in vulnerable_states:
            escalate(
                action="ACT",
                priority="CRITICAL",
                deadline_hours=24,
                human_review_required=True,
                prohibit_closure=True,
            )

    elif operational_profile in {
        "mission_essential",
        "high_criticality",
        "critical_cvss",
    }:
        if affectedness_status in vulnerable_states:
            escalate(
                action="ATTEND",
                priority="HIGH",
                deadline_hours=72,
            )

    elif operational_profile == "no_fix_available":
        if affectedness_status in vulnerable_states:
            escalate(
                action="ACT",
                priority="CRITICAL",
                deadline_hours=24,
                human_review_required=True,
                containment_required=True,
                prohibit_closure=True,
            )

    elif operational_profile == "trust_blocked":
        escalate(
            action="HOLD",
            priority="HIGH",
            deadline_hours=4,
            human_review_required=True,
            prohibit_closure=True,
        )

    else:
        raise ValueError(
            f"Unsupported operational profile: "
            f"{operational_profile}"
        )

    expectation["invariants_must_pass"] = True

    return expectation


class PolicyAssuranceRunner:
    def __init__(
        self,
        project_root: Path | str = PROJECT_ROOT,
        schema_path: Path | str = DEFAULT_SCHEMA_PATH,
        policy_path: Path | str = DEFAULT_POLICY_PATH,
    ) -> None:
        self.project_root = Path(
            project_root
        ).resolve()

        self.schema_path = Path(schema_path)
        self.policy_path = Path(policy_path)

        self.schema = load_json(
            self.schema_path
        )

        Draft202012Validator.check_schema(
            self.schema
        )

        self.schema_validator = (
            Draft202012Validator(
                self.schema,
                format_checker=FormatChecker(),
            )
        )

        self.engine = PolicyFloorEngine(
            policy_path=self.policy_path
        )

    def validate_case(
        self,
        case: dict[str, Any],
    ) -> list[str]:
        errors = sorted(
            self.schema_validator.iter_errors(
                case
            ),
            key=lambda error: list(
                error.absolute_path
            ),
        )

        return [
            (
                ".".join(
                    str(part)
                    for part
                    in error.absolute_path
                )
                + ": "
                + error.message
            ).lstrip(": ")
            for error in errors
        ]

    def verify_manifest(
        self,
        manifest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        checks: list[dict[str, Any]] = []

        records = {}

        records.update(
            manifest.get(
                "base_fixtures",
                {},
            )
        )

        records.update(
            manifest.get(
                "artifacts",
                {},
            )
        )

        for name, metadata in records.items():
            relative_path = metadata.get(
                "relative_path"
            )

            expected_hash = metadata.get(
                "sha256"
            )

            path = (
                self.project_root
                / relative_path
            ).resolve()

            safe = (
                path == self.project_root
                or self.project_root
                in path.parents
            )

            exists = safe and path.exists()

            actual_hash = (
                sha256_file(path)
                if exists
                else None
            )

            passed = (
                safe
                and exists
                and actual_hash
                == expected_hash
            )

            checks.append(
                {
                    "name": name,
                    "passed": passed,
                    "relative_path": relative_path,
                    "expected_sha256": (
                        expected_hash
                    ),
                    "actual_sha256": actual_hash,
                    "safe_path": safe,
                    "exists": exists,
                }
            )

        return checks

    def run(
        self,
        corpus_path: Path | str,
        manifest_path: Path | str,
        evaluated_at: datetime | None = None,
    ) -> dict[str, Any]:
        corpus_file = Path(corpus_path)
        manifest_file = Path(manifest_path)

        evaluation_time = (
            evaluated_at
            or datetime.now(timezone.utc)
        )

        manifest = load_json(
            manifest_file
        )

        manifest_checks = (
            self.verify_manifest(
                manifest
            )
        )

        if not all(
            check["passed"]
            for check in manifest_checks
        ):
            raise ValueError(
                "Assurance manifest verification failed."
            )

        cases = load_jsonl(
            corpus_file
        )

        base_fixtures = manifest[
            "base_fixtures"
        ]

        asset_path = (
            self.project_root
            / base_fixtures[
                "asset_context"
            ]["relative_path"]
        )

        intelligence_path = (
            self.project_root
            / base_fixtures[
                "vulnerability_intelligence"
            ]["relative_path"]
        )

        component_source_path = (
            self.project_root
            / base_fixtures[
                "component_source"
            ]["relative_path"]
        )

        base_asset = load_json(
            asset_path
        )

        base_intelligence = load_json(
            intelligence_path
        )

        component_source = load_json(
            component_source_path
        )

        base_component = component_source[
            "component_instance"
        ]

        case_results: list[
            dict[str, Any]
        ] = []

        grouped_results: dict[
            str,
            list[dict[str, Any]],
        ] = defaultdict(list)

        for case in cases:
            schema_errors = (
                self.validate_case(case)
            )

            scenario = case["scenario"]

            asset = apply_overrides(
                base_asset,
                scenario[
                    "asset_overrides"
                ],
            )

            intelligence = apply_overrides(
                base_intelligence,
                scenario[
                    "intelligence_overrides"
                ],
            )

            component = apply_overrides(
                base_component,
                scenario[
                    "component_overrides"
                ],
            )

            assessment = self.engine.evaluate(
                asset_context=asset,
                intelligence_record=(
                    intelligence
                ),
                component_instance=component,
                affectedness_assessment=(
                    scenario["affectedness"]
                ),
                evidence_trust=(
                    scenario["trust"]
                ),
                evaluated_at=evaluation_time,
            )

            actual = {
                "action": assessment.action,
                "priority": (
                    assessment.minimum_priority
                ),
                "deadline_hours": (
                    assessment
                    .response_deadline_hours
                ),
                "human_review_required": (
                    assessment
                    .human_review_required
                ),
                "containment_required": (
                    assessment
                    .containment_required
                ),
                "prohibit_closure": (
                    assessment
                    .prohibit_closure
                ),
                "invariants_passed": (
                    assessment
                    .invariants_passed
                ),
            }

            expected = case["expected"]

            checks = [
                {
                    "code": "CASE_SCHEMA_VALID",
                    "passed": not schema_errors,
                    "message": (
                        "Case conforms to the "
                        "assurance schema."
                        if not schema_errors
                        else "; ".join(
                            schema_errors
                        )
                    ),
                },
                {
                    "code": "ACTION_MATCHES_ORACLE",
                    "passed": (
                        actual["action"]
                        == expected["action"]
                    ),
                    "message": (
                        f"Expected action "
                        f"{expected['action']}, "
                        f"received "
                        f"{actual['action']}."
                    ),
                },
                {
                    "code": "PRIORITY_MATCHES_ORACLE",
                    "passed": (
                        actual["priority"]
                        == expected["priority"]
                    ),
                    "message": (
                        f"Expected priority "
                        f"{expected['priority']}, "
                        f"received "
                        f"{actual['priority']}."
                    ),
                },
                {
                    "code": "DEADLINE_MATCHES_ORACLE",
                    "passed": abs(
                        float(
                            actual[
                                "deadline_hours"
                            ]
                        )
                        - float(
                            expected[
                                "deadline_hours"
                            ]
                        )
                    )
                    <= 1e-9,
                    "message": (
                        f"Expected deadline "
                        f"{expected['deadline_hours']}, "
                        f"received "
                        f"{actual['deadline_hours']}."
                    ),
                },
                {
                    "code": "REVIEW_MATCHES_ORACLE",
                    "passed": (
                        actual[
                            "human_review_required"
                        ]
                        is expected[
                            "human_review_required"
                        ]
                    ),
                    "message": (
                        "Human-review requirement "
                        "must match the oracle."
                    ),
                },
                {
                    "code": "CONTAINMENT_MATCHES_ORACLE",
                    "passed": (
                        actual[
                            "containment_required"
                        ]
                        is expected[
                            "containment_required"
                        ]
                    ),
                    "message": (
                        "Containment requirement "
                        "must match the oracle."
                    ),
                },
                {
                    "code": "CLOSURE_MATCHES_ORACLE",
                    "passed": (
                        actual[
                            "prohibit_closure"
                        ]
                        is expected[
                            "prohibit_closure"
                        ]
                    ),
                    "message": (
                        "Closure prohibition must "
                        "match the oracle."
                    ),
                },
                {
                    "code": "POLICY_INVARIANTS_PASS",
                    "passed": (
                        actual[
                            "invariants_passed"
                        ]
                        is expected[
                            "invariants_must_pass"
                        ]
                    ),
                    "message": (
                        "Every executable policy "
                        "invariant must pass."
                    ),
                },
            ]

            passed = all(
                check["passed"]
                for check in checks
            )

            matched_rule_ids = [
                rule.rule_id
                for rule
                in assessment.matched_rules
            ]

            result = {
                "case_id": case["case_id"],
                "pair_id": case["pair_id"],
                "sector_label": (
                    case["sector_label"]
                ),
                "counterfactual_key": (
                    case[
                        "counterfactual_key"
                    ]
                ),
                "affectedness_profile": (
                    scenario[
                        "affectedness_profile"
                    ]
                ),
                "operational_profile": (
                    scenario[
                        "operational_profile"
                    ]
                ),
                "passed": passed,
                "expected": expected,
                "actual": actual,
                "checks": checks,
                "matched_rule_ids": (
                    matched_rule_ids
                ),
                "invariant_results": [
                    invariant.to_dict()
                    for invariant
                    in assessment
                    .invariant_results
                ],
            }

            case_results.append(result)

            grouped_results[
                case["pair_id"]
            ].append(result)

        counterfactual_results = []

        for pair_id in sorted(
            grouped_results
        ):
            pair = grouped_results[pair_id]

            sectors = sorted(
                item["sector_label"]
                for item in pair
            )

            decision_signatures = {
                json.dumps(
                    item["actual"],
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for item in pair
            }

            rule_signatures = {
                json.dumps(
                    item[
                        "matched_rule_ids"
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for item in pair
            }

            counterfactual_keys = {
                item[
                    "counterfactual_key"
                ]
                for item in pair
            }

            passed = (
                len(pair) == 2
                and sectors
                == [
                    "defence_logistics",
                    "healthcare",
                ]
                and len(
                    decision_signatures
                )
                == 1
                and len(rule_signatures) == 1
                and len(
                    counterfactual_keys
                )
                == 1
            )

            counterfactual_results.append(
                {
                    "pair_id": pair_id,
                    "case_ids": [
                        item["case_id"]
                        for item in pair
                    ],
                    "sectors": sectors,
                    "decision_equal": (
                        len(
                            decision_signatures
                        )
                        == 1
                    ),
                    "matched_rules_equal": (
                        len(rule_signatures)
                        == 1
                    ),
                    "counterfactual_key_equal": (
                        len(
                            counterfactual_keys
                        )
                        == 1
                    ),
                    "differing_fields": [
                        "sector_context.primary_sector"
                    ],
                    "passed": passed,
                }
            )

        affectedness_coverage = Counter(
            result[
                "affectedness_profile"
            ]
            for result in case_results
        )

        operational_coverage = Counter(
            result[
                "operational_profile"
            ]
            for result in case_results
        )

        sector_coverage = Counter(
            result["sector_label"]
            for result in case_results
        )

        action_distribution = Counter(
            result["actual"]["action"]
            for result in case_results
        )

        priority_distribution = Counter(
            result["actual"]["priority"]
            for result in case_results
        )

        rule_coverage = Counter(
            rule_id
            for result in case_results
            for rule_id
            in result["matched_rule_ids"]
        )

        passed_cases = sum(
            1
            for result in case_results
            if result["passed"]
        )

        passed_pairs = sum(
            1
            for result
            in counterfactual_results
            if result["passed"]
        )

        invariant_pass_cases = sum(
            1
            for result in case_results
            if result["actual"][
                "invariants_passed"
            ]
        )

        overall_passed = (
            len(case_results) == 120
            and passed_cases == 120
            and len(
                counterfactual_results
            )
            == 60
            and passed_pairs == 60
            and invariant_pass_cases == 120
            and all(
                check["passed"]
                for check in manifest_checks
            )
        )

        return {
            "report_id": (
                "AEG-ASR-POLICY-STEP9-001"
            ),
            "corpus_id": manifest[
                "corpus_id"
            ],
            "generator_version": manifest[
                "generator_version"
            ],
            "policy": {
                "policy_id": (
                    self.engine.metadata[
                        "policy_id"
                    ]
                ),
                "version": str(
                    self.engine.metadata[
                        "version"
                    ]
                ),
                "sha256": (
                    self.engine.policy_sha256
                ),
            },
            "summary": {
                "case_count": len(
                    case_results
                ),
                "passed_cases": (
                    passed_cases
                ),
                "failed_cases": (
                    len(case_results)
                    - passed_cases
                ),
                "invariant_pass_cases": (
                    invariant_pass_cases
                ),
                "pair_count": len(
                    counterfactual_results
                ),
                "passed_pairs": (
                    passed_pairs
                ),
                "failed_pairs": (
                    len(
                        counterfactual_results
                    )
                    - passed_pairs
                ),
                "sector_disparity_count": (
                    len(
                        counterfactual_results
                    )
                    - passed_pairs
                ),
                "manifest_checks_passed": (
                    sum(
                        1
                        for check
                        in manifest_checks
                        if check["passed"]
                    )
                ),
                "manifest_check_count": (
                    len(manifest_checks)
                ),
                "overall_passed": (
                    overall_passed
                ),
            },
            "coverage": {
                "affectedness_profiles": dict(
                    sorted(
                        affectedness_coverage
                        .items()
                    )
                ),
                "operational_profiles": dict(
                    sorted(
                        operational_coverage
                        .items()
                    )
                ),
                "sector_labels": dict(
                    sorted(
                        sector_coverage
                        .items()
                    )
                ),
                "action_distribution": dict(
                    sorted(
                        action_distribution
                        .items()
                    )
                ),
                "priority_distribution": dict(
                    sorted(
                        priority_distribution
                        .items()
                    )
                ),
                "triggered_rule_coverage": dict(
                    sorted(
                        rule_coverage.items()
                    )
                ),
            },
            "manifest_checks": (
                manifest_checks
            ),
            "case_results": case_results,
            "counterfactual_results": (
                counterfactual_results
            ),
            "generated_at": (
                evaluation_time.isoformat()
            ),
        }


def write_case_summary_csv(
    path: Path | str,
    cases: list[dict[str, Any]],
) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "case_id",
        "pair_id",
        "sector_label",
        "affectedness_profile",
        "operational_profile",
        "expected_action",
        "expected_priority",
        "expected_deadline_hours",
        "expected_human_review",
        "expected_containment",
        "expected_prohibit_closure",
        "counterfactual_key",
    ]

    with file_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for case in cases:
            scenario = case["scenario"]
            expected = case["expected"]

            writer.writerow(
                {
                    "case_id": case["case_id"],
                    "pair_id": case["pair_id"],
                    "sector_label": (
                        case["sector_label"]
                    ),
                    "affectedness_profile": (
                        scenario[
                            "affectedness_profile"
                        ]
                    ),
                    "operational_profile": (
                        scenario[
                            "operational_profile"
                        ]
                    ),
                    "expected_action": (
                        expected["action"]
                    ),
                    "expected_priority": (
                        expected["priority"]
                    ),
                    "expected_deadline_hours": (
                        expected[
                            "deadline_hours"
                        ]
                    ),
                    "expected_human_review": (
                        expected[
                            "human_review_required"
                        ]
                    ),
                    "expected_containment": (
                        expected[
                            "containment_required"
                        ]
                    ),
                    "expected_prohibit_closure": (
                        expected[
                            "prohibit_closure"
                        ]
                    ),
                    "counterfactual_key": (
                        case[
                            "counterfactual_key"
                        ]
                    ),
                }
            )

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_GATE_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "fairness_release_gates_v1.yaml"
)

DEFAULT_DECISION_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "federal_base_policy_v1.yaml"
)


class FairnessEvaluationError(ValueError):
    """Raised when evaluation inputs or policies are invalid."""


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


def safe_rate(
    numerator: int | float,
    denominator: int | float,
) -> float:
    if denominator == 0:
        return 1.0

    return float(numerator) / float(denominator)


def percentile(
    values: list[float],
    probability: float,
) -> float:
    if not values:
        raise ValueError(
            "Cannot calculate a percentile "
            "from an empty collection."
        )

    if probability < 0 or probability > 1:
        raise ValueError(
            "Probability must be between 0 and 1."
        )

    ordered = sorted(values)

    if len(ordered) == 1:
        return float(ordered[0])

    position = probability * (
        len(ordered) - 1
    )

    lower_index = math.floor(position)
    upper_index = math.ceil(position)

    if lower_index == upper_index:
        return float(
            ordered[lower_index]
        )

    lower_value = ordered[lower_index]
    upper_value = ordered[upper_index]

    fraction = position - lower_index

    return float(
        lower_value
        + fraction
        * (
            upper_value
            - lower_value
        )
    )


class FairnessRobustnessEvaluator:
    """
    Evaluate deterministic policy assurance results.

    This evaluator intentionally separates:

    1. stage assurance gates, which can pass for the current controlled scope;
    2. production readiness, which remains blocked until broader operational,
       security, policy-rule and model validation requirements are complete.
    """

    def __init__(
        self,
        gate_policy_path: Path | str = (
            DEFAULT_GATE_POLICY_PATH
        ),
        decision_policy_path: Path | str = (
            DEFAULT_DECISION_POLICY_PATH
        ),
    ) -> None:
        self.gate_policy_path = Path(
            gate_policy_path
        )

        self.decision_policy_path = Path(
            decision_policy_path
        )

        if not self.gate_policy_path.exists():
            raise FileNotFoundError(
                f"Release-gate policy not found: "
                f"{self.gate_policy_path}"
            )

        if not self.decision_policy_path.exists():
            raise FileNotFoundError(
                f"Decision policy not found: "
                f"{self.decision_policy_path}"
            )

        gate_bytes = (
            self.gate_policy_path.read_bytes()
        )

        decision_policy_bytes = (
            self.decision_policy_path.read_bytes()
        )

        self.gate_policy_sha256 = (
            hashlib.sha256(
                gate_bytes
            ).hexdigest()
        )

        self.decision_policy_sha256 = (
            hashlib.sha256(
                decision_policy_bytes
            ).hexdigest()
        )

        self.gate_policy = yaml.safe_load(
            gate_bytes.decode("utf-8")
        )

        self.decision_policy = yaml.safe_load(
            decision_policy_bytes.decode(
                "utf-8"
            )
        )

        if not isinstance(
            self.gate_policy,
            dict,
        ):
            raise FairnessEvaluationError(
                "Release-gate policy must be "
                "a YAML object."
            )

        if not isinstance(
            self.decision_policy,
            dict,
        ):
            raise FairnessEvaluationError(
                "Decision policy must be "
                "a YAML object."
            )

        self._validate_policies()

        self.metadata = self.gate_policy[
            "policy"
        ]

        self.thresholds = self.gate_policy[
            "thresholds"
        ]

        self.bootstrap_policy = (
            self.gate_policy["bootstrap"]
        )

        self.required_rule_ids = set(
            self.gate_policy[
                "required_rule_ids"
            ]
        )

        self.production_policy = (
            self.gate_policy[
                "production_readiness"
            ]
        )

        self.limitations = list(
            self.gate_policy["limitations"]
        )

        self.action_ranks = {
            str(name): int(rank)
            for name, rank
            in self.decision_policy[
                "action_ranks"
            ].items()
        }

        self.priority_ranks = {
            str(name): int(rank)
            for name, rank
            in self.decision_policy[
                "priority_ranks"
            ].items()
        }

        self.all_policy_rule_ids = {
            str(rule["rule_id"])
            for rule in self.decision_policy[
                "rules"
            ]
        }

    def _validate_policies(self) -> None:
        required_gate_sections = {
            "policy",
            "bootstrap",
            "thresholds",
            "required_rule_ids",
            "production_readiness",
            "limitations",
        }

        missing_gate_sections = (
            required_gate_sections
            - set(self.gate_policy)
        )

        if missing_gate_sections:
            raise FairnessEvaluationError(
                "Release-gate policy missing "
                f"sections: "
                f"{sorted(missing_gate_sections)}"
            )

        required_decision_sections = {
            "action_ranks",
            "priority_ranks",
            "rules",
        }

        missing_decision_sections = (
            required_decision_sections
            - set(self.decision_policy)
        )

        if missing_decision_sections:
            raise FairnessEvaluationError(
                "Decision policy missing "
                f"sections: "
                f"{sorted(missing_decision_sections)}"
            )

        iterations = self.gate_policy[
            "bootstrap"
        ]["iterations"]

        if (
            not isinstance(iterations, int)
            or isinstance(iterations, bool)
            or iterations < 100
        ):
            raise FairnessEvaluationError(
                "Bootstrap iterations must be "
                "an integer of at least 100."
            )

        confidence_level = float(
            self.gate_policy[
                "bootstrap"
            ]["confidence_level"]
        )

        if (
            confidence_level <= 0
            or confidence_level >= 1
        ):
            raise FairnessEvaluationError(
                "Bootstrap confidence level "
                "must be between zero and one."
            )

        all_rule_ids = {
            str(rule["rule_id"])
            for rule in self.decision_policy[
                "rules"
            ]
        }

        required_rule_ids = set(
            self.gate_policy[
                "required_rule_ids"
            ]
        )

        unknown_required_rules = (
            required_rule_ids
            - all_rule_ids
        )

        if unknown_required_rules:
            raise FairnessEvaluationError(
                "Release-gate policy references "
                "unknown decision rules: "
                f"{sorted(unknown_required_rules)}"
            )

    def evaluate(
        self,
        assurance_report: dict[str, Any],
        source_report_path: Path | str,
        evaluated_at: datetime | None = None,
    ) -> dict[str, Any]:
        self._validate_assurance_report(
            assurance_report
        )

        source_path = Path(
            source_report_path
        )

        evaluation_time = (
            evaluated_at
            or datetime.now(timezone.utc)
        )

        case_results = assurance_report[
            "case_results"
        ]

        pair_results = assurance_report[
            "counterfactual_results"
        ]

        exact_match_metrics = (
            self._exact_match_metrics(
                case_results
            )
        )

        safety_metrics = (
            self._safety_metrics(
                case_results
            )
        )

        abstention_metrics = (
            self._abstention_metrics(
                case_results
            )
        )

        counterfactual_metrics = (
            self._counterfactual_metrics(
                case_results=case_results,
                pair_results=pair_results,
            )
        )

        monotonicity_metrics = (
            self._monotonicity_metrics(
                case_results
            )
        )

        subgroup_metrics = {
            "by_sector": (
                self._subgroup_metrics(
                    case_results,
                    "sector_label",
                )
            ),
            "by_affectedness": (
                self._subgroup_metrics(
                    case_results,
                    "affectedness_profile",
                )
            ),
            "by_operational_profile": (
                self._subgroup_metrics(
                    case_results,
                    "operational_profile",
                )
            ),
        }

        rule_coverage = (
            self._rule_coverage(
                case_results
            )
        )

        bootstrap = (
            self._bootstrap_metrics(
                case_results=case_results,
                pair_results=pair_results,
            )
        )

        metric_view = {
            "case_exact_match_rate": (
                exact_match_metrics[
                    "case_exact_match_rate"
                ]
            ),
            "action_exact_match_rate": (
                exact_match_metrics[
                    "action_exact_match_rate"
                ]
            ),
            "priority_exact_match_rate": (
                exact_match_metrics[
                    "priority_exact_match_rate"
                ]
            ),
            "deadline_exact_match_rate": (
                exact_match_metrics[
                    "deadline_exact_match_rate"
                ]
            ),
            "invariant_pass_rate": (
                exact_match_metrics[
                    "invariant_pass_rate"
                ]
            ),
            "under_triage_count": (
                safety_metrics[
                    "under_triage_count"
                ]
            ),
            "safety_recall": (
                safety_metrics[
                    "safety_recall"
                ]
            ),
            "counterfactual_consistency_rate": (
                counterfactual_metrics[
                    "counterfactual_consistency_rate"
                ]
            ),
            "sector_disparity_count": (
                counterfactual_metrics[
                    "sector_disparity_count"
                ]
            ),
            "deadline_pair_max_gap_hours": (
                counterfactual_metrics[
                    "deadline_pair_max_gap_hours"
                ]
            ),
            "review_pair_gap_count": (
                counterfactual_metrics[
                    "review_pair_gap_count"
                ]
            ),
            "containment_pair_gap_count": (
                counterfactual_metrics[
                    "containment_pair_gap_count"
                ]
            ),
            "closure_pair_gap_count": (
                counterfactual_metrics[
                    "closure_pair_gap_count"
                ]
            ),
            "hold_precision": (
                abstention_metrics[
                    "hold_precision"
                ]
            ),
            "hold_recall": (
                abstention_metrics[
                    "hold_recall"
                ]
            ),
            "escalation_monotonicity_rate": (
                monotonicity_metrics[
                    "monotonicity_rate"
                ]
            ),
            "required_rule_coverage_rate": (
                rule_coverage[
                    "required_rule_coverage_rate"
                ]
            ),
            "bootstrap_case_pass_lower_bound": (
                bootstrap[
                    "case_exact_match_rate"
                ]["lower_bound"]
            ),
            "bootstrap_counterfactual_lower_bound": (
                bootstrap[
                    "counterfactual_consistency_rate"
                ]["lower_bound"]
            ),
            "bootstrap_safety_lower_bound": (
                bootstrap[
                    "safety_recall"
                ]["lower_bound"]
            ),
        }

        quality_gates = (
            self._evaluate_quality_gates(
                metric_view
            )
        )

        failed_release_gates = [
            gate
            for gate in quality_gates
            if (
                gate["release_blocking"]
                and not gate["passed"]
            )
        ]

        stage_gate_passed = (
            not failed_release_gates
        )

        production_blocking_reasons = []

        if not stage_gate_passed:
            production_blocking_reasons.append(
                "One or more mandatory Step 10 "
                "quality gates failed."
            )

        full_rule_coverage_required = bool(
            self.production_policy[
                "require_full_policy_rule_coverage"
            ]
        )

        if (
            full_rule_coverage_required
            and rule_coverage[
                "full_rule_coverage_rate"
            ]
            < 1.0
        ):
            production_blocking_reasons.append(
                "Full decision-policy rule coverage "
                "has not yet been demonstrated."
            )

        if self.production_policy[
            "require_real_operational_validation"
        ]:
            production_blocking_reasons.append(
                "Real operational validation has "
                "not yet been completed."
            )

        if self.production_policy[
            "require_independent_security_review"
        ]:
            production_blocking_reasons.append(
                "Independent security review has "
                "not yet been completed."
            )

        production_readiness = (
            stage_gate_passed
            and not production_blocking_reasons
        )

        return {
            "schema_version": "1.0.0",
            "report_id": (
                "AEG-EVAL-FAIRNESS-ROBUSTNESS-001"
            ),
            "source_assurance_report": {
                "relative_path": (
                    source_path
                    .relative_to(
                        PROJECT_ROOT
                    )
                    .as_posix()
                    if source_path.is_absolute()
                    and PROJECT_ROOT
                    in source_path.resolve().parents
                    else str(source_path)
                ),
                "sha256": sha256_file(
                    source_path
                ),
                "case_count": len(
                    case_results
                ),
                "pair_count": len(
                    pair_results
                ),
            },
            "evaluator": {
                "policy_id": (
                    self.metadata[
                        "policy_id"
                    ]
                ),
                "policy_version": str(
                    self.metadata[
                        "version"
                    ]
                ),
                "evaluator_version": str(
                    self.metadata[
                        "evaluator_version"
                    ]
                ),
                "policy_sha256": (
                    self.gate_policy_sha256
                ),
            },
            "decision_policy": {
                "policy_id": (
                    self.decision_policy[
                        "policy"
                    ]["policy_id"]
                ),
                "version": str(
                    self.decision_policy[
                        "policy"
                    ]["version"]
                ),
                "sha256": (
                    self.decision_policy_sha256
                ),
            },
            "summary": {
                "case_count": len(
                    case_results
                ),
                "pair_count": len(
                    pair_results
                ),
                "stage_gate_passed": (
                    stage_gate_passed
                ),
                "production_readiness": (
                    production_readiness
                ),
                "failed_quality_gate_count": (
                    len(
                        failed_release_gates
                    )
                ),
            },
            "exact_match_metrics": (
                exact_match_metrics
            ),
            "safety_metrics": (
                safety_metrics
            ),
            "abstention_metrics": (
                abstention_metrics
            ),
            "counterfactual_metrics": (
                counterfactual_metrics
            ),
            "monotonicity_metrics": (
                monotonicity_metrics
            ),
            "subgroup_metrics": (
                subgroup_metrics
            ),
            "rule_coverage": rule_coverage,
            "bootstrap": bootstrap,
            "quality_gates": quality_gates,
            "release_decision": {
                "stage_gate_status": (
                    "PASS"
                    if stage_gate_passed
                    else "FAIL"
                ),
                "production_readiness_status": (
                    "READY"
                    if production_readiness
                    else "BLOCKED"
                ),
                "blocking_reasons": (
                    production_blocking_reasons
                ),
                "scope_limitations": (
                    self.limitations
                ),
            },
            "limitations": self.limitations,
            "generated_at": (
                evaluation_time.isoformat()
            ),
        }

    def _validate_assurance_report(
        self,
        report: dict[str, Any],
    ) -> None:
        required_fields = {
            "summary",
            "case_results",
            "counterfactual_results",
        }

        missing = (
            required_fields - set(report)
        )

        if missing:
            raise FairnessEvaluationError(
                "Assurance report missing fields: "
                f"{sorted(missing)}"
            )

        if not isinstance(
            report["case_results"],
            list,
        ):
            raise FairnessEvaluationError(
                "case_results must be a list."
            )

        if not isinstance(
            report[
                "counterfactual_results"
            ],
            list,
        ):
            raise FairnessEvaluationError(
                "counterfactual_results must "
                "be a list."
            )

        if not report["case_results"]:
            raise FairnessEvaluationError(
                "Assurance report contains "
                "no policy cases."
            )

    def _exact_match_metrics(
        self,
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        count = len(cases)

        action_matches = sum(
            1
            for case in cases
            if (
                case["actual"]["action"]
                == case["expected"]["action"]
            )
        )

        priority_matches = sum(
            1
            for case in cases
            if (
                case["actual"]["priority"]
                == case["expected"]["priority"]
            )
        )

        deadline_matches = sum(
            1
            for case in cases
            if math.isclose(
                float(
                    case["actual"][
                        "deadline_hours"
                    ]
                ),
                float(
                    case["expected"][
                        "deadline_hours"
                    ]
                ),
                rel_tol=0,
                abs_tol=1e-9,
            )
        )

        review_matches = sum(
            1
            for case in cases
            if (
                case["actual"][
                    "human_review_required"
                ]
                is case["expected"][
                    "human_review_required"
                ]
            )
        )

        containment_matches = sum(
            1
            for case in cases
            if (
                case["actual"][
                    "containment_required"
                ]
                is case["expected"][
                    "containment_required"
                ]
            )
        )

        closure_matches = sum(
            1
            for case in cases
            if (
                case["actual"][
                    "prohibit_closure"
                ]
                is case["expected"][
                    "prohibit_closure"
                ]
            )
        )

        invariant_passes = sum(
            1
            for case in cases
            if case["actual"][
                "invariants_passed"
            ]
        )

        exact_cases = sum(
            1
            for case in cases
            if case["passed"]
        )

        return {
            "case_count": count,
            "exact_case_count": (
                exact_cases
            ),
            "case_exact_match_rate": (
                safe_rate(
                    exact_cases,
                    count,
                )
            ),
            "action_exact_match_rate": (
                safe_rate(
                    action_matches,
                    count,
                )
            ),
            "priority_exact_match_rate": (
                safe_rate(
                    priority_matches,
                    count,
                )
            ),
            "deadline_exact_match_rate": (
                safe_rate(
                    deadline_matches,
                    count,
                )
            ),
            "review_exact_match_rate": (
                safe_rate(
                    review_matches,
                    count,
                )
            ),
            "containment_exact_match_rate": (
                safe_rate(
                    containment_matches,
                    count,
                )
            ),
            "closure_exact_match_rate": (
                safe_rate(
                    closure_matches,
                    count,
                )
            ),
            "invariant_pass_rate": (
                safe_rate(
                    invariant_passes,
                    count,
                )
            ),
        }

    def _under_triage_reasons(
        self,
        case: dict[str, Any],
    ) -> list[str]:
        actual = case["actual"]
        expected = case["expected"]

        reasons = []

        if (
            self.action_ranks[
                actual["action"]
            ]
            < self.action_ranks[
                expected["action"]
            ]
        ):
            reasons.append(
                "ACTION_BELOW_EXPECTED_FLOOR"
            )

        if (
            self.priority_ranks[
                actual["priority"]
            ]
            < self.priority_ranks[
                expected["priority"]
            ]
        ):
            reasons.append(
                "PRIORITY_BELOW_EXPECTED_FLOOR"
            )

        if (
            float(
                actual["deadline_hours"]
            )
            > float(
                expected["deadline_hours"]
            )
            + 1e-9
        ):
            reasons.append(
                "DEADLINE_LONGER_THAN_EXPECTED"
            )

        boolean_requirements = (
            (
                "human_review_required",
                "REQUIRED_REVIEW_MISSING",
            ),
            (
                "containment_required",
                "REQUIRED_CONTAINMENT_MISSING",
            ),
            (
                "prohibit_closure",
                "REQUIRED_CLOSURE_BLOCK_MISSING",
            ),
        )

        for field_name, reason_code in (
            boolean_requirements
        ):
            if (
                expected[field_name]
                and not actual[field_name]
            ):
                reasons.append(
                    reason_code
                )

        return reasons

    def _over_triage_reasons(
        self,
        case: dict[str, Any],
    ) -> list[str]:
        actual = case["actual"]
        expected = case["expected"]

        reasons = []

        if (
            self.action_ranks[
                actual["action"]
            ]
            > self.action_ranks[
                expected["action"]
            ]
        ):
            reasons.append(
                "ACTION_ABOVE_EXPECTED"
            )

        if (
            self.priority_ranks[
                actual["priority"]
            ]
            > self.priority_ranks[
                expected["priority"]
            ]
        ):
            reasons.append(
                "PRIORITY_ABOVE_EXPECTED"
            )

        if (
            float(
                actual["deadline_hours"]
            )
            + 1e-9
            < float(
                expected["deadline_hours"]
            )
        ):
            reasons.append(
                "DEADLINE_SHORTER_THAN_EXPECTED"
            )

        return reasons

    def _safety_metrics(
        self,
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        safety_cases = [
            case
            for case in cases
            if (
                case["expected"]["action"]
                in {
                    "ACT",
                    "ATTEND",
                    "HOLD",
                }
                or self.priority_ranks[
                    case["expected"][
                        "priority"
                    ]
                ]
                >= self.priority_ranks[
                    "HIGH"
                ]
            )
        ]

        under_triage_cases = []

        over_triage_cases = []

        for case in cases:
            under_reasons = (
                self._under_triage_reasons(
                    case
                )
            )

            over_reasons = (
                self._over_triage_reasons(
                    case
                )
            )

            if under_reasons:
                under_triage_cases.append(
                    {
                        "case_id": (
                            case["case_id"]
                        ),
                        "reasons": (
                            under_reasons
                        ),
                    }
                )

            if over_reasons:
                over_triage_cases.append(
                    {
                        "case_id": (
                            case["case_id"]
                        ),
                        "reasons": (
                            over_reasons
                        ),
                    }
                )

        safety_under_triage_count = sum(
            1
            for case in safety_cases
            if self._under_triage_reasons(
                case
            )
        )

        return {
            "safety_relevant_case_count": (
                len(safety_cases)
            ),
            "under_triage_count": (
                len(
                    under_triage_cases
                )
            ),
            "over_triage_count": (
                len(
                    over_triage_cases
                )
            ),
            "safety_under_triage_count": (
                safety_under_triage_count
            ),
            "safety_recall": (
                1.0
                - safe_rate(
                    safety_under_triage_count,
                    len(safety_cases),
                )
            ),
            "under_triage_cases": (
                under_triage_cases
            ),
            "over_triage_cases": (
                over_triage_cases
            ),
        }

    def _abstention_metrics(
        self,
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        expected_hold = {
            case["case_id"]
            for case in cases
            if (
                case["expected"]["action"]
                == "HOLD"
            )
        }

        actual_hold = {
            case["case_id"]
            for case in cases
            if (
                case["actual"]["action"]
                == "HOLD"
            )
        }

        true_positive = len(
            expected_hold & actual_hold
        )

        false_positive = len(
            actual_hold - expected_hold
        )

        false_negative = len(
            expected_hold - actual_hold
        )

        precision = safe_rate(
            true_positive,
            true_positive
            + false_positive,
        )

        recall = safe_rate(
            true_positive,
            true_positive
            + false_negative,
        )

        f1 = (
            0.0
            if precision + recall == 0
            else (
                2
                * precision
                * recall
                / (
                    precision
                    + recall
                )
            )
        )

        return {
            "expected_hold_count": (
                len(expected_hold)
            ),
            "actual_hold_count": (
                len(actual_hold)
            ),
            "true_hold_count": (
                true_positive
            ),
            "false_hold_count": (
                false_positive
            ),
            "missed_hold_count": (
                false_negative
            ),
            "hold_precision": precision,
            "hold_recall": recall,
            "hold_f1": f1,
        }

    def _counterfactual_metrics(
        self,
        case_results: list[
            dict[str, Any]
        ],
        pair_results: list[
            dict[str, Any]
        ],
    ) -> dict[str, Any]:
        grouped: dict[
            str,
            list[dict[str, Any]],
        ] = defaultdict(list)

        for case in case_results:
            grouped[
                case["pair_id"]
            ].append(case)

        deadline_gaps = []
        review_gap_count = 0
        containment_gap_count = 0
        closure_gap_count = 0
        action_gap_count = 0
        priority_gap_count = 0

        for pair_id, pair in grouped.items():
            if len(pair) != 2:
                raise FairnessEvaluationError(
                    f"Counterfactual pair "
                    f"{pair_id} does not contain "
                    "exactly two cases."
                )

            first = pair[0]["actual"]
            second = pair[1]["actual"]

            deadline_gaps.append(
                abs(
                    float(
                        first[
                            "deadline_hours"
                        ]
                    )
                    - float(
                        second[
                            "deadline_hours"
                        ]
                    )
                )
            )

            if (
                first["action"]
                != second["action"]
            ):
                action_gap_count += 1

            if (
                first["priority"]
                != second["priority"]
            ):
                priority_gap_count += 1

            if (
                first[
                    "human_review_required"
                ]
                is not second[
                    "human_review_required"
                ]
            ):
                review_gap_count += 1

            if (
                first[
                    "containment_required"
                ]
                is not second[
                    "containment_required"
                ]
            ):
                containment_gap_count += 1

            if (
                first[
                    "prohibit_closure"
                ]
                is not second[
                    "prohibit_closure"
                ]
            ):
                closure_gap_count += 1

        passed_pairs = sum(
            1
            for pair in pair_results
            if pair["passed"]
        )

        return {
            "pair_count": (
                len(pair_results)
            ),
            "passed_pair_count": (
                passed_pairs
            ),
            "counterfactual_consistency_rate": (
                safe_rate(
                    passed_pairs,
                    len(pair_results),
                )
            ),
            "sector_disparity_count": (
                len(pair_results)
                - passed_pairs
            ),
            "action_pair_gap_count": (
                action_gap_count
            ),
            "priority_pair_gap_count": (
                priority_gap_count
            ),
            "review_pair_gap_count": (
                review_gap_count
            ),
            "containment_pair_gap_count": (
                containment_gap_count
            ),
            "closure_pair_gap_count": (
                closure_gap_count
            ),
            "deadline_pair_mean_gap_hours": (
                sum(deadline_gaps)
                / len(deadline_gaps)
                if deadline_gaps
                else 0.0
            ),
            "deadline_pair_max_gap_hours": (
                max(deadline_gaps)
                if deadline_gaps
                else 0.0
            ),
        }

    def _monotonicity_metrics(
        self,
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        grouped: dict[
            tuple[str, str],
            list[dict[str, Any]],
        ] = defaultdict(list)

        for case in cases:
            grouped[
                (
                    case["sector_label"],
                    case[
                        "affectedness_profile"
                    ],
                )
            ].append(case)

        comparisons = []
        violation_count = 0

        for (
            sector,
            affectedness,
        ), group in grouped.items():
            baseline_candidates = [
                case
                for case in group
                if (
                    case[
                        "operational_profile"
                    ]
                    == "baseline"
                )
            ]

            if len(
                baseline_candidates
            ) != 1:
                raise FairnessEvaluationError(
                    "Expected exactly one baseline "
                    f"for {sector}/{affectedness}."
                )

            baseline = baseline_candidates[0]
            baseline_actual = baseline[
                "actual"
            ]

            for case in group:
                if (
                    case[
                        "operational_profile"
                    ]
                    == "baseline"
                ):
                    continue

                actual = case["actual"]

                violations = []

                if (
                    self.action_ranks[
                        actual["action"]
                    ]
                    < self.action_ranks[
                        baseline_actual[
                            "action"
                        ]
                    ]
                ):
                    violations.append(
                        "ACTION_DEESCALATED"
                    )

                if (
                    self.priority_ranks[
                        actual["priority"]
                    ]
                    < self.priority_ranks[
                        baseline_actual[
                            "priority"
                        ]
                    ]
                ):
                    violations.append(
                        "PRIORITY_DEESCALATED"
                    )

                if (
                    float(
                        actual[
                            "deadline_hours"
                        ]
                    )
                    > float(
                        baseline_actual[
                            "deadline_hours"
                        ]
                    )
                    + 1e-9
                ):
                    violations.append(
                        "DEADLINE_LENGTHENED"
                    )

                for field_name in (
                    "human_review_required",
                    "containment_required",
                    "prohibit_closure",
                ):
                    if (
                        baseline_actual[
                            field_name
                        ]
                        and not actual[
                            field_name
                        ]
                    ):
                        violations.append(
                            f"{field_name.upper()}"
                            "_REMOVED"
                        )

                passed = not violations

                if not passed:
                    violation_count += 1

                comparisons.append(
                    {
                        "sector_label": sector,
                        "affectedness_profile": (
                            affectedness
                        ),
                        "operational_profile": (
                            case[
                                "operational_profile"
                            ]
                        ),
                        "baseline_case_id": (
                            baseline[
                                "case_id"
                            ]
                        ),
                        "comparison_case_id": (
                            case["case_id"]
                        ),
                        "passed": passed,
                        "violations": (
                            violations
                        ),
                    }
                )

        passed_count = (
            len(comparisons)
            - violation_count
        )

        return {
            "comparison_count": (
                len(comparisons)
            ),
            "passed_comparison_count": (
                passed_count
            ),
            "violation_count": (
                violation_count
            ),
            "monotonicity_rate": (
                safe_rate(
                    passed_count,
                    len(comparisons),
                )
            ),
            "violations": [
                comparison
                for comparison in comparisons
                if not comparison["passed"]
            ],
        }

    def _subgroup_metrics(
        self,
        cases: list[dict[str, Any]],
        group_field: str,
    ) -> dict[str, Any]:
        groups: dict[
            str,
            list[dict[str, Any]],
        ] = defaultdict(list)

        for case in cases:
            groups[
                str(case[group_field])
            ].append(case)

        output = {}

        for group_name, group_cases in (
            sorted(groups.items())
        ):
            passed_count = sum(
                1
                for case in group_cases
                if case["passed"]
            )

            under_triage_count = sum(
                1
                for case in group_cases
                if self._under_triage_reasons(
                    case
                )
            )

            output[group_name] = {
                "case_count": (
                    len(group_cases)
                ),
                "passed_case_count": (
                    passed_count
                ),
                "exact_match_rate": (
                    safe_rate(
                        passed_count,
                        len(group_cases),
                    )
                ),
                "under_triage_count": (
                    under_triage_count
                ),
                "under_triage_rate": (
                    safe_rate(
                        under_triage_count,
                        len(group_cases),
                    )
                ),
                "mean_deadline_hours": (
                    sum(
                        float(
                            case["actual"][
                                "deadline_hours"
                            ]
                        )
                        for case
                        in group_cases
                    )
                    / len(group_cases)
                ),
                "action_distribution": dict(
                    sorted(
                        Counter(
                            case["actual"][
                                "action"
                            ]
                            for case
                            in group_cases
                        ).items()
                    )
                ),
                "priority_distribution": dict(
                    sorted(
                        Counter(
                            case["actual"][
                                "priority"
                            ]
                            for case
                            in group_cases
                        ).items()
                    )
                ),
            }

        return output

    def _rule_coverage(
        self,
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        observed_rule_counts = Counter(
            rule_id
            for case in cases
            for rule_id in case[
                "matched_rule_ids"
            ]
            if rule_id
            in self.all_policy_rule_ids
        )

        observed_rules = set(
            observed_rule_counts
        )

        covered_required_rules = (
            self.required_rule_ids
            & observed_rules
        )

        missing_required_rules = (
            self.required_rule_ids
            - observed_rules
        )

        uncovered_policy_rules = (
            self.all_policy_rule_ids
            - observed_rules
        )

        return {
            "policy_rule_count": (
                len(
                    self.all_policy_rule_ids
                )
            ),
            "covered_policy_rule_count": (
                len(observed_rules)
            ),
            "full_rule_coverage_rate": (
                safe_rate(
                    len(observed_rules),
                    len(
                        self.all_policy_rule_ids
                    ),
                )
            ),
            "required_rule_count": (
                len(
                    self.required_rule_ids
                )
            ),
            "covered_required_rule_count": (
                len(
                    covered_required_rules
                )
            ),
            "required_rule_coverage_rate": (
                safe_rate(
                    len(
                        covered_required_rules
                    ),
                    len(
                        self.required_rule_ids
                    ),
                )
            ),
            "covered_required_rules": sorted(
                covered_required_rules
            ),
            "missing_required_rules": sorted(
                missing_required_rules
            ),
            "uncovered_policy_rules": sorted(
                uncovered_policy_rules
            ),
            "rule_trigger_counts": dict(
                sorted(
                    observed_rule_counts.items()
                )
            ),
        }

    def _bootstrap_metrics(
        self,
        case_results: list[
            dict[str, Any]
        ],
        pair_results: list[
            dict[str, Any]
        ],
    ) -> dict[str, Any]:
        cases_by_pair: dict[
            str,
            list[dict[str, Any]],
        ] = defaultdict(list)

        for case in case_results:
            cases_by_pair[
                case["pair_id"]
            ].append(case)

        pair_result_by_id = {
            pair["pair_id"]: pair
            for pair in pair_results
        }

        pair_ids = sorted(
            cases_by_pair
        )

        if not pair_ids:
            raise FairnessEvaluationError(
                "No counterfactual pairs "
                "available for bootstrap."
            )

        iterations = int(
            self.bootstrap_policy[
                "iterations"
            ]
        )

        confidence_level = float(
            self.bootstrap_policy[
                "confidence_level"
            ]
        )

        random_seed = int(
            self.bootstrap_policy[
                "random_seed"
            ]
        )

        rng = random.Random(
            random_seed
        )

        case_rates: list[float] = []
        pair_rates: list[float] = []
        safety_rates: list[float] = []

        for _ in range(iterations):
            sampled_pair_ids = [
                rng.choice(pair_ids)
                for _ in pair_ids
            ]

            sampled_cases = [
                case
                for pair_id
                in sampled_pair_ids
                for case
                in cases_by_pair[
                    pair_id
                ]
            ]

            case_rates.append(
                safe_rate(
                    sum(
                        1
                        for case
                        in sampled_cases
                        if case["passed"]
                    ),
                    len(sampled_cases),
                )
            )

            pair_rates.append(
                safe_rate(
                    sum(
                        1
                        for pair_id
                        in sampled_pair_ids
                        if pair_result_by_id[
                            pair_id
                        ]["passed"]
                    ),
                    len(
                        sampled_pair_ids
                    ),
                )
            )

            sampled_safety = (
                self._safety_metrics(
                    sampled_cases
                )
            )

            safety_rates.append(
                sampled_safety[
                    "safety_recall"
                ]
            )

        alpha = (
            1.0
            - confidence_level
        )

        lower_probability = (
            alpha / 2.0
        )

        upper_probability = (
            1.0
            - alpha / 2.0
        )

        def summarize(
            values: list[float],
        ) -> dict[str, float]:
            return {
                "mean": (
                    sum(values)
                    / len(values)
                ),
                "lower_bound": (
                    percentile(
                        values,
                        lower_probability,
                    )
                ),
                "upper_bound": (
                    percentile(
                        values,
                        upper_probability,
                    )
                ),
            }

        return {
            "iterations": iterations,
            "confidence_level": (
                confidence_level
            ),
            "random_seed": random_seed,
            "sampling_unit": (
                "counterfactual_pair"
            ),
            "case_exact_match_rate": (
                summarize(
                    case_rates
                )
            ),
            "counterfactual_consistency_rate": (
                summarize(
                    pair_rates
                )
            ),
            "safety_recall": (
                summarize(
                    safety_rates
                )
            ),
        }

    def _evaluate_quality_gates(
        self,
        metrics: dict[str, Any],
    ) -> list[dict[str, Any]]:
        specifications = [
            (
                "GATE-CASE-EXACT-001",
                "case_exact_match_rate",
                "gte",
                self.thresholds[
                    "case_exact_match_rate_minimum"
                ],
            ),
            (
                "GATE-ACTION-EXACT-001",
                "action_exact_match_rate",
                "gte",
                self.thresholds[
                    "action_exact_match_rate_minimum"
                ],
            ),
            (
                "GATE-PRIORITY-EXACT-001",
                "priority_exact_match_rate",
                "gte",
                self.thresholds[
                    "priority_exact_match_rate_minimum"
                ],
            ),
            (
                "GATE-DEADLINE-EXACT-001",
                "deadline_exact_match_rate",
                "gte",
                self.thresholds[
                    "deadline_exact_match_rate_minimum"
                ],
            ),
            (
                "GATE-INVARIANTS-001",
                "invariant_pass_rate",
                "gte",
                self.thresholds[
                    "invariant_pass_rate_minimum"
                ],
            ),
            (
                "GATE-UNDER-TRIAGE-001",
                "under_triage_count",
                "lte",
                self.thresholds[
                    "under_triage_count_maximum"
                ],
            ),
            (
                "GATE-SAFETY-RECALL-001",
                "safety_recall",
                "gte",
                self.thresholds[
                    "safety_recall_minimum"
                ],
            ),
            (
                "GATE-COUNTERFACTUAL-001",
                "counterfactual_consistency_rate",
                "gte",
                self.thresholds[
                    "counterfactual_consistency_rate_minimum"
                ],
            ),
            (
                "GATE-SECTOR-DISPARITY-001",
                "sector_disparity_count",
                "lte",
                self.thresholds[
                    "sector_disparity_count_maximum"
                ],
            ),
            (
                "GATE-DEADLINE-PARITY-001",
                "deadline_pair_max_gap_hours",
                "lte",
                self.thresholds[
                    "deadline_pair_max_gap_hours_maximum"
                ],
            ),
            (
                "GATE-REVIEW-PARITY-001",
                "review_pair_gap_count",
                "lte",
                self.thresholds[
                    "review_pair_gap_count_maximum"
                ],
            ),
            (
                "GATE-CONTAINMENT-PARITY-001",
                "containment_pair_gap_count",
                "lte",
                self.thresholds[
                    "containment_pair_gap_count_maximum"
                ],
            ),
            (
                "GATE-CLOSURE-PARITY-001",
                "closure_pair_gap_count",
                "lte",
                self.thresholds[
                    "closure_pair_gap_count_maximum"
                ],
            ),
            (
                "GATE-HOLD-PRECISION-001",
                "hold_precision",
                "gte",
                self.thresholds[
                    "hold_precision_minimum"
                ],
            ),
            (
                "GATE-HOLD-RECALL-001",
                "hold_recall",
                "gte",
                self.thresholds[
                    "hold_recall_minimum"
                ],
            ),
            (
                "GATE-MONOTONICITY-001",
                "escalation_monotonicity_rate",
                "gte",
                self.thresholds[
                    "escalation_monotonicity_rate_minimum"
                ],
            ),
            (
                "GATE-REQUIRED-RULE-COVERAGE-001",
                "required_rule_coverage_rate",
                "gte",
                self.thresholds[
                    "required_rule_coverage_rate_minimum"
                ],
            ),
            (
                "GATE-BOOTSTRAP-CASE-001",
                "bootstrap_case_pass_lower_bound",
                "gte",
                self.thresholds[
                    "bootstrap_case_pass_lower_bound_minimum"
                ],
            ),
            (
                "GATE-BOOTSTRAP-PAIR-001",
                "bootstrap_counterfactual_lower_bound",
                "gte",
                self.thresholds[
                    "bootstrap_counterfactual_lower_bound_minimum"
                ],
            ),
            (
                "GATE-BOOTSTRAP-SAFETY-001",
                "bootstrap_safety_lower_bound",
                "gte",
                self.thresholds[
                    "bootstrap_safety_lower_bound_minimum"
                ],
            ),
        ]

        results = []

        for (
            gate_id,
            metric_name,
            operator,
            threshold,
        ) in specifications:
            observed = metrics[
                metric_name
            ]

            if operator == "gte":
                passed = (
                    float(observed)
                    >= float(threshold)
                )

            elif operator == "lte":
                passed = (
                    float(observed)
                    <= float(threshold)
                )

            elif operator == "eq":
                passed = (
                    observed == threshold
                )

            else:
                raise FairnessEvaluationError(
                    f"Unsupported gate operator: "
                    f"{operator}"
                )

            results.append(
                {
                    "gate_id": gate_id,
                    "metric": metric_name,
                    "operator": operator,
                    "threshold": threshold,
                    "observed": observed,
                    "passed": passed,
                    "release_blocking": True,
                }
            )

        return results


def write_json(
    path: Path | str,
    payload: dict[str, Any],
) -> None:
    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")


def write_subgroup_csv(
    path: Path | str,
    subgroup_metrics: dict[str, Any],
) -> None:
    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "group_dimension",
        "group_name",
        "case_count",
        "passed_case_count",
        "exact_match_rate",
        "under_triage_count",
        "under_triage_rate",
        "mean_deadline_hours",
        "action_distribution",
        "priority_distribution",
    ]

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for (
            group_dimension,
            groups,
        ) in subgroup_metrics.items():
            for (
                group_name,
                metrics,
            ) in groups.items():
                writer.writerow(
                    {
                        "group_dimension": (
                            group_dimension
                        ),
                        "group_name": (
                            group_name
                        ),
                        "case_count": (
                            metrics[
                                "case_count"
                            ]
                        ),
                        "passed_case_count": (
                            metrics[
                                "passed_case_count"
                            ]
                        ),
                        "exact_match_rate": (
                            metrics[
                                "exact_match_rate"
                            ]
                        ),
                        "under_triage_count": (
                            metrics[
                                "under_triage_count"
                            ]
                        ),
                        "under_triage_rate": (
                            metrics[
                                "under_triage_rate"
                            ]
                        ),
                        "mean_deadline_hours": (
                            metrics[
                                "mean_deadline_hours"
                            ]
                        ),
                        "action_distribution": (
                            json.dumps(
                                metrics[
                                    "action_distribution"
                                ],
                                sort_keys=True,
                            )
                        ),
                        "priority_distribution": (
                            json.dumps(
                                metrics[
                                    "priority_distribution"
                                ],
                                sort_keys=True,
                            )
                        ),
                    }
                )

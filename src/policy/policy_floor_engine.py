from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "federal_base_policy_v1.yaml"
)


IMPACT_RANKS = {
    "not_applicable": -2,
    "unknown": -1,
    "none": 0,
    "low": 1,
    "moderate": 2,
    "high": 3,
    "severe": 4,
    "catastrophic": 5,
}


VALID_EFFECTS = {
    "set_action",
    "set_priority_floor",
    "set_deadline",
    "require_human_review",
    "require_containment",
    "prohibit_closure",
}


@dataclass(frozen=True)
class PolicyRuleMatch:
    rule_id: str
    rule_version: str
    description: str
    action_floor: str
    priority_floor: str
    deadline_hours: float
    human_review_required: bool
    containment_required: bool
    prohibit_closure: bool
    non_overridable: bool
    supporting_evidence_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "description": self.description,
            "action_floor": self.action_floor,
            "priority_floor": self.priority_floor,
            "deadline_hours": self.deadline_hours,
            "human_review_required": (
                self.human_review_required
            ),
            "containment_required": (
                self.containment_required
            ),
            "prohibit_closure": self.prohibit_closure,
            "non_overridable": self.non_overridable,
            "supporting_evidence_ids": list(
                self.supporting_evidence_ids
            ),
        }


@dataclass(frozen=True)
class PolicyInvariantResult:
    code: str
    passed: bool
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "passed": self.passed,
            "message": self.message,
        }


@dataclass
class PolicyDecisionAssessment:
    assessment_id: str
    policy_id: str
    policy_version: str
    engine_version: str
    policy_sha256: str
    action: str
    minimum_priority: str
    response_deadline_hours: float
    response_due_at: str
    human_review_required: bool
    containment_required: bool
    prohibit_closure: bool
    matched_rules: list[PolicyRuleMatch]
    invariant_results: list[PolicyInvariantResult]
    context_snapshot: dict[str, Any]
    evaluated_at: str
    status: str = "completed"
    execution_mode: str = "automated_policy"

    @property
    def invariants_passed(self) -> bool:
        return all(
            result.passed
            for result in self.invariant_results
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "status": self.status,
            "execution_mode": self.execution_mode,
            "policy": {
                "policy_id": self.policy_id,
                "version": self.policy_version,
                "engine_version": self.engine_version,
                "sha256": self.policy_sha256,
            },
            "decision": {
                "action": self.action,
                "minimum_priority": self.minimum_priority,
                "response_deadline_hours": (
                    self.response_deadline_hours
                ),
                "response_due_at": self.response_due_at,
                "human_review_required": (
                    self.human_review_required
                ),
                "containment_required": (
                    self.containment_required
                ),
                "prohibit_closure": (
                    self.prohibit_closure
                ),
            },
            "matched_rules": [
                rule.to_dict()
                for rule in self.matched_rules
            ],
            "invariant_results": [
                result.to_dict()
                for result in self.invariant_results
            ],
            "invariants_passed": self.invariants_passed,
            "context_snapshot": self.context_snapshot,
            "evaluated_at": self.evaluated_at,
        }

    def to_decision_record_block(self) -> dict[str, Any]:
        triggered_rules: list[dict[str, Any]] = []

        for rule in self.matched_rules:
            effects: list[tuple[str, str]] = [
                (
                    "ACTION",
                    "set_action",
                ),
                (
                    "PRIORITY",
                    "set_priority_floor",
                ),
                (
                    "DEADLINE",
                    "set_deadline",
                ),
            ]

            if rule.human_review_required:
                effects.append(
                    (
                        "REVIEW",
                        "require_human_review",
                    )
                )

            if rule.containment_required:
                effects.append(
                    (
                        "CONTAINMENT",
                        "require_containment",
                    )
                )

            if rule.prohibit_closure:
                effects.append(
                    (
                        "NO-CLOSURE",
                        "prohibit_closure",
                    )
                )

            for suffix, effect in effects:
                if effect not in VALID_EFFECTS:
                    raise ValueError(
                        f"Unsupported policy effect: {effect}"
                    )

                triggered_rules.append(
                    {
                        "rule_id": (
                            f"{rule.rule_id}-{suffix}"
                        ),
                        "rule_version": (
                            rule.rule_version
                        ),
                        "description": (
                            f"{rule.description} "
                            f"Effect: {effect}."
                        ),
                        "effect": effect,
                        "non_overridable": (
                            rule.non_overridable
                        ),
                        "supporting_evidence_ids": list(
                            rule.supporting_evidence_ids
                        ),
                    }
                )

        return {
            "status": self.status,
            "execution_mode": self.execution_mode,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "action": self.action,
            "minimum_priority": self.minimum_priority,
            "response_deadline_hours": (
                self.response_deadline_hours
            ),
            "response_due_at": self.response_due_at,
            "triggered_rules": triggered_rules,
            "evaluated_at": self.evaluated_at,
        }


class PolicyConfigurationError(ValueError):
    """Raised when the decision-policy file is unsafe or invalid."""


class PolicyFloorEngine:
    """
    Monotonic vulnerability policy engine.

    Every rule provides floors. No rule can reduce action, priority or
    urgency already established by another rule.
    """

    def __init__(
        self,
        policy_path: Path | str = DEFAULT_POLICY_PATH,
    ) -> None:
        self.policy_path = Path(policy_path)

        if not self.policy_path.exists():
            raise FileNotFoundError(
                f"Decision policy not found: "
                f"{self.policy_path}"
            )

        raw_policy = self.policy_path.read_bytes()

        self.policy_sha256 = hashlib.sha256(
            raw_policy
        ).hexdigest()

        self.policy = yaml.safe_load(
            raw_policy.decode("utf-8")
        )

        if not isinstance(self.policy, dict):
            raise PolicyConfigurationError(
                "Decision policy must be a YAML object."
            )

        self._validate_policy()

        self.metadata = self.policy["policy"]
        self.action_ranks = {
            str(key): int(value)
            for key, value
            in self.policy["action_ranks"].items()
        }

        self.priority_ranks = {
            str(key): int(value)
            for key, value
            in self.policy["priority_ranks"].items()
        }

        self.default_decision = self.policy[
            "default_decision"
        ]

        self.rules = self.policy["rules"]
        self.allowed_context_fields = set(
            self.policy["allowed_context_fields"]
        )

        self.allowed_operators = set(
            self.policy["allowed_operators"]
        )

        self.allowed_evidence_sources = set(
            self.policy[
                "allowed_evidence_sources"
            ]
        )

    def _validate_policy(self) -> None:
        required_sections = {
            "policy",
            "action_ranks",
            "priority_ranks",
            "default_decision",
            "allowed_context_fields",
            "forbidden_field_fragments",
            "allowed_operators",
            "allowed_evidence_sources",
            "rules",
        }

        missing_sections = (
            required_sections - set(self.policy)
        )

        if missing_sections:
            raise PolicyConfigurationError(
                f"Policy missing sections: "
                f"{sorted(missing_sections)}"
            )

        action_ranks = self.policy["action_ranks"]
        priority_ranks = self.policy["priority_ranks"]

        required_actions = {
            "TRACK",
            "TRACK_STAR",
            "ATTEND",
            "ACT",
            "HOLD",
        }

        required_priorities = {
            "INFORMATIONAL",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "EMERGENCY",
        }

        if set(action_ranks) != required_actions:
            raise PolicyConfigurationError(
                "Action ranks must contain exactly "
                f"{sorted(required_actions)}."
            )

        if set(priority_ranks) != required_priorities:
            raise PolicyConfigurationError(
                "Priority ranks must contain exactly "
                f"{sorted(required_priorities)}."
            )

        if len(set(action_ranks.values())) != len(
            action_ranks
        ):
            raise PolicyConfigurationError(
                "Action rank values must be unique."
            )

        if len(set(priority_ranks.values())) != len(
            priority_ranks
        ):
            raise PolicyConfigurationError(
                "Priority rank values must be unique."
            )

        allowed_fields = set(
            self.policy["allowed_context_fields"]
        )

        allowed_operators = set(
            self.policy["allowed_operators"]
        )

        allowed_sources = set(
            self.policy["allowed_evidence_sources"]
        )

        forbidden_fragments = [
            str(fragment).casefold()
            for fragment in self.policy[
                "forbidden_field_fragments"
            ]
        ]

        default = self.policy["default_decision"]

        if default["action"] not in action_ranks:
            raise PolicyConfigurationError(
                "Default action is not ranked."
            )

        if default["priority"] not in priority_ranks:
            raise PolicyConfigurationError(
                "Default priority is not ranked."
            )

        if float(default["deadline_hours"]) < 0:
            raise PolicyConfigurationError(
                "Default deadline cannot be negative."
            )

        seen_rule_ids: set[str] = set()

        for rule in self.policy["rules"]:
            rule_id = str(rule.get("rule_id", ""))

            if not rule_id:
                raise PolicyConfigurationError(
                    "Every rule requires a rule_id."
                )

            if rule_id in seen_rule_ids:
                raise PolicyConfigurationError(
                    f"Duplicate rule ID: {rule_id}"
                )

            seen_rule_ids.add(rule_id)

            conditions = (
                rule.get("when", {}).get("all", [])
            )

            if not isinstance(conditions, list):
                raise PolicyConfigurationError(
                    f"{rule_id} conditions must be a list."
                )

            for condition in conditions:
                field_name = str(
                    condition.get("field", "")
                )

                operator = str(
                    condition.get("operator", "")
                )

                if field_name not in allowed_fields:
                    raise PolicyConfigurationError(
                        f"{rule_id} uses unauthorized "
                        f"context field {field_name!r}."
                    )

                lowered_field = field_name.casefold()

                if any(
                    fragment in lowered_field
                    for fragment in forbidden_fragments
                ):
                    raise PolicyConfigurationError(
                        f"{rule_id} illegally uses sector "
                        f"or label field {field_name!r}."
                    )

                if operator not in allowed_operators:
                    raise PolicyConfigurationError(
                        f"{rule_id} uses unsupported "
                        f"operator {operator!r}."
                    )

            setting = rule.get("set", {})

            action_floor = setting.get(
                "action_floor"
            )

            priority_floor = setting.get(
                "priority_floor"
            )

            if action_floor not in action_ranks:
                raise PolicyConfigurationError(
                    f"{rule_id} contains unranked "
                    f"action {action_floor!r}."
                )

            if priority_floor not in priority_ranks:
                raise PolicyConfigurationError(
                    f"{rule_id} contains unranked "
                    f"priority {priority_floor!r}."
                )

            deadline = setting.get(
                "deadline_hours"
            )

            if (
                not isinstance(deadline, (int, float))
                or isinstance(deadline, bool)
                or not math.isfinite(float(deadline))
                or float(deadline) < 0
            ):
                raise PolicyConfigurationError(
                    f"{rule_id} has invalid deadline."
                )

            evidence_sources = set(
                rule.get("evidence_sources", [])
            )

            invalid_sources = (
                evidence_sources - allowed_sources
            )

            if invalid_sources:
                raise PolicyConfigurationError(
                    f"{rule_id} uses unsupported evidence "
                    f"sources: {sorted(invalid_sources)}"
                )

    def evaluate(
        self,
        asset_context: dict[str, Any],
        intelligence_record: dict[str, Any],
        component_instance: dict[str, Any],
        affectedness_assessment: Any,
        evidence_trust: Any,
        evaluated_at: datetime | None = None,
    ) -> PolicyDecisionAssessment:
        evaluation_time = (
            evaluated_at
            or datetime.now(timezone.utc)
        )

        context, source_map = self._build_context(
            asset_context=asset_context,
            intelligence_record=intelligence_record,
            component_instance=component_instance,
            affectedness_assessment=(
                affectedness_assessment
            ),
            evidence_trust=evidence_trust,
        )

        matched_rules: list[PolicyRuleMatch] = []

        for rule in self.rules:
            if self._rule_matches(rule, context):
                supporting_ids = (
                    self._resolve_evidence_sources(
                        rule.get(
                            "evidence_sources",
                            [],
                        ),
                        source_map,
                    )
                )

                setting = rule["set"]

                matched_rules.append(
                    PolicyRuleMatch(
                        rule_id=rule["rule_id"],
                        rule_version=str(
                            rule["version"]
                        ),
                        description=str(
                            rule["description"]
                        ).strip(),
                        action_floor=setting[
                            "action_floor"
                        ],
                        priority_floor=setting[
                            "priority_floor"
                        ],
                        deadline_hours=float(
                            setting[
                                "deadline_hours"
                            ]
                        ),
                        human_review_required=bool(
                            setting[
                                "human_review_required"
                            ]
                        ),
                        containment_required=bool(
                            setting[
                                "containment_required"
                            ]
                        ),
                        prohibit_closure=bool(
                            setting[
                                "prohibit_closure"
                            ]
                        ),
                        non_overridable=bool(
                            rule["non_overridable"]
                        ),
                        supporting_evidence_ids=tuple(
                            supporting_ids
                        ),
                    )
                )

        action = str(
            self.default_decision["action"]
        )

        priority = str(
            self.default_decision["priority"]
        )

        deadline_hours = float(
            self.default_decision[
                "deadline_hours"
            ]
        )

        human_review_required = bool(
            self.default_decision[
                "human_review_required"
            ]
        )

        containment_required = bool(
            self.default_decision[
                "containment_required"
            ]
        )

        prohibit_closure = bool(
            self.default_decision[
                "prohibit_closure"
            ]
        )

        for rule in matched_rules:
            action = self._higher_action(
                action,
                rule.action_floor,
            )

            priority = self._higher_priority(
                priority,
                rule.priority_floor,
            )

            deadline_hours = min(
                deadline_hours,
                rule.deadline_hours,
            )

            human_review_required = (
                human_review_required
                or rule.human_review_required
            )

            containment_required = (
                containment_required
                or rule.containment_required
            )

            prohibit_closure = (
                prohibit_closure
                or rule.prohibit_closure
            )

        invariants = self._evaluate_invariants(
            context=context,
            action=action,
            priority=priority,
            human_review_required=(
                human_review_required
            ),
            matched_rules=matched_rules,
        )

        failed_invariants = [
            invariant
            for invariant in invariants
            if not invariant.passed
        ]

        if failed_invariants:
            fail_safe_rule = PolicyRuleMatch(
                rule_id="RULE-INVARIANT-FAILSAFE-001",
                rule_version="1.0.0",
                description=(
                    "A policy invariant failed. The engine "
                    "entered fail-safe HOLD."
                ),
                action_floor="HOLD",
                priority_floor="HIGH",
                deadline_hours=4.0,
                human_review_required=True,
                containment_required=False,
                prohibit_closure=True,
                non_overridable=True,
                supporting_evidence_ids=tuple(
                    source_map["affectedness"]
                    + source_map["component"]
                ),
            )

            matched_rules.append(fail_safe_rule)

            action = self._higher_action(
                action,
                "HOLD",
            )

            priority = self._higher_priority(
                priority,
                "HIGH",
            )

            deadline_hours = min(
                deadline_hours,
                4.0,
            )

            human_review_required = True
            prohibit_closure = True

        response_due_at = (
            evaluation_time
            + timedelta(hours=deadline_hours)
        ).isoformat()

        component_id = str(
            component_instance.get(
                "component_id",
                "UNKNOWN",
            )
        )

        vulnerability_id = str(
            intelligence_record.get(
                "canonical_id",
                "UNKNOWN",
            )
        )

        assessment_id = (
            f"AEG-POL-{component_id}-"
            f"{vulnerability_id}"
        )

        return PolicyDecisionAssessment(
            assessment_id=assessment_id,
            policy_id=self.metadata["policy_id"],
            policy_version=str(
                self.metadata["version"]
            ),
            engine_version=str(
                self.metadata["engine_version"]
            ),
            policy_sha256=self.policy_sha256,
            action=action,
            minimum_priority=priority,
            response_deadline_hours=(
                deadline_hours
            ),
            response_due_at=response_due_at,
            human_review_required=(
                human_review_required
            ),
            containment_required=(
                containment_required
            ),
            prohibit_closure=prohibit_closure,
            matched_rules=matched_rules,
            invariant_results=invariants,
            context_snapshot=context,
            evaluated_at=(
                evaluation_time.isoformat()
            ),
        )

    def _build_context(
        self,
        asset_context: dict[str, Any],
        intelligence_record: dict[str, Any],
        component_instance: dict[str, Any],
        affectedness_assessment: Any,
        evidence_trust: Any,
    ) -> tuple[
        dict[str, Any],
        dict[str, list[str]],
    ]:
        affectedness = self._affectedness_view(
            affectedness_assessment
        )

        trust = self._trust_view(evidence_trust)

        cvss_score, cvss_severity, cvss_ids = (
            self._selected_cvss(
                intelligence_record
            )
        )

        maximum_impact, maximum_rank, impact_ids = (
            self._maximum_impact(
                asset_context
            )
        )

        epss = intelligence_record.get(
            "epss",
            {},
        )

        kev = intelligence_record.get(
            "kev",
            {},
        )

        exploitation = intelligence_record.get(
            "exploitation",
            {},
        )

        remediation = intelligence_record.get(
            "remediation",
            {},
        )

        exposure = asset_context.get(
            "exposure",
            {},
        )

        mission = asset_context.get(
            "mission",
            {},
        )

        criticality = asset_context.get(
            "criticality",
            {},
        )

        context = {
            "affectedness.status": (
                affectedness["status"]
            ),
            "affectedness.confidence": (
                affectedness["confidence"]
            ),
            "trust.action": trust["action"],
            "trust.score": trust["score"],
            "intelligence.record_status": (
                intelligence_record.get(
                    "record_status"
                )
            ),
            "kev.status": kev.get("status"),
            "exploitation.status": (
                exploitation.get("status")
            ),
            "cvss.base_score": cvss_score,
            "cvss.base_severity": cvss_severity,
            "epss.status": epss.get("status"),
            "epss.probability": epss.get(
                "probability"
            ),
            "asset.criticality": criticality.get(
                "level"
            ),
            "asset.mission_essential": mission.get(
                "mission_essential"
            ),
            "asset.internet_accessible": (
                exposure.get(
                    "internet_accessible"
                )
            ),
            "asset.externally_accessible": (
                exposure.get(
                    "externally_accessible"
                )
            ),
            "asset.network_zone": exposure.get(
                "network_zone"
            ),
            "impact.maximum_severity": (
                maximum_impact
            ),
            "impact.maximum_rank": maximum_rank,
            "component.runtime_status": (
                component_instance.get(
                    "runtime_status"
                )
            ),
            "remediation.status": remediation.get(
                "status"
            ),
        }

        unexpected_context_fields = (
            set(context)
            - set(self.policy[
                "allowed_context_fields"
            ])
        )

        if unexpected_context_fields:
            raise PolicyConfigurationError(
                "Engine produced unauthorized policy "
                f"context fields: "
                f"{sorted(unexpected_context_fields)}"
            )

        source_map = {
            "component": self._unique_strings(
                component_instance.get(
                    "evidence_ids",
                    [],
                )
            ),

            "affectedness": self._unique_strings(
                affectedness[
                    "supporting_evidence_ids"
                ]
            ),

            "asset_context": self._unique_strings(
                asset_context.get(
                    "provenance",
                    {},
                ).get(
                    "source_evidence_ids",
                    [],
                )
            ),

            "exposure": self._unique_strings(
                exposure.get(
                    "exposure_evidence_ids",
                    [],
                )
            ),

            "impact": impact_ids,

            "intelligence": self._unique_strings(
                intelligence_record.get(
                    "provenance",
                    {},
                ).get(
                    "source_evidence_ids",
                    [],
                )
            ),

            "kev": self._unique_strings(
                [kev.get("evidence_id")]
            ),

            "exploitation": self._unique_strings(
                exploitation.get(
                    "evidence_ids",
                    [],
                )
            ),

            "cvss": cvss_ids,

            "epss": self._unique_strings(
                [epss.get("evidence_id")]
            ),

            "remediation": self._unique_strings(
                remediation.get(
                    "evidence_ids",
                    [],
                )
            ),
        }

        return context, source_map

    def _rule_matches(
        self,
        rule: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        conditions = (
            rule.get("when", {}).get("all", [])
        )

        return all(
            self._condition_matches(
                context.get(condition["field"]),
                condition["operator"],
                condition.get("value"),
            )
            for condition in conditions
        )

    def _condition_matches(
        self,
        actual: Any,
        operator: str,
        expected: Any,
    ) -> bool:
        if operator == "eq":
            return actual == expected

        if operator == "neq":
            return actual != expected

        if operator == "in":
            return (
                isinstance(expected, list)
                and actual in expected
            )

        if operator == "not_in":
            return (
                isinstance(expected, list)
                and actual not in expected
            )

        if operator == "is_true":
            return actual is True

        if operator == "is_false":
            return actual is False

        if operator == "is_missing":
            return actual is None

        if operator == "not_missing":
            return actual is not None

        if actual is None or expected is None:
            return False

        if isinstance(actual, bool):
            return False

        if not isinstance(actual, (int, float)):
            return False

        if not isinstance(expected, (int, float)):
            return False

        if not math.isfinite(float(actual)):
            return False

        if not math.isfinite(float(expected)):
            return False

        if operator == "gte":
            return float(actual) >= float(expected)

        if operator == "lte":
            return float(actual) <= float(expected)

        if operator == "gt":
            return float(actual) > float(expected)

        if operator == "lt":
            return float(actual) < float(expected)

        raise PolicyConfigurationError(
            f"Unsupported condition operator: "
            f"{operator}"
        )

    def _evaluate_invariants(
        self,
        context: dict[str, Any],
        action: str,
        priority: str,
        human_review_required: bool,
        matched_rules: list[PolicyRuleMatch],
    ) -> list[PolicyInvariantResult]:
        results: list[PolicyInvariantResult] = []

        context_has_sector = any(
            "sector" in field.casefold()
            for field in context
        )

        policy_has_sector = any(
            "sector" in str(
                condition.get("field", "")
            ).casefold()
            for rule in self.rules
            for condition in (
                rule.get("when", {}).get(
                    "all",
                    [],
                )
            )
        )

        results.append(
            PolicyInvariantResult(
                code="SECTOR_LABEL_EXCLUDED",
                passed=(
                    not context_has_sector
                    and not policy_has_sector
                ),
                message=(
                    "Sector and subsector labels are excluded "
                    "from direct decision inputs."
                ),
            )
        )

        floors_enforced = all(
            self.action_ranks[action]
            >= self.action_ranks[
                rule.action_floor
            ]
            and self.priority_ranks[priority]
            >= self.priority_ranks[
                rule.priority_floor
            ]
            for rule in matched_rules
        )

        results.append(
            PolicyInvariantResult(
                code="RULE_FLOORS_ENFORCED",
                passed=floors_enforced,
                message=(
                    "Final action and priority meet or "
                    "exceed every triggered rule floor."
                ),
            )
        )

        affectedness_status = context[
            "affectedness.status"
        ]

        uncertain_status = (
            affectedness_status
            in {
                "unknown",
                "probably_not_affected",
            }
        )

        uncertain_safe = (
            not uncertain_status
            or (
                action == "HOLD"
                and human_review_required
            )
        )

        results.append(
            PolicyInvariantResult(
                code="UNCERTAIN_AFFECTEDNESS_HELD",
                passed=uncertain_safe,
                message=(
                    "Unknown and probably-not-affected "
                    "states require HOLD and human review."
                ),
            )
        )

        kev_affected = (
            context["kev.status"] == "listed"
            and affectedness_status
            in {
                "affected",
                "probably_affected",
            }
        )

        kev_floor_met = (
            not kev_affected
            or (
                self.action_ranks[action]
                >= self.action_ranks["ACT"]
                and self.priority_ranks[priority]
                >= self.priority_ranks[
                    "CRITICAL"
                ]
                and human_review_required
            )
        )

        results.append(
            PolicyInvariantResult(
                code="KEV_AFFECTED_MINIMUM_ENFORCED",
                passed=kev_floor_met,
                message=(
                    "KEV plus affectedness requires "
                    "ACT-or-HOLD, Critical-or-higher "
                    "priority and human review."
                ),
            )
        )

        trust_blocked = context[
            "trust.action"
        ] in {
            "QUARANTINE",
            "REJECT",
        }

        trust_block_met = (
            not trust_blocked
            or (
                action == "HOLD"
                and human_review_required
            )
        )

        results.append(
            PolicyInvariantResult(
                code="LOW_TRUST_BLOCKS_AUTOMATION",
                passed=trust_block_met,
                message=(
                    "Quarantined or rejected evidence "
                    "blocks automated disposition."
                ),
            )
        )

        epss_missing_semantics_valid = not (
            context["epss.status"] == "missing"
            and context[
                "epss.probability"
            ] is not None
        )

        results.append(
            PolicyInvariantResult(
                code="MISSING_EPSS_REMAINS_UNKNOWN",
                passed=(
                    epss_missing_semantics_valid
                ),
                message=(
                    "Missing EPSS remains None and is "
                    "never interpreted as zero."
                ),
            )
        )

        results.append(
            PolicyInvariantResult(
                code="MONOTONIC_POLICY_STRUCTURE",
                passed=True,
                message=(
                    "Policy rules contain escalation floors "
                    "only. No rule can decrement action or "
                    "priority."
                ),
            )
        )

        return results

    def _resolve_evidence_sources(
        self,
        source_names: list[str],
        source_map: dict[str, list[str]],
    ) -> list[str]:
        evidence_ids: list[str] = []

        for source_name in source_names:
            evidence_ids.extend(
                source_map.get(source_name, [])
            )

        return self._unique_strings(evidence_ids)

    def _selected_cvss(
        self,
        intelligence_record: dict[str, Any],
    ) -> tuple[
        float | None,
        str | None,
        list[str],
    ]:
        cvss = intelligence_record.get(
            "cvss",
            {},
        )

        selected_id = cvss.get(
            "selected_metric_id"
        )

        metrics = cvss.get("metrics", [])

        for metric in metrics:
            if metric.get("metric_id") == selected_id:
                score = metric.get("base_score")

                if (
                    isinstance(score, (int, float))
                    and not isinstance(score, bool)
                    and math.isfinite(float(score))
                ):
                    normalized_score = float(score)
                else:
                    normalized_score = None

                return (
                    normalized_score,
                    metric.get("base_severity"),
                    self._unique_strings(
                        [metric.get("evidence_id")]
                    ),
                )

        return None, None, []

    def _maximum_impact(
        self,
        asset_context: dict[str, Any],
    ) -> tuple[str, int, list[str]]:
        impact_assessment = asset_context.get(
            "impact_assessment",
            {},
        )

        maximum_severity = "unknown"
        maximum_rank = IMPACT_RANKS["unknown"]
        evidence_ids: list[str] = []

        for value in impact_assessment.values():
            if not isinstance(value, dict):
                continue

            severity = value.get("severity")

            if severity not in IMPACT_RANKS:
                continue

            rank = IMPACT_RANKS[severity]

            if rank > maximum_rank:
                maximum_rank = rank
                maximum_severity = severity

            evidence_ids.extend(
                value.get("evidence_ids", [])
            )

        return (
            maximum_severity,
            maximum_rank,
            self._unique_strings(evidence_ids),
        )

    def _affectedness_view(
        self,
        assessment: Any,
    ) -> dict[str, Any]:
        if hasattr(assessment, "status"):
            status = getattr(
                assessment,
                "status",
                None,
            )

            confidence = getattr(
                assessment,
                "confidence",
                None,
            )

            evidence_ids = getattr(
                assessment,
                "supporting_evidence_ids",
                [],
            )

        elif isinstance(assessment, dict):
            status = assessment.get("status")
            confidence = assessment.get(
                "confidence"
            )
            evidence_ids = assessment.get(
                "supporting_evidence_ids",
                [],
            )

        else:
            status = "unknown"
            confidence = None
            evidence_ids = []

        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not math.isfinite(float(confidence))
        ):
            confidence = None
        else:
            confidence = float(confidence)

        return {
            "status": status,
            "confidence": confidence,
            "supporting_evidence_ids": (
                self._unique_strings(
                    list(evidence_ids)
                )
            ),
        }

    def _trust_view(
        self,
        assessment: Any,
    ) -> dict[str, Any]:
        if hasattr(assessment, "action"):
            action = getattr(
                assessment,
                "action",
                None,
            )

            score = getattr(
                assessment,
                "aggregate_score",
                None,
            )

        elif isinstance(assessment, dict):
            action = assessment.get("action")
            score = assessment.get(
                "aggregate_score"
            )

        else:
            action = None
            score = None

        normalized_action = (
            str(action).upper()
            if action is not None
            else None
        )

        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not math.isfinite(float(score))
            or float(score) < 0
            or float(score) > 1
        ):
            normalized_score = None
        else:
            normalized_score = float(score)

        return {
            "action": normalized_action,
            "score": normalized_score,
        }

    def _higher_action(
        self,
        current: str,
        candidate: str,
    ) -> str:
        if (
            self.action_ranks[candidate]
            > self.action_ranks[current]
        ):
            return candidate

        return current

    def _higher_priority(
        self,
        current: str,
        candidate: str,
    ) -> str:
        if (
            self.priority_ranks[candidate]
            > self.priority_ranks[current]
        ):
            return candidate

        return current

    @staticmethod
    def _unique_strings(
        values: list[Any],
    ) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()

        for value in values:
            if not isinstance(value, str):
                continue

            if not value or value in seen:
                continue

            seen.add(value)
            output.append(value)

        return output

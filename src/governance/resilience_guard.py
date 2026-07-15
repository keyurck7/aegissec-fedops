from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence


RESILIENCE_OUTCOMES = {
    "COMPLETED_NORMALLY",
    "COMPLETED_DEGRADED_REVIEW_REQUIRED",
    "RETRY_SCHEDULED",
    "CIRCUIT_OPEN",
    "ROLLED_BACK",
    "QUARANTINED",
    "RECOVERED_IDEMPOTENTLY",
    "BLOCKED_DEPENDENCY_FAILURE",
    "BLOCKED_AUDIT_FAILURE",
    "BLOCKED_INTEGRITY_FAILURE",
}


class ResilienceGuardError(ValueError):
    """Raised when resilience controls receive an invalid configuration."""


class DependencyFault(str, Enum):
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    RATE_LIMIT = "rate_limit"
    AUTHENTICATION_REJECTED = "authentication_rejected"
    MALFORMED_RESPONSE = "malformed_response"
    POLICY_STORE_UNAVAILABLE = "policy_store_unavailable"
    SCHEMA_REGISTRY_UNAVAILABLE = "schema_registry_unavailable"
    INTEGRITY_SERVICE_UNAVAILABLE = "integrity_service_unavailable"
    CLOCK_SERVICE_UNAVAILABLE = "clock_service_unavailable"


@dataclass(frozen=True)
class ResilienceFinding:
    code: str
    control: str
    message: str
    severity: str = "critical"

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "control": self.control,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass
class ResilienceResult:
    outcome: str
    defended: bool
    unsafe_decision_released: bool = False
    human_review_required: bool = False
    prohibit_closure: bool = False
    degraded_mode: bool = False
    automated_release: bool = False
    retry_attempts: int = 0
    findings: list[ResilienceFinding] = field(default_factory=list)
    residual_risks: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.outcome not in RESILIENCE_OUTCOMES:
            raise ResilienceGuardError(
                f"Unsupported resilience outcome: {self.outcome!r}"
            )
        if self.automated_release and (
            self.unsafe_decision_released
            or self.human_review_required
            or self.prohibit_closure
        ):
            raise ResilienceGuardError(
                "Automated release cannot coexist with unsafe, review, or closure blocks."
            )

    @property
    def detection_oracles(self) -> list[str]:
        return sorted({finding.control for finding in self.findings})

    @property
    def finding_codes(self) -> list[str]:
        return sorted({finding.code for finding in self.findings})

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "defended": self.defended,
            "unsafe_decision_released": self.unsafe_decision_released,
            "human_review_required": self.human_review_required,
            "prohibit_closure": self.prohibit_closure,
            "degraded_mode": self.degraded_mode,
            "automated_release": self.automated_release,
            "retry_attempts": self.retry_attempts,
            "detection_oracles": self.detection_oracles,
            "finding_codes": self.finding_codes,
            "findings": [finding.to_dict() for finding in self.findings],
            "residual_risks": list(self.residual_risks),
            "details": copy.deepcopy(self.details),
        }


@dataclass(frozen=True)
class DeterministicResilienceClock:
    now: datetime

    def __post_init__(self) -> None:
        if self.now.tzinfo is None:
            raise ResilienceGuardError(
                "Deterministic resilience clock must be timezone-aware."
            )

    @classmethod
    def from_iso(cls, value: str) -> "DeterministicResilienceClock":
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            raise ResilienceGuardError("Clock timestamp must include a timezone.")
        return cls(parsed.astimezone(timezone.utc))

    def isoformat(self) -> str:
        return self.now.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    deterministic_backoff_seconds: tuple[int, ...] = (0, 1, 2)
    retryable_faults: frozenset[DependencyFault] = frozenset(
        {
            DependencyFault.TIMEOUT,
            DependencyFault.UNAVAILABLE,
            DependencyFault.RATE_LIMIT,
        }
    )

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ResilienceGuardError("max_attempts must be at least one.")
        if len(self.deterministic_backoff_seconds) < self.max_attempts:
            raise ResilienceGuardError(
                "Backoff schedule must contain an entry for every attempt."
            )
        if any(value < 0 for value in self.deterministic_backoff_seconds):
            raise ResilienceGuardError("Backoff values must be non-negative.")

    def retry_allowed(self, fault: DependencyFault, attempt: int) -> bool:
        return fault in self.retryable_faults and attempt < self.max_attempts

    def backoff_for_attempt(self, attempt: int) -> int:
        if attempt < 1 or attempt > self.max_attempts:
            raise ResilienceGuardError("Attempt is outside the retry policy.")
        return self.deterministic_backoff_seconds[attempt - 1]


@dataclass(frozen=True)
class CircuitBreakerPolicy:
    failure_threshold: int = 3
    reset_after_seconds: int = 60

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ResilienceGuardError(
                "Circuit-breaker failure_threshold must be positive."
            )
        if self.reset_after_seconds < 0:
            raise ResilienceGuardError(
                "Circuit-breaker reset_after_seconds must be non-negative."
            )


@dataclass
class CircuitBreakerState:
    consecutive_failures: int = 0
    opened_at: datetime | None = None

    @property
    def open(self) -> bool:
        return self.opened_at is not None

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.opened_at = None

    def record_failure(
        self,
        clock: DeterministicResilienceClock,
        policy: CircuitBreakerPolicy,
    ) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= policy.failure_threshold:
            self.opened_at = clock.now.astimezone(timezone.utc)

    def can_probe(
        self,
        clock: DeterministicResilienceClock,
        policy: CircuitBreakerPolicy,
    ) -> bool:
        if self.opened_at is None:
            return True
        elapsed = (
            clock.now.astimezone(timezone.utc) - self.opened_at
        ).total_seconds()
        return elapsed >= policy.reset_after_seconds


@dataclass(frozen=True)
class VerifiedFallback:
    available: bool
    integrity_verified: bool
    freshness_verified: bool
    source: str = "cache"
    age_seconds: int | None = None
    disclosed_missing_dependencies: tuple[str, ...] = ()

    @property
    def authorized(self) -> bool:
        return (
            self.available
            and self.integrity_verified
            and self.freshness_verified
            and bool(self.disclosed_missing_dependencies)
        )


@dataclass(frozen=True)
class DependencyGuardPolicy:
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    circuit_breaker: CircuitBreakerPolicy = field(
        default_factory=CircuitBreakerPolicy
    )
    allow_verified_degraded_fallback: bool = True
    require_human_review_in_degraded_mode: bool = True
    prohibit_closure_in_degraded_mode: bool = True


class ResilienceGuard:
    """
    Deterministic dependency and release guard.

    The guard never sleeps and never reads wall-clock time. Callers inject a
    deterministic clock and explicit failure state, making retry, circuit,
    fallback, and release decisions reproducible and auditable.
    """

    def __init__(
        self,
        clock: DeterministicResilienceClock,
        policy: DependencyGuardPolicy | None = None,
    ) -> None:
        self.clock = clock
        self.policy = policy or DependencyGuardPolicy()

    def bounded_retry_plan(
        self,
        fault: DependencyFault,
    ) -> tuple[int, ...]:
        if fault not in self.policy.retry.retryable_faults:
            return ()
        return tuple(
            self.policy.retry.backoff_for_attempt(attempt)
            for attempt in range(1, self.policy.retry.max_attempts + 1)
        )

    def evaluate_dependency_failure(
        self,
        fault: DependencyFault | str,
        *,
        attempt: int,
        consecutive_failures: int,
        fallback: VerifiedFallback | None = None,
        dependency_name: str = "dependency",
    ) -> ResilienceResult:
        try:
            normalized_fault = DependencyFault(fault)
        except ValueError as exc:
            raise ResilienceGuardError(
                f"Unsupported dependency fault: {fault!r}"
            ) from exc

        if attempt < 1:
            raise ResilienceGuardError("attempt must be positive.")
        if consecutive_failures < 0:
            raise ResilienceGuardError(
                "consecutive_failures must be non-negative."
            )

        breaker_state = CircuitBreakerState(
            consecutive_failures=consecutive_failures
        )
        breaker_state.record_failure(
            self.clock,
            self.policy.circuit_breaker,
        )

        if breaker_state.open:
            return ResilienceResult(
                outcome="CIRCUIT_OPEN",
                defended=True,
                human_review_required=True,
                prohibit_closure=True,
                findings=[
                    ResilienceFinding(
                        code="DEPENDENCY_CIRCUIT_OPEN",
                        control="CIRCUIT_BREAKER",
                        message=(
                            f"{dependency_name} exceeded the governed failure threshold."
                        ),
                    )
                ],
                residual_risks=[
                    f"{dependency_name} remains unavailable until a governed probe succeeds."
                ],
                details={
                    "dependency": dependency_name,
                    "fault": normalized_fault.value,
                    "consecutive_failures": breaker_state.consecutive_failures,
                    "failure_threshold": (
                        self.policy.circuit_breaker.failure_threshold
                    ),
                },
            )

        if self.policy.retry.retry_allowed(normalized_fault, attempt):
            next_attempt = attempt + 1
            return ResilienceResult(
                outcome="RETRY_SCHEDULED",
                defended=True,
                human_review_required=True,
                prohibit_closure=True,
                retry_attempts=attempt,
                findings=[
                    ResilienceFinding(
                        code="BOUNDED_RETRY_SCHEDULED",
                        control="RETRY_BUDGET",
                        message=(
                            f"{dependency_name} will be retried within the bounded policy."
                        ),
                    )
                ],
                residual_risks=[
                    f"{dependency_name} has not yet produced authoritative evidence."
                ],
                details={
                    "dependency": dependency_name,
                    "fault": normalized_fault.value,
                    "current_attempt": attempt,
                    "next_attempt": next_attempt,
                    "next_backoff_seconds": (
                        self.policy.retry.backoff_for_attempt(next_attempt)
                    ),
                    "max_attempts": self.policy.retry.max_attempts,
                },
            )

        if (
            self.policy.allow_verified_degraded_fallback
            and fallback is not None
            and fallback.authorized
            and normalized_fault
            in {
                DependencyFault.TIMEOUT,
                DependencyFault.UNAVAILABLE,
                DependencyFault.RATE_LIMIT,
            }
        ):
            return ResilienceResult(
                outcome="COMPLETED_DEGRADED_REVIEW_REQUIRED",
                defended=True,
                human_review_required=(
                    self.policy.require_human_review_in_degraded_mode
                ),
                prohibit_closure=(
                    self.policy.prohibit_closure_in_degraded_mode
                ),
                degraded_mode=True,
                automated_release=False,
                retry_attempts=attempt,
                findings=[
                    ResilienceFinding(
                        code="VERIFIED_DEGRADED_FALLBACK",
                        control="DEGRADED_MODE_GOVERNANCE",
                        message=(
                            "A verified, fresh fallback was used under mandatory review controls."
                        ),
                    )
                ],
                residual_risks=[
                    f"Live {dependency_name} evidence was unavailable.",
                    "The decision must not be automatically released or closed.",
                ],
                details={
                    "dependency": dependency_name,
                    "fault": normalized_fault.value,
                    "fallback_source": fallback.source,
                    "fallback_age_seconds": fallback.age_seconds,
                    "missing_dependencies": list(
                        fallback.disclosed_missing_dependencies
                    ),
                },
            )

        if normalized_fault == DependencyFault.INTEGRITY_SERVICE_UNAVAILABLE:
            outcome = "BLOCKED_INTEGRITY_FAILURE"
            code = "INTEGRITY_SERVICE_REQUIRED"
            control = "INTEGRITY_GATE"
        else:
            outcome = "BLOCKED_DEPENDENCY_FAILURE"
            code = "DEPENDENCY_FAIL_CLOSED"
            control = "DEPENDENCY_GATE"

        return ResilienceResult(
            outcome=outcome,
            defended=True,
            human_review_required=True,
            prohibit_closure=True,
            retry_attempts=attempt,
            findings=[
                ResilienceFinding(
                    code=code,
                    control=control,
                    message=(
                        f"{dependency_name} failure cannot be safely resolved or substituted."
                    ),
                )
            ],
            residual_risks=[
                f"Authoritative {dependency_name} evidence is unavailable.",
                "No automated release is permitted.",
            ],
            details={
                "dependency": dependency_name,
                "fault": normalized_fault.value,
                "fallback_present": fallback is not None,
                "fallback_authorized": (
                    fallback.authorized if fallback is not None else False
                ),
            },
        )

    def validate_degraded_result(
        self,
        result: ResilienceResult,
    ) -> bool:
        if not result.degraded_mode:
            return True
        return (
            result.outcome == "COMPLETED_DEGRADED_REVIEW_REQUIRED"
            and result.human_review_required
            and result.prohibit_closure
            and not result.automated_release
            and not result.unsafe_decision_released
            and bool(result.residual_risks)
            and bool(result.details.get("missing_dependencies"))
        )

    def release_gate(
        self,
        *,
        dependency_resolved: bool,
        audit_durable: bool,
        integrity_verified: bool,
        checkpoint_durable: bool,
        degraded_result: ResilienceResult | None = None,
    ) -> ResilienceResult:
        if degraded_result is not None and degraded_result.degraded_mode:
            if not self.validate_degraded_result(degraded_result):
                return ResilienceResult(
                    outcome="BLOCKED_INTEGRITY_FAILURE",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="INVALID_DEGRADED_GOVERNANCE",
                            control="RELEASE_GATE",
                            message=(
                                "Degraded operation does not satisfy mandatory governance controls."
                            ),
                        )
                    ],
                    residual_risks=[
                        "Degraded-mode governance evidence is incomplete."
                    ],
                )
            return degraded_result

        checks = {
            "dependency_resolved": dependency_resolved,
            "audit_durable": audit_durable,
            "integrity_verified": integrity_verified,
            "checkpoint_durable": checkpoint_durable,
        }
        failed = [name for name, passed in checks.items() if not passed]
        if failed:
            if "audit_durable" in failed:
                outcome = "BLOCKED_AUDIT_FAILURE"
                code = "AUDIT_NOT_DURABLE"
                control = "AUDIT_RELEASE_GATE"
            elif "integrity_verified" in failed:
                outcome = "BLOCKED_INTEGRITY_FAILURE"
                code = "INTEGRITY_NOT_VERIFIED"
                control = "INTEGRITY_GATE"
            else:
                outcome = "BLOCKED_DEPENDENCY_FAILURE"
                code = "RELEASE_PREREQUISITE_MISSING"
                control = "RELEASE_GATE"
            return ResilienceResult(
                outcome=outcome,
                defended=True,
                human_review_required=True,
                prohibit_closure=True,
                findings=[
                    ResilienceFinding(
                        code=code,
                        control=control,
                        message=(
                            "Decision release was blocked because durable governance prerequisites were missing."
                        ),
                    )
                ],
                residual_risks=[
                    f"Missing release prerequisites: {', '.join(sorted(failed))}."
                ],
                details={"failed_prerequisites": sorted(failed)},
            )
        return ResilienceResult(
            outcome="COMPLETED_NORMALLY",
            defended=True,
            automated_release=True,
            findings=[
                ResilienceFinding(
                    code="RELEASE_PREREQUISITES_SATISFIED",
                    control="RELEASE_GATE",
                    message="All durable governance prerequisites are satisfied.",
                    severity="informational",
                )
            ],
            details={"prerequisites": checks},
        )


def execute_bounded(
    operation: Callable[[], Any],
    *,
    retry_policy: RetryPolicy,
    fault_mapper: Callable[[BaseException], DependencyFault],
) -> tuple[Any | None, int, DependencyFault | None]:
    """Execute an operation within a deterministic attempt budget.

    No sleep is performed. The returned attempt count and final fault can be
    fed into ResilienceGuard for a governed retry, fallback, or block decision.
    """

    last_fault: DependencyFault | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        try:
            return operation(), attempt, None
        except BaseException as exc:  # caller provides explicit fault mapping
            last_fault = fault_mapper(exc)
            if not retry_policy.retry_allowed(last_fault, attempt):
                return None, attempt, last_fault
    return None, retry_policy.max_attempts, last_fault

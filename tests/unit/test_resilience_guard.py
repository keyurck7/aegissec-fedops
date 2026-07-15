from datetime import datetime, timezone

import pytest

from src.governance.resilience_guard import (
    CircuitBreakerPolicy,
    DependencyFault,
    DependencyGuardPolicy,
    DeterministicResilienceClock,
    ResilienceGuard,
    ResilienceGuardError,
    RetryPolicy,
    VerifiedFallback,
)


@pytest.fixture
def guard() -> ResilienceGuard:
    return ResilienceGuard(
        DeterministicResilienceClock(
            datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc)
        )
    )


def test_clock_requires_timezone() -> None:
    with pytest.raises(ResilienceGuardError):
        DeterministicResilienceClock(datetime(2026, 7, 15, 10, 0))


def test_retry_policy_is_bounded() -> None:
    policy = RetryPolicy(max_attempts=3, deterministic_backoff_seconds=(0, 1, 2))
    assert policy.retry_allowed(DependencyFault.TIMEOUT, 1)
    assert not policy.retry_allowed(DependencyFault.TIMEOUT, 3)
    assert not policy.retry_allowed(DependencyFault.AUTHENTICATION_REJECTED, 1)


def test_timeout_schedules_bounded_retry(guard: ResilienceGuard) -> None:
    result = guard.evaluate_dependency_failure(
        DependencyFault.TIMEOUT,
        attempt=1,
        consecutive_failures=0,
    )
    assert result.outcome == "RETRY_SCHEDULED"
    assert result.details["next_attempt"] == 2
    assert result.details["max_attempts"] == 3
    assert not result.automated_release


def test_authentication_failure_is_not_retried(guard: ResilienceGuard) -> None:
    result = guard.evaluate_dependency_failure(
        DependencyFault.AUTHENTICATION_REJECTED,
        attempt=1,
        consecutive_failures=0,
    )
    assert result.outcome == "BLOCKED_DEPENDENCY_FAILURE"
    assert result.human_review_required
    assert result.prohibit_closure


def test_circuit_opens_at_threshold(guard: ResilienceGuard) -> None:
    result = guard.evaluate_dependency_failure(
        DependencyFault.UNAVAILABLE,
        attempt=1,
        consecutive_failures=2,
    )
    assert result.outcome == "CIRCUIT_OPEN"
    assert "CIRCUIT_BREAKER" in result.detection_oracles


def test_verified_fallback_forces_governed_degraded_mode(
    guard: ResilienceGuard,
) -> None:
    fallback = VerifiedFallback(
        available=True,
        integrity_verified=True,
        freshness_verified=True,
        disclosed_missing_dependencies=("OSV",),
    )
    result = guard.evaluate_dependency_failure(
        DependencyFault.UNAVAILABLE,
        attempt=3,
        consecutive_failures=0,
        fallback=fallback,
    )
    assert result.outcome == "COMPLETED_DEGRADED_REVIEW_REQUIRED"
    assert guard.validate_degraded_result(result)
    assert result.human_review_required
    assert result.prohibit_closure
    assert not result.automated_release


def test_unverified_fallback_is_blocked(guard: ResilienceGuard) -> None:
    fallback = VerifiedFallback(
        available=True,
        integrity_verified=False,
        freshness_verified=True,
        disclosed_missing_dependencies=("OSV",),
    )
    result = guard.evaluate_dependency_failure(
        DependencyFault.UNAVAILABLE,
        attempt=3,
        consecutive_failures=0,
        fallback=fallback,
    )
    assert result.outcome == "BLOCKED_DEPENDENCY_FAILURE"


def test_integrity_service_failure_uses_integrity_block(guard: ResilienceGuard) -> None:
    result = guard.evaluate_dependency_failure(
        DependencyFault.INTEGRITY_SERVICE_UNAVAILABLE,
        attempt=1,
        consecutive_failures=0,
    )
    assert result.outcome == "BLOCKED_INTEGRITY_FAILURE"


def test_release_gate_requires_durable_audit(guard: ResilienceGuard) -> None:
    result = guard.release_gate(
        dependency_resolved=True,
        audit_durable=False,
        integrity_verified=True,
        checkpoint_durable=True,
    )
    assert result.outcome == "BLOCKED_AUDIT_FAILURE"
    assert not result.automated_release


def test_release_gate_allows_only_complete_prerequisites(guard: ResilienceGuard) -> None:
    result = guard.release_gate(
        dependency_resolved=True,
        audit_durable=True,
        integrity_verified=True,
        checkpoint_durable=True,
    )
    assert result.outcome == "COMPLETED_NORMALLY"
    assert result.automated_release

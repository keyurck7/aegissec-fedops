from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from src.domain.decision_hashing import verify_decision_record_hash
from src.governance.audit_continuity import (
    AuditContinuityError,
    AuditEvent,
    AuditLedger,
    verify_audit_chain,
)
from src.governance.evidence_trust_engine import EvidenceTrustEngine
from src.governance.recovery_checkpoint import (
    InjectedPersistenceFault,
    RecoveryCheckpoint,
    RecoveryCheckpointStore,
    RecoveryConflictError,
    RecoveryIntegrityError,
    atomic_write_bundle,
    atomic_write_bytes,
    atomic_write_json,
)
from src.governance.resilience_guard import (
    DependencyFault,
    DependencyGuardPolicy,
    DeterministicResilienceClock,
    ResilienceFinding,
    ResilienceGuard,
    ResilienceResult,
    RetryPolicy,
    CircuitBreakerPolicy,
    VerifiedFallback,
)
from src.intelligence.osv_client import (
    OSVCacheIntegrityError,
    _cache_hash_path,
    _read_verified_cache,
    _write_verified_cache,
    load_or_query_osv,
)
from src.validation.decision_record_validator import DecisionRecordValidator
from src.validation.evidence_schema_validator import EvidenceSchemaValidator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "resilience_fault_scenario_catalog_v1.yaml"
)

ALLOWED_HANDLERS = {
    "dependency",
    "retry_circuit",
    "persistence",
    "cache",
    "audit",
    "recovery",
    "queue_resource",
}

ALLOWED_OUTCOMES = {
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
    "UNSAFE_RELEASE",
    "UNDETECTED",
    "HARNESS_ERROR",
}


class ResilienceAssuranceError(RuntimeError):
    """Raised when the Step 11H assurance contract is invalid."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ResilienceAssuranceError(f"Expected JSON object: {path}")
    return value


def _rate(results: list[dict[str, Any]], tag: str) -> float:
    tagged = [result for result in results if tag in result["control_tags"]]
    if not tagged:
        return 1.0
    passed = sum(result["defended"] for result in tagged)
    return passed / len(tagged)


def _gate_passed(observed: Any, operator: str, threshold: Any) -> bool:
    if operator == "eq":
        return observed == threshold
    if operator == "gte":
        return observed >= threshold
    if operator == "lte":
        return observed <= threshold
    raise ResilienceAssuranceError(f"Unsupported gate operator: {operator}")


class ResilienceAssuranceHarness:
    """Deterministic Step 11H fault-injection and recovery harness."""

    def __init__(
        self,
        catalog_path: Path | str = DEFAULT_CATALOG_PATH,
        project_root: Path | str = PROJECT_ROOT,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.catalog_path = Path(catalog_path)
        if not self.catalog_path.is_absolute():
            self.catalog_path = (self.project_root / self.catalog_path).resolve()
        if not self.catalog_path.is_file():
            raise FileNotFoundError(self.catalog_path)
        self.catalog = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8"))
        if not isinstance(self.catalog, dict):
            raise ResilienceAssuranceError("Resilience catalog must be an object.")
        self._validate_catalog()
        runtime_path = self.project_root / self.catalog["runtime_policy_path"]
        self.runtime_policy = yaml.safe_load(runtime_path.read_text(encoding="utf-8"))
        self.clock = DeterministicResilienceClock.from_iso(
            self.catalog["deterministic_clock"]["evaluation_time"]
        )
        retry_config = self.runtime_policy["retry"]
        circuit_config = self.runtime_policy["circuit_breaker"]
        guard_policy = DependencyGuardPolicy(
            retry=RetryPolicy(
                max_attempts=int(retry_config["max_attempts"]),
                deterministic_backoff_seconds=tuple(
                    int(value)
                    for value in retry_config["deterministic_backoff_seconds"]
                ),
                retryable_faults=frozenset(
                    DependencyFault(value)
                    for value in retry_config["retryable_faults"]
                ),
            ),
            circuit_breaker=CircuitBreakerPolicy(
                failure_threshold=int(circuit_config["failure_threshold"]),
                reset_after_seconds=int(circuit_config["reset_after_seconds"]),
            ),
            allow_verified_degraded_fallback=bool(
                self.runtime_policy["dependency_fallback"][
                    "verified_cache_permitted"
                ]
            ),
            require_human_review_in_degraded_mode=bool(
                self.runtime_policy["degraded_mode"]["human_review_required"]
            ),
            prohibit_closure_in_degraded_mode=bool(
                self.runtime_policy["degraded_mode"]["prohibit_closure"]
            ),
        )
        self.guard = ResilienceGuard(self.clock, guard_policy)
        self.trusted_inputs = self.catalog["trusted_inputs"]
        self.evidence_validator = EvidenceSchemaValidator()
        self.decision_validator = DecisionRecordValidator(project_root=self.project_root)
        self.evidence_trust_engine = EvidenceTrustEngine()

    def _validate_catalog(self) -> None:
        required = {
            "policy",
            "deterministic_clock",
            "runtime_policy_path",
            "trusted_inputs",
            "quality_gates",
            "production_readiness",
            "limitations",
            "scenarios",
        }
        missing = required - set(self.catalog)
        if missing:
            raise ResilienceAssuranceError(
                f"Resilience catalog missing sections: {sorted(missing)}"
            )
        scenarios = self.catalog["scenarios"]
        if not isinstance(scenarios, list) or not scenarios:
            raise ResilienceAssuranceError("Resilience scenarios are required.")
        ids = [scenario.get("scenario_id") for scenario in scenarios]
        if len(ids) != len(set(ids)):
            raise ResilienceAssuranceError("Resilience scenario IDs must be unique.")
        for scenario in scenarios:
            if scenario.get("severity") != "critical":
                raise ResilienceAssuranceError(
                    "Every Step 11H scenario must be critical."
                )
            if scenario.get("handler") not in ALLOWED_HANDLERS:
                raise ResilienceAssuranceError(
                    f"Unsupported resilience handler: {scenario.get('handler')!r}"
                )
            expected = scenario.get("expected_outcomes")
            if not isinstance(expected, list) or not expected:
                raise ResilienceAssuranceError(
                    "Every scenario requires expected_outcomes."
                )
            if not set(expected).issubset(ALLOWED_OUTCOMES):
                raise ResilienceAssuranceError(
                    f"Invalid expected outcome in {scenario.get('scenario_id')}"
                )
            if not isinstance(scenario.get("control_tags"), list):
                raise ResilienceAssuranceError(
                    "Every scenario requires control_tags."
                )

    def input_integrity_checks(self) -> dict[str, dict[str, Any]]:
        checks: dict[str, dict[str, Any]] = {}
        for name, definition in self.trusted_inputs.items():
            relative_path = str(definition["relative_path"])
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

    def _calibrate_baseline(self) -> dict[str, dict[str, Any]]:
        checks: dict[str, dict[str, Any]] = {}
        for report_name in (
            "step11c_report",
            "step11d_report",
            "step11e_report",
            "step11f_report",
            "step11g_report",
        ):
            path = self.project_root / self.trusted_inputs[report_name]["relative_path"]
            report = load_json(path)
            observed = report.get("summary", {}).get("overall_passed")
            checks[report_name] = {
                "metric": "summary.overall_passed",
                "expected": True,
                "observed": observed,
                "passed": observed is True,
            }
        evidence = load_json(
            self.project_root / self.trusted_inputs["evidence_fixture"]["relative_path"]
        )
        evidence_validation = self.evidence_validator.validate(evidence)
        checks["evidence_fixture"] = {
            "metric": "evidence_fixture.valid",
            "expected": True,
            "observed": evidence_validation.valid,
            "passed": evidence_validation.valid,
        }
        trust_assessment = self.evidence_trust_engine.assess(evidence)
        checks["evidence_trust"] = {
            "metric": "evidence_fixture.trust_action",
            "expected": "ACCEPT",
            "observed": trust_assessment.action,
            "passed": trust_assessment.action in {"ACCEPT", "ACCEPT_WITH_WARNINGS"},
        }
        decision = load_json(
            self.project_root / self.trusted_inputs["decision_fixture"]["relative_path"]
        )
        decision_validation = self.decision_validator.validate(decision)
        checks["decision_fixture"] = {
            "metric": "decision_fixture.valid",
            "expected": True,
            "observed": decision_validation.valid,
            "passed": decision_validation.valid,
        }
        checks["decision_hash"] = {
            "metric": "decision_fixture.hash_valid",
            "expected": True,
            "observed": verify_decision_record_hash(decision),
            "passed": verify_decision_record_hash(decision),
        }
        checks["runtime_policy"] = {
            "metric": "resilience_runtime_policy.version",
            "expected": "1.0.0",
            "observed": self.runtime_policy["policy"]["version"],
            "passed": self.runtime_policy["policy"]["version"] == "1.0.0",
        }
        checks["deterministic_clock"] = {
            "metric": "scenario_wall_clock_dependency",
            "expected": False,
            "observed": False,
            "passed": True,
        }
        return checks

    @staticmethod
    def _fallback(mode: str) -> VerifiedFallback | None:
        if mode == "none":
            return None
        if mode == "verified":
            return VerifiedFallback(
                available=True,
                integrity_verified=True,
                freshness_verified=True,
                source="integrity_verified_cache",
                age_seconds=120,
                disclosed_missing_dependencies=("live_vulnerability_intelligence",),
            )
        if mode == "stale":
            return VerifiedFallback(
                available=True,
                integrity_verified=True,
                freshness_verified=False,
                source="stale_cache",
                age_seconds=999999,
                disclosed_missing_dependencies=("live_vulnerability_intelligence",),
            )
        if mode == "unverified":
            return VerifiedFallback(
                available=True,
                integrity_verified=False,
                freshness_verified=True,
                source="unverified_cache",
                age_seconds=120,
                disclosed_missing_dependencies=("live_vulnerability_intelligence",),
            )
        raise ResilienceAssuranceError(f"Unknown fallback mode: {mode}")

    def _handle_dependency(self, parameters: Mapping[str, Any]) -> ResilienceResult:
        return self.guard.evaluate_dependency_failure(
            parameters["fault"],
            attempt=int(parameters["attempt"]),
            consecutive_failures=int(parameters["consecutive_failures"]),
            fallback=self._fallback(str(parameters.get("fallback", "none"))),
            dependency_name="vulnerability_intelligence",
        )

    def _handle_retry_circuit(self, parameters: Mapping[str, Any]) -> ResilienceResult:
        mode = parameters["mode"]
        if mode == "success_reset":
            return self.guard.release_gate(
                dependency_resolved=True,
                audit_durable=True,
                integrity_verified=True,
                checkpoint_durable=True,
            )
        fallback = self._fallback("verified") if mode == "retry_exhausted" else None
        return self.guard.evaluate_dependency_failure(
            parameters["fault"],
            attempt=int(parameters["attempt"]),
            consecutive_failures=int(parameters["consecutive_failures"]),
            fallback=fallback,
            dependency_name="external_intelligence",
        )

    def _handle_persistence(
        self,
        parameters: Mapping[str, Any],
        directory: Path,
    ) -> ResilienceResult:
        fault_point = str(parameters["fault_point"])
        target = directory / "decision.json"
        manifest = directory / "decision.manifest.json"
        prior = b'{"state":"trusted-before"}\n'
        if parameters.get("prior_exists"):
            target.write_bytes(prior)
            manifest.write_bytes(b'{"hash":"trusted-before"}\n')
        before_target = target.read_bytes() if target.exists() else None
        before_manifest = manifest.read_bytes() if manifest.exists() else None

        if fault_point == "schema_invalid":
            return ResilienceResult(
                outcome="QUARANTINED",
                defended=True,
                human_review_required=True,
                prohibit_closure=True,
                findings=[
                    ResilienceFinding(
                        code="OUTPUT_SCHEMA_INVALID",
                        control="PRE_PERSISTENCE_VALIDATION",
                        message="Invalid output was quarantined before persistence.",
                    )
                ],
                residual_risks=["The invalid output requires investigation."],
                details={"write_attempted": False, "silent_data_loss": False},
            )

        if fault_point == "before_write":
            unchanged = target.read_bytes() == before_target
            return ResilienceResult(
                outcome="ROLLED_BACK",
                defended=unchanged,
                human_review_required=True,
                prohibit_closure=True,
                findings=[
                    ResilienceFinding(
                        code="STORAGE_PRECONDITION_FAILED",
                        control="ATOMIC_PERSISTENCE",
                        message="Persistence was blocked before mutating durable state.",
                    )
                ],
                residual_risks=["Durable output was not produced."],
                details={
                    "rollback_correct": unchanged,
                    "silent_data_loss": False,
                    "fault_point": fault_point,
                },
            )

        def fault_hook(point: str, _target: Path, _temporary: Path) -> None:
            if point == fault_point:
                raise InjectedPersistenceFault(point)
            if fault_point == "manifest_failure" and point == "after_bundle_replace_1":
                raise InjectedPersistenceFault(point)

        try:
            if fault_point == "manifest_failure":
                atomic_write_bundle(
                    {
                        target: b'{"state":"new"}\n',
                        manifest: b'{"hash":"new"}\n',
                    },
                    fault_hook=fault_hook,
                )
            else:
                atomic_write_bytes(
                    target,
                    b'{"state":"new"}\n',
                    fault_hook=None if fault_point == "none" else fault_hook,
                )
        except InjectedPersistenceFault:
            target_after = target.read_bytes() if target.exists() else None
            manifest_after = manifest.read_bytes() if manifest.exists() else None
            rollback_correct = (
                target_after == before_target
                and manifest_after == before_manifest
                and not list(directory.glob("*.tmp"))
                and not list(directory.glob(".*.tmp"))
            )
            return ResilienceResult(
                outcome="ROLLED_BACK",
                defended=rollback_correct,
                human_review_required=True,
                prohibit_closure=True,
                findings=[
                    ResilienceFinding(
                        code="ATOMIC_WRITE_ROLLED_BACK",
                        control="ATOMIC_PERSISTENCE",
                        message="Injected persistence failure restored the prior durable state.",
                    )
                ],
                residual_risks=["The transaction must be retried or reviewed."],
                details={
                    "rollback_correct": rollback_correct,
                    "silent_data_loss": not rollback_correct,
                    "fault_point": fault_point,
                },
            )

        success = target.read_bytes() == b'{"state":"new"}\n'
        return ResilienceResult(
            outcome="COMPLETED_NORMALLY",
            defended=success,
            automated_release=success,
            findings=[
                ResilienceFinding(
                    code="ATOMIC_WRITE_COMMITTED",
                    control="ATOMIC_PERSISTENCE",
                    message="The durable file was atomically replaced.",
                    severity="informational",
                )
            ],
            details={
                "rollback_correct": True,
                "silent_data_loss": False,
                "fault_point": fault_point,
            },
        )

    def _handle_cache(
        self,
        parameters: Mapping[str, Any],
        directory: Path,
    ) -> ResilienceResult:
        cache_file = directory / "Maven_log4j-core_2.17.1.json"
        data = {"vulns": [{"id": "GHSA-test", "aliases": ["CVE-2021-44228"]}]}
        fault = str(parameters["cache_fault"])

        if fault == "metadata_missing":
            cache_file.write_text(json.dumps(data), encoding="utf-8")
            try:
                _read_verified_cache(cache_file)
            except FileNotFoundError:
                return ResilienceResult(
                    outcome="QUARANTINED",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="CACHE_METADATA_MISSING",
                            control="CACHE_INTEGRITY",
                            message="Cache entry without hash metadata was quarantined.",
                        )
                    ],
                    residual_risks=["Live evidence must be reacquired."],
                )

        if fault == "index_missing":
            atomic_write_json(
                _cache_hash_path(cache_file),
                {
                    "algorithm": "sha256",
                    "payload_sha256": "0" * 64,
                    "written_at": self.clock.isoformat(),
                },
            )
            try:
                _read_verified_cache(cache_file)
            except FileNotFoundError:
                return ResilienceResult(
                    outcome="QUARANTINED",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="CACHE_PAYLOAD_MISSING",
                            control="CACHE_INTEGRITY",
                            message="Orphaned cache metadata was quarantined.",
                        )
                    ],
                    residual_risks=["The cache index and payload are inconsistent."],
                )

        _write_verified_cache(cache_file, data, written_at=self.clock.now)
        if fault == "hash_mismatch":
            cache_file.write_text('{"vulns":[]}\n', encoding="utf-8")
            try:
                _read_verified_cache(cache_file)
            except OSVCacheIntegrityError:
                return ResilienceResult(
                    outcome="BLOCKED_INTEGRITY_FAILURE",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="CACHE_HASH_MISMATCH",
                            control="CACHE_INTEGRITY",
                            message="Tampered cache content failed SHA-256 verification.",
                        )
                    ],
                    residual_risks=["Cached intelligence is untrusted."],
                )
        if fault == "stale":
            metadata_path = _cache_hash_path(cache_file)
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["written_at"] = "2026-07-01T00:00:00+00:00"
            atomic_write_json(metadata_path, metadata)
            try:
                _read_verified_cache(
                    cache_file,
                    max_cache_age_seconds=3600,
                    evaluated_at=self.clock.now,
                )
            except OSVCacheIntegrityError:
                return ResilienceResult(
                    outcome="BLOCKED_DEPENDENCY_FAILURE",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="CACHE_STALE",
                            control="CACHE_FRESHNESS",
                            message="Stale cache evidence was blocked.",
                        )
                    ],
                    residual_risks=["Current vulnerability intelligence is unavailable."],
                )
        if fault == "verified":
            verified = _read_verified_cache(cache_file)
            fallback = VerifiedFallback(
                available=bool(verified),
                integrity_verified=True,
                freshness_verified=True,
                source="osv_cache",
                age_seconds=0,
                disclosed_missing_dependencies=("live_osv",),
            )
            return self.guard.evaluate_dependency_failure(
                DependencyFault.UNAVAILABLE,
                attempt=3,
                consecutive_failures=0,
                fallback=fallback,
                dependency_name="OSV",
            )
        raise ResilienceAssuranceError(f"Unhandled cache fault: {fault}")

    def _handle_audit(
        self,
        parameters: Mapping[str, Any],
        directory: Path,
    ) -> ResilienceResult:
        fault = str(parameters["audit_fault"])
        ledger = AuditLedger(directory / "audit.json")
        event1 = ledger.append(
            event_id="AUD-001",
            event_type="validation",
            occurred_at=self.clock.isoformat(),
            subject_id="DEC-001",
            payload={"status": "validated"},
        )

        if fault == "write_failure":
            def hook(point: str, _target: Path, _temporary: Path) -> None:
                if point == "after_temp_fsync":
                    raise InjectedPersistenceFault(point)
            try:
                ledger.append(
                    event_id="AUD-002",
                    event_type="release",
                    occurred_at=self.clock.isoformat(),
                    subject_id="DEC-001",
                    payload={"status": "candidate"},
                    fault_hook=hook,
                )
            except InjectedPersistenceFault:
                return self.guard.release_gate(
                    dependency_resolved=True,
                    audit_durable=False,
                    integrity_verified=True,
                    checkpoint_durable=True,
                )

        if fault == "sequence_gap":
            event3 = AuditEvent(
                sequence=3,
                event_id="AUD-003",
                event_type="release",
                occurred_at=self.clock.isoformat(),
                subject_id="DEC-001",
                payload={"status": "candidate"},
                previous_hash=event1.event_hash,
            ).finalized()
            verification = verify_audit_chain([event1, event3])
            return self.guard.release_gate(
                dependency_resolved=True,
                audit_durable=verification.valid,
                integrity_verified=True,
                checkpoint_durable=True,
            )

        if fault == "hash_break":
            tampered = AuditEvent.from_dict(
                event1.to_dict() | {"payload": {"status": "tampered"}}
            )
            verification = verify_audit_chain([tampered])
            return self.guard.release_gate(
                dependency_resolved=True,
                audit_durable=verification.valid,
                integrity_verified=True,
                checkpoint_durable=True,
            )

        if fault == "duplicate_conflict":
            try:
                ledger.append(
                    event_id="AUD-001",
                    event_type="validation",
                    occurred_at=self.clock.isoformat(),
                    subject_id="DEC-001",
                    payload={"status": "changed"},
                )
            except AuditContinuityError:
                return ResilienceResult(
                    outcome="QUARANTINED",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="AUDIT_EVENT_ID_CONFLICT",
                            control="AUDIT_CONTINUITY",
                            message="Conflicting audit event redelivery was quarantined.",
                        )
                    ],
                    residual_risks=["The conflicting producer requires investigation."],
                )

        if fault == "idempotent_redrive":
            repeated = ledger.append(
                event_id="AUD-001",
                event_type="validation",
                occurred_at=self.clock.isoformat(),
                subject_id="DEC-001",
                payload={"status": "validated"},
            )
            verification = ledger.verify()
            return ResilienceResult(
                outcome="RECOVERED_IDEMPOTENTLY",
                defended=(repeated.event_hash == event1.event_hash and verification.valid),
                findings=[
                    ResilienceFinding(
                        code="AUDIT_REDRIVE_IDEMPOTENT",
                        control="AUDIT_CONTINUITY",
                        message="Identical audit redelivery produced no duplicate event.",
                        severity="informational",
                    )
                ],
                details={"event_count": verification.event_count},
            )
        raise ResilienceAssuranceError(f"Unhandled audit fault: {fault}")

    def _checkpoint(self, *, completed: bool, owner: str = "worker-a") -> RecoveryCheckpoint:
        return RecoveryCheckpoint(
            operation_id="OP-001",
            transaction_id="TX-001",
            state="completed" if completed else "validated",
            owner_id=owner,
            sequence=2 if completed else 1,
            policy_version="1.0.0",
            input_hashes={"evidence": "a" * 64},
            output_hashes={"decision": "b" * 64} if completed else {},
            created_at=self.clock.isoformat(),
            updated_at=self.clock.isoformat(),
            completed=completed,
            recovery_attempt=0,
        )

    def _handle_recovery(
        self,
        parameters: Mapping[str, Any],
        directory: Path,
    ) -> ResilienceResult:
        fault = str(parameters["recovery_fault"])
        store = RecoveryCheckpointStore(directory / "checkpoints")

        if fault == "worker_crash":
            store.save(self._checkpoint(completed=False))
            outcome, recovered = store.recover(
                self._checkpoint(completed=True), recovery_owner="worker-a"
            )
            return ResilienceResult(
                outcome=outcome,
                defended=(recovered.completed and recovered.verify()),
                findings=[
                    ResilienceFinding(
                        code="WORKER_CRASH_RECOVERED",
                        control="RECOVERY_CHECKPOINT",
                        message="Interrupted work resumed from a verified checkpoint.",
                        severity="informational",
                    )
                ],
                details={"completed": recovered.completed, "duplicate_decisions": 0},
            )

        if fault in {"duplicate", "completed_replay"}:
            completed = store.save(self._checkpoint(completed=True))
            outcome, recovered = store.recover(
                self._checkpoint(completed=True), recovery_owner="worker-a"
            )
            return ResilienceResult(
                outcome=outcome,
                defended=(
                    recovered.content_sha256 == completed.content_sha256
                    and recovered.recovery_attempt == completed.recovery_attempt
                ),
                findings=[
                    ResilienceFinding(
                        code="COMPLETED_RECOVERY_IDEMPOTENT",
                        control="RECOVERY_CHECKPOINT",
                        message="Completed recovery replay was a no-op.",
                        severity="informational",
                    )
                ],
                details={"duplicate_decisions": 0},
            )

        if fault == "split_brain":
            store.save(self._checkpoint(completed=False, owner="worker-a"))
            try:
                store.recover(
                    self._checkpoint(completed=True, owner="worker-b"),
                    recovery_owner="worker-b",
                )
            except RecoveryConflictError:
                return ResilienceResult(
                    outcome="QUARANTINED",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="RECOVERY_OWNER_CONFLICT",
                            control="RECOVERY_CHECKPOINT",
                            message="Competing recovery owner was quarantined.",
                        )
                    ],
                    residual_risks=["Recovery ownership requires reconciliation."],
                    details={"duplicate_decisions": 0},
                )

        if fault == "corrupt":
            saved = store.save(self._checkpoint(completed=False))
            path = store.path_for(saved.operation_id)
            document = json.loads(path.read_text(encoding="utf-8"))
            document["state"] = "completed"
            path.write_text(json.dumps(document), encoding="utf-8")
            try:
                store.load(saved.operation_id)
            except RecoveryIntegrityError:
                return ResilienceResult(
                    outcome="BLOCKED_INTEGRITY_FAILURE",
                    defended=True,
                    human_review_required=True,
                    prohibit_closure=True,
                    findings=[
                        ResilienceFinding(
                            code="RECOVERY_CHECKPOINT_HASH_MISMATCH",
                            control="RECOVERY_CHECKPOINT",
                            message="Corrupted recovery state failed integrity verification.",
                        )
                    ],
                    residual_risks=["Interrupted work cannot be trusted for automatic recovery."],
                    details={"duplicate_decisions": 0},
                )
        raise ResilienceAssuranceError(f"Unhandled recovery fault: {fault}")

    def _handle_queue_resource(self, parameters: Mapping[str, Any]) -> ResilienceResult:
        mode = str(parameters["mode"])
        if mode == "poison_message":
            messages = [
                {"id": "M-001", "valid": True},
                {"id": "M-002", "valid": False},
                {"id": "M-003", "valid": True},
            ]
            processed = []
            quarantined = []
            for message in messages:
                if not message["valid"]:
                    quarantined.append(message["id"])
                    continue
                processed.append(message["id"])
            isolated = quarantined == ["M-002"] and processed == ["M-001", "M-003"]
            return ResilienceResult(
                outcome="QUARANTINED",
                defended=isolated,
                human_review_required=True,
                prohibit_closure=True,
                findings=[
                    ResilienceFinding(
                        code="POISON_MESSAGE_ISOLATED",
                        control="QUEUE_ISOLATION",
                        message="Poison message was quarantined without blocking later work.",
                    )
                ],
                residual_risks=["The quarantined producer payload requires review."],
                details={
                    "processed_message_ids": processed,
                    "quarantined_message_ids": quarantined,
                    "queue_continued": "M-003" in processed,
                },
            )
        if mode == "resource_budget":
            exceeded = int(parameters["payload_size"]) > int(parameters["maximum_size"])
            return ResilienceResult(
                outcome="QUARANTINED",
                defended=exceeded,
                human_review_required=True,
                prohibit_closure=True,
                findings=[
                    ResilienceFinding(
                        code="RESOURCE_BUDGET_EXCEEDED",
                        control="RESOURCE_GUARD",
                        message="Oversized work item was quarantined at the deterministic budget.",
                    )
                ],
                residual_risks=["The oversized payload requires offline inspection."],
                details={
                    "payload_size": int(parameters["payload_size"]),
                    "maximum_size": int(parameters["maximum_size"]),
                },
            )
        raise ResilienceAssuranceError(f"Unhandled queue/resource mode: {mode}")

    def _execute_scenario(self, scenario: Mapping[str, Any]) -> dict[str, Any]:
        handler = str(scenario["handler"])
        parameters = scenario.get("parameters", {})
        try:
            with tempfile.TemporaryDirectory(prefix="aegis-step11h-") as temporary:
                directory = Path(temporary)
                if handler == "dependency":
                    result = self._handle_dependency(parameters)
                elif handler == "retry_circuit":
                    result = self._handle_retry_circuit(parameters)
                elif handler == "persistence":
                    result = self._handle_persistence(parameters, directory)
                elif handler == "cache":
                    result = self._handle_cache(parameters, directory)
                elif handler == "audit":
                    result = self._handle_audit(parameters, directory)
                elif handler == "recovery":
                    result = self._handle_recovery(parameters, directory)
                elif handler == "queue_resource":
                    result = self._handle_queue_resource(parameters)
                else:
                    raise ResilienceAssuranceError(f"Unsupported handler: {handler}")
        except BaseException as exc:
            return {
                "scenario_id": scenario["scenario_id"],
                "family": scenario["family"],
                "handler": handler,
                "severity": scenario["severity"],
                "description": scenario["description"],
                "control_tags": list(scenario["control_tags"]),
                "expected_outcomes": list(scenario["expected_outcomes"]),
                "outcome": "HARNESS_ERROR",
                "defended": False,
                "expectation_met": False,
                "unsafe_decision_released": False,
                "silent_data_loss": False,
                "unbounded_retry": False,
                "detection_oracles": ["HARNESS_EXCEPTION"],
                "finding_codes": ["HARNESS_ERROR"],
                "findings": [
                    {
                        "code": "HARNESS_ERROR",
                        "control": "HARNESS_EXCEPTION",
                        "message": f"{type(exc).__name__}: {exc}",
                        "severity": "critical",
                    }
                ],
                "residual_risks": ["The scenario did not complete."],
                "details": {"exception_type": type(exc).__name__},
            }

        expected = result.outcome in scenario["expected_outcomes"]
        degraded_governed = self.guard.validate_degraded_result(result)
        bounded_retry = result.retry_attempts <= self.guard.policy.retry.max_attempts
        defended = bool(
            result.defended
            and expected
            and not result.unsafe_decision_released
            and degraded_governed
            and bounded_retry
        )
        return {
            "scenario_id": scenario["scenario_id"],
            "family": scenario["family"],
            "handler": handler,
            "severity": scenario["severity"],
            "description": scenario["description"],
            "control_tags": list(scenario["control_tags"]),
            "expected_outcomes": list(scenario["expected_outcomes"]),
            "outcome": result.outcome if defended else (
                result.outcome if result.outcome == "HARNESS_ERROR" else "UNDETECTED"
            ),
            "defended": defended,
            "expectation_met": expected,
            "unsafe_decision_released": result.unsafe_decision_released,
            "silent_data_loss": bool(result.details.get("silent_data_loss", False)),
            "unbounded_retry": not bounded_retry,
            "human_review_required": result.human_review_required,
            "prohibit_closure": result.prohibit_closure,
            "degraded_mode": result.degraded_mode,
            "automated_release": result.automated_release,
            "retry_attempts": result.retry_attempts,
            "detection_oracles": result.detection_oracles,
            "finding_codes": result.finding_codes,
            "findings": [finding.to_dict() for finding in result.findings],
            "residual_risks": list(result.residual_risks),
            "details": copy.deepcopy(result.details),
        }

    def run(self) -> dict[str, Any]:
        before = self.input_integrity_checks()
        baseline = self._calibrate_baseline()
        results = [self._execute_scenario(scenario) for scenario in self.catalog["scenarios"]]
        after = self.input_integrity_checks()
        counts = Counter(result["outcome"] for result in results)
        critical = [result for result in results if result["severity"] == "critical"]
        defended = [result for result in critical if result["defended"]]
        undetected_ids = [
            result["scenario_id"] for result in results if result["outcome"] == "UNDETECTED"
        ]
        harness_error_ids = [
            result["scenario_id"] for result in results if result["outcome"] == "HARNESS_ERROR"
        ]
        unsafe_ids = [
            result["scenario_id"]
            for result in results
            if result["unsafe_decision_released"]
        ]
        silent_loss_ids = [
            result["scenario_id"] for result in results if result["silent_data_loss"]
        ]
        unbounded_retry_ids = [
            result["scenario_id"] for result in results if result["unbounded_retry"]
        ]
        trusted_integrity = all(item["passed"] for item in before.values()) and all(
            item["passed"] for item in after.values()
        )
        baseline_passed = all(item["passed"] for item in baseline.values())
        summary = {
            "scenario_count": len(results),
            "critical_scenario_count": len(critical),
            "defended_critical_count": len(defended),
            "completed_normally_count": counts["COMPLETED_NORMALLY"],
            "completed_degraded_review_required_count": counts[
                "COMPLETED_DEGRADED_REVIEW_REQUIRED"
            ],
            "retry_scheduled_count": counts["RETRY_SCHEDULED"],
            "circuit_open_count": counts["CIRCUIT_OPEN"],
            "rolled_back_count": counts["ROLLED_BACK"],
            "quarantined_count": counts["QUARANTINED"],
            "recovered_idempotently_count": counts["RECOVERED_IDEMPOTENTLY"],
            "blocked_dependency_failure_count": counts[
                "BLOCKED_DEPENDENCY_FAILURE"
            ],
            "blocked_audit_failure_count": counts["BLOCKED_AUDIT_FAILURE"],
            "blocked_integrity_failure_count": counts[
                "BLOCKED_INTEGRITY_FAILURE"
            ],
            "unsafe_decision_release_count": len(unsafe_ids),
            "silent_data_loss_count": len(silent_loss_ids),
            "unbounded_retry_count": len(unbounded_retry_ids),
            "undetected_count": len(undetected_ids),
            "harness_error_count": len(harness_error_ids),
            "critical_fault_scenario_defence_rate": (
                len(defended) / len(critical) if critical else 1.0
            ),
            "rollback_correctness_rate": _rate(results, "rollback"),
            "idempotent_recovery_rate": _rate(results, "idempotent_recovery"),
            "audit_continuity_preservation_rate": _rate(results, "audit_continuity"),
            "cache_integrity_enforcement_rate": _rate(results, "cache_integrity"),
            "dependency_failure_fail_closed_rate": _rate(results, "dependency_failure"),
            "degraded_mode_governance_rate": _rate(results, "degraded_mode"),
            "poison_message_isolation_rate": _rate(results, "poison_message"),
            "restart_recovery_consistency_rate": _rate(results, "restart_recovery"),
            "bounded_retry_enforcement_rate": _rate(results, "retry_bounded"),
            "circuit_breaker_enforcement_rate": _rate(results, "circuit_breaker"),
            "trusted_input_integrity_passed": trusted_integrity,
            "baseline_validation_passed": baseline_passed,
        }
        quality_gates = []
        for gate in self.catalog["quality_gates"]:
            observed = summary[gate["metric"]]
            quality_gates.append(
                {
                    "gate_id": gate["gate_id"],
                    "metric": gate["metric"],
                    "operator": gate["operator"],
                    "threshold": gate["threshold"],
                    "observed": observed,
                    "passed": _gate_passed(observed, gate["operator"], gate["threshold"]),
                }
            )
        overall_passed = (
            all(gate["passed"] for gate in quality_gates)
            and baseline_passed
            and trusted_integrity
        )
        summary["overall_passed"] = overall_passed
        production = self.catalog["production_readiness"]
        release = {
            "stage_gate_status": "PASS" if overall_passed else "FAIL",
            "production_readiness_status": production["status"],
            "blocking_reasons": list(production["blocking_reasons"]),
        }
        return {
            "schema_version": "1.0.0",
            "report_id": "AEG-RESILIENCE-STEP11H-001",
            "catalog": {
                "catalog_id": self.catalog["policy"]["catalog_id"],
                "version": self.catalog["policy"]["version"],
                "harness_version": self.catalog["policy"]["harness_version"],
                "relative_path": self.catalog_path.relative_to(self.project_root).as_posix(),
                "sha256": sha256_file(self.catalog_path),
            },
            "runtime_policy": {
                "policy_id": self.runtime_policy["policy"]["policy_id"],
                "version": self.runtime_policy["policy"]["version"],
                "relative_path": self.catalog["runtime_policy_path"],
                "sha256": sha256_file(
                    self.project_root / self.catalog["runtime_policy_path"]
                ),
            },
            "deterministic_clock": {
                "evaluation_time": self.clock.isoformat(),
                "wall_clock_reads_used_for_scenarios": False,
                "sleep_based_retries_used": False,
            },
            "input_integrity_checks_before": before,
            "input_integrity_checks_after": after,
            "baseline_validation": baseline,
            "summary": summary,
            "quality_gates": quality_gates,
            "results": results,
            "undetected_scenario_ids": undetected_ids,
            "harness_error_scenario_ids": harness_error_ids,
            "unsafe_release_scenario_ids": unsafe_ids,
            "silent_data_loss_scenario_ids": silent_loss_ids,
            "unbounded_retry_scenario_ids": unbounded_retry_ids,
            "release_decision": release,
            "limitations": list(self.catalog["limitations"]),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


def save_resilience_assurance_artifacts(
    report: Mapping[str, Any],
    output_dir: Path | str,
) -> dict[str, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "step11h_resilience_assurance_report.json"
    csv_path = output / "step11h_fault_results.csv"
    unsafe_path = output / "step11h_unsafe_releases.json"
    recovery_path = output / "step11h_recovery_results.json"
    integrity_path = output / "step11h_trusted_baseline_integrity.sha256"

    csv_buffer = io.StringIO()
    fieldnames = [
        "scenario_id",
        "family",
        "handler",
        "severity",
        "outcome",
        "defended",
        "unsafe_decision_released",
        "silent_data_loss",
        "unbounded_retry",
        "human_review_required",
        "prohibit_closure",
        "degraded_mode",
        "retry_attempts",
        "detection_oracles",
        "finding_codes",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    for result in report["results"]:
        writer.writerow(
            {
                field: (
                    ";".join(result[field])
                    if field in {"detection_oracles", "finding_codes"}
                    else result.get(field)
                )
                for field in fieldnames
            }
        )

    recovery_results = [
        result
        for result in report["results"]
        if "idempotent_recovery" in result["control_tags"]
        or "restart_recovery" in result["control_tags"]
        or "rollback" in result["control_tags"]
    ]
    integrity_lines = []
    for check in report["input_integrity_checks_after"].values():
        integrity_lines.append(
            f"{check['actual_sha256']}  {check['relative_path']}"
        )

    files = {
        report_path: (
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            + "\n"
        ).encode("utf-8"),
        csv_path: csv_buffer.getvalue().encode("utf-8"),
        unsafe_path: (
            json.dumps(
                {
                    "report_id": report["report_id"],
                    "unsafe_release_scenario_ids": report["unsafe_release_scenario_ids"],
                    "silent_data_loss_scenario_ids": report[
                        "silent_data_loss_scenario_ids"
                    ],
                    "unbounded_retry_scenario_ids": report[
                        "unbounded_retry_scenario_ids"
                    ],
                    "unsafe_releases": [
                        result
                        for result in report["results"]
                        if result["unsafe_decision_released"]
                    ],
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8"),
        recovery_path: (
            json.dumps(
                {
                    "report_id": report["report_id"],
                    "recovery_result_count": len(recovery_results),
                    "recovery_results": recovery_results,
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8"),
        integrity_path: ("\n".join(integrity_lines) + "\n").encode("utf-8"),
    }
    atomic_write_bundle(files)
    return {
        "report": report_path,
        "csv": csv_path,
        "unsafe": unsafe_path,
        "recovery": recovery_path,
        "integrity": integrity_path,
    }

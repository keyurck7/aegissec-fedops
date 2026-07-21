"""Dependency-gated execution framework for AegisSec assessment stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from src.orchestration.assessment_ledger import (
    BLOCKED,
    FAILED,
    PASSED,
    PASSED_WITH_WARNINGS,
    PENDING,
    RUNNING,
    SKIPPED,
    STAGE_DEFINITIONS,
    AssessmentLedgerError,
    transition_stage,
    verify_ledger,
)


StageAdapter = Callable[
    [dict[str, Any]],
    "StageResult",
]


@dataclass(frozen=True)
class StageResult:
    """Governed result returned by one engine adapter."""

    status: str
    message: str
    reason_code: str | None = None
    warnings: tuple[str, ...] = ()
    outputs: tuple[
        Mapping[str, Any],
        ...
    ] = ()
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        allowed = {
            PASSED,
            PASSED_WITH_WARNINGS,
            BLOCKED,
            FAILED,
        }

        if self.status not in allowed:
            raise ValueError(
                "Adapter result status must be one of: "
                + ", ".join(sorted(allowed))
            )

        if (
            self.status
            == PASSED_WITH_WARNINGS
            and not self.warnings
        ):
            raise ValueError(
                "PASSED_WITH_WARNINGS requires warnings."
            )

        if (
            self.status
            in {
                BLOCKED,
                FAILED,
            }
            and not self.reason_code
        ):
            raise ValueError(
                f"{self.status} requires a reason code."
            )


class DynamicAssessmentOrchestrator:
    """Execute registered adapters while preserving ledger authority."""

    def __init__(
        self,
        *,
        adapters: Mapping[
            str,
            StageAdapter,
        ],
        actor_id: str = (
            "aegissec-dynamic-orchestrator"
        ),
    ) -> None:
        self.adapters = dict(adapters)
        self.actor_id = actor_id

        known_stages = {
            definition["stage_id"]
            for definition
            in STAGE_DEFINITIONS
        }

        unknown = sorted(
            set(self.adapters)
            - known_stages
        )

        if unknown:
            raise ValueError(
                "Adapters registered for unknown stages: "
                + ", ".join(unknown)
            )

    def run_through(
        self,
        *,
        ledger: dict[str, Any],
        context: dict[str, Any],
        through_stage: str,
    ) -> dict[str, Any]:
        valid, errors = verify_ledger(
            ledger
        )

        if not valid:
            raise AssessmentLedgerError(
                "Cannot orchestrate an invalid ledger: "
                + "; ".join(errors)
            )

        definitions = sorted(
            STAGE_DEFINITIONS,
            key=lambda item: item["order"],
        )

        target = next(
            (
                item
                for item in definitions
                if item["stage_id"]
                == through_stage
            ),
            None,
        )

        if target is None:
            raise ValueError(
                f"Unknown target stage: {through_stage}"
            )

        current = ledger

        for definition in definitions:
            if (
                definition["order"]
                > target["order"]
            ):
                break

            stage_id = definition[
                "stage_id"
            ]

            current_status = current[
                "stages"
            ][stage_id]["status"]

            if current_status != PENDING:
                continue

            adapter = self.adapters.get(
                stage_id
            )

            if adapter is None:
                if definition["required"]:
                    current = transition_stage(
                        current,
                        stage_id=stage_id,
                        to_status=BLOCKED,
                        actor_type="SYSTEM",
                        actor_id=self.actor_id,
                        reason_code=(
                            "REQUIRED_STAGE_ADAPTER_MISSING"
                        ),
                        message=(
                            f"No governed adapter is registered "
                            f"for required stage {stage_id}."
                        ),
                        metadata={
                            "adapter_registered": False,
                        },
                    )

                    break

                current = transition_stage(
                    current,
                    stage_id=stage_id,
                    to_status=SKIPPED,
                    actor_type="SYSTEM",
                    actor_id=self.actor_id,
                    reason_code=(
                        "OPTIONAL_STAGE_ADAPTER_NOT_REGISTERED"
                    ),
                    message=(
                        f"Optional stage {stage_id} "
                        "has no registered adapter."
                    ),
                    metadata={
                        "adapter_registered": False,
                    },
                )

                continue

            try:
                current = transition_stage(
                    current,
                    stage_id=stage_id,
                    to_status=RUNNING,
                    actor_type="ENGINE",
                    actor_id=self.actor_id,
                    message=(
                        f"Executing governed adapter "
                        f"for {stage_id}."
                    ),
                    metadata={
                        "adapter_registered": True,
                        "adapter_name": (
                            getattr(
                                adapter,
                                "__name__",
                                type(adapter).__name__,
                            )
                        ),
                    },
                )

            except AssessmentLedgerError:
                raise

            try:
                result = adapter(
                    context
                )

            except Exception as exc:
                current = transition_stage(
                    current,
                    stage_id=stage_id,
                    to_status=FAILED,
                    actor_type="ENGINE",
                    actor_id=self.actor_id,
                    reason_code=(
                        "STAGE_ADAPTER_EXECUTION_FAILED"
                    ),
                    message=(
                        f"{stage_id} adapter raised "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    metadata={
                        "exception_type": (
                            type(exc).__name__
                        ),
                    },
                )

                if (
                    definition["required"]
                    or definition["authority"]
                    == "AUTHORITATIVE"
                ):
                    break

                continue

            current = transition_stage(
                current,
                stage_id=stage_id,
                to_status=result.status,
                actor_type="ENGINE",
                actor_id=self.actor_id,
                reason_code=(
                    result.reason_code
                ),
                message=result.message,
                warnings=list(
                    result.warnings
                ),
                outputs=[
                    dict(item)
                    for item in result.outputs
                ],
                metadata=dict(
                    result.metadata
                ),
            )

            context.setdefault(
                "stage_results",
                {},
            )[stage_id] = result

            if (
                result.status
                in {
                    BLOCKED,
                    FAILED,
                }
                and (
                    definition["required"]
                    or definition["authority"]
                    == "AUTHORITATIVE"
                )
            ):
                break

        valid, errors = verify_ledger(
            current
        )

        if not valid:
            raise AssessmentLedgerError(
                "Orchestration produced an invalid ledger: "
                + "; ".join(errors)
            )

        return current

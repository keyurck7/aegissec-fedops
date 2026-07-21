from __future__ import annotations

import pytest

from src.orchestration.assessment_ledger import (
    verify_ledger,
)
from src.orchestration.per_finding_executor import (
    STATUS_ATTRIBUTION_BLOCKED,
    STATUS_CANONICAL_BLOCKED,
    STATUS_EXECUTED,
    STATUS_IDENTITY_BLOCKED,
    build_execution_manifest,
    verify_execution_manifest,
)
from src.presentation_demo.assessment_review_queue import (
    queue_frame,
    queue_summary,
)


@pytest.fixture(scope="session")
def execution_manifest():
    return build_execution_manifest()


def test_real_execution_distribution(
    execution_manifest,
):
    counts = execution_manifest[
        "statistics"
    ]["execution_status_counts"]

    assert (
        execution_manifest[
            "statistics"
        ]["total_requests"]
        == 403
    )

    assert counts[STATUS_EXECUTED] == 1

    assert (
        counts[
            STATUS_IDENTITY_BLOCKED
        ]
        == 229
    )

    assert (
        counts[
            STATUS_ATTRIBUTION_BLOCKED
        ]
        == 6
    )

    assert (
        counts[
            STATUS_CANONICAL_BLOCKED
        ]
        == 167
    )


def test_log4shell_executes_full_chain(
    execution_manifest,
):
    executed = [
        result
        for result
        in execution_manifest["results"]
        if result["execution_status"]
        == STATUS_EXECUTED
    ]

    assert len(executed) == 1

    result = executed[0]
    summary = result["summary"]

    assert (
        result["cve_id"]
        == "CVE-2021-44228"
    )

    assert (
        result["component"]["name"]
        == "log4j-core"
    )

    assert (
        result["component"]["version"]
        == "2.14.1"
    )

    assert (
        summary["affectedness_status"]
        == "AFFECTED"
    )

    assert (
        summary["ssvc_vector"]
        == "A/O/Y/M"
    )

    assert (
        summary["ssvc_matched_row"]
        == 69
    )

    assert (
        summary["ssvc_outcome"]
        == "OUT_OF_CYCLE"
    )

    assert (
        summary[
            "final_disposition_status"
        ]
        == "NOT_AUTHORIZED"
    )

    assert (
        result["ledger"]["run_status"]
        == "AWAITING_HUMAN_REVIEW"
    )


def test_all_ledgers_verify(
    execution_manifest,
):
    invalid = []

    for result in execution_manifest[
        "results"
    ]:
        valid, errors = verify_ledger(
            result["ledger"]
        )

        if not valid:
            invalid.append(
                {
                    "request_id": (
                        result["request_id"]
                    ),
                    "errors": errors,
                }
            )

    assert invalid == []


def test_blocked_results_are_not_safe(
    execution_manifest,
):
    blocked = [
        result
        for result
        in execution_manifest["results"]
        if result["execution_status"]
        != STATUS_EXECUTED
    ]

    assert blocked

    prohibited = {
        "SAFE",
        "NOT_AFFECTED",
        "not_affected",
    }

    for result in blocked:
        summary = result.get("summary")

        if not isinstance(
            summary,
            dict,
        ):
            continue

        assert (
            summary.get(
                "affectedness_status"
            )
            not in prohibited
        )


def test_manifest_governance(
    execution_manifest,
):
    assert verify_execution_manifest(
        execution_manifest
    )

    governance = execution_manifest[
        "governance"
    ]

    assert (
        governance[
            "affectedness_authority"
        ]
        == "DETERMINISTIC_ENGINE"
    )

    assert (
        governance["policy_authority"]
        == "SSVC"
    )

    assert (
        governance[
            "model_authority"
        ]
        == "ADVISORY_ONLY"
    )

    assert (
        governance[
            "final_disposition_authority"
        ]
        == "HUMAN"
    )

    assert (
        governance[
            "no_match_means_safe"
        ]
        is False
    )

    assert (
        governance[
            "production_readiness"
        ]
        == "BLOCKED"
    )


def test_review_queue_projection(
    execution_manifest,
):
    frame = queue_frame(
        execution_manifest
    )

    summary = queue_summary(
        execution_manifest
    )

    assert len(frame) == 403

    assert summary[
        "executed_count"
    ] == 1

    assert (
        summary["lane_counts"][
            "HUMAN_DECISION_REQUIRED"
        ]
        == 1
    )

    assert (
        summary["lane_counts"][
            "IDENTITY_REMEDIATION"
        ]
        == 229
    )

    assert (
        summary["lane_counts"][
            "EVIDENCE_REMEDIATION"
        ]
        == 173
    )

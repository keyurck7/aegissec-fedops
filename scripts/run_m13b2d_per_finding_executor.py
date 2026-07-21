#!/usr/bin/env python3
"""Run the governed fail-closed per-finding assessment pilot."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.orchestration.per_finding_executor import (
    DEFAULT_OUTPUT,
    STATUS_EXECUTED,
    build_execution_manifest,
    verify_execution_manifest,
    write_json_atomic,
)


def main() -> int:
    print("=" * 76)
    print("MILESTONE 13B.2D FAIL-CLOSED PER-FINDING EXECUTOR")
    print("=" * 76)

    manifest = build_execution_manifest()

    if not verify_execution_manifest(manifest):
        raise RuntimeError(
            "Execution manifest integrity verification failed."
        )

    path, sidecar = write_json_atomic(
        manifest,
        DEFAULT_OUTPUT,
    )

    statistics = manifest["statistics"]
    counts = statistics[
        "execution_status_counts"
    ]

    print(
        "Total requests          :",
        statistics["total_requests"],
    )

    for status, count in sorted(
        counts.items()
    ):
        print(
            f"{status:44}: {count}"
        )

    print(
        "Human decision queue    :",
        statistics[
            "human_decision_queue"
        ],
    )

    print(
        "Identity remediation    :",
        statistics[
            "identity_remediation_queue"
        ],
    )

    print(
        "Evidence remediation    :",
        statistics[
            "evidence_remediation_queue"
        ],
    )

    executed = [
        result
        for result in manifest["results"]
        if result["execution_status"]
        == STATUS_EXECUTED
    ]

    print()
    print(
        "Executed assessments    :",
        len(executed),
    )

    for result in executed:
        summary = result["summary"]

        print()
        print(
            "Request ID             :",
            result["request_id"],
        )

        print(
            "Assessment ID          :",
            result["ledger"][
                "assessment_id"
            ],
        )

        print(
            "CVE                    :",
            result["cve_id"],
        )

        print(
            "Component              :",
            result["component"]["name"],
            result["component"]["version"],
        )

        print(
            "Affectedness           :",
            summary[
                "affectedness_status"
            ],
        )

        print(
            "SSVC vector            :",
            summary["ssvc_vector"],
        )

        print(
            "SSVC row               :",
            summary[
                "ssvc_matched_row"
            ],
        )

        print(
            "SSVC outcome           :",
            summary["ssvc_outcome"],
        )

        print(
            "Run status             :",
            result["ledger"][
                "run_status"
            ],
        )

        print(
            "Final disposition      :",
            summary[
                "final_disposition_status"
            ],
        )

        print(
            "Production readiness   :",
            summary[
                "production_readiness"
            ],
        )

    print()
    print(
        "Manifest               :",
        path.relative_to(ROOT),
    )

    print(
        "Sidecar                :",
        sidecar.relative_to(ROOT),
    )

    print(
        "Manifest SHA-256       :",
        manifest["integrity"][
            "manifest_sha256"
        ],
    )

    assert (
        statistics["total_requests"]
        == 403
    )

    assert len(executed) == 1

    assert (
        executed[0]["summary"][
            "final_disposition_status"
        ]
        == "NOT_AUTHORIZED"
    )

    assert (
        manifest["governance"][
            "production_readiness"
        ]
        == "BLOCKED"
    )

    print()
    print("=" * 76)
    print(
        "MILESTONE 13B.2D "
        "PER-FINDING EXECUTION: PASS"
    )
    print(
        "DETERMINISTIC EXECUTIONS: 1"
    )
    print(
        "ADJACENT-CVE RANGE "
        "INHERITANCE: PROHIBITED"
    )
    print(
        "NO-MATCH-MEANS-SAFE: PROHIBITED"
    )
    print(
        "HUMAN DECISION QUEUE: ACTIVE"
    )
    print(
        "FINAL DISPOSITION: NOT_AUTHORIZED"
    )
    print(
        "PRODUCTION READINESS: BLOCKED"
    )
    print("=" * 76)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

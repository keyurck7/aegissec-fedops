"""Human-review queue projection for per-finding assessments."""

from __future__ import annotations

import json

from pathlib import Path
from typing import Any, Mapping

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DEFAULT_MANIFEST = (
    ROOT
    / "reports"
    / "orchestration"
    / "m13b2d_per_finding_execution.json"
)


def load_execution_manifest(
    path: Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    value = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        value,
        dict,
    ):
        raise ValueError(
            "Execution manifest must be a JSON object."
        )

    return value


def queue_frame(
    manifest: Mapping[str, Any],
) -> pd.DataFrame:
    rows = []

    for result in manifest[
        "results"
    ]:
        component = result[
            "component"
        ]

        summary = result.get(
            "summary"
        )

        if not isinstance(
            summary,
            Mapping,
        ):
            summary = {}

        rows.append(
            {
                "queue_lane": (
                    result[
                        "queue_lane"
                    ]
                ),
                "execution_status": (
                    result[
                        "execution_status"
                    ]
                ),
                "request_id": (
                    result["request_id"]
                ),
                "assessment_id": (
                    result["ledger"][
                        "assessment_id"
                    ]
                ),
                "asset_id": (
                    result["asset_id"]
                ),
                "component": (
                    component.get("name")
                ),
                "version": (
                    component.get(
                        "version"
                    )
                ),
                "ecosystem": (
                    component.get(
                        "ecosystem"
                    )
                ),
                "cve_id": (
                    result["cve_id"]
                ),
                "reason_code": (
                    result.get(
                        "reason_code"
                    )
                ),
                "affectedness": (
                    summary.get(
                        "affectedness_status"
                    )
                ),
                "ssvc_vector": (
                    summary.get(
                        "ssvc_vector"
                    )
                ),
                "ssvc_outcome": (
                    summary.get(
                        "ssvc_outcome"
                    )
                ),
                "final_disposition": (
                    summary.get(
                        "final_disposition_status"
                    )
                ),
                "human_review_required": (
                    summary.get(
                        "human_review_required",
                        (
                            result[
                                "queue_lane"
                            ]
                            == (
                                "HUMAN_DECISION_REQUIRED"
                            )
                        ),
                    )
                ),
                "run_status": (
                    result["ledger"][
                        "run_status"
                    ]
                ),
                "production_readiness": (
                    (
                        summary.get(
                            "production_readiness"
                        )
                    )
                    or "BLOCKED"
                ),
            }
        )

    return pd.DataFrame(
        rows
    )


def queue_summary(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    frame = queue_frame(
        manifest
    )

    lane_counts = (
        frame["queue_lane"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    status_counts = (
        frame["execution_status"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    executed = frame[
        frame["execution_status"]
        == (
            "EXECUTED_AWAITING_HUMAN_REVIEW"
        )
    ]

    return {
        "total_requests": len(
            frame
        ),
        "lane_counts": lane_counts,
        "status_counts": (
            status_counts
        ),
        "executed_count": len(
            executed
        ),
        "production_readiness": (
            manifest["governance"][
                "production_readiness"
            ]
        ),
        "final_disposition_authority": (
            manifest["governance"][
                "final_disposition_authority"
            ]
        ),
        "policy_authority": (
            manifest["governance"][
                "policy_authority"
            ]
        ),
    }

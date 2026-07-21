"""AegisSec per-finding assessment and human-review queue."""

from __future__ import annotations

import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )


import streamlit as st

from src.presentation_demo.assessment_review_queue import (
    load_execution_manifest,
    queue_frame,
    queue_summary,
)


st.set_page_config(
    page_title=(
        "AegisSec Assessment Queue"
    ),
    page_icon="🛡️",
    layout="wide",
)

st.title(
    "AegisSec-FedOps Assessment Queue"
)

st.caption(
    "Fail-closed per-finding execution with "
    "deterministic affectedness, authoritative "
    "SSVC and mandatory human disposition."
)

try:
    manifest = (
        load_execution_manifest()
    )

except Exception as exc:
    st.error(
        "Assessment execution manifest "
        f"is unavailable: {exc}"
    )

    st.stop()

summary = queue_summary(
    manifest
)

frame = queue_frame(
    manifest
)

metric_columns = st.columns(
    5
)

metric_columns[0].metric(
    "Total findings",
    summary[
        "total_requests"
    ],
)

metric_columns[1].metric(
    "Executed",
    summary[
        "executed_count"
    ],
)

metric_columns[2].metric(
    "Human decisions",
    summary[
        "lane_counts"
    ].get(
        "HUMAN_DECISION_REQUIRED",
        0,
    ),
)

metric_columns[3].metric(
    "Identity remediation",
    summary[
        "lane_counts"
    ].get(
        "IDENTITY_REMEDIATION",
        0,
    ),
)

metric_columns[4].metric(
    "Evidence remediation",
    summary[
        "lane_counts"
    ].get(
        "EVIDENCE_REMEDIATION",
        0,
    ),
)

st.warning(
    "Production readiness: BLOCKED. "
    "No automated final disposition is permitted."
)

st.subheader(
    "Execution status distribution"
)

status_frame = (
    frame[
        "execution_status"
    ]
    .value_counts()
    .rename_axis(
        "execution_status"
    )
    .reset_index(
        name="count"
    )
)

st.bar_chart(
    status_frame.set_index(
        "execution_status"
    )
)

st.subheader(
    "Human decision queue"
)

human_queue = frame[
    frame["queue_lane"]
    == "HUMAN_DECISION_REQUIRED"
]

if human_queue.empty:
    st.info(
        "No finding currently awaits "
        "human disposition."
    )

else:
    st.dataframe(
        human_queue,
        use_container_width=True,
        hide_index=True,
    )

st.subheader(
    "Remediation and evidence queue"
)

lane = st.selectbox(
    "Queue lane",
    options=[
        "ALL",
        "IDENTITY_REMEDIATION",
        "EVIDENCE_REMEDIATION",
        "ENGINE_EXCEPTION_REVIEW",
    ],
)

visible = frame

if lane != "ALL":
    visible = frame[
        frame["queue_lane"]
        == lane
    ]

st.dataframe(
    visible,
    use_container_width=True,
    hide_index=True,
)

st.subheader(
    "Governance boundary"
)

st.json(
    {
        "affectedness_authority": (
            manifest[
                "governance"
            ][
                "affectedness_authority"
            ]
        ),
        "policy_authority": (
            manifest[
                "governance"
            ]["policy_authority"]
        ),
        "model_authority": (
            manifest[
                "governance"
            ]["model_authority"]
        ),
        "final_disposition_authority": (
            manifest[
                "governance"
            ][
                "final_disposition_authority"
            ]
        ),
        "no_match_means_safe": (
            manifest[
                "governance"
            ]["no_match_means_safe"]
        ),
        "production_readiness": (
            manifest[
                "governance"
            ]["production_readiness"]
        ),
    }
)

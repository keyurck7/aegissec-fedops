from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.command_center_data import (  # noqa: E402
    load_command_center_bundle,
    recursive_first,
)
from src.presentation_demo.xai_analysis import load_xai_bundle


st.set_page_config(
    page_title="AegisSec-FedOps",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
.block-container {
    padding-top: 1.2rem;
    padding-bottom: 3rem;
}
[data-testid="stSidebar"] {
    background: linear-gradient(
        180deg,
        #071624,
        #123952
    );
}
[data-testid="stSidebar"] * {
    color: #f4fbff;
}
.aegis-hero {
    border-radius: 18px;
    padding: 1.6rem 2rem;
    margin-bottom: 1rem;
    background:
        radial-gradient(
            circle at top right,
            rgba(31, 181, 255, .32),
            transparent 36%
        ),
        linear-gradient(
            135deg,
            #051522,
            #12405e
        );
    color: white;
}
.aegis-hero h1 {
    margin: 0;
}
.aegis-hero p {
    color: #d2f1ff;
    margin-bottom: 0;
}
.aegis-warning {
    border-left: 5px solid #f2a900;
    background: #fff7da;
    color: #382a00;
    padding: .8rem 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
}
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner=False)
def get_bundle(
    refresh_token: int,
):
    del refresh_token
    return load_command_center_bundle()


if "refresh_token" not in st.session_state:
    st.session_state.refresh_token = 0


with st.sidebar:
    st.markdown("## 🛡️ AegisSec-FedOps")
    st.caption(
        "Evidence-governed vulnerability "
        "intelligence and prioritization"
    )

    page = st.radio(
        "Command workspace",
        [
            "Executive Overview",
            "Component Explorer",
            "Threat Intelligence",
            "Real-Data ML Benchmark",
            "XAI and Error Analysis",
            "Governance and Assurance",
            "Pipeline Architecture",
        ],
    )

    st.divider()

    if st.button(
        "Refresh evidence",
        use_container_width=True,
    ):
        st.session_state.refresh_token += 1
        st.cache_data.clear()
        st.rerun()

    st.warning(
        "Development demonstration. "
        "Production readiness is BLOCKED."
    )


bundle = get_bundle(
    st.session_state.refresh_token
)

components = bundle["components"]
sectors = bundle["sectors"]
vulnerabilities = bundle[
    "vulnerabilities"
]
links = bundle[
    "component_vulnerabilities"
]
model = bundle["model_report"]
metrics = model["test_metrics"]


st.markdown(
    """
<div class="aegis-hero">
  <h1>AegisSec-FedOps Command Center</h1>
  <p>
    Live OSV intelligence, CISA KEV,
    FIRST EPSS, governed SQLite analytics,
    SSVC authority and independent ML evidence.
  </p>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class="aegis-warning">
<strong>Authority boundary:</strong>
SSVC remains authoritative. Analytics and ML are
advisory-only. Neither may change affectedness,
authorize remediation or declare production readiness.
</div>
""",
    unsafe_allow_html=True,
)


if page == "Executive Overview":
    columns = st.columns(6)

    columns[0].metric(
        "Components",
        len(components),
    )

    columns[1].metric(
        "Vulnerable",
        int(
            (
                components[
                    "vulnerability_count"
                ]
                > 0
            ).sum()
        ),
    )

    columns[2].metric(
        "KEV components",
        int(
            (
                components["kev_count"]
                > 0
            ).sum()
        ),
    )

    columns[3].metric(
        "Vulnerability links",
        int(
            components[
                "vulnerability_count"
            ].sum()
        ),
    )

    columns[4].metric(
        "Model recall",
        f"{metrics['recall']:.1%}",
    )

    columns[5].metric(
        "Model PR-AUC",
        f"{metrics['pr_auc']:.3f}",
    )

    st.subheader(
        "Operational attention queue"
    )

    display_columns = [
        "component_id",
        "sector",
        "target",
        "criticality",
        "vulnerability_count",
        "kev_count",
        "max_epss",
        "source_signal",
        "analytics_signal",
        "attention_score",
    ]

    st.dataframe(
        components[display_columns],
        use_container_width=True,
        hide_index=True,
    )

    left, right = st.columns(2)

    with left:
        st.subheader(
            "Vulnerability matches by sector"
        )

        chart = (
            sectors[
                [
                    "sector",
                    "vulnerability_matches",
                ]
            ]
            .set_index("sector")
        )

        st.bar_chart(chart)

    with right:
        st.subheader(
            "Average attention by sector"
        )

        chart = (
            sectors[
                [
                    "sector",
                    "average_attention_score",
                ]
            ]
            .set_index("sector")
        )

        st.bar_chart(chart)

    st.download_button(
        "Download component queue",
        data=components.to_csv(
            index=False
        ),
        file_name=(
            "aegissec_component_queue.csv"
        ),
        mime="text/csv",
    )


elif page == "Component Explorer":
    st.subheader(
        "Vulnerable system parts"
    )

    filter_columns = st.columns(3)

    sector_options = sorted(
        components["sector"]
        .dropna()
        .unique()
        .tolist()
    )

    signal_options = sorted(
        components[
            "analytics_signal"
        ]
        .dropna()
        .unique()
        .tolist()
    )

    selected_sectors = (
        filter_columns[0].multiselect(
            "Sector",
            sector_options,
            default=sector_options,
        )
    )

    selected_signals = (
        filter_columns[1].multiselect(
            "Attention signal",
            signal_options,
            default=signal_options,
        )
    )

    search = filter_columns[2].text_input(
        "Search component"
    ).strip().lower()

    filtered = components[
        components["sector"].isin(
            selected_sectors
        )
        & components[
            "analytics_signal"
        ].isin(selected_signals)
    ].copy()

    if search:
        filtered = filtered[
            filtered["target"]
            .astype(str)
            .str.lower()
            .str.contains(
                search,
                regex=False,
            )
            |
            filtered["component_id"]
            .astype(str)
            .str.lower()
            .str.contains(
                search,
                regex=False,
            )
        ]

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )

    if not filtered.empty:
        selected_component = (
            st.selectbox(
                "Inspect component",
                filtered[
                    "component_id"
                ].tolist(),
                format_func=lambda value: (
                    value
                    + " | "
                    + filtered.loc[
                        filtered[
                            "component_id"
                        ]
                        == value,
                        "target",
                    ].iloc[0]
                ),
            )
        )

        row = filtered[
            filtered["component_id"]
            == selected_component
        ].iloc[0]

        metric_columns = st.columns(5)

        metric_columns[0].metric(
            "Attention score",
            f"{row['attention_score']:.2f}",
        )

        metric_columns[1].metric(
            "Maximum EPSS",
            (
                "N/A"
                if pd.isna(
                    row["max_epss"]
                )
                else f"{row['max_epss']:.2%}"
            ),
        )

        metric_columns[2].metric(
            "KEV CVEs",
            int(row["kev_count"]),
        )

        metric_columns[3].metric(
            "Matches",
            int(
                row[
                    "vulnerability_count"
                ]
            ),
        )

        metric_columns[4].metric(
            "Criticality",
            row["criticality"],
        )

        component_findings = links[
            links["component_id"]
            == selected_component
        ]

        st.subheader(
            "Associated vulnerability evidence"
        )

        st.dataframe(
            component_findings,
            use_container_width=True,
            hide_index=True,
        )


elif page == "Threat Intelligence":
    st.subheader(
        "CVE and advisory catalogue"
    )

    threat_columns = st.columns(3)

    kev_only = threat_columns[0].toggle(
        "CISA KEV only"
    )

    minimum_epss = (
        threat_columns[1].slider(
            "Minimum EPSS",
            min_value=0.0,
            max_value=1.0,
            value=0.0,
            step=0.01,
        )
    )

    query = threat_columns[2].text_input(
        "Search vulnerability"
    ).strip().lower()

    filtered = vulnerabilities.copy()

    if kev_only:
        filtered = filtered[
            filtered["kev"] == 1
        ]

    filtered = filtered[
        filtered["epss_score"].fillna(
            0.0
        )
        >= minimum_epss
    ]

    if query:
        filtered = filtered[
            filtered[
                "vulnerability_id"
            ]
            .astype(str)
            .str.lower()
            .str.contains(
                query,
                regex=False,
            )
        ]

    st.caption(
        f"{len(filtered):,} vulnerability "
        "record(s)"
    )

    st.dataframe(
        filtered.head(1000),
        use_container_width=True,
        hide_index=True,
    )

    kev_catalogue = vulnerabilities[
        vulnerabilities["kev"] == 1
    ]

    st.subheader(
        "Known-exploited evidence"
    )

    st.dataframe(
        kev_catalogue,
        use_container_width=True,
        hide_index=True,
    )


elif page == "Real-Data ML Benchmark":
    st.subheader(
        "Current CISA KEV membership benchmark"
    )

    prevalence = model[
        "dataset"
    ]["prevalence"]

    lift = (
        metrics["pr_auc"]
        / prevalence
    )

    top_columns = st.columns(6)

    top_columns[0].metric(
        "Dataset rows",
        f"{model['dataset']['rows']:,}",
    )

    top_columns[1].metric(
        "KEV positives",
        f"{model['dataset']['positive_rows']:,}",
    )

    top_columns[2].metric(
        "Balanced accuracy",
        f"{metrics['balanced_accuracy']:.3f}",
    )

    top_columns[3].metric(
        "Recall",
        f"{metrics['recall']:.3f}",
    )

    top_columns[4].metric(
        "PR-AUC",
        f"{metrics['pr_auc']:.3f}",
    )

    top_columns[5].metric(
        "PR lift",
        f"{lift:.1f}×",
    )

    st.info(
        "This model classifies current CISA KEV "
        "membership. It does not predict future "
        "exploitation and does not replace SSVC."
    )

    st.warning(
        "Precision is "
        f"{metrics['precision']:.1%}. "
        "The benchmark prioritizes recall, so it "
        "produces false positives that require "
        "policy and human review."
    )

    metric_frame = pd.DataFrame(
        {
            "Metric": [
                "Accuracy",
                "Balanced accuracy",
                "Precision",
                "Recall",
                "F1",
                "ROC-AUC",
                "PR-AUC",
                "Brier score",
                "Calibration error",
            ],
            "Value": [
                metrics["accuracy"],
                metrics[
                    "balanced_accuracy"
                ],
                metrics["precision"],
                metrics["recall"],
                metrics["f1"],
                metrics["roc_auc"],
                metrics["pr_auc"],
                metrics["brier_score"],
                metrics[
                    "expected_calibration_error"
                ],
            ],
        }
    )

    st.dataframe(
        metric_frame,
        use_container_width=True,
        hide_index=True,
    )

    confusion = metrics[
        "confusion_matrix"
    ]

    confusion_frame = pd.DataFrame(
        [
            [
                confusion[
                    "true_negative"
                ],
                confusion[
                    "false_positive"
                ],
            ],
            [
                confusion[
                    "false_negative"
                ],
                confusion[
                    "true_positive"
                ],
            ],
        ],
        index=[
            "Actual non-KEV",
            "Actual KEV",
        ],
        columns=[
            "Predicted non-KEV",
            "Predicted KEV",
        ],
    )

    st.subheader(
        "Confusion matrix"
    )

    st.dataframe(
        confusion_frame,
        use_container_width=True,
    )

    candidate_rows = []

    for candidate in bundle[
        "candidates"
    ]:
        candidate_metrics = candidate[
            "validation_metrics"
        ]

        candidate_rows.append(
            {
                "Candidate":
                    candidate[
                        "candidate_name"
                    ],
                "Family":
                    candidate["family"],
                "Balanced accuracy":
                    candidate_metrics[
                        "balanced_accuracy"
                    ],
                "Recall":
                    candidate_metrics[
                        "recall"
                    ],
                "Precision":
                    candidate_metrics[
                        "precision"
                    ],
                "PR-AUC":
                    candidate_metrics[
                        "pr_auc"
                    ],
                "ROC-AUC":
                    candidate_metrics[
                        "roc_auc"
                    ],
            }
        )

    st.subheader(
        "Candidate comparison"
    )

    st.dataframe(
        pd.DataFrame(
            candidate_rows
        ),
        use_container_width=True,
        hide_index=True,
    )

    importance = pd.DataFrame(
        bundle["importance"]
    )

    st.subheader(
        "Permutation feature importance"
    )

    st.bar_chart(
        importance.head(10).set_index(
            "feature"
        )["importance_mean"]
    )

    synthetic = bundle[
        "synthetic_baseline"
    ]

    if synthetic is not None:
        document = synthetic[
            "document"
        ]

        st.subheader(
            "Earlier fail-closed advisory model"
        )

        baseline_columns = st.columns(4)

        baseline_columns[0].metric(
            "Balanced accuracy",
            recursive_first(
                document,
                "balanced_accuracy",
            ),
        )

        baseline_columns[1].metric(
            "Macro F1",
            recursive_first(
                document,
                "macro_f1",
            ),
        )

        baseline_columns[2].metric(
            "Coverage",
            recursive_first(
                document,
                "coverage_rate",
            ),
        )

        baseline_columns[3].metric(
            "Abstention",
            recursive_first(
                document,
                "abstention_rate",
            ),
        )

        st.caption(
            "The earlier four-class model failed "
            "its quality gate, abstained and "
            "preserved SSVC authority."
        )



elif page == "XAI and Error Analysis":
    st.subheader(
        "Explainability and automated weakness analysis"
    )

    xai_bundle = load_xai_bundle()

    xai_report = xai_bundle["report"]
    coefficients = xai_bundle["coefficients"]
    examples = xai_bundle["examples"]
    contributions = xai_bundle["contributions"]
    slices = xai_bundle["slices"]

    reconstruction_error = (
        xai_report[
            "local_explanation"
        ][
            "maximum_probability_reconstruction_error"
        ]
    )

    outcome_counts = (
        xai_report[
            "weakness_analysis"
        ][
            "outcome_counts"
        ]
    )

    columns = st.columns(4)

    columns[0].metric(
        "XAI gate",
        xai_report[
            "quality_gate"
        ][
            "stage_gate"
        ],
    )

    columns[1].metric(
        "False positives",
        outcome_counts[
            "FALSE_POSITIVE"
        ],
    )

    columns[2].metric(
        "False negatives",
        outcome_counts[
            "FALSE_NEGATIVE"
        ],
    )

    columns[3].metric(
        "Reconstruction error",
        format(
            reconstruction_error,
            ".2e",
        ),
    )

    st.info(
        "Positive coefficients move the standardized "
        "Logistic Regression score toward current "
        "CISA KEV membership. Negative coefficients "
        "move it away. These explanations do not "
        "authorize remediation."
    )

    st.subheader(
        "Global directional coefficients"
    )

    st.dataframe(
        coefficients[
            [
                "feature",
                "standardized_coefficient",
                "direction",
                "odds_ratio_per_standard_deviation",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.bar_chart(
        coefficients.set_index(
            "feature"
        )[
            "standardized_coefficient"
        ]
    )

    st.subheader(
        "Representative TP, FP, FN and TN outcomes"
    )

    st.dataframe(
        examples,
        use_container_width=True,
        hide_index=True,
    )

    selected_outcome = st.selectbox(
        "Inspect a local explanation",
        examples[
            "outcome_type"
        ].tolist(),
    )

    selected_contributions = (
        contributions[
            contributions[
                "outcome_type"
            ]
            == selected_outcome
        ]
        .sort_values(
            "absolute_contribution",
            ascending=False,
        )
    )

    st.dataframe(
        selected_contributions[
            [
                "cve",
                "feature",
                "raw_value",
                "standardized_value",
                "logit_contribution",
                "direction",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.bar_chart(
        selected_contributions.head(
            10
        ).set_index(
            "feature"
        )[
            "logit_contribution"
        ]
    )

    st.subheader(
        "Automated weakness slices"
    )

    selected_dimension = st.radio(
        "Slice dimension",
        [
            "epss_band",
            "age_band",
        ],
        horizontal=True,
    )

    selected_slices = slices[
        slices[
            "slice_dimension"
        ]
        == selected_dimension
    ]

    st.dataframe(
        selected_slices,
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(
        "Automated XAI assurance checks"
    )

    check_frame = pd.DataFrame(
        [
            {
                "Check": check_name,
                "Passed": passed,
            }
            for check_name, passed in (
                xai_report[
                    "quality_gate"
                ][
                    "checks"
                ].items()
            )
        ]
    )

    st.dataframe(
        check_frame,
        use_container_width=True,
        hide_index=True,
    )

    st.error(
        "False positives create review burden. "
        "False negatives prohibit replacing CISA "
        "KEV, SSVC or human review. The model remains "
        "advisory-only and production-blocked."
    )


elif page == "Governance and Assurance":
    st.subheader(
        "Governance boundaries"
    )

    governance = model[
        "governance"
    ]

    governance_frame = pd.DataFrame(
        [
            {
                "Control":
                    "Authoritative policy engine",
                "Status":
                    governance[
                        "authoritative_policy_engine"
                    ],
            },
            {
                "Control":
                    "Model authority",
                "Status":
                    governance[
                        "model_authority"
                    ],
            },
            {
                "Control":
                    "Future exploitation claim",
                "Status":
                    governance[
                        "future_exploitation_prediction"
                    ],
            },
            {
                "Control":
                    "Automated disposition",
                "Status":
                    governance[
                        "automated_disposition_permitted"
                    ],
            },
            {
                "Control":
                    "Production readiness",
                "Status":
                    governance[
                        "production_readiness"
                    ],
            },
        ]
    )

    st.dataframe(
        governance_frame,
        use_container_width=True,
        hide_index=True,
    )

    st.markdown(
        """
### Controls implemented

- Schema and identity validation
- SHA-256 artifact integrity
- Source provenance
- Controlled multi-sector inventory
- Live OSV package/version affectedness
- CISA KEV enrichment
- FIRST EPSS enrichment
- SQLite evidence mart
- Leakage-controlled model features
- Natural-prevalence test evaluation
- Calibration and class-imbalance metrics
- SSVC authority preservation
- Automated-disposition prohibition
- Human-review escalation
- Complete repository regression
"""
    )

    st.error(
        "Production remains blocked pending "
        "temporal validation, external validation, "
        "approved operational labels, monitoring "
        "and release authority."
    )


elif page == "Pipeline Architecture":
    st.subheader(
        "End-to-end architecture"
    )

    st.code(
        """
Controlled SBOM and component inventory
                    ↓
Validation, authorization and source trust
                    ↓
Package identity: ecosystem + name + version
                    ↓
Live OSV package/version affectedness
                    ↓
CVE and advisory correlation
                    ↓
CISA KEV + FIRST EPSS enrichment
                    ↓
Sector and asset context
                    ↓
Integrity-verified SQLite risk data mart
              ↙                         ↘
Authoritative SSVC              Independent ML
              ↘                         ↙
       Agreement, abstention and escalation
                    ↓
        Notebook + Streamlit command center
                    ↓
        Human review and audit evidence
""",
        language="text",
    )

    st.markdown(
        """
### What makes this different

This system does not rank vendors or train one
logistic-regression model on a tiny spreadsheet.
It connects real package versions to live public
vulnerability intelligence, preserves evidence
provenance, applies sector context, separates
deterministic policy from machine learning, exposes
model limitations and blocks automatic disposition.
"""
    )

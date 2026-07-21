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
            "Scan a System",
            "Component Explorer",
            "Threat Intelligence",
            "Real-Data ML Benchmark",
            "SSVC Decision and Prediction",
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


elif page == "Scan a System":
    import json

    from src.intake.unified_gateway import (
        InputGatewayError,
    )
    from src.presentation_demo.master_vertical_slice import (
        load_master_vertical_slice,
    )
    from src.presentation_demo.unified_scan_workbench import (
        run_unified_scan,
    )

    st.markdown(
        """
        <div class="aegis-hero">
            <h1>Scan a System</h1>
            <p>
                Upload authorised software evidence, normalize it into
                one governed component inventory, compare it with current
                vulnerability intelligence, and preserve uncertainty for
                human review.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption(
        "Supported evidence: CycloneDX JSON, SPDX JSON, "
        "requirements.txt, package.json, package-lock.json, "
        "component CSV, Syft JSON and Trivy JSON."
    )

    source_mode = st.radio(
        "Evidence source",
        [
            "Controlled demonstration",
            "Upload authorised evidence",
        ],
        horizontal=True,
    )

    payload = None
    filename = None
    media_type = None
    authorized = True

    if source_mode == "Controlled demonstration":
        demonstration_options = {
            "CycloneDX project SBOM": (
                ROOT
                / "data"
                / "demo"
                / "aegissec_demo_project.cdx.json"
            ),
            "Python requirements": (
                ROOT
                / "data"
                / "sample_inputs"
                / "citizen_portal"
                / "requirements.txt"
            ),
            "Node package manifest": (
                ROOT
                / "data"
                / "sample_inputs"
                / "citizen_portal"
                / "package.json"
            ),
        }

        selected_demo = st.selectbox(
            "Demonstration evidence",
            list(
                demonstration_options
            ),
        )

        demo_path = demonstration_options[
            selected_demo
        ]

        if demo_path.is_file():
            payload = demo_path.read_bytes()
            filename = demo_path.name
        else:
            st.error(
                "The selected controlled demonstration "
                "file is missing."
            )

    else:
        authorized = st.checkbox(
            "I confirm that I am authorised to assess "
            "this software evidence.",
            value=False,
            help=(
                "AegisSec rejects unauthorised evidence. "
                "Do not upload production secrets, private "
                "keys or restricted data."
            ),
        )

        uploaded = st.file_uploader(
            "Upload software evidence",
            type=[
                "json",
                "txt",
                "csv",
            ],
            help=(
                "Maximum 20 MB. Archives and executable "
                "content are rejected. Format detection uses "
                "both content and filename."
            ),
            key="unified_system_evidence",
        )

        if uploaded is not None:
            payload = uploaded.getvalue()
            filename = uploaded.name
            media_type = uploaded.type

    if payload is None:
        st.info(
            "Choose a controlled example or upload "
            "authorised software evidence."
        )

    elif (
        source_mode
        == "Upload authorised evidence"
        and not authorized
    ):
        st.warning(
            "Confirm assessment authorisation before "
            "the evidence can enter the pipeline."
        )

    else:
        try:
            result = run_unified_scan(
                payload,
                filename=(
                    filename
                    or "uploaded_evidence"
                ),
                authorized=authorized,
                declared_media_type=(
                    media_type
                ),
            )

        except InputGatewayError as exc:
            st.error(
                "Evidence rejected: "
                + str(exc)
            )

            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Reason code": (
                                exc.reason_code
                            ),
                            "Filename": (
                                exc.filename
                            ),
                            "Content SHA-256": (
                                exc.content_sha256
                            ),
                            "Disposition": (
                                "REJECTED"
                            ),
                        }
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )

        else:
            envelope = result[
                "envelope"
            ]

            statistics = envelope[
                "statistics"
            ]

            trust = envelope["trust"]

            metric_columns = st.columns(6)

            metric_columns[0].metric(
                "Format",
                envelope[
                    "detection"
                ]["format"].replace(
                    "_",
                    " ",
                ),
            )

            metric_columns[1].metric(
                "Components",
                statistics[
                    "component_count"
                ],
            )

            metric_columns[2].metric(
                "Exact identities",
                statistics[
                    "exact_identity_count"
                ],
            )

            metric_columns[3].metric(
                "Unknown versions",
                statistics[
                    "unknown_version_count"
                ],
            )

            metric_columns[4].metric(
                "Vulnerability hints",
                statistics[
                    "vulnerability_hint_count"
                ],
            )

            metric_columns[5].metric(
                "Trust action",
                trust["action"],
            )

            st.success(
                "Unified intake validation: PASS"
            )

            st.caption(
                "File: "
                + envelope["source"][
                    "filename"
                ]
                + " | SHA-256: "
                + envelope["source"][
                    "sha256"
                ]
                + " | Envelope: "
                + envelope["integrity"][
                    "envelope_sha256"
                ]
            )

            if envelope[
                "validation"
            ]["warnings"]:
                st.warning(
                    "\n".join(
                        "• " + warning
                        for warning
                        in envelope[
                            "validation"
                        ]["warnings"]
                    )
                )

            st.download_button(
                "Download governed input envelope",
                data=result[
                    "envelope_bytes"
                ],
                file_name=(
                    envelope["input_id"]
                    + ".input-envelope.json"
                ),
                mime="application/json",
                use_container_width=False,
            )

            (
                components_tab,
                matches_tab,
                unmatched_tab,
                findings_tab,
                snapshot_tab,
                envelope_tab,
                governance_tab,
            ) = st.tabs(
                [
                    "Component inventory",
                    "Matched components",
                    "Unknown components",
                    "Vulnerability evidence",
                    "Janvi snapshot evidence",
                    "Integrity envelope",
                    "Governance",
                ]
            )

            with components_tab:
                components_frame = result[
                    "component_frame"
                ]

                if components_frame.empty:
                    st.info(
                        "No components were extracted."
                    )
                else:
                    st.dataframe(
                        components_frame,
                        use_container_width=True,
                        hide_index=True,
                    )

                st.caption(
                    str(
                        result[
                            "exact_scan_components"
                        ]
                    )
                    + " exact-version components were "
                    "eligible for vulnerability matching."
                )

            scan = result["scan"]

            with matches_tab:
                if scan is None:
                    st.info(
                        result["scan_error"]
                        or (
                            "No governed vulnerability "
                            "matches are available."
                        )
                    )
                else:
                    matched = scan[
                        "matched_components"
                    ]

                    if matched.empty:
                        st.info(
                            "No exact governed component "
                            "matches were found."
                        )
                    else:
                        st.dataframe(
                            matched,
                            use_container_width=True,
                            hide_index=True,
                        )

            with unmatched_tab:
                if scan is None:
                    unknown = result[
                        "component_frame"
                    ]

                    if not unknown.empty:
                        unknown = unknown[
                            unknown[
                                "identity_status"
                            ]
                            != "EXACT"
                        ]

                    if unknown.empty:
                        st.info(
                            "No unresolved component "
                            "identities are available."
                        )
                    else:
                        st.dataframe(
                            unknown,
                            use_container_width=True,
                            hide_index=True,
                        )
                else:
                    unmatched = scan[
                        "unmatched_components"
                    ]

                    if unmatched.empty:
                        st.success(
                            "All scan-eligible components "
                            "matched the governed risk mart."
                        )
                    else:
                        st.dataframe(
                            unmatched,
                            use_container_width=True,
                            hide_index=True,
                        )

            with findings_tab:
                if scan is None:
                    st.info(
                        result["scan_error"]
                        or (
                            "No vulnerability evidence "
                            "was generated."
                        )
                    )
                else:
                    findings = scan[
                        "vulnerability_findings"
                    ]

                    if findings.empty:
                        st.info(
                            "No known vulnerability "
                            "evidence was found."
                        )
                    else:
                        st.dataframe(
                            findings,
                            use_container_width=True,
                            hide_index=True,
                        )

                hints = envelope[
                    "vulnerability_hints"
                ]

                if hints:
                    st.markdown(
                        "#### Scanner-provided advisory hints"
                    )

                    st.dataframe(
                        pd.DataFrame(hints),
                        use_container_width=True,
                        hide_index=True,
                    )

                    st.caption(
                        "Scanner findings remain "
                        "ADVISORY_ONLY and cannot determine "
                        "affectedness or override SSVC."
                    )

            with snapshot_tab:
                snapshot_summary = result[
                    "snapshot_summary"
                ]

                if snapshot_summary is None:
                    st.warning(
                        "Janvi's governed intelligence "
                        "provider is unavailable."
                    )
                else:
                    snapshot_metrics = st.columns(4)

                    snapshot_metrics[0].metric(
                        "Indexed CVEs",
                        snapshot_summary[
                            "total_cves"
                        ],
                    )

                    snapshot_metrics[1].metric(
                        "Snapshot KEV",
                        snapshot_summary[
                            "kev_cves"
                        ],
                    )

                    snapshot_metrics[2].metric(
                        "Missing EPSS",
                        snapshot_summary[
                            "missing_epss"
                        ],
                    )

                    snapshot_metrics[3].metric(
                        "Maximum EPSS",
                        snapshot_summary[
                            "maximum_epss"
                        ],
                    )

                snapshot_frame = result[
                    "snapshot_evidence"
                ]

                if snapshot_frame.empty:
                    st.info(
                        "No CVE identifiers from this "
                        "input matched the July 14 governed "
                        "snapshot."
                    )
                else:
                    st.dataframe(
                        snapshot_frame,
                        use_container_width=True,
                        hide_index=True,
                    )

                st.caption(
                    "This snapshot is historical and "
                    "read-only. Fresher live CISA KEV, "
                    "FIRST EPSS and vendor evidence take "
                    "precedence."
                )

            with envelope_tab:
                preview = dict(envelope)

                if len(
                    preview["components"]
                ) > 100:
                    preview[
                        "components"
                    ] = preview[
                        "components"
                    ][:100]

                    st.info(
                        "The screen preview shows the first "
                        "100 components. The downloaded "
                        "envelope contains the complete set."
                    )

                st.json(preview)

            with governance_tab:
                governance = result[
                    "governance"
                ]

                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Control": (
                                    "Input authority"
                                ),
                                "Status": (
                                    "INPUT_EVIDENCE_ONLY"
                                ),
                            },
                            {
                                "Control": (
                                    "Live source precedence"
                                ),
                                "Status": (
                                    "PRESERVED"
                                ),
                            },
                            {
                                "Control": (
                                    "Historical snapshot"
                                ),
                                "Status": governance[
                                    "snapshot_authority"
                                ],
                            },
                            {
                                "Control": (
                                    "Scanner findings"
                                ),
                                "Status": governance[
                                    "scanner_authority"
                                ],
                            },
                            {
                                "Control": (
                                    "Affectedness authority"
                                ),
                                "Status": (
                                    "DETERMINISTIC_ENGINE"
                                ),
                            },
                            {
                                "Control": (
                                    "Policy authority"
                                ),
                                "Status": governance[
                                    "ssvc_authority"
                                ],
                            },
                            {
                                "Control": (
                                    "Final disposition"
                                ),
                                "Status": governance[
                                    "final_disposition"
                                ],
                            },
                            {
                                "Control": (
                                    "Production readiness"
                                ),
                                "Status": governance[
                                    "production_readiness"
                                ],
                            },
                        ]
                    ),
                    use_container_width=True,
                    hide_index=True,
                )

                st.warning(
                    "A successful intake does not certify "
                    "that a system is safe. Unknown package "
                    "identity, missing versions and absent "
                    "vulnerability matches remain explicit."
                )

            names = (
                result["component_frame"][
                    "name"
                ].astype(str)
                if not result[
                    "component_frame"
                ].empty
                else pd.Series(
                    dtype=str
                )
            )

            has_log4j = names.str.contains(
                "log4j",
                case=False,
                regex=False,
            ).any()

            if has_log4j:
                st.subheader(
                    "Governed SSVC escalation"
                )

                master = (
                    load_master_vertical_slice()
                )

                ssvc = master["summary"]

                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "CVE": ssvc[
                                    "cve_id"
                                ],
                                "SSVC vector": (
                                    ssvc["vector"]
                                ),
                                "Decision row": (
                                    ssvc[
                                        "matched_row"
                                    ]
                                ),
                                "Outcome": ssvc[
                                    "outcome_name"
                                ],
                                "Human review": (
                                    ssvc[
                                        "human_review_required"
                                    ]
                                ),
                                "Final disposition": (
                                    ssvc[
                                        "final_disposition_status"
                                    ]
                                ),
                                "Production": (
                                    ssvc[
                                        "production_readiness"
                                    ]
                                ),
                            }
                        ]
                    ),
                    use_container_width=True,
                    hide_index=True,
                )

                st.error(
                    "Log4j evidence detected. Confirmed "
                    "Log4Shell conditions trigger the "
                    "governed SSVC path and mandatory "
                    "human review."
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



elif page == "SSVC Decision and Prediction":
    from src.presentation_demo.master_vertical_slice import (
        load_master_vertical_slice,
    )

    master = load_master_vertical_slice()
    summary = master["summary"]

    st.subheader(
        "Governed SSVC decision and predictive-policy separation"
    )

    metric_columns = st.columns(6)

    metric_columns[0].metric(
        "SSVC vector",
        summary["vector"],
    )

    metric_columns[1].metric(
        "Decision row",
        summary["matched_row"],
    )

    metric_columns[2].metric(
        "Official outcome",
        summary["outcome_name"],
    )

    metric_columns[3].metric(
        "Stage gate",
        summary["stage_gate"],
    )

    metric_columns[4].metric(
        "Human review",
        str(summary["human_review_required"]),
    )

    metric_columns[5].metric(
        "Production",
        summary["production_readiness"],
    )

    st.info(
        "SSVC converts governed evidence and operational context "
        "into a stakeholder action. It is not a future-exploitation "
        "prediction model."
    )

    st.subheader(
        "Golden Log4Shell decision trace"
    )

    review_record = pd.DataFrame(
        [
            {
                "Decision ID": summary["decision_id"],
                "CVE": summary["cve_id"],
                "SSVC vector": summary["vector"],
                "Matched row": summary["matched_row"],
                "Official outcome": summary["outcome_name"],
                "Human review": summary["human_review_required"],
                "Final disposition": summary[
                    "final_disposition_status"
                ],
                "Production readiness": summary[
                    "production_readiness"
                ],
            }
        ]
    )

    st.dataframe(
        review_record,
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(
        "Governed SSVC decision points"
    )

    st.dataframe(
        master["decision_points"],
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "The official deployer decision uses the governed vector "
        "A/O/Y/M and pinned decision-table row 69. Safety and "
        "mission impact remain part of the human-impact and "
        "review evidence."
    )

    st.subheader(
        "SSVC quality gates"
    )

    st.dataframe(
        master["quality_gates"],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(
        "Evidence, prediction and action boundaries"
    )

    st.dataframe(
        master["claim_boundary"],
        use_container_width=True,
        hide_index=True,
    )

    st.warning(
        "The current custom model classifies current CISA KEV "
        "membership. FIRST EPSS is the current near-term forecast "
        "lane. A custom future-exploitation model is not yet authorized."
    )

    st.subheader(
        "Threshold operating policies"
    )

    operating_points = master[
        "operating_points"
    ].copy()

    for metric_name in [
        "threshold",
        "precision",
        "recall",
        "f1",
        "balanced_accuracy",
    ]:
        if metric_name in operating_points.columns:
            operating_points[metric_name] = (
                operating_points[metric_name]
                .astype(float)
                .round(4)
            )

    st.dataframe(
        operating_points,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "Changing the threshold changes the precision-recall "
        "operating policy. It does not create new predictive evidence."
    )

    frontier = (
        master["threshold_frontier"][
            [
                "recall",
                "precision",
            ]
        ]
        .sort_values("recall")
        .drop_duplicates(subset=["recall"])
        .set_index("recall")
    )

    st.line_chart(frontier)

    st.subheader(
        "Evidence and prediction agreement matrix"
    )

    st.dataframe(
        master["agreement_matrix"],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(
        "Screenshot and low-trust input policy"
    )

    st.dataframe(
        master["screenshot_policy"],
        use_container_width=True,
        hide_index=True,
    )

    st.error(
        "A high exploitation forecast cannot rewrite confirmed "
        "exploitation evidence. Unknown identity or affectedness "
        "fails closed and requires human review. Final disposition "
        "remains unauthorized."
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

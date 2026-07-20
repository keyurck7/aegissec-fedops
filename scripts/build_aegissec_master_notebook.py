#!/usr/bin/env python3
"""Build the unified AegisSec-FedOps presentation notebook."""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).resolve().parents[1]

OUTPUT = (
    ROOT
    / "notebooks"
    / "AegisSec_FedOps_Master_End_to_End_Presentation.ipynb"
)


def markdown(value: str):
    return nbf.v4.new_markdown_cell(
        value
    )


def code(value: str):
    return nbf.v4.new_code_cell(
        value
    )


def main() -> int:
    notebook = nbf.v4.new_notebook()

    notebook["metadata"] = {
        "kernelspec": {
            "display_name":
                "Python 3 (ipykernel)",
            "language":
                "python",
            "name":
                "python3",
        },
        "language_info": {
            "name":
                "python",
            "version":
                "3.12",
        },
    }

    notebook["cells"] = [
        markdown(
            """# AegisSec-FedOps

## End-to-End Evidence, Prediction, SSVC and Human Review

This notebook demonstrates one controlled vertical slice from
component evidence to an auditable policy decision.

**Development boundary**

- SSVC remains authoritative.
- Machine learning remains advisory-only.
- FIRST EPSS is the current near-term forecast lane.
- The custom model classifies current CISA KEV membership.
- Final disposition is not authorized.
- Production readiness remains blocked."""
        ),
        code(
            """from pathlib import Path
import sys
import json
import sqlite3

import matplotlib.pyplot as plt
import pandas as pd
from IPython.display import display

ROOT = Path.cwd().resolve()

if ROOT.name == "notebooks":
    ROOT = ROOT.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.presentation_demo.master_vertical_slice import (
    load_master_vertical_slice,
)
from src.presentation_demo.xai_analysis import (
    load_xai_bundle,
)

master = load_master_vertical_slice()
xai = load_xai_bundle()

DB_PATH = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "aegissec_presentation_risk_mart.sqlite"
)

print("Master vertical slice : PASS")
print("XAI evidence          : PASS")
print("SQLite risk mart      :", DB_PATH.is_file())"""
        ),
        markdown(
            """## 1. The problem

Vulnerability teams do not only need another severity score.
They need a defensible answer to several different questions:

1. What component is present?
2. Is the exact version affected?
3. Is exploitation already confirmed?
4. Could exploitation occur soon?
5. What is the mission and human impact?
6. What action should the stakeholder take?
7. What still requires human authority?"""
        ),
        code(
            """display(
    master["claim_boundary"]
)"""
        ),
        markdown(
            """## 2. End-to-end architecture

```text
SBOM / dependencies / screenshot / API
                  ↓
Validation and Trust
schema, authorization, provenance, freshness, integrity
                  ↓
Component extraction and identity confidence
                  ↓
PURL / CPE / alias / version normalization
                  ↓
OSV / NVD / vendor / CISA KEV / FIRST EPSS
                  ↓
Deterministic affectedness
                  ↓
Governed decision-feature envelope
             ↙                         ↘
      SSVC policy engine          Predictive advisory
             ↘                         ↙
        Agreement, conflict and abstention
                  ↓
        Human review and audit record
```"""
        ),
        markdown(
            """## 3. Controlled portfolio and live risk mart

The presentation inventory contains 16 controlled components
across healthcare, education, public administration and
defence logistics."""
        ),
        code(
            """with sqlite3.connect(DB_PATH) as connection:
    priority_queue = pd.read_sql_query(
        "SELECT * FROM v_top_priority_queue LIMIT 20",
        connection,
    )

    sector_summary = pd.read_sql_query(
        "SELECT * FROM v_sector_summary",
        connection,
    )

display(priority_queue)
display(sector_summary)"""
        ),
        markdown(
            """## 4. Screenshot and low-trust input workflow

A screenshot is an observation, not an authoritative SBOM.

The system may extract a candidate package and version, but
ambiguous identity remains **UNKNOWN** and blocks automated
disposition."""
        ),
        code(
            """display(
    master["screenshot_policy"]
)"""
        ),
        markdown(
            """## 5. Governed artifact chain

The Log4Shell vertical slice reads the actual earlier milestone
artifacts:

- affectedness adjudication
- decision-feature envelope
- official SSVC decision

The notebook does not recreate these decisions."""
        ),
        code(
            """artifact_chain = pd.DataFrame(
    [
        {
            "Stage": "Affectedness",
            "Artifact": master["paths"]["affectedness"],
        },
        {
            "Stage": "Decision features",
            "Artifact": master["paths"]["decision_features"],
        },
        {
            "Stage": "SSVC decision",
            "Artifact": master["paths"]["ssvc"],
        },
        {
            "Stage": "Model report",
            "Artifact": master["paths"]["model_report"],
        },
        {
            "Stage": "Predictions",
            "Artifact": master["paths"]["predictions"],
        },
    ]
)

display(artifact_chain)"""
        ),
        markdown(
            """## 6. Deterministic affectedness

Whether a package version falls inside a vulnerable range is an
evidence and version-semantics question. It should not be guessed
by the machine-learning model."""
        ),
        code(
            """affectedness_flat = (
    pd.json_normalize(
        [master["affectedness"]],
        sep=".",
    )
    .transpose()
    .reset_index()
)

affectedness_flat.columns = [
    "Affectedness field",
    "Value",
]

display(
    affectedness_flat.head(60)
)"""
        ),
        markdown(
            """## 7. Governed decision-feature envelope

The feature envelope binds technical, threat, exposure, mission,
human-impact and trust evidence into a decision-neutral contract."""
        ),
        code(
            """feature_flat = (
    pd.json_normalize(
        [master["feature_envelope"]],
        sep=".",
    )
    .transpose()
    .reset_index()
)

feature_flat.columns = [
    "Feature field",
    "Value",
]

display(
    feature_flat.head(80)
)"""
        ),
        markdown(
            """## 8. SSVC decision tree

The implemented deployer policy resolves:

- exploitation
- system exposure
- automatable exploitation
- safety impact
- mission impact
- human impact

The official vector selects a pinned decision-table row and
stakeholder outcome."""
        ),
        code(
            """summary = master["summary"]

display(
    master["decision_points"]
)

display(
    pd.DataFrame(
        [
            {
                "Decision ID":
                    summary["decision_id"],
                "CVE":
                    summary["cve_id"],
                "SSVC vector":
                    summary["vector"],
                "Matched table row":
                    summary["matched_row"],
                "Official outcome":
                    summary["outcome_name"],
                "Human review":
                    summary[
                        "human_review_required"
                    ],
                "Final disposition":
                    summary[
                        "final_disposition_status"
                    ],
                "Production readiness":
                    summary[
                        "production_readiness"
                    ],
            }
        ]
    )
)"""
        ),
        markdown(
            """## 9. SSVC quality gates and provenance

A decision is accepted only after contract, mapping,
determinism, integrity and governance gates pass."""
        ),
        code(
            """display(
    master["quality_gates"]
)

display(
    master["provenance"]
)

assert summary["stage_gate"] == "PASS"
assert (
    summary["production_readiness"]
    == "BLOCKED"
)
assert (
    summary["final_disposition_status"]
    == "NOT_AUTHORIZED"
)

print("SSVC assurance: PASS")"""
        ),
        markdown(
            """## 10. Prediction and SSVC are different

A high forecast does not prove active exploitation.
Confirmed exploitation evidence must not be rewritten by a
probabilistic model."""
        ),
        code(
            """display(
    master["agreement_matrix"]
)"""
        ),
        markdown(
            """## 11. Current real-data model

The custom model currently classifies **current CISA KEV
membership**. It is useful for advisory triage research, but
it is not a future-exploitation forecast."""
        ),
        code(
            """model_report = master["model_report"]

metrics = model_report[
    "test_metrics"
]

model_summary = pd.DataFrame(
    [
        {
            "Metric":
                "Winning model",
            "Value":
                model_report[
                    "winner"
                ][
                    "candidate_name"
                ],
        },
        {
            "Metric":
                "Label",
            "Value":
                model_report[
                    "governance"
                ][
                    "label_definition"
                ],
        },
        {
            "Metric":
                "Accuracy",
            "Value":
                metrics["accuracy"],
        },
        {
            "Metric":
                "Balanced accuracy",
            "Value":
                metrics[
                    "balanced_accuracy"
                ],
        },
        {
            "Metric":
                "Precision",
            "Value":
                metrics["precision"],
        },
        {
            "Metric":
                "Recall",
            "Value":
                metrics["recall"],
        },
        {
            "Metric":
                "F1",
            "Value":
                metrics["f1"],
        },
        {
            "Metric":
                "ROC-AUC",
            "Value":
                metrics["roc_auc"],
        },
        {
            "Metric":
                "PR-AUC",
            "Value":
                metrics["pr_auc"],
        },
    ]
)

display(model_summary)"""
        ),
        markdown(
            """## 12. Can the model score be improved?

The operating threshold can improve precision or F1, but the
trade-off is lower recall. This changes the review policy rather
than adding new predictive knowledge."""
        ),
        code(
            """display(
    master["operating_points"]
)

frontier = master[
    "threshold_frontier"
]

plt.figure(figsize=(9, 5))

plt.plot(
    frontier["recall"],
    frontier["precision"],
)

plt.xlabel("Recall")
plt.ylabel("Precision")
plt.title(
    "Precision-Recall Operating Frontier"
)
plt.grid(alpha=0.25)
plt.tight_layout()
plt.show()"""
        ),
        markdown(
            """## 13. Near-term exploitation forecast

FIRST EPSS is the present 30-day exploitation forecast lane.

A future AegisSec-native forecasting model requires:

- historical features available at time **t**
- exploitation observed during **t+1 to t+30**
- temporal train, validation and test windows
- no post-event leakage
- calibration and drift monitoring
- explicit abstention and human review"""
        ),
        code(
            """forecast_examples = (
    master["predictions"][
        [
            "cve",
            "epss",
            "percentile",
            "is_kev",
            "predicted_probability",
            "prediction",
        ]
    ]
    .sort_values(
        [
            "epss",
            "percentile",
        ],
        ascending=False,
    )
    .head(20)
)

display(forecast_examples)

print(
    "Current near-term forecast lane:",
    summary[
        "near_term_forecast_lane"
    ],
)

print(
    "Future custom forecast:",
    summary[
        "future_custom_forecast"
    ],
)"""
        ),
        markdown(
            """## 14. Global and local XAI

The Logistic Regression explanation is exact: standardized
feature contributions reconstruct the decision probability."""
        ),
        code(
            """display(
    xai["coefficients"]
)

display(
    xai["examples"]
)

print(
    "Maximum probability reconstruction error:",
    xai["report"][
        "local_explanation"
    ][
        "maximum_probability_reconstruction_error"
    ],
)"""
        ),
        markdown(
            """## 15. Weakness analysis

False positives create analyst workload. False negatives show
why the model cannot replace KEV evidence, SSVC or human review."""
        ),
        code(
            """display(
    xai["slices"]
)

xai_checks = pd.DataFrame(
    [
        {
            "Check": key,
            "Passed": value,
        }
        for key, value in (
            xai["report"][
                "quality_gate"
            ][
                "checks"
            ].items()
        )
    ]
)

display(xai_checks)

assert xai_checks["Passed"].all()

print(
    "Automated XAI assurance: PASS"
)"""
        ),
        markdown(
            """## 16. Human-review record

The human reviewer receives evidence, policy, forecast,
explanations, conflicts and authorization boundaries in one case."""
        ),
        code(
            """human_review = pd.DataFrame(
    [
        {
            "Case":
                summary["decision_id"],
            "CVE":
                summary["cve_id"],
            "SSVC vector":
                summary["vector"],
            "SSVC outcome":
                summary["outcome_name"],
            "Forecast lane":
                summary[
                    "near_term_forecast_lane"
                ],
            "Custom model":
                summary["model_winner"],
            "Model authority":
                summary[
                    "model_authority"
                ],
            "Human review":
                summary[
                    "human_review_required"
                ],
            "Final disposition":
                summary[
                    "final_disposition_status"
                ],
            "Production":
                summary[
                    "production_readiness"
                ],
        }
    ]
)

display(human_review)"""
        ),
        markdown(
            """## 17. Responsible-AI and assurance evidence

The architecture separates evidence, prediction, policy and
human authority. It also preserves integrity, provenance,
testing, explainability, fail-closed behavior and release gates."""
        ),
        code(
            """coverage_rows = []

coverage_files = [
    (
        "Full-source coverage",
        ROOT
        / "reports"
        / "presentation"
        / "full_source_coverage_final.json",
    ),
    (
        "XAI-focused coverage",
        ROOT
        / "reports"
        / "presentation"
        / "xai_coverage_final.json",
    ),
]

for label, path in coverage_files:
    if path.is_file():
        document = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        coverage_rows.append(
            {
                "Evidence": label,
                "Result": (
                    str(
                        round(
                            float(
                                document[
                                    "totals"
                                ][
                                    "percent_covered"
                                ]
                            ),
                            2,
                        )
                    )
                    + "%"
                ),
            }
        )

coverage_rows.extend(
    [
        {
            "Evidence":
                "SSVC stage gate",
            "Result":
                summary["stage_gate"],
        },
        {
            "Evidence":
                "Model authority",
            "Result":
                summary[
                    "model_authority"
                ],
        },
        {
            "Evidence":
                "Final disposition",
            "Result":
                summary[
                    "final_disposition_status"
                ],
        },
        {
            "Evidence":
                "Production readiness",
            "Result":
                summary[
                    "production_readiness"
                ],
        },
    ]
)

display(
    pd.DataFrame(
        coverage_rows
    )
)"""
        ),
        markdown(
            """# Final conclusion

AegisSec-FedOps does not collapse vulnerability management
into one score.

It separates:

1. what is present
2. what is affected
3. what is already exploited
4. what may be exploited soon
5. what the operational impact is
6. what SSVC recommends
7. what still requires human authority

That separation is the foundation of a trustworthy,
auditable and government-oriented system."""
        ),
    ]

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    nbf.write(
        notebook,
        OUTPUT,
    )

    print(
        "Master notebook created:",
        OUTPUT,
    )

    print(
        "Notebook cells:",
        len(
            notebook["cells"]
        ),
    )

    print(
        "MASTER NOTEBOOK BUILD: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

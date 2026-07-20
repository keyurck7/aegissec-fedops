#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).resolve().parents[1]

OUTPUT = (
    ROOT
    / "notebooks"
    / "AegisSec_FedOps_Week3_XAI_Deep_Dive.ipynb"
)


def markdown(value: str):
    return nbf.v4.new_markdown_cell(value)


def code(value: str):
    return nbf.v4.new_code_cell(value)


def main() -> int:
    notebook = nbf.v4.new_notebook()

    notebook["metadata"] = {
        "kernelspec": {
            "display_name": "Python 3 (ipykernel)",
            "language": "python",
            "name": "python3",
        },
        "language_info": {
            "name": "python",
            "version": "3.12",
        },
    }

    notebook["cells"] = [
        markdown(
            """# AegisSec-FedOps Week 3 XAI Deep Dive

## Global, directional, local and weakness explanations

This notebook explains the selected real-data model and
its operational weaknesses.

> The model classifies current CISA KEV membership. It
> does not predict future exploitation, replace SSVC,
> change affectedness or authorize remediation."""
        ),
        code(
            """from pathlib import Path
import sys

import matplotlib.pyplot as plt
import pandas as pd
from IPython.display import display

ROOT = Path.cwd().resolve()

if ROOT.name == "notebooks":
    ROOT = ROOT.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.presentation_demo.xai_analysis import (
    load_xai_bundle,
)

xai = load_xai_bundle()
report = xai["report"]

print(
    "XAI stage gate:",
    report["quality_gate"]["stage_gate"],
)

print(
    "SSVC authority:",
    report["governance"][
        "authoritative_policy_engine"
    ],
)

print(
    "Model authority:",
    report["governance"][
        "model_authority"
    ],
)

print(
    "Production readiness:",
    report["governance"][
        "production_readiness"
    ],
)"""
        ),
        markdown(
            """## 1. Global directional explanation

The winning model is standardized Logistic Regression.

- Positive coefficients move the result toward current
  KEV membership.
- Negative coefficients move it away.
- Odds ratios are shown per one-standard-deviation
  feature change."""
        ),
        code(
            """coefficients = xai["coefficients"]

display(
    coefficients[
        [
            "feature",
            "standardized_coefficient",
            "direction",
            "odds_ratio_per_standard_deviation",
        ]
    ]
)

ordered = coefficients.sort_values(
    "standardized_coefficient"
)

plt.figure(figsize=(10, 6))

plt.barh(
    ordered["feature"],
    ordered["standardized_coefficient"],
)

plt.axvline(
    0.0,
    linewidth=1,
)

plt.title(
    "Directional Logistic Regression Coefficients"
)

plt.xlabel(
    "Standardized coefficient"
)

plt.tight_layout()
plt.show()"""
        ),
        markdown(
            """## 2. Representative decision outcomes

The model evidence includes examples of:

- True positive
- False positive
- False negative
- True negative

The two failure categories are retained deliberately
because they expose model weaknesses."""
        ),
        code(
            """examples = xai["examples"]

display(examples)

counts = report[
    "weakness_analysis"
]["outcome_counts"]

print(
    "True positives:",
    counts["TRUE_POSITIVE"],
)

print(
    "False positives:",
    counts["FALSE_POSITIVE"],
)

print(
    "False negatives:",
    counts["FALSE_NEGATIVE"],
)

print(
    "True negatives:",
    counts["TRUE_NEGATIVE"],
)"""
        ),
        markdown(
            """## 3. Exact local additive explanations

Each standardized feature contributes additively to the
Logistic Regression decision logit.

The intercept plus all feature contributions reconstructs
the predicted probability."""
        ),
        code(
            """contributions = xai["contributions"]

for outcome in [
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "FALSE_NEGATIVE",
    "TRUE_NEGATIVE",
]:
    print()
    print(outcome)

    selected = (
        contributions[
            contributions["outcome_type"]
            == outcome
        ]
        .sort_values(
            "absolute_contribution",
            ascending=False,
        )
        .head(8)
    )

    display(
        selected[
            [
                "cve",
                "feature",
                "raw_value",
                "standardized_value",
                "logit_contribution",
                "direction",
            ]
        ]
    )

    chart = selected.sort_values(
        "logit_contribution"
    )

    plt.figure(figsize=(9, 4))

    plt.barh(
        chart["feature"],
        chart["logit_contribution"],
    )

    plt.axvline(
        0.0,
        linewidth=1,
    )

    plt.title(
        outcome.replace(
            "_",
            " ",
        ).title()
    )

    plt.xlabel(
        "Contribution to decision logit"
    )

    plt.tight_layout()
    plt.show()"""
        ),
        markdown(
            """## 4. Probability reconstruction assurance

The local explanation must mathematically reconstruct
the model probability. This prevents decorative or
approximate explanations from being presented as exact."""
        ),
        code(
            """error = report[
    "local_explanation"
][
    "maximum_probability_reconstruction_error"
]

print(
    "Maximum reconstruction error:",
    error,
)

assert error < 1e-9

print(
    "Local explanation fidelity: PASS"
)"""
        ),
        markdown(
            """## 5. Automated weakness slices

Errors are analyzed by:

- EPSS band
- CVE age band

This shows where review burden and missed detections
concentrate."""
        ),
        code(
            """slices = xai["slices"]

display(slices)

for dimension in [
    "epss_band",
    "age_band",
]:
    print()
    print(dimension)

    selected = slices[
        slices["slice_dimension"]
        == dimension
    ]

    display(selected)"""
        ),
        markdown(
            """## 6. Automated XAI and governance checks"""
        ),
        code(
            """checks = pd.DataFrame(
    [
        {
            "Check": key,
            "Passed": value,
        }
        for key, value in report[
            "quality_gate"
        ]["checks"].items()
    ]
)

display(checks)

assert checks["Passed"].all()

print(
    "Automated XAI checks: PASS"
)"""
        ),
        markdown(
            """## 7. Week 3 conclusion

AegisSec-FedOps now demonstrates:

- Multi-model comparison
- Class-imbalance-aware evaluation
- Global permutation importance
- Directional coefficients
- Odds ratios
- Local TP, FP, FN and TN explanations
- Exact probability reconstruction
- EPSS and CVE-age weakness slices
- Automated XAI assurance tests
- More than 80% focused XAI coverage
- At least 80% full-source coverage
- SSVC authority preservation
- Advisory-only machine learning
- Production blocking

The false-positive burden shows why the model requires
human review. The false negatives show why it cannot
replace CISA KEV evidence or SSVC."""
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

    print("Notebook created :", OUTPUT)
    print("Notebook cells   :", len(notebook["cells"]))
    print("Notebook build   : PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

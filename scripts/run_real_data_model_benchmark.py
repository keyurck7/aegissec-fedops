#!/usr/bin/env python3
"""Build and run the real EPSS and KEV model benchmark."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.real_benchmark_data import (  # noqa: E402
    build_real_benchmark_dataset,
)
from src.presentation_demo.real_model_benchmark import (  # noqa: E402
    run_real_model_benchmark,
)


def main() -> int:
    print("=" * 76)
    print(
        "AEGISSEC-FEDOPS REAL EPSS + "
        "CISA KEV BENCHMARK"
    )
    print("=" * 76)

    print()
    print("===== REAL DATASET BUILD =====")

    manifest = (
        build_real_benchmark_dataset()
    )

    print(
        json.dumps(
            {
                "dataset_id":
                    manifest["dataset_id"],
                "rows":
                    manifest["rows"],
                "positive_rows":
                    manifest[
                        "positive_rows"
                    ],
                "positive_prevalence":
                    manifest[
                        "positive_prevalence"
                    ],
                "snapshot_date":
                    manifest[
                        "epss_source"
                    ]["score_date"],
                "kev_catalog_cves":
                    manifest[
                        "kev_source"
                    ]["validated_cves"],
            },
            indent=2,
            sort_keys=True,
        )
    )

    print()
    print("===== MODEL COMPARISON =====")

    report = (
        run_real_model_benchmark()
    )

    metrics = report[
        "test_metrics"
    ]

    print(
        json.dumps(
            {
                "winner":
                    report["winner"][
                        "candidate_name"
                    ],
                "family":
                    report["winner"][
                        "family"
                    ],
                "threshold":
                    metrics["threshold"],
                "accuracy":
                    metrics["accuracy"],
                "balanced_accuracy":
                    metrics[
                        "balanced_accuracy"
                    ],
                "precision":
                    metrics["precision"],
                "recall":
                    metrics["recall"],
                "f1":
                    metrics["f1"],
                "roc_auc":
                    metrics["roc_auc"],
                "pr_auc":
                    metrics["pr_auc"],
                "brier_score":
                    metrics["brier_score"],
                "expected_calibration_error":
                    metrics[
                        "expected_calibration_error"
                    ],
                "confusion_matrix":
                    metrics[
                        "confusion_matrix"
                    ],
                "development_gate":
                    report[
                        "quality_gate"
                    ][
                        "development_gate"
                    ],
            },
            indent=2,
            sort_keys=True,
        )
    )

    print()
    print("Top feature importance:")

    for row in report[
        "feature_importance"
    ][:8]:
        print(
            f"  {row['feature']:<24} "
            f"{row['importance_mean']:.6f}"
        )

    print()
    print(
        "Label: CURRENT CISA KEV MEMBERSHIP"
    )
    print(
        "Future exploitation claim: FALSE"
    )
    print("SSVC authority: PRESERVED")
    print(
        "Model authority: ADVISORY ONLY"
    )
    print(
        "Production readiness: BLOCKED"
    )
    print(
        "Next stage: notebook and "
        "Streamlit command center"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

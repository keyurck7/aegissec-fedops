#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.command_center_data import (  # noqa: E402
    load_command_center_bundle,
)


def main() -> int:
    bundle = load_command_center_bundle()

    components = bundle["components"]
    sectors = bundle["sectors"]
    model = bundle["model_report"]
    metrics = model["test_metrics"]

    assert len(components) == 16
    assert len(sectors) == 4
    assert int(
        (components["kev_count"] > 0).sum()
    ) == 2

    print("=" * 76)
    print("AEGISSEC-FEDOPS COMMAND CENTER SMOKE TEST")
    print("=" * 76)
    print("Components          :", len(components))
    print("Sectors             :", len(sectors))
    print(
        "KEV components      :",
        int(
            (components["kev_count"] > 0).sum()
        ),
    )
    print(
        "Vulnerability links :",
        int(
            components[
                "vulnerability_count"
            ].sum()
        ),
    )
    print(
        "Winning model       :",
        model["winner"]["candidate_name"],
    )
    print(
        "Balanced accuracy   :",
        metrics["balanced_accuracy"],
    )
    print("Recall              :", metrics["recall"])
    print("PR-AUC              :", metrics["pr_auc"])
    print("SSVC authority      : PRESERVED")
    print("Production readiness: BLOCKED")
    print("COMMAND CENTER SMOKE TEST: PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

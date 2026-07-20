#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.xai_analysis import (  # noqa: E402
    build_xai_artifacts,
)


def main() -> int:
    report = build_xai_artifacts()

    print("=" * 76)
    print(
        "AEGISSEC-FEDOPS XAI AND "
        "WEAKNESS ANALYSIS"
    )
    print("=" * 76)

    print(
        json.dumps(
            {
                "model":
                    report["model"],
                "global_explanation":
                    report[
                        "global_explanation"
                    ],
                "local_explanation":
                    report[
                        "local_explanation"
                    ],
                "weakness_analysis":
                    report[
                        "weakness_analysis"
                    ],
                "quality_gate":
                    report[
                        "quality_gate"
                    ],
                "governance":
                    report["governance"],
            },
            indent=2,
            sort_keys=True,
        )
    )

    print()
    print(
        "XAI stage gate:",
        report[
            "quality_gate"
        ]["stage_gate"],
    )

    print("SSVC authority: PRESERVED")
    print("Model authority: ADVISORY ONLY")
    print("Production readiness: BLOCKED")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run CISA KEV and FIRST EPSS enrichment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.threat_enrichment import (  # noqa: E402
    DEFAULT_INPUT_PATH,
    DEFAULT_OUTPUT_PATH,
    ThreatEnrichmentError,
    build_enriched_report,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Enrich governed OSV intelligence using "
            "CISA KEV and FIRST EPSS."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        report = build_enriched_report(
            input_path=args.input,
            output_path=args.output,
            timeout=args.timeout,
        )
    except ThreatEnrichmentError as exc:
        print(
            f"THREAT ENRICHMENT: FAIL\n{exc}",
            file=sys.stderr,
        )
        return 2

    print("=" * 76)
    print("AEGISSEC-FEDOPS CISA KEV AND FIRST EPSS ENRICHMENT")
    print("=" * 76)

    print(
        json.dumps(
            report["summary"],
            indent=2,
            sort_keys=True,
        )
    )

    print()
    print("Component attention signals:")

    signal_rank = {
        "IMMEDIATE_REVIEW": 0,
        "PRIORITY_REVIEW": 1,
        "SCHEDULED_REVIEW": 2,
        "MONITOR": 3,
    }

    ordered = sorted(
        report["components"],
        key=lambda component: (
            signal_rank.get(
                component["threat_enrichment"][
                    "attention_signal"
                ],
                99,
            ),
            -component["threat_enrichment"][
                "kev_confirmed_cves"
            ],
            -(
                component["threat_enrichment"][
                    "maximum_epss"
                ]
                or 0.0
            ),
            component["component_id"],
        ),
    )

    for component in ordered:
        package = component["package"]
        enrichment = component["threat_enrichment"]

        epss = enrichment["maximum_epss_percent"]
        epss_display = (
            f"{epss:.2f}%"
            if epss is not None
            else "N/A"
        )

        print(
            f"  {component['component_id']} | "
            f"{component['sector']:<22} | "
            f"{enrichment['attention_signal']:<18} | "
            f"KEV={enrichment['kev_confirmed_cves']:<2} | "
            f"Max EPSS={epss_display:<8} | "
            f"{package['name']}@{package['version']}"
        )

    print()
    print(f"Report    : {args.output}")
    print(
        "Integrity : "
        f"{args.output.with_suffix(args.output.suffix + '.sha256')}"
    )
    print("SSVC authority: PRESERVED")
    print("Production readiness: BLOCKED")
    print(
        "Next stage: MILESTONE 12P.3 SQLITE "
        "AND PRESENTATION ANALYTICS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

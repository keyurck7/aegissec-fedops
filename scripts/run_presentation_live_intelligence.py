#!/usr/bin/env python3
"""Run live OSV intelligence against the controlled demo inventory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.presentation_demo.live_intelligence import (  # noqa: E402
    DEFAULT_INVENTORY_PATH,
    DEFAULT_OUTPUT_PATH,
    LiveIntelligenceError,
    ingest_osv,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Query live OSV intelligence for the controlled "
            "AegisSec-FedOps presentation inventory."
        )
    )

    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY_PATH,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=25.0,
    )

    parser.add_argument(
        "--max-details",
        type=int,
        default=100,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        report = ingest_osv(
            inventory_path=args.inventory,
            output_path=args.output,
            timeout=args.timeout,
            max_details=args.max_details,
        )
    except LiveIntelligenceError as exc:
        print(
            f"LIVE INTELLIGENCE INGESTION: FAIL\n{exc}",
            file=sys.stderr,
        )
        return 2

    summary = report["summary"]

    print("=" * 76)
    print("AEGISSEC-FEDOPS LIVE OSV INTELLIGENCE")
    print("=" * 76)
    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

    print()
    print("Component findings:")

    ordered = sorted(
        report["components"],
        key=lambda row: (
            -row["matched_vulnerability_count"],
            row["component_id"],
        ),
    )

    for component in ordered:
        package = component["package"]

        print(
            f"  {component['component_id']} | "
            f"{component['sector']:<22} | "
            f"{package['ecosystem']:<9} | "
            f"{package['name']}@{package['version']} | "
            f"matches={component['matched_vulnerability_count']}"
        )

    print()
    print(f"Report: {args.output}")
    print(
        "Integrity: "
        f"{args.output.with_suffix(args.output.suffix + '.sha256')}"
    )
    print("Live source claim: VERIFIED")
    print("Production readiness: BLOCKED")
    print(
        "Next stage: "
        "MILESTONE 12P.2B KEV AND EPSS ENRICHMENT"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

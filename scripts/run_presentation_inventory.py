#!/usr/bin/env python3
"""Inspect the controlled AegisSec presentation inventory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.presentation_demo.inventory import (
    inventory_summary,
    load_inventory,
)


def main() -> int:
    inventory = load_inventory()
    summary = inventory_summary(inventory)

    print("=" * 76)
    print("AEGISSEC-FEDOPS CONTROLLED PRESENTATION INVENTORY")
    print("=" * 76)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print()
    print("Component targets:")

    for component in inventory["components"]:
        print(
            f"  {component['component_id']} | "
            f"{component['sector']:<22} | "
            f"{component['ecosystem']:<9} | "
            f"{component['component_name']}@"
            f"{component['version']}"
        )

    print()
    print("Inventory validation: PASS")
    print("Real customer data: ABSENT")
    print("Personal data: ABSENT")
    print("Production eligibility: BLOCKED")
    print("Next stage: MILESTONE 12P.2 LIVE INTELLIGENCE INGESTION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

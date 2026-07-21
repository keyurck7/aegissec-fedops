#!/usr/bin/env python3
"""Build the controlled AegisSec CycloneDX presentation SBOM."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

INVENTORY_PATH = (
    ROOT
    / "data"
    / "demo"
    / "aegissec_demo_component_inventory.json"
)

OUTPUT_PATH = (
    ROOT
    / "data"
    / "demo"
    / "aegissec_demo_project.cdx.json"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def property_item(
    name: str,
    value: Any,
) -> dict[str, str]:
    if isinstance(value, bool):
        rendered = (
            "true"
            if value
            else "false"
        )
    else:
        rendered = str(value)

    return {
        "name": name,
        "value": rendered,
    }


def cyclonedx_component(
    component: dict[str, Any],
) -> dict[str, Any]:
    ecosystem = component[
        "ecosystem"
    ]

    component_name = component[
        "component_name"
    ]

    group = ""
    name = component_name

    if ecosystem == "Maven":
        if ":" not in component_name:
            raise ValueError(
                "Maven component name must contain "
                "group and artifact."
            )

        group, name = (
            component_name.split(
                ":",
                1,
            )
        )

    return {
        "type": "library",
        "bom-ref": component[
            "component_id"
        ],
        "group": group,
        "name": name,
        "version": component[
            "version"
        ],
        "purl": component[
            "purl"
        ],
        "properties": [
            property_item(
                "aegissec:ecosystem",
                ecosystem,
            ),
            property_item(
                "aegissec:component_name",
                component_name,
            ),
            property_item(
                "aegissec:asset_id",
                component["asset_id"],
            ),
            property_item(
                "aegissec:asset_name",
                component["asset_name"],
            ),
            property_item(
                "aegissec:sector",
                component["sector"],
            ),
            property_item(
                "aegissec:criticality",
                component[
                    "asset_criticality"
                ],
            ),
            property_item(
                "aegissec:internet_exposed",
                component[
                    "internet_exposed"
                ],
            ),
            property_item(
                "aegissec:externally_accessible",
                component[
                    "externally_accessible"
                ],
            ),
            property_item(
                "aegissec:mission_essential",
                component[
                    "mission_essential"
                ],
            ),
            property_item(
                "aegissec:contains_health_data",
                component[
                    "contains_health_data"
                ],
            ),
            property_item(
                "aegissec:data_sensitivity",
                component[
                    "data_sensitivity"
                ],
            ),
            property_item(
                "aegissec:source_type",
                "CONTROLLED_DEMO_CYCLONEDX_SBOM",
            ),
            property_item(
                "aegissec:production_eligible",
                False,
            ),
        ],
    }


def main() -> int:
    if not INVENTORY_PATH.is_file():
        raise SystemExit(
            "Controlled component inventory "
            "is missing."
        )

    inventory = json.loads(
        INVENTORY_PATH.read_text(
            encoding="utf-8"
        )
    )

    components = inventory.get(
        "components"
    )

    if not isinstance(
        components,
        list,
    ):
        raise SystemExit(
            "Inventory components must be an array."
        )

    if len(components) != 16:
        raise SystemExit(
            "Expected exactly 16 controlled "
            f"components, observed {len(components)}."
        )

    cdx_components = [
        cyclonedx_component(
            component
        )
        for component in components
    ]

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": (
            "urn:uuid:"
            + str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    (
                        "aegissec-fedops-"
                        "controlled-demo-project"
                    ),
                )
            )
        ),
        "version": 1,
        "metadata": {
            "timestamp":
                "2026-07-20T00:00:00Z",
            "authors": [
                {
                    "name": (
                        "AegisSec-FedOps "
                        "controlled demonstration"
                    ),
                }
            ],
            "component": {
                "type": "application",
                "bom-ref":
                    "AEG-DEMO-SYSTEM",
                "name": (
                    "AegisSec Multi-Sector "
                    "Demonstration System"
                ),
                "version": "1.0.0",
            },
            "properties": [
                property_item(
                    "aegissec:authorized_demo",
                    True,
                ),
                property_item(
                    "aegissec:customer_data",
                    False,
                ),
                property_item(
                    "aegissec:personal_data",
                    False,
                ),
                property_item(
                    "aegissec:production_eligible",
                    False,
                ),
            ],
        },
        "components": cdx_components,
    }

    OUTPUT_PATH.write_text(
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    digest = sha256_file(
        OUTPUT_PATH
    )

    sidecar = Path(
        f"{OUTPUT_PATH}.sha256"
    )

    sidecar.write_text(
        f"{digest}  "
        f"{OUTPUT_PATH.name}\n",
        encoding="utf-8",
    )

    print("=" * 78)
    print(
        "AEGISSEC-FEDOPS CONTROLLED "
        "CYCLONEDX SBOM"
    )
    print("=" * 78)

    print(
        "SBOM path       :",
        OUTPUT_PATH,
    )

    print(
        "CycloneDX spec  :",
        document["specVersion"],
    )

    print(
        "Components      :",
        len(cdx_components),
    )

    print(
        "Serial number   :",
        document["serialNumber"],
    )

    print(
        "SHA-256         :",
        digest,
    )

    print(
        "Customer data   : ABSENT"
    )

    print(
        "Personal data   : ABSENT"
    )

    print(
        "Production use  : BLOCKED"
    )

    print(
        "CONTROLLED SBOM BUILD: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

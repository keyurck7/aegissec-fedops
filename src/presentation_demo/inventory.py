"""Validation for the controlled presentation component inventory."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

INVENTORY_PATH = Path(
    "data/demo/aegissec_demo_component_inventory.json"
)

ALLOWED_ECOSYSTEMS = {
    "Maven",
    "PyPI",
    "npm",
    "RubyGems",
    "NuGet",
    "Go",
}

ALLOWED_SECTORS = {
    "HEALTHCARE",
    "PUBLIC_ADMINISTRATION",
    "DEFENCE_LOGISTICS",
    "EDUCATION",
}

ALLOWED_CRITICALITY = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

ALLOWED_SENSITIVITY = {
    "PUBLIC",
    "INTERNAL",
    "CONFIDENTIAL",
    "RESTRICTED",
}

ALLOWED_RUNTIME_REACHABILITY = {
    "REACHABLE",
    "NOT_REACHABLE",
    "UNKNOWN",
}

COMPONENT_ID_PATTERN = re.compile(r"^AEG-CMP-[0-9]{4}$")

REQUIRED_COMPONENT_FIELDS = {
    "component_id",
    "component_name",
    "display_name",
    "version",
    "ecosystem",
    "purl",
    "asset_id",
    "asset_name",
    "sector",
    "asset_criticality",
    "deployment_environment",
    "internet_exposed",
    "externally_accessible",
    "mission_essential",
    "contains_health_data",
    "data_sensitivity",
    "runtime_reachability",
    "source_type",
    "source_trust",
    "authorized_demo",
}


class InventoryValidationError(ValueError):
    """Raised when the controlled inventory violates its contract."""


def load_inventory(
    path: Path | str = INVENTORY_PATH,
) -> dict[str, Any]:
    """Load and validate the controlled inventory."""

    inventory_path = Path(path)

    if not inventory_path.is_file():
        raise InventoryValidationError(
            f"Inventory file does not exist: {inventory_path}"
        )

    try:
        document = json.loads(
            inventory_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise InventoryValidationError(
            f"Inventory is not valid JSON: {exc}"
        ) from exc

    validate_inventory(document)
    return document


def _require_nonempty_string(
    component: Mapping[str, Any],
    field: str,
) -> str:
    value = component.get(field)

    if not isinstance(value, str) or not value.strip():
        raise InventoryValidationError(
            f"{component.get('component_id', '<unknown>')}: "
            f"{field} must be a non-empty string"
        )

    return value.strip()


def _require_boolean(
    component: Mapping[str, Any],
    field: str,
) -> bool:
    value = component.get(field)

    if not isinstance(value, bool):
        raise InventoryValidationError(
            f"{component.get('component_id', '<unknown>')}: "
            f"{field} must be boolean"
        )

    return value


def validate_inventory(
    document: Mapping[str, Any],
) -> None:
    """Validate inventory identity, governance and component records."""

    if not isinstance(document, Mapping):
        raise InventoryValidationError(
            "Inventory root must be an object"
        )

    if document.get("authorized_demo") is not True:
        raise InventoryValidationError(
            "Inventory must be explicitly authorized for demonstration"
        )

    if document.get("production_eligible") is not False:
        raise InventoryValidationError(
            "Presentation inventory must remain production-ineligible"
        )

    if document.get("contains_real_customer_data") is not False:
        raise InventoryValidationError(
            "Presentation inventory cannot contain real customer data"
        )

    if document.get("contains_personal_data") is not False:
        raise InventoryValidationError(
            "Presentation inventory cannot contain personal data"
        )

    components = document.get("components")

    if not isinstance(components, list) or not components:
        raise InventoryValidationError(
            "Inventory must contain at least one component"
        )

    component_ids: set[str] = set()
    component_targets: set[tuple[str, str, str]] = set()

    for index, component in enumerate(components, start=1):
        if not isinstance(component, Mapping):
            raise InventoryValidationError(
                f"Component {index} must be an object"
            )

        missing = REQUIRED_COMPONENT_FIELDS - set(component)

        if missing:
            raise InventoryValidationError(
                f"Component {index} is missing fields: "
                f"{sorted(missing)}"
            )

        component_id = _require_nonempty_string(
            component,
            "component_id",
        )

        if not COMPONENT_ID_PATTERN.fullmatch(component_id):
            raise InventoryValidationError(
                f"Invalid component ID: {component_id}"
            )

        if component_id in component_ids:
            raise InventoryValidationError(
                f"Duplicate component ID: {component_id}"
            )

        component_ids.add(component_id)

        name = _require_nonempty_string(
            component,
            "component_name",
        )
        version = _require_nonempty_string(component, "version")
        ecosystem = _require_nonempty_string(
            component,
            "ecosystem",
        )
        purl = _require_nonempty_string(component, "purl")
        sector = _require_nonempty_string(component, "sector")
        criticality = _require_nonempty_string(
            component,
            "asset_criticality",
        )
        sensitivity = _require_nonempty_string(
            component,
            "data_sensitivity",
        )
        reachability = _require_nonempty_string(
            component,
            "runtime_reachability",
        )
        source_trust = _require_nonempty_string(
            component,
            "source_trust",
        )

        if ecosystem not in ALLOWED_ECOSYSTEMS:
            raise InventoryValidationError(
                f"{component_id}: unsupported ecosystem {ecosystem}"
            )

        if sector not in ALLOWED_SECTORS:
            raise InventoryValidationError(
                f"{component_id}: unsupported sector {sector}"
            )

        if criticality not in ALLOWED_CRITICALITY:
            raise InventoryValidationError(
                f"{component_id}: invalid criticality {criticality}"
            )

        if sensitivity not in ALLOWED_SENSITIVITY:
            raise InventoryValidationError(
                f"{component_id}: invalid sensitivity {sensitivity}"
            )

        if reachability not in ALLOWED_RUNTIME_REACHABILITY:
            raise InventoryValidationError(
                f"{component_id}: invalid reachability {reachability}"
            )

        if source_trust != "HIGH":
            raise InventoryValidationError(
                f"{component_id}: controlled fixture must be HIGH trust"
            )

        if not purl.startswith("pkg:"):
            raise InventoryValidationError(
                f"{component_id}: invalid PURL {purl}"
            )

        for field in (
            "internet_exposed",
            "externally_accessible",
            "mission_essential",
            "contains_health_data",
            "authorized_demo",
        ):
            _require_boolean(component, field)

        if component["authorized_demo"] is not True:
            raise InventoryValidationError(
                f"{component_id}: component is not authorized"
            )

        target = (ecosystem, name, version)

        if target in component_targets:
            raise InventoryValidationError(
                f"Duplicate package target: {target}"
            )

        component_targets.add(target)


def inventory_summary(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Produce a stable presentation summary."""

    validate_inventory(document)

    components = document["components"]

    sectors = Counter(
        component["sector"] for component in components
    )
    ecosystems = Counter(
        component["ecosystem"] for component in components
    )
    criticality = Counter(
        component["asset_criticality"]
        for component in components
    )

    return {
        "inventory_id": document["inventory_id"],
        "components": len(components),
        "sectors": dict(sorted(sectors.items())),
        "ecosystems": dict(sorted(ecosystems.items())),
        "criticality": dict(sorted(criticality.items())),
        "internet_exposed": sum(
            bool(component["internet_exposed"])
            for component in components
        ),
        "mission_essential": sum(
            bool(component["mission_essential"])
            for component in components
        ),
        "health_data_assets": sum(
            bool(component["contains_health_data"])
            for component in components
        ),
        "production_eligible": document["production_eligible"],
        "authorized_demo": document["authorized_demo"],
    }

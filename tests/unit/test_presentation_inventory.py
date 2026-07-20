"""Tests for the presentation component inventory."""

from __future__ import annotations

import copy

import pytest

from src.presentation_demo.inventory import (
    InventoryValidationError,
    inventory_summary,
    load_inventory,
    validate_inventory,
)


def test_controlled_inventory_is_valid() -> None:
    inventory = load_inventory()
    summary = inventory_summary(inventory)

    assert summary["components"] == 16
    assert len(summary["sectors"]) == 4
    assert summary["authorized_demo"] is True
    assert summary["production_eligible"] is False


def test_every_sector_has_multiple_components() -> None:
    summary = inventory_summary(load_inventory())

    assert all(
        count >= 3
        for count in summary["sectors"].values()
    )


def test_inventory_contains_multiple_ecosystems() -> None:
    summary = inventory_summary(load_inventory())

    assert len(summary["ecosystems"]) >= 5


def test_inventory_contains_mission_and_exposure_context() -> None:
    summary = inventory_summary(load_inventory())

    assert summary["mission_essential"] >= 8
    assert summary["internet_exposed"] >= 5
    assert summary["health_data_assets"] >= 4


def test_duplicate_component_id_is_rejected() -> None:
    inventory = load_inventory()
    mutated = copy.deepcopy(inventory)

    mutated["components"][1]["component_id"] = (
        mutated["components"][0]["component_id"]
    )

    with pytest.raises(
        InventoryValidationError,
        match="Duplicate component ID",
    ):
        validate_inventory(mutated)


def test_duplicate_package_target_is_rejected() -> None:
    inventory = load_inventory()
    mutated = copy.deepcopy(inventory)

    for field in (
        "component_name",
        "version",
        "ecosystem",
    ):
        mutated["components"][1][field] = (
            mutated["components"][0][field]
        )

    with pytest.raises(
        InventoryValidationError,
        match="Duplicate package target",
    ):
        validate_inventory(mutated)


def test_real_customer_data_is_rejected() -> None:
    inventory = load_inventory()
    mutated = copy.deepcopy(inventory)
    mutated["contains_real_customer_data"] = True

    with pytest.raises(
        InventoryValidationError,
        match="real customer data",
    ):
        validate_inventory(mutated)


def test_production_eligibility_is_rejected() -> None:
    inventory = load_inventory()
    mutated = copy.deepcopy(inventory)
    mutated["production_eligible"] = True

    with pytest.raises(
        InventoryValidationError,
        match="production-ineligible",
    ):
        validate_inventory(mutated)


def test_unsupported_ecosystem_is_rejected() -> None:
    inventory = load_inventory()
    mutated = copy.deepcopy(inventory)
    mutated["components"][0]["ecosystem"] = "MysteryPkg"

    with pytest.raises(
        InventoryValidationError,
        match="unsupported ecosystem",
    ):
        validate_inventory(mutated)

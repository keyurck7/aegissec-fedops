from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from src.assurance.compound_attack_assurance import (
    CompoundAttackAssuranceHarness,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = (
    PROJECT_ROOT / "policies" / "assurance" / "compound_attack_chain_catalog_v1.yaml"
)
SCHEMA_PATH = (
    PROJECT_ROOT / "schemas" / "aegis_compound_attack_assurance_report.schema.json"
)


def test_catalog_contains_30_unique_critical_cross_layer_chains() -> None:
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    chains = catalog["chains"]
    assert len(chains) == 30
    assert len({item["chain_id"] for item in chains}) == 30
    assert all(item["severity"] == "critical" for item in chains)
    assert all(
        len({step["layer"] for step in item["ordered_steps"]}) >= 2
        for item in chains
    )


def test_trusted_input_integrity_passes() -> None:
    harness = CompoundAttackAssuranceHarness()
    checks = harness.input_integrity_checks()
    assert checks
    assert all(item["passed"] for item in checks.values())


def test_source_ids_resolve_to_real_assurance_controls() -> None:
    harness = CompoundAttackAssuranceHarness()
    maps = {
        "tamper": harness.tamper_items,
        "hostile_input": harness.hostile_items,
        "policy_mutation": harness.mutation_items,
        "metamorphic": harness.metamorphic_items,
    }
    for chain in harness.catalog["chains"]:
        for step in chain["ordered_steps"]:
            assert step["source_id"] in maps[step["layer"]]


def test_real_tamper_and_hostile_steps_are_defended() -> None:
    harness = CompoundAttackAssuranceHarness()
    tamper = harness._execute_step(
        {"layer": "tamper", "source_id": "TAMPER-PATH-TRAVERSAL-001"}
    )
    hostile = harness._execute_step(
        {"layer": "hostile_input", "source_id": "INPUT-CVE-CYRILLIC-001"}
    )
    assert tamper["defended"] is True
    assert hostile["defended"] is True


def test_real_policy_mutation_step_is_killed() -> None:
    harness = CompoundAttackAssuranceHarness()
    result = harness._execute_step(
        {
            "layer": "policy_mutation",
            "source_id": "MUT-KEV-ACTION-DOWNGRADE-001",
        }
    )
    assert result["defended"] is True
    assert result["raw_outcome"] == "KILLED_BY_ASSURANCE"


def test_real_metamorphic_step_passes() -> None:
    harness = CompoundAttackAssuranceHarness()
    result = harness._execute_step(
        {"layer": "metamorphic", "source_id": "META-KEV-ADD-001"}
    )
    assert result["defended"] is True
    assert result["raw_outcome"] == "PASSED"


def test_single_compound_chain_is_fail_closed_and_multi_control() -> None:
    harness = CompoundAttackAssuranceHarness()
    result = harness.execute_chain(harness.catalog["chains"][0])
    assert result["defended"] is True
    assert result["unsafe_decision_released"] is False
    assert result["multi_control_detected"] is True
    assert result["order_consistent"] is True


def test_full_compound_campaign_passes_every_gate() -> None:
    report = CompoundAttackAssuranceHarness().run()
    summary = report["summary"]
    assert summary["chain_count"] == 30
    assert summary["defended_critical_count"] == 30
    assert summary["undetected_count"] == 0
    assert summary["harness_error_count"] == 0
    assert summary["unsafe_decision_release_count"] == 0
    assert summary["critical_compound_chain_defence_rate"] == 1.0
    assert summary["fail_closed_chain_handling_rate"] == 1.0
    assert summary["multi_control_detection_rate"] == 1.0
    assert summary["order_sensitive_chain_consistency_rate"] == 1.0
    assert summary["cross_layer_integrity_defence_rate"] == 1.0
    assert summary["trusted_input_integrity_passed"] is True
    assert summary["overall_passed"] is True
    assert report["undetected_chain_ids"] == []
    assert report["unsafe_release_chain_ids"] == []


def test_generated_report_validates_against_schema() -> None:
    report = CompoundAttackAssuranceHarness().run()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(report)) == []


def test_cli_runner_imports_project_from_any_working_directory(tmp_path: Path) -> None:
    runner = PROJECT_ROOT / "scripts" / "run_step11f_compound_attack_assurance.py"
    result = subprocess.run(
        [sys.executable, str(runner), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Run Step 11F compound attack-chain assurance." in result.stdout

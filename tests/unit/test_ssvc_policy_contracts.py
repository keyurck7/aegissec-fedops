from __future__ import annotations

import itertools
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policies/decision/ssvc_deployer_policy_v1.yaml"
TABLE = ROOT / "policies/decision/ssvc_deployer_decision_table_v1.yaml"
HUMAN = ROOT / "policies/decision/ssvc_human_impact_decision_table_v1.yaml"
MAPPING = ROOT / "policies/decision/ssvc_mapping_policy_v1.yaml"
REASONS = ROOT / "policies/decision/ssvc_reason_codes_v1.yaml"
SCHEMA = ROOT / "schemas/aegis_ssvc_policy_decision.schema.json"


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_contract_files_parse_and_schema_is_valid() -> None:
    for path in (POLICY, TABLE, HUMAN, MAPPING, REASONS):
        assert load_yaml(path)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_official_versions_are_pinned() -> None:
    policy = load_yaml(POLICY)
    points = policy["decision_points"]
    assert points["exploitation"]["version"] == "1.1.0"
    assert points["system_exposure"]["version"] == "1.0.1"
    assert points["automatable"]["version"] == "2.0.0"
    assert points["safety_impact"]["version"] == "2.0.1"
    assert points["mission_impact"]["version"] == "2.0.0"
    assert points["human_impact"]["version"] == "2.0.2"
    assert policy["policy"]["official_model"]["decision_table_version"] == "1.0.0"


def test_deployer_table_is_complete_unique_and_row_ordered() -> None:
    table = load_yaml(TABLE)
    rows = table["rows"]
    assert len(rows) == 72
    assert [row["row"] for row in rows] == list(range(72))
    observed = {
        (
            row["inputs"]["exploitation"]["key"],
            row["inputs"]["system_exposure"]["key"],
            row["inputs"]["automatable"]["key"],
            row["inputs"]["human_impact"]["key"],
        )
        for row in rows
    }
    expected = set(itertools.product("NPA", "SCO", "NY", ("L", "M", "H", "VH")))
    assert observed == expected


def test_human_impact_table_is_complete_unique_and_pinned() -> None:
    table = load_yaml(HUMAN)
    rows = table["rows"]
    assert len(rows) == 16
    assert [row["row"] for row in rows] == list(range(16))
    observed = {(r["safety_impact_key"], r["mission_impact_key"]) for r in rows}
    assert observed == set(itertools.product(("N", "M", "R", "C"), ("D", "MSC", "MEF", "MF")))
    lookup = {(r["safety_impact_key"], r["mission_impact_key"]): r["human_impact_key"] for r in rows}
    assert lookup[("M", "MEF")] == "M"
    assert lookup[("R", "MEF")] == "H"
    assert lookup[("C", "D")] == "VH"


def test_decision_table_is_monotonic() -> None:
    policy = load_yaml(POLICY)
    table = load_yaml(TABLE)
    outcome_rank = {key: value["rank"] for key, value in policy["outcomes"].items()}
    orders = {
        "exploitation": {v: i for i, v in enumerate(("N", "P", "A"))},
        "system_exposure": {v: i for i, v in enumerate(("S", "C", "O"))},
        "automatable": {v: i for i, v in enumerate(("N", "Y"))},
        "human_impact": {v: i for i, v in enumerate(("L", "M", "H", "VH"))},
    }
    lookup = {}
    for row in table["rows"]:
        key = tuple(row["inputs"][name]["key"] for name in ("exploitation", "system_exposure", "automatable", "human_impact"))
        lookup[key] = outcome_rank[row["outcome_key"]]
    keys = list(lookup)
    for a in keys:
        for b in keys:
            if all(orders[name][av] <= orders[name][bv] for name, av, bv in zip(orders, a, b)):
                assert lookup[a] <= lookup[b]


def test_mapping_policy_fails_closed_and_preserves_separation() -> None:
    policy = load_yaml(POLICY)
    mapping = load_yaml(MAPPING)["mappings"]
    governance = policy["governance"]
    assert mapping["exploitation"]["unknown_action"] == "BLOCK"
    assert mapping["automatable"]["unknown_action"] == "BLOCK"
    assert mapping["human_impact"]["unknown_action"] == "BLOCK"
    assert mapping["system_exposure"]["unknown_action"] == "ASSUME_OPEN_WITH_RECORDED_JUSTIFICATION"
    assert mapping["automatable"]["cvss_only_inference_allowed"] is False
    assert governance["official_and_extension_outputs_must_remain_separate"] is True
    assert governance["sector_label_must_not_directly_select_ssvc_outcome"] is True
    assert governance["epss_must_not_replace_exploitation_state"] is True


def test_reason_registry_is_closed_and_unique() -> None:
    registry = load_yaml(REASONS)
    assert registry["registry"]["closed_registry"] is True
    codes = [item["code"] for item in registry["codes"]]
    assert len(codes) == len(set(codes))
    assert "SSVC_OFFICIAL_ROW_MATCHED" in codes
    assert "SSVC_PRODUCTION_BLOCK_PRESERVED" in codes

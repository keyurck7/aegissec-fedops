from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.ml_advisory.dataset import build_dataset, deterministic_group_split, leakage_audit, load_training_policy
from src.ml_advisory.governance import build_ml_feature_view
from src.ml_advisory.synthetic import generate_development_pairs

ROOT = Path(__file__).resolve().parents[2]
FEATURE = ROOT / "data" / "processed" / "decision_features" / "log4shell-20260718T141317Z-decision-features" / "aeg-dfe-aa60735b0e2c053c1b002c64.features.json"


def base_view():
    envelope = json.loads(FEATURE.read_text(encoding="utf-8"))
    return build_ml_feature_view(envelope, generated_at="2026-07-20T00:00:00Z")


def test_synthetic_development_dataset_is_governed_and_blocked_from_production():
    dataset = build_dataset(generate_development_pairs(base_view(), count=240))
    assert dataset["quality"]["row_count"] == 240
    assert dataset["quality"]["leakage_audit"]["status"] == "PASS"
    assert dataset["release"]["stage_gate"] == "PASS"
    assert dataset["release"]["production_dataset_eligible"] is False


def test_split_has_no_row_or_group_leakage():
    dataset = build_dataset(generate_development_pairs(base_view(), count=240))
    split = deterministic_group_split(dataset)
    partitions = [set(split["partitions"][name]) for name in ["train", "validation", "test"]]
    assert not partitions[0] & partitions[1]
    assert not partitions[0] & partitions[2]
    assert not partitions[1] & partitions[2]
    assert split["leakage_check"]["status"] == "PASS"


def test_leakage_firewall_detects_policy_derived_feature_names():
    audit = leakage_audit(
        [
            "cvss_base_score",
            "combined_trust_action",
            "official_ssvc_decision",
        ],
        load_training_policy(),
    )
    assert audit["status"] == "FAIL"
    assert audit["violations"] == ["official_ssvc_decision"]
    assert audit["exempted_features"] == [
        {
            "feature_name": "combined_trust_action",
            "matched_terms": ["action"],
            "disposition": "APPROVED_PRE_POLICY_FEATURE_EXCEPTION",
        }
    ]


def test_tampered_label_target_is_rejected():
    pair = generate_development_pairs(base_view(), count=240)[0]
    view, label = copy.deepcopy(pair)
    label["target"]["asset_id"] = "OTHER-ASSET"
    with pytest.raises(Exception):
        build_dataset([(view, label)])

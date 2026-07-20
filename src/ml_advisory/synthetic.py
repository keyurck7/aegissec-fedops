from __future__ import annotations

import copy
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .dataset import canonical_bytes, stable_id

CLASSES = ["MONITOR", "SCHEDULED", "PRIORITY", "IMMEDIATE"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
IMPACTS = ["LOW", "MEDIUM", "HIGH", "SEVERE", "CRITICAL"]
CRITICALITY = ["low", "medium", "high", "critical"]
REACHABILITY = ["NOT_REACHABLE", "UNKNOWN", "REACHABLE"]


def _label_for(features: Mapping[str, Any]) -> str:
    # Controlled development oracle, explicitly independent of SSVC outputs.
    score = 0.0
    score += float(features.get("cvss_base_score") or 0.0) * 0.9
    score += float(features.get("epss_probability") or 0.0) * 8.0
    score += 5.0 if features.get("kev_listed") else 0.0
    score += 3.5 if features.get("mission_essential") else 0.0
    score += 2.0 if features.get("externally_accessible") else 0.0
    score += 2.0 if features.get("internet_accessible") else 0.0
    score += 2.5 if features.get("privileged_interface_exposed") else 0.0
    score += {"low": 0.0, "medium": 1.5, "high": 3.5, "critical": 5.0}.get(str(features.get("asset_criticality_level")), 0.0)
    score += {"LOW": 0.0, "MEDIUM": 1.0, "HIGH": 2.5, "SEVERE": 4.5, "CRITICAL": 6.0}.get(str(features.get("maximum_impact_severity")), 0.0)
    score += {"NOT_REACHABLE": -3.0, "UNKNOWN": 0.0, "REACHABLE": 3.5}.get(str(features.get("runtime_reachability")), 0.0)
    score -= min(int(features.get("compensating_control_count") or 0), 5) * 0.7
    score -= 2.0 if features.get("manual_alternative_available") else 0.0
    score += max(0.0, 0.75 - float(features.get("combined_trust_score") or 0.0)) * 2.0
    if score >= 24.0:
        return "IMMEDIATE"
    if score >= 17.0:
        return "PRIORITY"
    if score >= 10.0:
        return "SCHEDULED"
    return "MONITOR"


def generate_development_pairs(
    base_feature_view: Mapping[str, Any],
    *,
    count: int = 480,
    seed: int = 12062026,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    if count < 240:
        raise ValueError("At least 240 development scenarios are required.")
    rng = random.Random(seed)
    pairs = []
    base_features = dict(base_feature_view["model_features"])
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)

    base_quota, remainder = divmod(count, len(CLASSES))
    class_quotas = {
        label: base_quota + int(position < remainder)
        for position, label in enumerate(CLASSES)
    }
    class_counts = {label: 0 for label in CLASSES}
    candidate_index = 0
    max_candidates = count * 100

    while len(pairs) < count:
        if candidate_index >= max_candidates:
            raise RuntimeError(
                "Unable to generate a class-balanced controlled dataset "
                f"within {max_candidates} candidates: {class_counts}"
            )
        index = candidate_index
        candidate_index += 1
        view = copy.deepcopy(dict(base_feature_view))
        features = dict(base_features)
        severity = rng.choices(SEVERITIES, weights=[0.16, 0.28, 0.32, 0.24])[0]
        cvss_ranges = {"LOW": (0.1, 3.9), "MEDIUM": (4.0, 6.9), "HIGH": (7.0, 8.9), "CRITICAL": (9.0, 10.0)}
        lo, hi = cvss_ranges[severity]
        features["cvss_base_severity"] = severity
        features["cvss_base_score"] = round(rng.uniform(lo, hi), 1)
        features["cvss_exploitability_score"] = round(rng.uniform(0.5, 4.0), 1)
        features["cvss_impact_score"] = round(rng.uniform(1.0, 6.0), 1)
        features["epss_probability"] = round(min(0.99999, rng.betavariate(1.3, 3.0)), 6)
        features["epss_percentile"] = round(min(1.0, features["epss_probability"] ** 0.42), 6)
        features["kev_listed"] = rng.random() < (0.08 + features["epss_probability"] * 0.55)
        features["known_ransomware_campaign_use"] = rng.choice(["Known", "Unknown", "No"])
        features["affectedness_status"] = rng.choices(["AFFECTED", "PROBABLY_AFFECTED", "UNKNOWN"], weights=[0.72, 0.20, 0.08])[0]
        features["affectedness_confidence"] = round(rng.uniform(0.55, 1.0), 3)
        features["affectedness_supporting_evidence_count"] = rng.randint(1, 12)
        features["asset_criticality_level"] = rng.choice(CRITICALITY)
        features["mission_essential"] = rng.random() < 0.38
        features["contains_personal_data"] = rng.random() < 0.60
        features["contains_health_data"] = rng.random() < 0.32
        features["highest_data_sensitivity"] = rng.choice(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"])
        features["lifecycle_stage"] = rng.choice(["development", "staging", "production"])
        features["operational_status"] = rng.choice(["operational", "degraded", "maintenance"])
        features["mission_tier"] = rng.choice(["TIER_1", "TIER_2", "TIER_3", "TIER_4"])
        features["maximum_impact_severity"] = rng.choice(IMPACTS)
        for name in ["availability_impact", "integrity_impact", "confidentiality_impact", "patient_safety_impact", "public_service_impact"]:
            features[name] = rng.choice(IMPACTS + ["NOT_APPLICABLE"])
        features["rto_hours"] = round(rng.uniform(0.25, 72.0), 2)
        features["maximum_tolerable_downtime_hours"] = round(rng.uniform(features["rto_hours"], 168.0), 2)
        features["manual_alternative_available"] = rng.random() < 0.45
        features["externally_accessible"] = rng.random() < 0.48
        features["internet_accessible"] = features["externally_accessible"] and rng.random() < 0.72
        features["authentication_required"] = rng.random() < 0.78
        features["privileged_interface_exposed"] = rng.random() < 0.18
        features["compensating_control_count"] = rng.randint(0, 6)
        features["exposure_confidence"] = round(rng.uniform(0.45, 1.0), 3)
        features["network_zone"] = rng.choice(["INTERNET", "DMZ", "INTERNAL", "RESTRICTED", "ISOLATED"])
        features["runtime_reachability"] = rng.choices(REACHABILITY, weights=[0.18, 0.35, 0.47])[0]
        features["runtime_reachability_confidence"] = round(rng.uniform(0.35, 1.0), 3)
        features["runtime_configuration"] = rng.choice(["DEFAULT", "HARDENED", "MITIGATED", "UNKNOWN"])
        features["combined_trust_score"] = round(rng.uniform(0.55, 1.0), 3)
        features["component_trust_score"] = round(rng.uniform(0.55, 1.0), 3)
        # Preserve any remaining governed features with safe deterministic values.
        for key, value in list(features.items()):
            if value is None:
                features[key] = 0.0 if any(token in key for token in ["score", "count", "hours", "probability", "percentile", "confidence"]) else "UNKNOWN"

        group_index = index // 4
        cve_id = f"CVE-{2020 + (group_index % 7)}-{10000 + group_index:05d}"
        asset_id = f"AEG-ASSET-{group_index:04d}"
        purl = f"pkg:generic/aegis/component-{group_index:04d}@{1 + group_index % 5}.{index % 10}.0"
        target = {"cve_id": cve_id, "asset_id": asset_id, "component_purl": purl}
        view["target"] = dict(target)
        view["source"] = dict(view["source"])
        view["source"]["envelope_id"] = f"AEG-SYN-DFE-{index:06d}"
        view["feature_view_id"] = stable_id("AEG-MLF-SYN", {"index": index, "target": target, "features": features})
        view["generated_at"] = (start + timedelta(hours=index)).isoformat().replace("+00:00", "Z")
        view["model_features"] = features
        view["evaluation_context"] = dict(view.get("evaluation_context", {}))
        view["evaluation_context"]["synthetic_or_demo_context"] = True
        view["release_decision"] = dict(view["release_decision"])
        view["release_decision"]["production_dataset_eligible"] = False
        view["release_decision"]["production_readiness"] = "BLOCKED"

        label = _label_for(features)
        if class_counts[label] >= class_quotas[label]:
            continue
        class_counts[label] += 1

        label_payload = {
            "scenario_id": f"AEG-SYN-LABEL-{index:06d}",
            "label": label,
            "target": target,
            "features_digest": hashlib.sha256(canonical_bytes(features)).hexdigest(),
            "oracle_version": "CONTROLLED-DEVELOPMENT-ORACLE-1.0.0",
        }
        label_record = {
            "label": label,
            "source_type": "CONTROLLED_SYNTHETIC_SCENARIO",
            "source_record_id": label_payload["scenario_id"],
            "source_sha256": hashlib.sha256(canonical_bytes(label_payload)).hexdigest(),
            "observed_at": (start + timedelta(hours=index, days=30)).isoformat().replace("+00:00", "Z"),
            "observation_window_days": 30,
            "target": dict(target),
            "synthetic": True,
        }
        pairs.append((view, label_record))
    return pairs

from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.policy.policy_floor_engine import (
    PolicyFloorEngine,
)


ASSET_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)

INTELLIGENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "intelligence"
    / "valid_log4shell_intelligence.json"
)

DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_affectedness.json"
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def affectedness(
    status: str,
    confidence: float | None,
    evidence_ids: list[str],
) -> dict:
    return {
        "status": status,
        "confidence": confidence,
        "supporting_evidence_ids": (
            evidence_ids
        ),
    }


def main() -> int:
    asset = load_json(ASSET_PATH)
    intelligence = load_json(
        INTELLIGENCE_PATH
    )
    decision = load_json(DECISION_PATH)

    component = decision[
        "component_instance"
    ]

    engine = PolicyFloorEngine()

    evaluation_time = datetime(
        2026,
        7,
        13,
        19,
        15,
        tzinfo=timezone.utc,
    )

    accepted_trust = {
        "action": "ACCEPT",
        "aggregate_score": 0.95,
    }

    scenarios = []

    scenarios.append(
        (
            "KEV affected",
            asset,
            intelligence,
            affectedness(
                "affected",
                0.95,
                [
                    "AEG-EVD-SBOM-LOG4J-001",
                    "AEG-EVD-OSV-LOG4J-001",
                ],
            ),
            accepted_trust,
        )
    )

    active = copy.deepcopy(intelligence)
    active["exploitation"]["status"] = (
        "active_exploitation"
    )

    scenarios.append(
        (
            "Active exploitation",
            asset,
            active,
            affectedness(
                "affected",
                0.95,
                [
                    "AEG-EVD-SBOM-LOG4J-001",
                    "AEG-EVD-OSV-LOG4J-001",
                ],
            ),
            accepted_trust,
        )
    )

    scenarios.append(
        (
            "Unknown affectedness",
            asset,
            intelligence,
            affectedness(
                "unknown",
                None,
                [
                    "AEG-EVD-SBOM-LOG4J-001"
                ],
            ),
            accepted_trust,
        )
    )

    scenarios.append(
        (
            "Fixed version",
            asset,
            intelligence,
            affectedness(
                "fixed",
                0.95,
                [
                    "AEG-EVD-SBOM-LOG4J-001",
                    "AEG-EVD-OSV-LOG4J-001",
                ],
            ),
            accepted_trust,
        )
    )

    scenarios.append(
        (
            "Quarantined evidence",
            asset,
            intelligence,
            affectedness(
                "affected",
                0.80,
                [
                    "AEG-EVD-SBOM-LOG4J-001"
                ],
            ),
            {
                "action": "QUARANTINE",
                "aggregate_score": 0.80,
            },
        )
    )

    results = []

    for (
        scenario_name,
        scenario_asset,
        scenario_intelligence,
        scenario_affectedness,
        scenario_trust,
    ) in scenarios:
        result = engine.evaluate(
            asset_context=scenario_asset,
            intelligence_record=(
                scenario_intelligence
            ),
            component_instance=component,
            affectedness_assessment=(
                scenario_affectedness
            ),
            evidence_trust=scenario_trust,
            evaluated_at=evaluation_time,
        )

        results.append(
            {
                "scenario": scenario_name,
                "action": result.action,
                "priority": (
                    result.minimum_priority
                ),
                "deadline_hours": (
                    result.response_deadline_hours
                ),
                "human_review_required": (
                    result.human_review_required
                ),
                "containment_required": (
                    result.containment_required
                ),
                "matched_rules": [
                    rule.rule_id
                    for rule in result.matched_rules
                ],
                "invariants_passed": (
                    result.invariants_passed
                ),
            }
        )

    print(
        json.dumps(
            {
                "scenario_count": len(results),
                "results": results,
            },
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

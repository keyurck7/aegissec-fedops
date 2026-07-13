from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.affectedness.affectedness_engine import (
    AffectednessEngine,
)
from src.governance.evidence_trust_engine import (
    EvidenceTrustEngine,
)


DECISION_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record.json"
)

INTELLIGENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "intelligence"
    / "valid_log4shell_intelligence.json"
)

EVIDENCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_log4j_sbom_evidence.json"
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def main() -> int:
    decision = load_json(DECISION_PATH)
    intelligence = load_json(INTELLIGENCE_PATH)
    evidence = load_json(EVIDENCE_PATH)

    component = decision["component_instance"]

    fixed_time = datetime(
        2026,
        7,
        13,
        19,
        0,
        tzinfo=timezone.utc,
    )

    trust = EvidenceTrustEngine().assess(
        evidence,
        assessed_at=fixed_time,
    )

    engine = AffectednessEngine()

    scenarios = {}

    affected = copy.deepcopy(component)
    affected["version"] = "2.14.1"
    scenarios["Affected version"] = (
        affected,
        intelligence,
        trust,
    )

    fixed = copy.deepcopy(component)
    fixed["version"] = "2.15.0"
    scenarios["Fixed boundary"] = (
        fixed,
        intelligence,
        trust,
    )

    not_affected = copy.deepcopy(component)
    not_affected["version"] = "1.2.17"
    scenarios["Before introduction"] = (
        not_affected,
        intelligence,
        trust,
    )

    no_match = copy.deepcopy(component)
    no_match["name"] = "different-package"
    no_match["purl"] = (
        "pkg:maven/example/different-package@1.0.0"
    )
    scenarios["No package match"] = (
        no_match,
        intelligence,
        trust,
    )

    partial_intelligence = copy.deepcopy(intelligence)
    partial_intelligence[
        "affected_packages"
    ][0]["range_status"] = "partial"

    probably_affected = copy.deepcopy(component)
    probably_affected["version"] = "2.14.1"

    scenarios["Partial range coverage"] = (
        probably_affected,
        partial_intelligence,
        trust,
    )

    results = []

    for name, (
        scenario_component,
        scenario_intelligence,
        scenario_trust,
    ) in scenarios.items():
        assessment = engine.assess(
            component_instance=scenario_component,
            intelligence_record=scenario_intelligence,
            evidence_trust=scenario_trust,
            assessed_at=fixed_time,
        )

        results.append(
            {
                "scenario": name,
                "component_version": (
                    scenario_component.get("version")
                ),
                "status": assessment.status,
                "confidence": assessment.confidence,
                "human_review_required": (
                    assessment.human_review_required
                ),
                "reason_codes": (
                    assessment.reason_codes
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

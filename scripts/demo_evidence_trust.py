from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.governance.evidence_trust_engine import (
    EvidenceTrustEngine,
)


SAMPLE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "evidence"
    / "valid_requirements_evidence.json"
)


def load_sample() -> dict:
    with SAMPLE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def main() -> int:
    engine = EvidenceTrustEngine()
    base_record = load_sample()

    high_trust = copy.deepcopy(base_record)
    high_trust["evidence_id"] = "AEG-EVD-TRUST-HIGH-001"

    stale = copy.deepcopy(base_record)
    stale["evidence_id"] = "AEG-EVD-TRUST-STALE-001"
    stale["freshness"]["status"] = "stale"
    stale["freshness"]["age_seconds"] = 172800
    stale["freshness"]["maximum_age_seconds"] = 86400

    unauthorized = copy.deepcopy(base_record)
    unauthorized["evidence_id"] = (
        "AEG-EVD-TRUST-UNAUTHORIZED-001"
    )
    unauthorized["authorization"]["status"] = "unauthorized"

    scenarios = {
        "high_trust": high_trust,
        "stale": stale,
        "unauthorized": unauthorized,
    }

    assessment_time = datetime(
        2026,
        7,
        13,
        18,
        45,
        tzinfo=timezone.utc,
    )

    results = []

    for scenario_name, record in scenarios.items():
        assessment = engine.assess(
            record,
            assessed_at=assessment_time,
        )

        results.append(
            {
                "scenario": scenario_name,
                "evidence_id": assessment.evidence_id,
                "aggregate_score": assessment.aggregate_score,
                "trust_level": assessment.trust_level,
                "action": assessment.action,
                "gate_codes": [
                    gate.code
                    for gate in assessment.gate_results
                ],
                "warning_codes": [
                    warning.code
                    for warning in assessment.warnings
                ],
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

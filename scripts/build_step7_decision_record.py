from __future__ import annotations

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
from src.domain.decision_hashing import (
    finalize_decision_record_hash,
)
from src.governance.evidence_trust_engine import (
    EvidenceTrustEngine,
)
from src.validation.decision_record_validator import (
    DecisionRecordValidator,
)


SOURCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_affectedness.json"
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return payload


def resolve_reference(reference: dict) -> Path:
    resolved = (
        PROJECT_ROOT / reference["relative_path"]
    ).resolve()

    if (
        resolved != PROJECT_ROOT
        and PROJECT_ROOT not in resolved.parents
    ):
        raise ValueError(
            "Referenced path escapes project root."
        )

    return resolved


def main() -> int:
    decision = load_json(SOURCE_PATH)

    intelligence = load_json(
        resolve_reference(
            decision["input_records"][
                "vulnerability_intelligence"
            ]
        )
    )

    evidence = load_json(
        resolve_reference(
            decision["input_records"][
                "evidence_records"
            ][0]
        )
    )

    fixed_time = datetime(
        2026,
        7,
        13,
        19,
        0,
        tzinfo=timezone.utc,
    )

    trust_assessment = EvidenceTrustEngine().assess(
        evidence,
        assessed_at=fixed_time,
    )

    affectedness = AffectednessEngine().assess(
        component_instance=decision["component_instance"],
        intelligence_record=intelligence,
        evidence_trust=trust_assessment,
        assessed_at=fixed_time,
    )

    decision["decision_id"] = (
        "AEG-DEC-LOG4J-HOSP-AFFECTEDNESS-001"
    )

    decision["affectedness"] = (
        affectedness.to_decision_record_block()
    )

    decision["provenance"]["workflow_version"] = (
        "step7-affectedness-0.1.0"
    )

    decision["provenance"]["generated_at"] = (
        fixed_time.isoformat()
    )

    decision["audit"]["workflow_run_id"] = (
        "RUN-STEP7-AFFECTEDNESS-001"
    )

    decision["audit"]["created_by"] = (
        "AegisSec Step 7 Affectedness Pipeline"
    )

    decision["audit"]["generated_at"] = (
        fixed_time.isoformat()
    )

    decision["updated_at"] = fixed_time.isoformat()

    finalized = finalize_decision_record_hash(decision)

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            finalized,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")

    validation_result = (
        DecisionRecordValidator().validate(finalized)
    )

    print("Decision Record:", OUTPUT_PATH)
    print("Affectedness:", affectedness.status)
    print("Confidence:", affectedness.confidence)
    print(
        "Record hash:",
        finalized["audit"]["record_hash"],
    )
    print(
        "Decision validation:",
        validation_result.status,
    )

    if not validation_result.valid:
        print(
            json.dumps(
                validation_result.to_dict(),
                indent=2,
            )
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

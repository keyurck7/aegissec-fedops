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
from src.policy.policy_floor_engine import (
    PolicyFloorEngine,
)
from src.validation.decision_record_validator import (
    DecisionRecordValidator,
)


SOURCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_affectedness.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_policy.json"
)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError(
            f"Expected JSON object: {path}"
        )

    return payload


def resolve_reference(
    reference: dict,
) -> Path:
    resolved = (
        PROJECT_ROOT
        / reference["relative_path"]
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

    asset = load_json(
        resolve_reference(
            decision["input_records"][
                "asset_context"
            ]
        )
    )

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

    evaluation_time = datetime(
        2026,
        7,
        13,
        19,
        15,
        tzinfo=timezone.utc,
    )

    trust = EvidenceTrustEngine().assess(
        evidence,
        assessed_at=evaluation_time,
    )

    affectedness = (
        AffectednessEngine().assess(
            component_instance=(
                decision["component_instance"]
            ),
            intelligence_record=intelligence,
            evidence_trust=trust,
            assessed_at=evaluation_time,
        )
    )

    policy = PolicyFloorEngine().evaluate(
        asset_context=asset,
        intelligence_record=intelligence,
        component_instance=(
            decision["component_instance"]
        ),
        affectedness_assessment=affectedness,
        evidence_trust=trust,
        evaluated_at=evaluation_time,
    )

    decision["decision_id"] = (
        "AEG-DEC-LOG4J-HOSP-POLICY-001"
    )

    decision["affectedness"] = (
        affectedness.to_decision_record_block()
    )

    decision["policy_decision"] = (
        policy.to_decision_record_block()
    )

    uncertainty_level = (
        "high"
        if affectedness.status == "unknown"
        or trust.action
        in {"QUARANTINE", "REJECT"}
        else (
            "medium"
            if policy.human_review_required
            else "low"
        )
    )

    arbitration_reasons = [
        "POLICY_FLOOR_APPLIED",
        "POLICY_INVARIANTS_EVALUATED",
        "ML_NOT_RUN",
    ]

    arbitration_reasons.extend(
        rule.rule_id.replace("-", "_")
        for rule in policy.matched_rules
    )

    decision["arbitration"] = {
        "status": "policy_only",
        "final_system_priority": (
            policy.minimum_priority
        ),
        "final_action": policy.action,
        "decision_basis": "policy_only",
        "human_review_required": (
            policy.human_review_required
        ),
        "reason_codes": list(
            dict.fromkeys(
                arbitration_reasons
            )
        ),
        "uncertainty_level": (
            uncertainty_level
        ),
        "policy_floor_enforced": True,
        "evaluated_at": (
            evaluation_time.isoformat()
        ),
    }

    decision["decision_status"] = (
        "pending_human_review"
        if policy.human_review_required
        else "draft"
    )

    decision["provenance"]["workflow_version"] = (
        "step8-policy-floor-0.1.0"
    )

    decision["provenance"]["generated_at"] = (
        evaluation_time.isoformat()
    )

    decision["audit"]["workflow_run_id"] = (
        "RUN-STEP8-POLICY-001"
    )

    decision["audit"]["created_by"] = (
        "AegisSec Step 8 Policy Pipeline"
    )

    decision["audit"]["generated_at"] = (
        evaluation_time.isoformat()
    )

    decision["updated_at"] = (
        evaluation_time.isoformat()
    )

    finalized = finalize_decision_record_hash(
        decision
    )

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
        DecisionRecordValidator().validate(
            finalized
        )
    )

    print("Decision Record:", OUTPUT_PATH)
    print("Affectedness:", affectedness.status)
    print("Policy action:", policy.action)
    print(
        "Minimum priority:",
        policy.minimum_priority,
    )
    print(
        "Human review required:",
        policy.human_review_required,
    )
    print(
        "Policy invariants passed:",
        policy.invariants_passed,
    )
    print(
        "Decision validation:",
        validation_result.status,
    )
    print(
        "Record hash:",
        finalized["audit"]["record_hash"],
    )

    if not validation_result.valid:
        print(
            json.dumps(
                validation_result.to_dict(),
                indent=2,
            )
        )
        return 1

    if not policy.invariants_passed:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

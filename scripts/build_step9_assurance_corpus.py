from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.assurance.policy_assurance import (
    AFFECTEDNESS_PROFILES,
    OPERATIONAL_PROFILES,
    SECTOR_LABELS,
    build_expected_decision,
    canonical_json_hash,
    load_json,
    sha256_file,
    write_case_summary_csv,
    write_json,
    write_jsonl,
)


CASE_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_policy_assurance_case.schema.json"
)

POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "federal_base_policy_v1.yaml"
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

COMPONENT_SOURCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "sample_inputs"
    / "decisions"
    / "valid_log4shell_decision_record_policy.json"
)

CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_corpus.jsonl"
)

SUMMARY_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_summary.csv"
)

MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_manifest.json"
)


BUILD_TIME = datetime(
    2026,
    7,
    13,
    19,
    30,
    tzinfo=timezone.utc,
)


def relative(path: Path) -> str:
    return path.relative_to(
        PROJECT_ROOT
    ).as_posix()


def neutral_asset_overrides(
    asset: dict[str, Any],
) -> dict[str, Any]:
    overrides: dict[str, Any] = {
        "exposure.internet_accessible": False,
        "exposure.externally_accessible": False,
        "mission.mission_essential": False,
        "criticality.level": "low",
    }

    impact_assessment = asset.get(
        "impact_assessment",
        {},
    )

    for name, assessment in (
        impact_assessment.items()
    ):
        if (
            isinstance(assessment, dict)
            and "severity" in assessment
        ):
            overrides[
                f"impact_assessment.{name}.severity"
            ] = "low"

    return overrides


def neutral_intelligence_overrides() -> dict[str, Any]:
    return {
        "record_status": "active",

        "kev.status": "not_listed",
        "kev.date_added": None,
        "kev.due_date": None,
        "kev.required_action": None,
        "kev.evidence_id": None,

        "exploitation.status": "unknown",
        "exploitation.confidence": 0.0,
        "exploitation.last_observed_at": None,
        "exploitation.evidence_ids": [],

        "epss.status": "available",
        "epss.probability": 0.10,
        "epss.percentile": 0.20,
        "epss.score_date": "2026-07-13",
        "epss.retrieved_at": (
            "2026-07-13T19:00:00Z"
        ),
        "epss.evidence_id": (
            "AEG-EVD-EPSS-ASR-001"
        ),
        "epss.model_version": "assurance-fixture",
        "epss.missing_reason": None,

        "cvss.metrics.0.base_score": 6.5,
        "cvss.metrics.0.base_severity": "MEDIUM",

        "remediation.status": "fix_available",
    }


def first_impact_dimension(
    asset: dict[str, Any],
) -> str:
    impact_assessment = asset.get(
        "impact_assessment",
        {},
    )

    preferred = (
        "availability",
        "patient_safety",
        "mission_readiness",
        "public_service",
    )

    for name in preferred:
        value = impact_assessment.get(name)

        if (
            isinstance(value, dict)
            and "severity" in value
        ):
            return name

    for name, value in (
        impact_assessment.items()
    ):
        if (
            isinstance(value, dict)
            and "severity" in value
        ):
            return name

    raise ValueError(
        "Asset fixture contains no impact "
        "dimension with a severity field."
    )


def profile_overrides(
    operational_profile: str,
    affectedness_status: str,
    impact_dimension: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    asset_overrides: dict[str, Any] = {}
    intelligence_overrides: dict[
        str,
        Any,
    ] = {}

    component_overrides: dict[
        str,
        Any,
    ] = {
        "runtime_status": (
            "present_runtime_unknown"
        )
    }

    trust = {
        "action": "ACCEPT",
        "aggregate_score": 0.95,
    }

    if operational_profile == "baseline":
        pass

    elif operational_profile == "kev_listed":
        intelligence_overrides.update(
            {
                "kev.status": "listed",
                "kev.catalog_version": (
                    "ASSURANCE-CATALOG-1"
                ),
                "kev.date_added": "2026-07-01",
                "kev.due_date": "2026-07-15",
                "kev.required_action": (
                    "Apply approved remediation."
                ),
                "kev.evidence_id": (
                    "AEG-EVD-KEV-ASR-001"
                ),
            }
        )

    elif operational_profile == "active_exploitation":
        intelligence_overrides.update(
            {
                "exploitation.status": (
                    "active_exploitation"
                ),
                "exploitation.confidence": 1.0,
                "exploitation.last_observed_at": (
                    "2026-07-13T18:00:00Z"
                ),
                "exploitation.evidence_ids": [
                    "AEG-EVD-EXPLOIT-ASR-001"
                ],
            }
        )

    elif operational_profile == "internet_exposed":
        asset_overrides.update(
            {
                "exposure.internet_accessible": True,
                "exposure.externally_accessible": True,
            }
        )

    elif operational_profile == "exposure_unknown":
        asset_overrides.update(
            {
                "exposure.internet_accessible": None
            }
        )

    elif operational_profile == "catastrophic_impact":
        asset_overrides[
            "impact_assessment."
            f"{impact_dimension}.severity"
        ] = "catastrophic"

    elif operational_profile == "severe_impact":
        asset_overrides[
            "impact_assessment."
            f"{impact_dimension}.severity"
        ] = "severe"

    elif operational_profile == "mission_essential":
        asset_overrides[
            "mission.mission_essential"
        ] = True

    elif operational_profile == "high_criticality":
        asset_overrides[
            "criticality.level"
        ] = "high"

    elif operational_profile == "critical_cvss":
        intelligence_overrides.update(
            {
                "cvss.metrics.0.base_score": 9.8,
                "cvss.metrics.0.base_severity": (
                    "CRITICAL"
                ),
            }
        )

    elif operational_profile == "no_fix_available":
        intelligence_overrides[
            "remediation.status"
        ] = "no_fix_available"

    elif operational_profile == "trust_blocked":
        if affectedness_status in {
            "affected",
            "unknown",
            "fixed",
        }:
            trust = {
                "action": "QUARANTINE",
                "aggregate_score": 0.55,
            }
        else:
            trust = {
                "action": "REJECT",
                "aggregate_score": 0.20,
            }

    else:
        raise ValueError(
            f"Unsupported operational profile: "
            f"{operational_profile}"
        )

    return (
        asset_overrides,
        intelligence_overrides,
        component_overrides,
        trust,
    )


def main() -> int:
    asset = load_json(ASSET_PATH)
    schema = load_json(CASE_SCHEMA_PATH)

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    neutral_asset = neutral_asset_overrides(
        asset
    )

    neutral_intelligence = (
        neutral_intelligence_overrides()
    )

    impact_dimension = (
        first_impact_dimension(asset)
    )

    cases: list[dict[str, Any]] = []

    pair_index = 0
    case_index = 0

    for affectedness_profile in (
        AFFECTEDNESS_PROFILES
    ):
        affectedness_status = (
            affectedness_profile["name"]
        )

        for operational_profile in (
            OPERATIONAL_PROFILES
        ):
            pair_index += 1

            pair_id = (
                f"PAIR-{pair_index:03d}"
            )

            (
                profile_asset_overrides,
                profile_intelligence_overrides,
                profile_component_overrides,
                trust,
            ) = profile_overrides(
                operational_profile=(
                    operational_profile
                ),
                affectedness_status=(
                    affectedness_status
                ),
                impact_dimension=(
                    impact_dimension
                ),
            )

            base_scenario = {
                "affectedness_profile": (
                    affectedness_status
                ),
                "operational_profile": (
                    operational_profile
                ),
                "affectedness": {
                    "status": affectedness_status,
                    "confidence": (
                        affectedness_profile[
                            "confidence"
                        ]
                    ),
                    "supporting_evidence_ids": [
                        "AEG-EVD-SBOM-LOG4J-001",
                        "AEG-EVD-OSV-LOG4J-001",
                    ],
                },
                "trust": trust,
                "asset_overrides": {
                    **neutral_asset,
                    **profile_asset_overrides,
                },
                "intelligence_overrides": {
                    **neutral_intelligence,
                    **profile_intelligence_overrides,
                },
                "component_overrides": {
                    **profile_component_overrides,
                },
            }

            counterfactual_key = (
                canonical_json_hash(
                    base_scenario
                )
            )

            expected = (
                build_expected_decision(
                    affectedness_status=(
                        affectedness_status
                    ),
                    operational_profile=(
                        operational_profile
                    ),
                )
            )

            for sector in SECTOR_LABELS:
                case_index += 1

                scenario = copy.deepcopy(
                    base_scenario
                )

                scenario[
                    "asset_overrides"
                ][
                    "sector_context.primary_sector"
                ] = sector["label"]

                case = {
                    "schema_version": "1.0.0",
                    "case_id": (
                        f"AEG-ASR-"
                        f"{pair_index:03d}-"
                        f"{sector['suffix']}"
                    ),
                    "pair_id": pair_id,
                    "case_index": case_index,
                    "sector_label": (
                        sector["label"]
                    ),
                    "counterfactual_key": (
                        counterfactual_key
                    ),
                    "differing_fields": [
                        "sector_context.primary_sector"
                    ],
                    "scenario": scenario,
                    "expected": expected,
                    "tags": [
                        "controlled-assurance-case",
                        affectedness_status,
                        operational_profile,
                        sector["label"],
                    ],
                }

                errors = list(
                    validator.iter_errors(
                        case
                    )
                )

                if errors:
                    messages = [
                        error.message
                        for error in errors
                    ]

                    raise ValueError(
                        f"Generated case "
                        f"{case['case_id']} failed "
                        f"schema validation: "
                        f"{messages}"
                    )

                cases.append(case)

    if len(cases) != 120:
        raise RuntimeError(
            f"Expected 120 cases, generated "
            f"{len(cases)}."
        )

    if pair_index != 60:
        raise RuntimeError(
            f"Expected 60 pairs, generated "
            f"{pair_index}."
        )

    write_jsonl(
        CORPUS_PATH,
        cases,
    )

    write_case_summary_csv(
        SUMMARY_PATH,
        cases,
    )

    manifest = {
        "schema_version": "1.0.0",
        "corpus_id": (
            "AEG-ASR-POLICY-CORPUS-STEP9-001"
        ),
        "generator_version": "1.0.0",
        "description": (
            "One hundred twenty controlled policy "
            "assurance cases formed from sixty "
            "counterfactual sector pairs."
        ),
        "created_at": BUILD_TIME.isoformat(),
        "case_count": len(cases),
        "pair_count": pair_index,
        "design": {
            "affectedness_profiles": [
                profile["name"]
                for profile
                in AFFECTEDNESS_PROFILES
            ],
            "operational_profiles": list(
                OPERATIONAL_PROFILES
            ),
            "sector_labels": [
                sector["label"]
                for sector
                in SECTOR_LABELS
            ],
            "counterfactual_differing_fields": [
                "sector_context.primary_sector"
            ],
            "decision_relevant_sector_fields": [],
        },
        "base_fixtures": {
            "asset_context": {
                "relative_path": relative(
                    ASSET_PATH
                ),
                "sha256": sha256_file(
                    ASSET_PATH
                ),
            },
            "vulnerability_intelligence": {
                "relative_path": relative(
                    INTELLIGENCE_PATH
                ),
                "sha256": sha256_file(
                    INTELLIGENCE_PATH
                ),
            },
            "component_source": {
                "relative_path": relative(
                    COMPONENT_SOURCE_PATH
                ),
                "sha256": sha256_file(
                    COMPONENT_SOURCE_PATH
                ),
            },
        },
        "artifacts": {
            "case_schema": {
                "relative_path": relative(
                    CASE_SCHEMA_PATH
                ),
                "sha256": sha256_file(
                    CASE_SCHEMA_PATH
                ),
            },
            "decision_policy": {
                "relative_path": relative(
                    POLICY_PATH
                ),
                "sha256": sha256_file(
                    POLICY_PATH
                ),
            },
            "corpus": {
                "relative_path": relative(
                    CORPUS_PATH
                ),
                "sha256": sha256_file(
                    CORPUS_PATH
                ),
            },
            "summary": {
                "relative_path": relative(
                    SUMMARY_PATH
                ),
                "sha256": sha256_file(
                    SUMMARY_PATH
                ),
            },
        },
    }

    write_json(
        MANIFEST_PATH,
        manifest,
    )

    print("Step 9 assurance corpus created")
    print(f"Cases: {len(cases)}")
    print(f"Counterfactual pairs: {pair_index}")
    print(
        f"Corpus: {relative(CORPUS_PATH)}"
    )
    print(
        f"Summary: {relative(SUMMARY_PATH)}"
    )
    print(
        f"Manifest: {relative(MANIFEST_PATH)}"
    )
    print(
        "Corpus SHA-256:",
        manifest["artifacts"][
            "corpus"
        ]["sha256"],
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

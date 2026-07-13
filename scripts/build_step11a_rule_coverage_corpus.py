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
    SECTOR_LABELS,
    TARGETED_RULE_PROFILES,
    build_expected_decision,
    canonical_json_hash,
    load_json,
    load_jsonl,
    sha256_file,
    write_case_summary_csv,
    write_json,
    write_jsonl,
)


SOURCE_CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_corpus.jsonl"
)

SOURCE_MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step9_policy_assurance_manifest.json"
)

CASE_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "aegis_policy_assurance_case_v1_1.schema.json"
)

POLICY_PATH = (
    PROJECT_ROOT
    / "policies"
    / "decision"
    / "federal_base_policy_v1.yaml"
)

CORPUS_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step11a_policy_rule_coverage_corpus.jsonl"
)

SUMMARY_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step11a_policy_rule_coverage_summary.csv"
)

MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "assurance"
    / "step11a_policy_rule_coverage_manifest.json"
)

BUILD_TIME = datetime(
    2026,
    7,
    13,
    20,
    15,
    tzinfo=timezone.utc,
)

EXPECTED_SOURCE_CASE_COUNT = 120
EXPECTED_SOURCE_PAIR_COUNT = 60
EXPECTED_TARGETED_PAIR_COUNT = 5
EXPECTED_COMBINED_CASE_COUNT = 130
EXPECTED_COMBINED_PAIR_COUNT = 65


def relative(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def verify_source_chain(
    source_manifest: dict[str, Any],
) -> None:
    if source_manifest.get("case_count") != EXPECTED_SOURCE_CASE_COUNT:
        raise ValueError("Unexpected Step 9 source case count.")

    if source_manifest.get("pair_count") != EXPECTED_SOURCE_PAIR_COUNT:
        raise ValueError("Unexpected Step 9 source pair count.")

    records: dict[str, dict[str, Any]] = {}
    records.update(source_manifest.get("base_fixtures", {}))
    records.update(source_manifest.get("artifacts", {}))

    failures = []

    for name, metadata in records.items():
        relative_path = metadata.get("relative_path")
        expected_hash = metadata.get("sha256")

        if not isinstance(relative_path, str):
            failures.append(f"{name}: missing relative_path")
            continue

        path = (PROJECT_ROOT / relative_path).resolve()
        safe = path == PROJECT_ROOT or PROJECT_ROOT in path.parents
        exists = safe and path.is_file()
        actual_hash = sha256_file(path) if exists else None

        if not safe or not exists or actual_hash != expected_hash:
            failures.append(
                f"{name}: safe={safe}, exists={exists}, "
                f"expected={expected_hash}, actual={actual_hash}"
            )

    if failures:
        raise ValueError(
            "Step 9 source-chain verification failed:\n"
            + "\n".join(f" - {item}" for item in failures)
        )


def baseline_case_by_affectedness(
    source_cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}

    for case in source_cases:
        scenario = case["scenario"]
        if (
            scenario["operational_profile"] == "baseline"
            and case["sector_label"] == "healthcare"
        ):
            selected[scenario["affectedness_profile"]] = case

    required = {
        profile["affectedness_profile"]
        for profile in TARGETED_RULE_PROFILES
    }
    missing = required - set(selected)

    if missing:
        raise ValueError(
            "Missing Step 9 baseline cases for affectedness profiles: "
            f"{sorted(missing)}"
        )

    return selected


def impact_override_path(
    scenario: dict[str, Any],
) -> str:
    overrides = scenario["asset_overrides"]
    preferred = (
        "impact_assessment.availability.severity",
        "impact_assessment.patient_safety.severity",
        "impact_assessment.mission_readiness.severity",
        "impact_assessment.public_service.severity",
    )

    for field_path in preferred:
        if field_path in overrides:
            return field_path

    candidates = sorted(
        field_path
        for field_path in overrides
        if field_path.startswith("impact_assessment.")
        and field_path.endswith(".severity")
    )

    if not candidates:
        raise ValueError(
            "No impact-assessment severity override is available."
        )

    return candidates[0]


def apply_targeted_profile(
    scenario: dict[str, Any],
    profile_name: str,
) -> None:
    if profile_name == "trust_warnings":
        scenario["trust"] = {
            "action": "ACCEPT_WITH_WARNINGS",
            "aggregate_score": 0.85,
        }

    elif profile_name == "known_exploitation":
        scenario["intelligence_overrides"].update(
            {
                "exploitation.status": "known_exploited",
                "exploitation.confidence": 0.95,
                "exploitation.last_observed_at": (
                    "2026-07-13T18:30:00Z"
                ),
                "exploitation.evidence_ids": [
                    "AEG-EVD-KNOWN-EXPLOIT-ASR-001"
                ],
            }
        )

    elif profile_name == "runtime_reachable":
        scenario["component_overrides"]["runtime_status"] = (
            "reachable"
        )

    elif profile_name == "high_impact":
        scenario["asset_overrides"][
            impact_override_path(scenario)
        ] = "high"

    elif profile_name == "epss_missing_affected":
        scenario["intelligence_overrides"].update(
            {
                "epss.status": "missing",
                "epss.probability": None,
                "epss.percentile": None,
                "epss.score_date": None,
                "epss.model_version": None,
                "epss.missing_reason": (
                    "No EPSS observation was available at the fixed "
                    "assurance evaluation time."
                ),
                "epss.evidence_id": (
                    "AEG-EVD-EPSS-MISSING-ASR-001"
                ),
            }
        )

    else:
        raise ValueError(
            f"Unsupported targeted profile: {profile_name}"
        )


def main() -> int:
    source_manifest = load_json(SOURCE_MANIFEST_PATH)
    verify_source_chain(source_manifest)

    source_cases = load_jsonl(SOURCE_CORPUS_PATH)

    if len(source_cases) != EXPECTED_SOURCE_CASE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_SOURCE_CASE_COUNT} Step 9 cases, "
            f"received {len(source_cases)}."
        )

    schema = load_json(CASE_SCHEMA_PATH)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    baseline_cases = baseline_case_by_affectedness(source_cases)
    combined_cases = copy.deepcopy(source_cases)

    pair_index = max(
        int(case["pair_id"].split("-")[-1])
        for case in source_cases
    )
    case_index = max(case["case_index"] for case in source_cases)

    targeted_design = []

    for profile in TARGETED_RULE_PROFILES:
        profile_name = profile["name"]
        affectedness_profile = profile["affectedness_profile"]
        target_rule_id = profile["target_rule_id"]

        source_case = baseline_cases[affectedness_profile]
        base_scenario = copy.deepcopy(source_case["scenario"])
        base_scenario["operational_profile"] = profile_name
        base_scenario["asset_overrides"].pop(
            "sector_context.primary_sector",
            None,
        )

        apply_targeted_profile(base_scenario, profile_name)

        pair_index += 1
        pair_id = f"PAIR-{pair_index:03d}"
        counterfactual_key = canonical_json_hash(base_scenario)
        expected = build_expected_decision(
            affectedness_status=affectedness_profile,
            operational_profile=profile_name,
        )

        targeted_design.append(
            {
                "operational_profile": profile_name,
                "affectedness_profile": affectedness_profile,
                "target_rule_id": target_rule_id,
                "pair_id": pair_id,
            }
        )

        for sector in SECTOR_LABELS:
            case_index += 1
            scenario = copy.deepcopy(base_scenario)
            scenario["asset_overrides"][
                "sector_context.primary_sector"
            ] = sector["label"]

            case = {
                "schema_version": "1.1.0",
                "case_id": (
                    f"AEG-ASR-{pair_index:03d}-{sector['suffix']}"
                ),
                "pair_id": pair_id,
                "case_index": case_index,
                "sector_label": sector["label"],
                "counterfactual_key": counterfactual_key,
                "differing_fields": [
                    "sector_context.primary_sector"
                ],
                "scenario": scenario,
                "expected": copy.deepcopy(expected),
                "tags": [
                    "controlled-assurance-case",
                    "step11a-rule-coverage",
                    affectedness_profile,
                    profile_name,
                    target_rule_id,
                    sector["label"],
                ],
            }

            errors = sorted(
                validator.iter_errors(case),
                key=lambda error: list(error.absolute_path),
            )

            if errors:
                messages = [
                    {
                        "path": ".".join(
                            str(part) for part in error.absolute_path
                        ),
                        "message": error.message,
                    }
                    for error in errors
                ]
                raise ValueError(
                    f"Generated case {case['case_id']} failed schema "
                    f"validation: {messages}"
                )

            combined_cases.append(case)

    if len(combined_cases) != EXPECTED_COMBINED_CASE_COUNT:
        raise RuntimeError(
            f"Expected {EXPECTED_COMBINED_CASE_COUNT} combined cases, "
            f"generated {len(combined_cases)}."
        )

    if pair_index != EXPECTED_COMBINED_PAIR_COUNT:
        raise RuntimeError(
            f"Expected {EXPECTED_COMBINED_PAIR_COUNT} pairs, "
            f"generated {pair_index}."
        )

    all_errors = {}
    for case in combined_cases:
        errors = list(validator.iter_errors(case))
        if errors:
            all_errors[case["case_id"]] = [
                error.message for error in errors
            ]

    if all_errors:
        raise ValueError(
            "Combined corpus failed schema validation: "
            + json.dumps(all_errors, indent=2)
        )

    write_jsonl(CORPUS_PATH, combined_cases)
    write_case_summary_csv(SUMMARY_PATH, combined_cases)

    manifest = {
        "schema_version": "1.1.0",
        "corpus_id": "AEG-ASR-POLICY-CORPUS-STEP11A-001",
        "generator_version": "1.1.0",
        "description": (
            "The immutable 120-case Step 9 assurance corpus extended "
            "with ten targeted cases forming five counterfactual pairs "
            "for complete decision-policy rule coverage."
        ),
        "created_at": BUILD_TIME.isoformat(),
        "case_count": len(combined_cases),
        "pair_count": pair_index,
        "design": {
            "source_case_count": EXPECTED_SOURCE_CASE_COUNT,
            "source_pair_count": EXPECTED_SOURCE_PAIR_COUNT,
            "targeted_pair_count": EXPECTED_TARGETED_PAIR_COUNT,
            "targeted_profiles": targeted_design,
            "sector_labels": [
                sector["label"] for sector in SECTOR_LABELS
            ],
            "counterfactual_differing_fields": [
                "sector_context.primary_sector"
            ],
            "decision_relevant_sector_fields": [],
        },
        "base_fixtures": copy.deepcopy(
            source_manifest["base_fixtures"]
        ),
        "artifacts": {
            "case_schema": {
                "relative_path": relative(CASE_SCHEMA_PATH),
                "sha256": sha256_file(CASE_SCHEMA_PATH),
            },
            "decision_policy": {
                "relative_path": relative(POLICY_PATH),
                "sha256": sha256_file(POLICY_PATH),
            },
            "source_step9_corpus": {
                "relative_path": relative(SOURCE_CORPUS_PATH),
                "sha256": sha256_file(SOURCE_CORPUS_PATH),
            },
            "source_step9_manifest": {
                "relative_path": relative(SOURCE_MANIFEST_PATH),
                "sha256": sha256_file(SOURCE_MANIFEST_PATH),
            },
            "corpus": {
                "relative_path": relative(CORPUS_PATH),
                "sha256": sha256_file(CORPUS_PATH),
            },
            "summary": {
                "relative_path": relative(SUMMARY_PATH),
                "sha256": sha256_file(SUMMARY_PATH),
            },
        },
    }

    write_json(MANIFEST_PATH, manifest)

    print("Step 11A policy-rule coverage corpus created")
    print(f"Source cases preserved: {len(source_cases)}")
    print(f"Targeted cases added: {len(combined_cases) - len(source_cases)}")
    print(f"Combined cases: {len(combined_cases)}")
    print(f"Counterfactual pairs: {pair_index}")
    print(f"Corpus: {relative(CORPUS_PATH)}")
    print(f"Summary: {relative(SUMMARY_PATH)}")
    print(f"Manifest: {relative(MANIFEST_PATH)}")
    print(
        "Corpus SHA-256:",
        manifest["artifacts"]["corpus"]["sha256"],
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

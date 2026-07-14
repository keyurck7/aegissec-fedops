from __future__ import annotations

import copy
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from src.assurance.hostile_input_assurance import HostileInputAssuranceHarness
from src.assurance.metamorphic_assurance import (
    MetamorphicAssuranceHarness,
    _changed_paths,
)
from src.assurance.policy_mutation import PolicyMutationHarness
from src.assurance.tamper_assurance import TamperAssuranceHarness


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "compound_attack_chain_catalog_v1.yaml"
)

FAIL_CLOSED_OUTCOMES = {
    "BLOCKED_BEFORE_DECISION",
    "REJECTED_BY_ASSURANCE",
    "QUARANTINED",
}


class CompoundAttackAssuranceError(ValueError):
    """Raised when the compound attack catalog or execution is invalid."""


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_rate(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else float(numerator) / float(denominator)


def write_json(path: Path | str, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def write_results_csv(path: Path | str, results: list[dict[str, Any]]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "chain_id",
        "family",
        "severity",
        "outcome",
        "defended",
        "unsafe_decision_released",
        "step_count",
        "layer_count",
        "detection_oracle_count",
        "multi_control_detected",
        "order_consistent",
        "first_blocking_control",
        "layers",
        "detection_oracles",
        "error",
    ]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "chain_id": result["chain_id"],
                    "family": result["family"],
                    "severity": result["severity"],
                    "outcome": result["outcome"],
                    "defended": result["defended"],
                    "unsafe_decision_released": result[
                        "unsafe_decision_released"
                    ],
                    "step_count": len(result["forward_steps"]),
                    "layer_count": len(result["layers_activated"]),
                    "detection_oracle_count": len(
                        result["detection_oracles"]
                    ),
                    "multi_control_detected": result[
                        "multi_control_detected"
                    ],
                    "order_consistent": result["order_consistent"],
                    "first_blocking_control": result[
                        "first_blocking_control"
                    ] or "",
                    "layers": ";".join(result["layers_activated"]),
                    "detection_oracles": ";".join(
                        result["detection_oracles"]
                    ),
                    "error": result.get("error") or "",
                }
            )


class CompoundAttackAssuranceHarness:
    def __init__(
        self,
        catalog_path: Path | str = DEFAULT_CATALOG_PATH,
        project_root: Path | str = PROJECT_ROOT,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.catalog_path = Path(catalog_path).resolve()
        self.catalog = yaml.safe_load(
            self.catalog_path.read_text(encoding="utf-8")
        )
        if not isinstance(self.catalog, dict):
            raise CompoundAttackAssuranceError(
                "Compound attack catalog must be a YAML object."
            )
        self._validate_catalog()
        self.trusted_inputs = self.catalog["trusted_inputs"]

        self.tamper_harness = TamperAssuranceHarness(
            project_root=self.project_root
        )
        self.hostile_harness = HostileInputAssuranceHarness(
            project_root=self.project_root
        )
        self.mutation_harness = PolicyMutationHarness(
            project_root=self.project_root
        )
        self.metamorphic_harness = MetamorphicAssuranceHarness(
            project_root=self.project_root
        )

        self.tamper_items = {
            item["scenario_id"]: item
            for item in self.tamper_harness.catalog["scenarios"]
        }
        self.hostile_items = {
            item["scenario_id"]: item
            for item in self.hostile_harness.catalog["scenarios"]
        }
        self.mutation_items = {
            item["mutation_id"]: item
            for item in self.mutation_harness.catalog["mutations"]
        }
        self.metamorphic_items = {
            item["relation_id"]: item
            for item in self.metamorphic_harness.catalog["relations"]
        }
        self._step_cache: dict[tuple[str, str], dict[str, Any]] = {}

    def _validate_catalog(self) -> None:
        required = {
            "policy",
            "trusted_inputs",
            "quality_gates",
            "production_readiness",
            "limitations",
            "chains",
        }
        missing = required - set(self.catalog)
        if missing:
            raise CompoundAttackAssuranceError(
                f"Compound catalog missing sections: {sorted(missing)}"
            )
        chains = self.catalog["chains"]
        if not isinstance(chains, list) or not chains:
            raise CompoundAttackAssuranceError(
                "Compound catalog must contain chains."
            )
        ids = [item.get("chain_id") for item in chains]
        if len(ids) != len(set(ids)):
            raise CompoundAttackAssuranceError("Chain IDs must be unique.")
        allowed_layers = {
            "tamper",
            "hostile_input",
            "policy_mutation",
            "metamorphic",
        }
        for chain in chains:
            if chain.get("severity") != "critical":
                raise CompoundAttackAssuranceError(
                    "Every Step 11F chain must be critical."
                )
            steps = chain.get("ordered_steps")
            if not isinstance(steps, list) or len(steps) < 2:
                raise CompoundAttackAssuranceError(
                    f"{chain.get('chain_id')} requires at least two steps."
                )
            if len({step.get("layer") for step in steps}) < 2:
                raise CompoundAttackAssuranceError(
                    f"{chain.get('chain_id')} must span at least two layers."
                )
            for step in steps:
                if step.get("layer") not in allowed_layers:
                    raise CompoundAttackAssuranceError(
                        f"Unsupported compound layer: {step.get('layer')!r}"
                    )
                if not step.get("source_id"):
                    raise CompoundAttackAssuranceError(
                        "Every chain step requires a source_id."
                    )

    def input_integrity_checks(self) -> dict[str, dict[str, Any]]:
        checks: dict[str, dict[str, Any]] = {}
        for name, definition in self.trusted_inputs.items():
            relative_path = definition["relative_path"]
            candidate = Path(relative_path)
            resolved = (self.project_root / candidate).resolve()
            safe = (
                not candidate.is_absolute()
                and (
                    resolved == self.project_root
                    or self.project_root in resolved.parents
                )
            )
            exists = safe and resolved.is_file()
            actual = sha256_file(resolved) if exists else None
            checks[name] = {
                "relative_path": relative_path,
                "expected_sha256": definition["expected_sha256"],
                "actual_sha256": actual,
                "safe_path": safe,
                "exists": exists,
                "passed": bool(
                    safe
                    and exists
                    and actual == definition["expected_sha256"]
                ),
            }
        return checks

    def _calibrate_prior_reports(self) -> dict[str, Any]:
        checks: dict[str, Any] = {}
        expectations = {
            "step11b_report": ("overall_passed", True),
            "step11c_report": ("overall_passed", True),
            "step11d_report": ("overall_passed", True),
            "step11e_report": ("overall_passed", True),
        }
        for name, (metric, expected) in expectations.items():
            path = self.project_root / self.trusted_inputs[name]["relative_path"]
            report = json.loads(path.read_text(encoding="utf-8"))
            observed = report.get("summary", {}).get(metric)
            checks[name] = {
                "metric": metric,
                "expected": expected,
                "observed": observed,
                "passed": observed is expected,
            }
        if not all(item["passed"] for item in checks.values()):
            raise CompoundAttackAssuranceError(
                "Prior assurance calibration failed."
            )
        return checks

    def _execute_metamorphic(self, relation: dict[str, Any]) -> dict[str, Any]:
        harness = self.metamorphic_harness
        evaluated_at = datetime.fromisoformat(
            harness.catalog["policy"]["evaluated_at"]
        )
        base_id = relation["baseline_case_id"]
        baseline_case = copy.deepcopy(harness.cases[base_id])
        transformed_case, transformed_id = harness._transformed_case(relation)
        changed_paths = _changed_paths(
            baseline_case["scenario"], transformed_case["scenario"]
        )
        baseline = harness._evaluate_case(baseline_case, evaluated_at)
        transformed = harness._evaluate_case(transformed_case, evaluated_at)
        checks = harness._relation_checks(
            relation, baseline, transformed, changed_paths
        )
        violations = [check["code"] for check in checks if not check["passed"]]
        passed = not violations
        return {
            "source_id": relation["relation_id"],
            "layer": "metamorphic",
            "raw_outcome": "PASSED" if passed else "VIOLATED",
            "defended": passed,
            "detection_oracles": [
                "METAMORPHIC_PROPERTY",
                *sorted(check["code"] for check in checks if check["passed"]),
            ],
            "finding_codes": violations,
            "details": {
                "baseline_case_id": base_id,
                "transformed_case_id": transformed_id,
                "changed_paths": changed_paths,
            },
            "error": None,
        }

    def _execute_step(self, step: dict[str, Any]) -> dict[str, Any]:
        layer = step["layer"]
        source_id = step["source_id"]
        key = (layer, source_id)
        if key in self._step_cache:
            return copy.deepcopy(self._step_cache[key])
        try:
            if layer == "tamper":
                raw = self.tamper_harness.execute_scenario(
                    self.tamper_items[source_id]
                )
                result = {
                    "source_id": source_id,
                    "layer": layer,
                    "raw_outcome": raw["outcome"],
                    "defended": raw["defended"],
                    "detection_oracles": raw["detection_oracles"],
                    "finding_codes": [
                        item["code"] for item in raw["findings"]
                    ],
                    "details": {},
                    "error": raw.get("error"),
                }
            elif layer == "hostile_input":
                raw = self.hostile_harness.execute_scenario(
                    self.hostile_items[source_id]
                )
                result = {
                    "source_id": source_id,
                    "layer": layer,
                    "raw_outcome": raw["outcome"],
                    "defended": raw["defended"],
                    "detection_oracles": raw["detection_oracles"],
                    "finding_codes": [
                        item["code"] for item in raw["findings"]
                    ],
                    "details": raw.get("observed", {}),
                    "error": raw.get("error"),
                }
            elif layer == "policy_mutation":
                execution = self.mutation_harness.execute_mutation(
                    self.mutation_items[source_id]
                )
                raw = execution.result
                defended = raw["status"] in {
                    "BLOCKED_AT_LOAD",
                    "KILLED_BY_ASSURANCE",
                }
                result = {
                    "source_id": source_id,
                    "layer": layer,
                    "raw_outcome": raw["status"],
                    "defended": defended,
                    "detection_oracles": raw["detection_oracles"],
                    "finding_codes": [
                        item.get("code", "STATIC_CONTRACT_FAILURE")
                        if isinstance(item, dict)
                        else str(item)
                        for item in raw["static_contract_failures"]
                    ],
                    "details": {
                        "executable": raw["executable"],
                        "failed_case_count": raw["assurance"][
                            "failed_case_count"
                        ],
                    },
                    "error": raw.get("error") or raw.get("load_error"),
                }
            else:
                result = self._execute_metamorphic(
                    self.metamorphic_items[source_id]
                )
        except Exception as exc:  # fail-safe reporting
            result = {
                "source_id": source_id,
                "layer": layer,
                "raw_outcome": "HARNESS_ERROR",
                "defended": False,
                "detection_oracles": [],
                "finding_codes": [],
                "details": {},
                "error": f"{type(exc).__name__}: {exc}",
            }
        self._step_cache[key] = copy.deepcopy(result)
        return result

    @staticmethod
    def _aggregate_order(steps: list[dict[str, Any]]) -> dict[str, Any]:
        unsafe = any(
            not step["defended"]
            or step["raw_outcome"]
            in {
                "UNDETECTED",
                "SURVIVED",
                "VIOLATED",
                "HARNESS_ERROR",
            }
            for step in steps
        )
        layers = sorted({step["layer"] for step in steps})
        oracles = sorted(
            {
                oracle
                for step in steps
                for oracle in step["detection_oracles"]
            }
        )
        multi_control = len(layers) >= 2 and len(oracles) >= 2
        first_blocking = next(
            (
                f"{step['layer']}:{step['source_id']}"
                for step in steps
                if step["defended"]
            ),
            None,
        )
        raw_outcomes = {step["raw_outcome"] for step in steps}
        if raw_outcomes & {"BLOCKED", "BLOCKED_AT_LOAD"}:
            outcome = "BLOCKED_BEFORE_DECISION"
        elif "QUARANTINED" in raw_outcomes:
            outcome = "QUARANTINED"
        else:
            outcome = "REJECTED_BY_ASSURANCE"
        return {
            "outcome": outcome,
            "unsafe_decision_released": unsafe,
            "layers_activated": layers,
            "detection_oracles": oracles,
            "multi_control_detected": multi_control,
            "first_blocking_control": first_blocking,
            "defended": (
                not unsafe
                and multi_control
                and outcome in FAIL_CLOSED_OUTCOMES
            ),
        }

    def execute_chain(self, chain: dict[str, Any]) -> dict[str, Any]:
        base = {
            "chain_id": chain["chain_id"],
            "title": chain["title"],
            "family": chain["family"],
            "severity": chain["severity"],
            "description": chain["description"],
            "control_tags": list(chain.get("control_tags", [])),
            "ephemeral_only": True,
        }
        try:
            forward_steps = [
                self._execute_step(step) for step in chain["ordered_steps"]
            ]
            reverse_steps = [
                self._execute_step(step)
                for step in reversed(chain["ordered_steps"])
            ]
            forward = self._aggregate_order(forward_steps)
            reverse = self._aggregate_order(reverse_steps)
            order_consistent = (
                forward["defended"]
                and reverse["defended"]
                and not forward["unsafe_decision_released"]
                and not reverse["unsafe_decision_released"]
            )
            defended = forward["defended"] and order_consistent
            base.update(
                {
                    **forward,
                    "defended": defended,
                    "order_consistent": order_consistent,
                    "forward_steps": forward_steps,
                    "reverse_steps": reverse_steps,
                    "error": None,
                }
            )
        except Exception as exc:  # pragma: no cover
            base.update(
                {
                    "outcome": "HARNESS_ERROR",
                    "defended": False,
                    "unsafe_decision_released": True,
                    "layers_activated": [],
                    "detection_oracles": [],
                    "multi_control_detected": False,
                    "first_blocking_control": None,
                    "order_consistent": False,
                    "forward_steps": [],
                    "reverse_steps": [],
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
        return base

    @staticmethod
    def _tag_rate(results: list[dict[str, Any]], tag: str) -> float:
        group = [item for item in results if tag in item["control_tags"]]
        return safe_rate(sum(item["defended"] for item in group), len(group))

    def run(self) -> dict[str, Any]:
        before = self.input_integrity_checks()
        if not all(item["passed"] for item in before.values()):
            raise CompoundAttackAssuranceError(
                "Trusted baseline verification failed before execution."
            )
        baseline_validation = self._calibrate_prior_reports()
        results = [self.execute_chain(chain) for chain in self.catalog["chains"]]
        after = self.input_integrity_checks()
        trusted_integrity = all(
            before[name]["passed"]
            and after[name]["passed"]
            and before[name]["actual_sha256"] == after[name]["actual_sha256"]
            for name in before
        )
        critical = [item for item in results if item["severity"] == "critical"]
        defended = [item for item in critical if item["defended"]]
        undetected = [item for item in results if not item["defended"]]
        errors = [item for item in results if item["outcome"] == "HARNESS_ERROR"]
        unsafe = [item for item in results if item["unsafe_decision_released"]]
        fail_closed = [
            item
            for item in critical
            if item["outcome"] in FAIL_CLOSED_OUTCOMES
            and not item["unsafe_decision_released"]
        ]
        multi_control = [item for item in critical if item["multi_control_detected"]]
        order_consistent = [item for item in critical if item["order_consistent"]]
        summary = {
            "chain_count": len(results),
            "critical_chain_count": len(critical),
            "defended_critical_count": len(defended),
            "blocked_before_decision_count": sum(
                item["outcome"] == "BLOCKED_BEFORE_DECISION"
                for item in results
            ),
            "rejected_by_assurance_count": sum(
                item["outcome"] == "REJECTED_BY_ASSURANCE"
                for item in results
            ),
            "quarantined_count": sum(
                item["outcome"] == "QUARANTINED" for item in results
            ),
            "undetected_count": len(undetected),
            "harness_error_count": len(errors),
            "unsafe_decision_release_count": len(unsafe),
            "critical_compound_chain_defence_rate": safe_rate(
                len(defended), len(critical)
            ),
            "fail_closed_chain_handling_rate": safe_rate(
                len(fail_closed), len(critical)
            ),
            "multi_control_detection_rate": safe_rate(
                len(multi_control), len(critical)
            ),
            "order_sensitive_chain_consistency_rate": safe_rate(
                len(order_consistent), len(critical)
            ),
            "cross_layer_integrity_defence_rate": self._tag_rate(
                results, "cross_layer_integrity"
            ),
            "trusted_input_integrity_passed": trusted_integrity,
        }
        gates = self.catalog["quality_gates"]
        specs = [
            ("COMPOUND-CRITICAL-DEFENCE", summary["critical_compound_chain_defence_rate"], "gte", gates["critical_compound_chain_defence_rate_minimum"]),
            ("COMPOUND-UNDETECTED", summary["undetected_count"], "lte", gates["undetected_critical_chains_maximum"]),
            ("COMPOUND-HARNESS-ERRORS", summary["harness_error_count"], "lte", gates["harness_errors_maximum"]),
            ("COMPOUND-UNSAFE-RELEASES", summary["unsafe_decision_release_count"], "lte", gates["unsafe_decision_release_count_maximum"]),
            ("COMPOUND-FAIL-CLOSED", summary["fail_closed_chain_handling_rate"], "gte", gates["fail_closed_chain_handling_rate_minimum"]),
            ("COMPOUND-MULTI-CONTROL", summary["multi_control_detection_rate"], "gte", gates["multi_control_detection_rate_minimum"]),
            ("COMPOUND-ORDER-CONSISTENCY", summary["order_sensitive_chain_consistency_rate"], "gte", gates["order_sensitive_chain_consistency_rate_minimum"]),
            ("COMPOUND-CROSS-LAYER-INTEGRITY", summary["cross_layer_integrity_defence_rate"], "gte", gates["cross_layer_integrity_defence_rate_minimum"]),
            ("COMPOUND-TRUSTED-INTEGRITY", trusted_integrity, "eq", gates["trusted_input_integrity_required"]),
        ]
        quality_gates = []
        for gate_id, observed, operator, threshold in specs:
            if operator == "gte":
                passed = observed >= threshold
            elif operator == "lte":
                passed = observed <= threshold
            else:
                passed = observed == threshold
            quality_gates.append(
                {
                    "gate_id": gate_id,
                    "operator": operator,
                    "threshold": threshold,
                    "observed": observed,
                    "passed": passed,
                }
            )
        summary["overall_passed"] = all(
            gate["passed"] for gate in quality_gates
        )
        release = {
            "stage_gate_status": "PASS" if summary["overall_passed"] else "FAIL",
            "production_readiness_status": "BLOCKED",
            "blocking_reasons": list(
                self.catalog["production_readiness"]["blocking_reasons"]
            ),
        }
        return {
            "schema_version": "1.0.0",
            "report_id": "AEG-COMPOUND-STEP11F-001",
            "catalog": {
                "catalog_id": self.catalog["policy"]["catalog_id"],
                "version": self.catalog["policy"]["version"],
                "harness_version": self.catalog["policy"]["harness_version"],
                "relative_path": self.catalog_path.relative_to(
                    self.project_root
                ).as_posix(),
                "sha256": sha256_file(self.catalog_path),
            },
            "input_integrity_checks_before": before,
            "input_integrity_checks_after": after,
            "baseline_validation": baseline_validation,
            "summary": summary,
            "quality_gates": quality_gates,
            "results": results,
            "undetected_chain_ids": [item["chain_id"] for item in undetected],
            "harness_error_chain_ids": [item["chain_id"] for item in errors],
            "unsafe_release_chain_ids": [item["chain_id"] for item in unsafe],
            "release_decision": release,
            "limitations": list(self.catalog["limitations"]),
            "generated_at": datetime.now().astimezone().isoformat(),
        }


def save_compound_attack_artifacts(
    report: dict[str, Any], output_dir: Path | str
) -> dict[str, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "report": directory / "step11f_compound_attack_report.json",
        "csv": directory / "step11f_chain_results.csv",
        "undetected": directory / "step11f_undetected_chains.json",
        "integrity": directory / "step11f_trusted_baseline_integrity.sha256",
    }
    write_json(paths["report"], report)
    write_results_csv(paths["csv"], report["results"])
    write_json(
        paths["undetected"],
        {
            "schema_version": "1.0.0",
            "report_id": report["report_id"],
            "undetected_chain_ids": report["undetected_chain_ids"],
            "unsafe_release_chain_ids": report["unsafe_release_chain_ids"],
            "undetected_chains": [
                item for item in report["results"] if not item["defended"]
            ],
        },
    )
    paths["integrity"].write_text(
        "".join(
            f"{item['actual_sha256']}  {item['relative_path']}\n"
            for item in report["input_integrity_checks_after"].values()
        ),
        encoding="utf-8",
    )
    return paths

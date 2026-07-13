from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
import shutil
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote

import yaml

from src.domain.decision_hashing import (
    finalize_decision_record_hash,
    sha256_file,
    verify_decision_record_hash,
)
from src.validation.decision_record_validator import DecisionRecordValidator
from src.validation.evidence_schema_validator import EvidenceSchemaValidator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "tamper_scenario_catalog_v1.yaml"
)

DEFENDED_OUTCOMES = {
    "BLOCKED",
    "REJECTED",
    "QUARANTINED",
    "DETECTED_WITH_WARNING",
}
CRITICAL_ALLOWED_OUTCOMES = {"BLOCKED", "REJECTED", "QUARANTINED"}


@dataclass(frozen=True)
class TamperFinding:
    code: str
    oracle: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "oracle": self.oracle,
            "message": self.message,
        }


def load_json(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return payload


def load_jsonl(path: Path | str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(
                f"Expected JSON object at {path}:{line_number}"
            )
        rows.append(payload)
    return rows


def write_json(path: Path | str, payload: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_results_csv(
    path: Path | str,
    results: list[dict[str, Any]],
) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "scenario_id",
        "family",
        "severity",
        "outcome",
        "defended",
        "ephemeral_only",
        "detection_oracles",
        "finding_codes",
        "baseline_sha256",
        "mutated_sha256",
        "error",
    ]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "scenario_id": result["scenario_id"],
                    "family": result["family"],
                    "severity": result["severity"],
                    "outcome": result["outcome"],
                    "defended": result["defended"],
                    "ephemeral_only": result["ephemeral_only"],
                    "detection_oracles": ";".join(
                        result["detection_oracles"]
                    ),
                    "finding_codes": ";".join(
                        finding["code"] for finding in result["findings"]
                    ),
                    "baseline_sha256": result.get("baseline_sha256") or "",
                    "mutated_sha256": result.get("mutated_sha256") or "",
                    "error": result.get("error") or "",
                }
            )


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _reference_signature(record: dict[str, Any]) -> dict[str, Any]:
    inputs = record["input_records"]
    references = [
        inputs["asset_context"],
        inputs["vulnerability_intelligence"],
        *inputs["evidence_records"],
    ]
    return {
        "input_references": [
            {
                "record_type": item["record_type"],
                "record_id": item["record_id"],
                "relative_path": item["relative_path"],
                "required_for_decision": item["required_for_decision"],
            }
            for item in references
        ],
        "component_evidence_ids": list(
            record["component_instance"]["evidence_ids"]
        ),
        "affectedness_evidence_ids": list(
            record["affectedness"]["supporting_evidence_ids"]
        ),
        "policy_evidence_ids": [
            {
                "rule_id": rule["rule_id"],
                "evidence_ids": list(rule["supporting_evidence_ids"]),
            }
            for rule in record["policy_decision"]["triggered_rules"]
        ],
    }


def _finding(
    code: str,
    oracle: str,
    message: str,
) -> TamperFinding:
    return TamperFinding(code=code, oracle=oracle, message=message)


def _decision_findings(
    validator: DecisionRecordValidator,
    record: dict[str, Any],
) -> tuple[list[TamperFinding], Any]:
    validation = validator.validate(record)
    findings: list[TamperFinding] = []
    if validation.errors:
        findings.append(
            _finding(
                "DECISION_RECORD_REJECTED",
                "DECISION_VALIDATOR",
                "Decision Record validation rejected the tampered record.",
            )
        )
    for issue in validation.errors:
        oracle = "DECISION_VALIDATOR"
        if issue.code == "DECISION_RECORD_HASH_MISMATCH":
            oracle = "DECISION_RECORD_HASH"
        elif issue.code == "INPUT_PATH_ESCAPE":
            oracle = "SAFE_PATH"
        elif issue.code == "INPUT_RECORD_HASH_MISMATCH":
            oracle = "INPUT_RECORD_HASH"
        elif issue.code == "INPUT_RECORD_ID_MISMATCH":
            oracle = "INPUT_ID_BINDING"
        elif issue.code in {
            "INPUT_RECORD_VALIDATION_FAILED",
            "INPUT_RECORD_NOT_OBJECT",
            "INPUT_RECORD_INVALID_JSON",
        }:
            oracle = "INPUT_SCHEMA"
        elif issue.code == "DUPLICATE_INPUT_REFERENCE":
            oracle = "DUPLICATE_ID"
        elif issue.code == "SCHEMA_VALIDATION_ERROR":
            oracle = "JSON_SCHEMA"
        findings.append(_finding(issue.code, oracle, issue.message))
    return findings, validation


def _signature_findings(record: dict[str, Any]) -> list[TamperFinding]:
    integrity = record["integrity"]
    status = integrity["signature_status"]
    reference = integrity.get("signature_reference")
    findings: list[TamperFinding] = []
    if status == "invalid":
        findings.append(
            _finding(
                "INVALID_EVIDENCE_SIGNATURE",
                "SIGNATURE_POLICY",
                "Evidence declares an invalid signature and cannot be trusted.",
            )
        )
    if status == "valid" and not reference:
        findings.append(
            _finding(
                "VALID_SIGNATURE_REFERENCE_MISSING",
                "SIGNATURE_POLICY",
                "A valid signature declaration requires a traceable reference.",
            )
        )
    return findings


def _freshness_findings(record: dict[str, Any]) -> list[TamperFinding]:
    collection = record["collection"]
    freshness = record.get("freshness")
    if not freshness:
        return []
    findings: list[TamperFinding] = []
    collected_at = _parse_timestamp(collection["collected_at"])
    evaluated_at = _parse_timestamp(freshness["evaluated_at"])
    if collected_at > evaluated_at:
        findings.append(
            _finding(
                "COLLECTION_AFTER_FRESHNESS_EVALUATION",
                "TIMESTAMP_CONSISTENCY",
                "Evidence collection time occurs after freshness evaluation.",
            )
        )
        return findings
    derived_age = int((evaluated_at - collected_at).total_seconds())
    declared_age = freshness["age_seconds"]
    maximum_age = freshness["maximum_age_seconds"]
    if abs(derived_age - declared_age) > 1:
        findings.append(
            _finding(
                "DECLARED_EVIDENCE_AGE_MISMATCH",
                "FRESHNESS_CONSISTENCY",
                "Declared evidence age does not match its timestamps.",
            )
        )
    if freshness["status"] == "current" and derived_age > maximum_age:
        findings.append(
            _finding(
                "STALE_EVIDENCE_DECLARED_CURRENT",
                "FRESHNESS_CONSISTENCY",
                "Evidence exceeds its maximum age but is declared current.",
            )
        )
    valid_until = collection.get("valid_until")
    if valid_until is not None:
        expiry = _parse_timestamp(valid_until)
        if freshness["status"] == "current" and expiry < evaluated_at:
            findings.append(
                _finding(
                    "EXPIRED_EVIDENCE_DECLARED_CURRENT",
                    "FRESHNESS_CONSISTENCY",
                    "Evidence expired before freshness evaluation but is current.",
                )
            )
    return findings


def _identifier_findings(identifier: str) -> list[TamperFinding]:
    normalized = unicodedata.normalize("NFKC", identifier)
    if not identifier.isascii() or normalized != identifier:
        return [
            _finding(
                "NON_ASCII_OR_NON_CANONICAL_IDENTIFIER",
                "IDENTIFIER_POLICY",
                "Security identifiers must use canonical ASCII characters.",
            )
        ]
    return []


def _provenance_findings(record: dict[str, Any]) -> list[TamperFinding]:
    evidence_id = record["evidence_id"]
    parents = record["provenance"]["parent_evidence_ids"]
    if evidence_id in parents:
        return [
            _finding(
                "SELF_REFERENTIAL_EVIDENCE_PROVENANCE",
                "PROVENANCE_GRAPH",
                "An evidence record cannot name itself as a provenance parent.",
            )
        ]
    return []


def _validation_attestation_findings(
    record: dict[str, Any],
    validator: EvidenceSchemaValidator,
) -> list[TamperFinding]:
    actual = validator.validate(record)
    declared = record["validation"]["status"]
    if actual.status != declared:
        return [
            _finding(
                "DECLARED_VALIDATION_STATUS_MISMATCH",
                "VALIDATION_ATTESTATION",
                f"Record declares {declared}, but validator returns {actual.status}.",
            )
        ]
    return []


def _safe_path_findings(
    project_root: Path,
    relative_path: str,
) -> list[TamperFinding]:
    findings: list[TamperFinding] = []
    decoded = relative_path
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if decoded != relative_path and ".." in Path(decoded).parts:
        findings.append(
            _finding(
                "ENCODED_PATH_TRAVERSAL",
                "ENCODED_PATH_POLICY",
                "Percent-decoded path contains parent traversal.",
            )
        )
    supplied = Path(decoded)
    if supplied.is_absolute():
        findings.append(
            _finding(
                "ABSOLUTE_REFERENCE_PATH",
                "SAFE_PATH",
                "Absolute referenced paths are prohibited.",
            )
        )
        return findings
    if ".." in supplied.parts:
        findings.append(
            _finding(
                "PARENT_PATH_TRAVERSAL",
                "SAFE_PATH",
                "Referenced path contains parent traversal.",
            )
        )
    resolved = (project_root / supplied).resolve()
    root = project_root.resolve()
    if resolved != root and root not in resolved.parents:
        findings.append(
            _finding(
                "REFERENCE_PATH_ESCAPE",
                "SAFE_PATH",
                "Referenced path resolves outside the approved project root.",
            )
        )
    return findings


def _duplicate_ids(
    records: list[dict[str, Any]],
    field: str,
) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for record in records:
        identifier = record[field]
        if identifier in seen:
            duplicates.add(identifier)
        seen.add(identifier)
    return sorted(duplicates)


class TamperAssuranceHarness:
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
            raise ValueError("Tamper scenario catalog must be a mapping.")
        self._validate_catalog()
        self.trusted_paths = {
            name: self.project_root / item["relative_path"]
            for name, item in self.catalog["trusted_inputs"].items()
        }
        self.expected_hashes = {
            name: item["expected_sha256"]
            for name, item in self.catalog["trusted_inputs"].items()
        }
        self.handlers: dict[str, Callable[[], dict[str, Any]]] = {
            name.removeprefix("_scenario_"): method
            for name in dir(self)
            if name.startswith("_scenario_")
            and callable(method := getattr(self, name))
        }

    def _validate_catalog(self) -> None:
        policy = self.catalog.get("policy")
        scenarios = self.catalog.get("scenarios")
        if not isinstance(policy, dict) or not isinstance(scenarios, list):
            raise ValueError("Catalog requires policy and scenarios.")
        ids = [item.get("scenario_id") for item in scenarios]
        if len(ids) != len(set(ids)):
            raise ValueError("Scenario IDs must be unique.")
        for scenario in scenarios:
            if scenario.get("severity") != "critical":
                raise ValueError("Step 11C scenarios must be critical.")
            if not scenario.get("handler"):
                raise ValueError("Each scenario requires a handler.")
            if not scenario.get("expected_outcomes"):
                raise ValueError("Each scenario requires expected outcomes.")

    def _input_integrity_checks(self) -> dict[str, dict[str, Any]]:
        checks: dict[str, dict[str, Any]] = {}
        for name, path in self.trusted_paths.items():
            if not path.is_file():
                raise FileNotFoundError(f"Trusted input not found: {path}")
            actual = sha256_file(path)
            expected = self.expected_hashes[name]
            checks[name] = {
                "relative_path": path.relative_to(self.project_root).as_posix(),
                "expected_sha256": expected,
                "actual_sha256": actual,
                "passed": actual == expected,
            }
        return checks

    def _copy_decision_project(self, root: Path) -> Path:
        project = root / "project"
        relative_paths = [
            "data/sample_inputs/decisions/valid_log4shell_decision_record.json",
            "data/sample_inputs/assets/valid_healthcare_asset.json",
            "data/sample_inputs/intelligence/valid_log4shell_intelligence.json",
            "data/sample_inputs/evidence/valid_log4j_sbom_evidence.json",
        ]
        for relative in relative_paths:
            source = self.project_root / relative
            destination = project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return project

    def _load_temp_decision(self, project: Path) -> dict[str, Any]:
        return load_json(
            project
            / "data/sample_inputs/decisions/valid_log4shell_decision_record.json"
        )

    def _decision_validator(self, project: Path) -> DecisionRecordValidator:
        return DecisionRecordValidator(project_root=project)

    @staticmethod
    def _result(
        outcome: str,
        findings: list[TamperFinding],
        baseline_sha256: str | None = None,
        mutated_sha256: str | None = None,
    ) -> dict[str, Any]:
        return {
            "outcome": outcome,
            "findings": findings,
            "baseline_sha256": baseline_sha256,
            "mutated_sha256": mutated_sha256,
        }

    def _scenario_policy_file_modified(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            path = Path(temp) / "policy.yaml"
            shutil.copy2(self.trusted_paths["decision_policy"], path)
            before = sha256_file(path)
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\n# unauthorized policy modification\n",
                encoding="utf-8",
            )
            after = sha256_file(path)
            findings = []
            if before != after:
                findings.append(
                    _finding(
                        "TRUSTED_POLICY_HASH_MISMATCH",
                        "BASELINE_HASH",
                        "Trusted decision-policy bytes changed.",
                    )
                )
            return self._result("BLOCKED", findings, before, after)

    def _scenario_corpus_line_modified(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            corpus = Path(temp) / "corpus.jsonl"
            shutil.copy2(self.trusted_paths["assurance_corpus"], corpus)
            manifest = load_json(self.trusted_paths["assurance_manifest"])
            before = sha256_file(corpus)
            rows = load_jsonl(corpus)
            rows[0]["expected"]["priority"] = "INFORMATIONAL"
            corpus.write_text(
                "".join(
                    json.dumps(row, sort_keys=True) + "\n" for row in rows
                ),
                encoding="utf-8",
            )
            after = sha256_file(corpus)
            declared = manifest["artifacts"]["corpus"]["sha256"]
            findings = []
            if after != declared:
                findings.append(
                    _finding(
                        "CORPUS_MANIFEST_HASH_MISMATCH",
                        "MANIFEST_HASH",
                        "Assurance corpus no longer matches its manifest.",
                    )
                )
            return self._result("REJECTED", findings, before, after)

    def _scenario_manifest_corpus_hash_replaced(self) -> dict[str, Any]:
        manifest = load_json(self.trusted_paths["assurance_manifest"])
        baseline = sha256_file(self.trusted_paths["assurance_manifest"])
        manifest["artifacts"]["corpus"]["sha256"] = "0" * 64
        mutated_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        mutated = hashlib.sha256(mutated_bytes).hexdigest()
        findings = [
            _finding(
                "TRUSTED_MANIFEST_MODIFIED",
                "TRUSTED_MANIFEST_HASH",
                "The assurance manifest was modified.",
            )
        ]
        actual = sha256_file(self.trusted_paths["assurance_corpus"])
        if actual != manifest["artifacts"]["corpus"]["sha256"]:
            findings.append(
                _finding(
                    "DECLARED_CORPUS_HASH_INVALID",
                    "MANIFEST_HASH",
                    "Manifest corpus hash does not match the corpus.",
                )
            )
        return self._result("REJECTED", findings, baseline, mutated)

    def _scenario_manifest_fixture_hash_replaced(self) -> dict[str, Any]:
        manifest = load_json(self.trusted_paths["assurance_manifest"])
        baseline = sha256_file(self.trusted_paths["assurance_manifest"])
        manifest["base_fixtures"]["asset_context"]["sha256"] = "f" * 64
        mutated = hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode("utf-8")
        ).hexdigest()
        findings = [
            _finding(
                "TRUSTED_MANIFEST_MODIFIED",
                "TRUSTED_MANIFEST_HASH",
                "The assurance manifest was modified.",
            )
        ]
        actual = sha256_file(self.trusted_paths["asset_context"])
        if actual != manifest["base_fixtures"]["asset_context"]["sha256"]:
            findings.append(
                _finding(
                    "DECLARED_FIXTURE_HASH_INVALID",
                    "FIXTURE_HASH",
                    "Manifest fixture hash does not match the asset fixture.",
                )
            )
        return self._result("REJECTED", findings, baseline, mutated)

    def _scenario_fixture_substitution(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            asset = project / "data/sample_inputs/assets/valid_healthcare_asset.json"
            before = sha256_file(asset)
            shutil.copy2(
                project / "data/sample_inputs/evidence/valid_log4j_sbom_evidence.json",
                asset,
            )
            after = sha256_file(asset)
            decision = self._load_temp_decision(project)
            findings, _ = _decision_findings(
                self._decision_validator(project), decision
            )
            return self._result("REJECTED", findings, before, after)

    def _scenario_decision_content_modified(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            decision = self._load_temp_decision(project)
            before = decision["audit"]["record_hash"]
            decision["arbitration"]["final_action"] = "TRACK"
            after = hashlib.sha256(
                json.dumps(decision, sort_keys=True).encode("utf-8")
            ).hexdigest()
            findings, _ = _decision_findings(
                self._decision_validator(project), decision
            )
            return self._result("REJECTED", findings, before, after)

    def _scenario_decision_hash_invalid(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            decision = self._load_temp_decision(project)
            before = decision["audit"]["record_hash"]
            decision["audit"]["record_hash"] = "0" * 64
            findings, _ = _decision_findings(
                self._decision_validator(project), decision
            )
            return self._result(
                "REJECTED", findings, before, decision["audit"]["record_hash"]
            )

    def _scenario_decision_hash_malformed(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            decision = self._load_temp_decision(project)
            before = decision["audit"]["record_hash"]
            decision["audit"]["record_hash"] = "not-a-sha256"
            findings, _ = _decision_findings(
                self._decision_validator(project), decision
            )
            mutated_digest = hashlib.sha256(
                json.dumps(decision, sort_keys=True).encode("utf-8")
            ).hexdigest()
            return self._result(
                "BLOCKED", findings, before, mutated_digest
            )

    def _scenario_signature_invalid(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["integrity"]["signature_status"] = "invalid"
        findings = _signature_findings(evidence)
        return self._result("REJECTED", findings)

    def _scenario_signature_valid_missing_reference(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["integrity"]["signature_status"] = "valid"
        evidence["integrity"]["signature_reference"] = None
        findings = _signature_findings(evidence)
        return self._result("REJECTED", findings)

    def _scenario_evidence_substitution_same_id(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        before = sha256_file(self.trusted_paths["evidence_record"])
        evidence["title"] = "Substituted evidence with retained identity"
        evidence["source"]["external_reference"] = "ATTACKER-CONTENT-001"
        mutated = hashlib.sha256(
            json.dumps(evidence, sort_keys=True).encode("utf-8")
        ).hexdigest()
        findings = [
            _finding(
                "EVIDENCE_ID_CONTENT_BINDING_CHANGED",
                "EVIDENCE_ID_BINDING",
                "Trusted evidence ID was reused for different content.",
            ),
            _finding(
                "REFERENCED_EVIDENCE_HASH_MISMATCH",
                "INPUT_RECORD_HASH",
                "Substituted evidence does not match the trusted hash.",
            ),
        ]
        return self._result("REJECTED", findings, before, mutated)

    def _path_scenario(
        self,
        path_value: str,
        outcome: str,
        create_symlink: bool = False,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            temp_root = Path(temp)
            project = self._copy_decision_project(temp_root)
            decision = self._load_temp_decision(project)
            reference = decision["input_records"]["evidence_records"][0]
            if create_symlink:
                outside_dir = temp_root / "outside"
                outside_dir.mkdir()
                outside_file = outside_dir / "outside_evidence.json"
                shutil.copy2(self.trusted_paths["evidence_record"], outside_file)
                link_path = project / path_value
                link_path.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(outside_file, link_path)
                reference["sha256"] = sha256_file(outside_file)
            reference["relative_path"] = path_value
            decision = finalize_decision_record_hash(decision)
            findings = _safe_path_findings(project, path_value)
            validator_findings, _ = _decision_findings(
                self._decision_validator(project), decision
            )
            findings.extend(validator_findings)
            return self._result(outcome, findings)

    def _scenario_path_traversal(self) -> dict[str, Any]:
        return self._path_scenario("../outside.json", "BLOCKED")

    def _scenario_absolute_path(self) -> dict[str, Any]:
        return self._path_scenario("/tmp/aegis-outside.json", "BLOCKED")

    def _scenario_encoded_path_traversal(self) -> dict[str, Any]:
        return self._path_scenario("%2e%2e/outside.json", "BLOCKED")

    def _scenario_symlink_escape(self) -> dict[str, Any]:
        return self._path_scenario(
            "data/sample_inputs/evidence/escaped_link.json",
            "BLOCKED",
            create_symlink=True,
        )

    def _scenario_duplicate_input_reference(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            decision = self._load_temp_decision(project)
            duplicate = copy.deepcopy(
                decision["input_records"]["evidence_records"][0]
            )
            decision["input_records"]["evidence_records"].append(duplicate)
            decision = finalize_decision_record_hash(decision)
            findings, _ = _decision_findings(
                self._decision_validator(project), decision
            )
            return self._result("REJECTED", findings)

    def _scenario_duplicate_corpus_case_id(self) -> dict[str, Any]:
        rows = load_jsonl(self.trusted_paths["assurance_corpus"])
        before = sha256_file(self.trusted_paths["assurance_corpus"])
        rows.append(copy.deepcopy(rows[0]))
        duplicates = _duplicate_ids(rows, "case_id")
        mutated = hashlib.sha256(
            "".join(
                json.dumps(row, sort_keys=True) + "\n" for row in rows
            ).encode("utf-8")
        ).hexdigest()
        findings: list[TamperFinding] = []
        if duplicates:
            findings.append(
                _finding(
                    "DUPLICATE_ASSURANCE_CASE_ID",
                    "DUPLICATE_ID",
                    f"Duplicate case identifiers: {duplicates}",
                )
            )
        manifest = load_json(self.trusted_paths["assurance_manifest"])
        if mutated != manifest["artifacts"]["corpus"]["sha256"]:
            findings.append(
                _finding(
                    "CORPUS_MANIFEST_HASH_MISMATCH",
                    "MANIFEST_HASH",
                    "Duplicate case changed the manifest-bound corpus.",
                )
            )
        return self._result("REJECTED", findings, before, mutated)

    def _scenario_reference_deletion(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            baseline = self._load_temp_decision(project)
            expected = _reference_signature(baseline)
            mutated = copy.deepcopy(baseline)
            mutated["affectedness"]["supporting_evidence_ids"].pop()
            mutated = finalize_decision_record_hash(mutated)
            actual = _reference_signature(mutated)
            findings = []
            if actual != expected:
                findings.append(
                    _finding(
                        "DECISION_REFERENCE_SET_CHANGED",
                        "REFERENCE_SET_INTEGRITY",
                        "A supporting evidence reference was deleted.",
                    )
                )
            return self._result("REJECTED", findings)

    def _scenario_reference_injection(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            baseline = self._load_temp_decision(project)
            expected = _reference_signature(baseline)
            mutated = copy.deepcopy(baseline)
            mutated["component_instance"]["evidence_ids"].append(
                "AEG-EVD-REQ-000001"
            )
            mutated = finalize_decision_record_hash(mutated)
            actual = _reference_signature(mutated)
            findings = []
            if actual != expected:
                findings.append(
                    _finding(
                        "DECISION_REFERENCE_SET_CHANGED",
                        "REFERENCE_SET_INTEGRITY",
                        "An unrelated evidence reference was injected.",
                    )
                )
            return self._result("REJECTED", findings)

    def _scenario_reference_reordering(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-tamper-") as temp:
            project = self._copy_decision_project(Path(temp))
            decision = self._load_temp_decision(project)
            baseline_order = list(
                decision["affectedness"]["supporting_evidence_ids"]
            )
            decision["affectedness"]["supporting_evidence_ids"].reverse()
            findings, _ = _decision_findings(
                self._decision_validator(project), decision
            )
            if decision["affectedness"]["supporting_evidence_ids"] != baseline_order:
                findings.append(
                    _finding(
                        "EVIDENCE_REFERENCE_ORDER_CHANGED",
                        "REFERENCE_ORDER_INTEGRITY",
                        "Order-sensitive canonical record content changed.",
                    )
                )
            return self._result("REJECTED", findings)

    def _scenario_stale_as_current(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["collection"]["collected_at"] = "2020-01-01T00:00:00Z"
        evidence["freshness"]["status"] = "current"
        evidence["freshness"]["age_seconds"] = 60
        findings = _freshness_findings(evidence)
        return self._result("REJECTED", findings)

    def _scenario_future_collection_timestamp(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["collection"]["collected_at"] = "2027-01-01T00:00:00Z"
        findings = _freshness_findings(evidence)
        return self._result("REJECTED", findings)

    def _scenario_unicode_confusable_id(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["evidence_id"] = "А" + evidence["evidence_id"][1:]
        findings = _identifier_findings(evidence["evidence_id"])
        validation = EvidenceSchemaValidator().validate(evidence)
        if not validation.schema_valid:
            findings.append(
                _finding(
                    "EVIDENCE_IDENTIFIER_SCHEMA_REJECTION",
                    "JSON_SCHEMA",
                    "Confusable identifier fails the evidence schema.",
                )
            )
        return self._result("BLOCKED", findings)

    def _chain_scenario(self, replacement: str | None) -> dict[str, Any]:
        baseline = load_json(self.trusted_paths["decision_record"])
        expected_previous = "a" * 64
        baseline["audit"]["previous_record_hash"] = expected_previous
        baseline = finalize_decision_record_hash(baseline)
        mutated = copy.deepcopy(baseline)
        mutated["audit"]["previous_record_hash"] = replacement
        mutated = finalize_decision_record_hash(mutated)
        findings = []
        if mutated["audit"]["previous_record_hash"] != expected_previous:
            findings.append(
                _finding(
                    "DECISION_CHAIN_LINK_MISMATCH",
                    "CHAIN_OF_CUSTODY",
                    "The previous-record chain link was deleted or replaced.",
                )
            )
        return self._result(
            "REJECTED",
            findings,
            baseline["audit"]["record_hash"],
            mutated["audit"]["record_hash"],
        )

    def _scenario_chain_link_deleted(self) -> dict[str, Any]:
        return self._chain_scenario(None)

    def _scenario_chain_link_replaced(self) -> dict[str, Any]:
        return self._chain_scenario("b" * 64)

    def _scenario_evidence_parent_cycle(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["provenance"]["parent_evidence_ids"] = [
            evidence["evidence_id"]
        ]
        findings = _provenance_findings(evidence)
        return self._result("REJECTED", findings)

    def _scenario_duplicate_decision_id(self) -> dict[str, Any]:
        first = load_json(self.trusted_paths["decision_record"])
        second = copy.deepcopy(first)
        second["created_at"] = "2026-07-13T17:13:00Z"
        second = finalize_decision_record_hash(second)
        duplicates = _duplicate_ids([first, second], "decision_id")
        findings = []
        if duplicates:
            findings.append(
                _finding(
                    "DUPLICATE_DECISION_ID",
                    "DUPLICATE_ID",
                    f"Different records share decision IDs: {duplicates}",
                )
            )
        return self._result("REJECTED", findings)

    def _scenario_verified_evidence_without_hash(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["integrity"]["hash_algorithm"] = "none"
        evidence["integrity"]["content_hash"] = None
        validation = EvidenceSchemaValidator().validate(evidence)
        findings = [
            _finding(issue.code, "EVIDENCE_VALIDATOR", issue.message)
            for issue in validation.errors
        ]
        return self._result("REJECTED", findings)

    def _scenario_validation_status_forgery(self) -> dict[str, Any]:
        evidence = load_json(self.trusted_paths["evidence_record"])
        evidence["validation"]["status"] = "accepted"
        findings = _validation_attestation_findings(
            evidence, EvidenceSchemaValidator()
        )
        return self._result("REJECTED", findings)

    def _scenario_required_reference_flag_removed(self) -> dict[str, Any]:
        baseline = load_json(self.trusted_paths["decision_record"])
        expected = _reference_signature(baseline)
        mutated = copy.deepcopy(baseline)
        mutated["input_records"]["evidence_records"][0][
            "required_for_decision"
        ] = False
        mutated = finalize_decision_record_hash(mutated)
        actual = _reference_signature(mutated)
        findings = []
        if actual != expected:
            findings.append(
                _finding(
                    "REQUIRED_INPUT_FLAG_CHANGED",
                    "REFERENCE_SET_INTEGRITY",
                    "A required decision input was relabeled as optional.",
                )
            )
        return self._result("REJECTED", findings)

    def execute_scenario(self, scenario: dict[str, Any]) -> dict[str, Any]:
        scenario_id = scenario["scenario_id"]
        handler_name = scenario["handler"]
        base_result: dict[str, Any] = {
            "scenario_id": scenario_id,
            "title": scenario["title"],
            "family": scenario["family"],
            "severity": scenario["severity"],
            "handler": handler_name,
            "control_tags": list(scenario.get("control_tags", [])),
            "expected_outcomes": list(scenario["expected_outcomes"]),
            "expected_oracles": list(scenario["expected_oracles"]),
            "ephemeral_only": True,
        }
        try:
            handler = self.handlers.get(handler_name)
            if handler is None:
                raise KeyError(f"Unknown scenario handler: {handler_name}")
            execution = handler()
            findings: list[TamperFinding] = execution["findings"]
            outcome = execution["outcome"]
            detection_oracles = sorted({item.oracle for item in findings})
            expected_oracles = set(scenario["expected_oracles"])
            expected_outcomes = set(scenario["expected_outcomes"])
            expectation_met = (
                outcome in expected_outcomes
                and expected_oracles.issubset(set(detection_oracles))
            )
            defended = (
                outcome in DEFENDED_OUTCOMES
                and bool(findings)
                and expectation_met
                and (
                    scenario["severity"] != "critical"
                    or outcome in CRITICAL_ALLOWED_OUTCOMES
                )
            )
            if not findings or not expectation_met:
                outcome = "UNDETECTED"
                defended = False
            base_result.update(
                {
                    "outcome": outcome,
                    "defended": defended,
                    "expectation_met": expectation_met,
                    "detection_oracles": detection_oracles,
                    "findings": [item.to_dict() for item in findings],
                    "baseline_sha256": execution.get("baseline_sha256"),
                    "mutated_sha256": execution.get("mutated_sha256"),
                    "error": None,
                }
            )
        except Exception as exc:  # fail closed and report harness faults
            base_result.update(
                {
                    "outcome": "HARNESS_ERROR",
                    "defended": False,
                    "expectation_met": False,
                    "detection_oracles": [],
                    "findings": [],
                    "baseline_sha256": None,
                    "mutated_sha256": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
        return base_result

    @staticmethod
    def _control_rate(
        results: list[dict[str, Any]],
        tag: str,
    ) -> tuple[int, int, float]:
        applicable = [
            result for result in results if tag in result["control_tags"]
        ]
        defended = [result for result in applicable if result["defended"]]
        rate = len(defended) / len(applicable) if applicable else 1.0
        return len(applicable), len(defended), rate

    def run(self) -> dict[str, Any]:
        before_checks = self._input_integrity_checks()
        baseline_valid = all(item["passed"] for item in before_checks.values())
        if not baseline_valid:
            failed = [name for name, item in before_checks.items() if not item["passed"]]
            raise ValueError(f"Trusted input integrity failed: {failed}")

        baseline_decision = load_json(self.trusted_paths["decision_record"])
        baseline_decision_validation = DecisionRecordValidator(
            project_root=self.project_root
        ).validate(baseline_decision)
        baseline_evidence = load_json(self.trusted_paths["evidence_record"])
        baseline_evidence_validation = EvidenceSchemaValidator().validate(
            baseline_evidence
        )
        if not baseline_decision_validation.valid:
            raise ValueError("Trusted Decision Record baseline is invalid.")
        if not baseline_evidence_validation.valid:
            raise ValueError("Trusted Evidence Record baseline is invalid.")

        results = [
            self.execute_scenario(scenario)
            for scenario in self.catalog["scenarios"]
        ]

        after_checks = self._input_integrity_checks()
        trusted_unchanged = all(
            item["passed"] and item["actual_sha256"] == before_checks[name]["actual_sha256"]
            for name, item in after_checks.items()
        )

        critical = [result for result in results if result["severity"] == "critical"]
        defended_critical = [result for result in critical if result["defended"]]
        undetected = [result for result in results if result["outcome"] == "UNDETECTED"]
        errors = [result for result in results if result["outcome"] == "HARNESS_ERROR"]
        blocked = [result for result in results if result["outcome"] == "BLOCKED"]
        rejected = [result for result in results if result["outcome"] == "REJECTED"]
        quarantined = [result for result in results if result["outcome"] == "QUARANTINED"]
        warnings = [
            result
            for result in results
            if result["outcome"] == "DETECTED_WITH_WARNING"
        ]

        path_total, path_defended, path_rate = self._control_rate(
            results, "path_escape"
        )
        hash_total, hash_defended, hash_rate = self._control_rate(
            results, "hash_corruption"
        )
        identity_total, identity_defended, identity_rate = self._control_rate(
            results, "identity_collision"
        )
        defence_rate = (
            len(defended_critical) / len(critical) if critical else 1.0
        )

        gates = self.catalog["release_gates"]
        quality_gates = [
            {
                "gate_id": "GATE-CRITICAL-TAMPER-DEFENCE",
                "observed": defence_rate,
                "operator": "gte",
                "threshold": gates[
                    "critical_tamper_defence_rate_minimum"
                ],
                "passed": defence_rate
                >= gates["critical_tamper_defence_rate_minimum"],
            },
            {
                "gate_id": "GATE-UNDETECTED-CRITICAL",
                "observed": len(undetected),
                "operator": "lte",
                "threshold": gates[
                    "undetected_critical_tampering_maximum"
                ],
                "passed": len(undetected)
                <= gates["undetected_critical_tampering_maximum"],
            },
            {
                "gate_id": "GATE-HARNESS-ERRORS",
                "observed": len(errors),
                "operator": "lte",
                "threshold": gates["harness_errors_maximum"],
                "passed": len(errors) <= gates["harness_errors_maximum"],
            },
            {
                "gate_id": "GATE-PATH-ESCAPE",
                "observed": path_rate,
                "operator": "gte",
                "threshold": gates["path_escape_defence_rate_minimum"],
                "passed": path_rate
                >= gates["path_escape_defence_rate_minimum"],
            },
            {
                "gate_id": "GATE-HASH-CORRUPTION",
                "observed": hash_rate,
                "operator": "gte",
                "threshold": gates[
                    "hash_corruption_detection_rate_minimum"
                ],
                "passed": hash_rate
                >= gates["hash_corruption_detection_rate_minimum"],
            },
            {
                "gate_id": "GATE-IDENTITY-COLLISION",
                "observed": identity_rate,
                "operator": "gte",
                "threshold": gates[
                    "identity_collision_detection_rate_minimum"
                ],
                "passed": identity_rate
                >= gates["identity_collision_detection_rate_minimum"],
            },
            {
                "gate_id": "GATE-TRUSTED-INPUT-INTEGRITY",
                "observed": trusted_unchanged,
                "operator": "eq",
                "threshold": gates["require_trusted_inputs_unchanged"],
                "passed": trusted_unchanged
                == gates["require_trusted_inputs_unchanged"],
            },
        ]
        overall_passed = all(gate["passed"] for gate in quality_gates)
        summary = {
            "scenario_count": len(results),
            "critical_scenario_count": len(critical),
            "blocked_count": len(blocked),
            "rejected_count": len(rejected),
            "quarantined_count": len(quarantined),
            "warning_detection_count": len(warnings),
            "undetected_count": len(undetected),
            "harness_error_count": len(errors),
            "defended_critical_count": len(defended_critical),
            "critical_tamper_defence_rate": defence_rate,
            "path_escape_scenario_count": path_total,
            "path_escape_defended_count": path_defended,
            "path_escape_defence_rate": path_rate,
            "hash_corruption_scenario_count": hash_total,
            "hash_corruption_detected_count": hash_defended,
            "hash_corruption_detection_rate": hash_rate,
            "identity_collision_scenario_count": identity_total,
            "identity_collision_detected_count": identity_defended,
            "identity_collision_detection_rate": identity_rate,
            "trusted_input_integrity_passed": trusted_unchanged,
            "overall_passed": overall_passed,
        }
        blockers = gates["approved_remaining_production_blockers"]
        return {
            "schema_version": "1.0.0",
            "report_id": "AEG-TAMPER-STEP11C-001",
            "catalog": {
                "catalog_id": self.catalog["policy"]["catalog_id"],
                "version": self.catalog["policy"]["version"],
                "harness_version": self.catalog["policy"]["harness_version"],
                "relative_path": self.catalog_path.relative_to(
                    self.project_root
                ).as_posix(),
                "sha256": sha256_file(self.catalog_path),
            },
            "input_integrity_checks_before": before_checks,
            "input_integrity_checks_after": after_checks,
            "baseline_validation": {
                "decision_record_status": baseline_decision_validation.status,
                "decision_record_valid": baseline_decision_validation.valid,
                "decision_record_hash_valid": verify_decision_record_hash(
                    baseline_decision
                ),
                "evidence_record_status": baseline_evidence_validation.status,
                "evidence_record_valid": baseline_evidence_validation.valid,
            },
            "summary": summary,
            "quality_gates": quality_gates,
            "results": results,
            "undetected_attack_ids": [
                result["scenario_id"] for result in undetected
            ],
            "harness_error_attack_ids": [
                result["scenario_id"] for result in errors
            ],
            "release_decision": {
                "stage_gate_status": "PASS" if overall_passed else "FAIL",
                "production_readiness_status": "BLOCKED",
                "blocking_reasons": blockers,
            },
            "limitations": [
                "The suite uses controlled repository fixtures rather than live operational systems.",
                "Cryptographic signature verification is policy-contract testing; no external PKI trust chain is exercised.",
                "Filesystem behavior is evaluated in the local Linux test environment and requires independent deployment testing.",
                "Passing Step 11C does not replace independent security assessment or authorization to operate.",
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import json
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.governance.provenance_verifier import (
    ProvenancePolicy,
    build_dsse_envelope,
    verify_dsse_provenance,
)
from src.governance.release_integrity import (
    ReleasePolicy,
    finalize_release_manifest,
    reconcile_cyclonedx_sbom,
    verify_release_manifest,
    verify_reproducible_artifact_sets,
)
from src.governance.supply_chain_guard import (
    DependencyPolicy,
    ModelPolicy,
    SourceState,
    SupplyChainFinding,
    VerificationResult,
    WorkflowPolicy,
    canonical_json_bytes,
    compute_lock_digest,
    normalize_package_name,
    sha256_bytes,
    sha256_file,
    verify_dependency_lock,
    verify_model_manifest,
    verify_source_state,
    verify_workflow_text,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG_PATH = (
    PROJECT_ROOT
    / "policies"
    / "assurance"
    / "supply_chain_scenario_catalog_v1.yaml"
)

ALLOWED_HANDLERS = {
    "dependency",
    "provenance",
    "build_ci",
    "release",
    "sbom",
    "model",
}

ALLOWED_OUTCOMES = {
    "RELEASE_VERIFIED",
    "RELEASE_VERIFIED_WITH_REVIEW",
    "BLOCKED_UNPINNED_DEPENDENCY",
    "BLOCKED_DEPENDENCY_HASH_FAILURE",
    "BLOCKED_BUILD_POLICY_VIOLATION",
    "BLOCKED_PROVENANCE_FAILURE",
    "BLOCKED_ARTIFACT_DIGEST_FAILURE",
    "BLOCKED_SBOM_RECONCILIATION_FAILURE",
    "BLOCKED_SIGNATURE_FAILURE",
    "BLOCKED_REPRODUCIBILITY_FAILURE",
    "BLOCKED_MODEL_PROVENANCE_FAILURE",
    "QUARANTINED_UNTRUSTED_ARTIFACT",
    "QUARANTINED_RELEASE_CONFLICT",
    "UNSAFE_RELEASE",
    "UNDETECTED",
    "HARNESS_ERROR",
}

SIGNATURE_FINDING_CODES = {
    "DSSE_PAYLOAD_TYPE_MISMATCH",
    "DSSE_PAYLOAD_INVALID",
    "DSSE_SIGNATURE_COUNT_INVALID",
    "DSSE_SIGNATURE_RECORD_INVALID",
    "SIGNING_KEY_NOT_TRUSTED",
    "SIGNING_KEY_FINGERPRINT_MISMATCH",
    "SIGNATURE_VERIFICATION_FAILED",
}

UNPINNED_FINDING_CODES = {
    "DEPENDENCY_NOT_EXACTLY_PINNED",
}

RELEASE_CONFLICT_CODES = {
    "RELEASE_ARTIFACT_DUPLICATE",
    "UNAUTHORIZED_RELEASE_EXCEPTION",
}

UNTRUSTED_ARTIFACT_CODES = {
    "RELEASE_ARTIFACT_MEDIA_TYPE_NOT_ALLOWED",
    "RELEASE_ARTIFACT_MISSING_OR_UNSAFE",
}

REPRODUCIBILITY_CODES = {
    "RELEASE_ROLLBACK_DETECTED",
    "REPRODUCIBLE_BUILD_DIGEST_MISMATCH",
}


class SupplyChainAssuranceError(RuntimeError):
    """Raised when Step 11I assurance inputs violate the harness contract."""


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SupplyChainAssuranceError(f"Expected JSON object: {path}")
    return value


def _gate_passed(observed: Any, operator: str, threshold: Any) -> bool:
    if operator == "eq":
        return observed == threshold
    if operator == "gte":
        return observed >= threshold
    if operator == "lte":
        return observed <= threshold
    raise SupplyChainAssuranceError(f"Unsupported gate operator: {operator}")


def _rate(results: list[dict[str, Any]], tag: str) -> float:
    tagged = [result for result in results if tag in result["control_tags"]]
    if not tagged:
        return 1.0
    return sum(bool(result["defended"]) for result in tagged) / len(tagged)


def _finding_codes(result: VerificationResult) -> set[str]:
    return {finding.code for finding in result.findings}


def _document_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


class SupplyChainAssuranceHarness:
    """Deterministic Step 11I supply-chain and release-integrity harness."""

    def __init__(
        self,
        catalog_path: Path | str = DEFAULT_CATALOG_PATH,
        project_root: Path | str = PROJECT_ROOT,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.catalog_path = Path(catalog_path)
        if not self.catalog_path.is_absolute():
            self.catalog_path = (self.project_root / self.catalog_path).resolve()
        self.catalog = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8"))
        if not isinstance(self.catalog, dict):
            raise SupplyChainAssuranceError("Supply-chain catalog must be an object.")
        self._validate_catalog()
        policy_path = self.project_root / self.catalog["release_policy_path"]
        self.policy_document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        if not isinstance(self.policy_document, dict):
            raise SupplyChainAssuranceError("Supply-chain release policy must be an object.")
        self.trusted_inputs = self.catalog["trusted_inputs"]
        self.seen_invocation_ids: set[str] = set()
        self._configure_policies()

    def _validate_catalog(self) -> None:
        required = {
            "policy",
            "deterministic_clock",
            "release_policy_path",
            "trusted_inputs",
            "quality_gates",
            "production_readiness",
            "limitations",
            "scenarios",
        }
        missing = required - set(self.catalog)
        if missing:
            raise SupplyChainAssuranceError(
                f"Supply-chain catalog missing sections: {sorted(missing)}"
            )
        scenarios = self.catalog["scenarios"]
        if not isinstance(scenarios, list) or not scenarios:
            raise SupplyChainAssuranceError("Supply-chain scenarios are required.")
        ids = [scenario.get("scenario_id") for scenario in scenarios]
        if len(ids) != len(set(ids)):
            raise SupplyChainAssuranceError("Scenario IDs must be unique.")
        for scenario in scenarios:
            if scenario.get("severity") != "critical":
                raise SupplyChainAssuranceError("Every Step 11I scenario must be critical.")
            if scenario.get("handler") not in ALLOWED_HANDLERS:
                raise SupplyChainAssuranceError(
                    f"Unsupported handler: {scenario.get('handler')!r}"
                )
            expected = scenario.get("expected_outcomes")
            if not isinstance(expected, list) or not expected:
                raise SupplyChainAssuranceError("Every scenario requires expected_outcomes.")
            if not set(expected).issubset(ALLOWED_OUTCOMES):
                raise SupplyChainAssuranceError(
                    f"Invalid expected outcome in {scenario.get('scenario_id')}"
                )
            if not isinstance(scenario.get("control_tags"), list):
                raise SupplyChainAssuranceError("Every scenario requires control_tags.")
            parameters = scenario.get("parameters")
            if not isinstance(parameters, dict) or not parameters.get("mutation"):
                raise SupplyChainAssuranceError("Every scenario requires a mutation parameter.")

    def _configure_policies(self) -> None:
        dependency = self.policy_document["dependency"]
        self.dependency_policy = DependencyPolicy(
            exact_pin_required=bool(dependency["exact_pin_required"]),
            sha256_required=bool(dependency["sha256_required"]),
            direct_references_permitted=bool(
                dependency["direct_references_permitted"]
            ),
            allowed_registry_hosts=frozenset(
                dependency["allowed_registry_hosts"]
            ),
            normalized_name_uniqueness_required=bool(
                dependency["normalized_name_uniqueness_required"]
            ),
            artifact_verification_required=bool(
                dependency["artifact_verification_required"]
            ),
        )
        workflow = self.policy_document["workflow"]
        self.workflow_policy = WorkflowPolicy(
            action_commit_pin_required=bool(
                workflow["action_commit_pin_required"]
            ),
            container_digest_pin_required=bool(
                workflow["container_digest_pin_required"]
            ),
            allowed_runner_labels=frozenset(workflow["allowed_runner_labels"]),
            forbidden_triggers=frozenset(workflow["forbidden_triggers"]),
            forbidden_tokens=tuple(workflow["forbidden_tokens"]),
            network_disabled_required=bool(workflow["network_disabled_required"]),
            hermetic_required=bool(workflow["hermetic_required"]),
        )
        provenance = self.policy_document["provenance"]
        self.provenance_policy = ProvenancePolicy(
            allowed_builder_ids=frozenset(provenance["allowed_builder_ids"]),
            allowed_build_types=frozenset(provenance["allowed_build_types"]),
            allowed_key_fingerprints=dict(provenance["allowed_key_fingerprints"]),
            expected_source_uri=provenance["expected_source_uri"],
            expected_source_revision=provenance["expected_source_revision"],
            expected_source_digest=provenance["expected_source_digest"],
            predicate_type=provenance["predicate_type"],
            statement_type=provenance["statement_type"],
            payload_type=provenance["payload_type"],
            require_material_completeness=bool(
                provenance["require_material_completeness"]
            ),
            require_parameter_completeness=bool(
                provenance["require_parameter_completeness"]
            ),
            require_environment_completeness=bool(
                provenance["require_environment_completeness"]
            ),
            require_reproducible=bool(provenance["require_reproducible"]),
            require_network_disabled=bool(provenance["require_network_disabled"]),
        )
        model = self.policy_document["model"]
        self.model_policy = ModelPolicy(
            allowed_registry_hosts=frozenset(model["allowed_registry_hosts"]),
            revision_pattern=model["revision_pattern"],
            remote_code_permitted=bool(model["remote_code_permitted"]),
            dataset_provenance_required=bool(
                model["dataset_provenance_required"]
            ),
            file_hashes_required=bool(model["file_hashes_required"]),
        )
        release = self.policy_document["release"]
        self.release_policy = ReleasePolicy(
            minimum_release_sequence=int(release["minimum_release_sequence"]),
            allowed_artifact_media_types=frozenset(
                release["allowed_artifact_media_types"]
            ),
            required_evidence_roles=frozenset(release["required_evidence_roles"]),
            authorized_exception_ids=frozenset(
                release["authorized_exception_ids"]
            ),
            atomic_manifest_required=bool(release["atomic_manifest_required"]),
            rollback_protection_required=bool(
                release["rollback_protection_required"]
            ),
        )

    def input_integrity_checks(self) -> dict[str, dict[str, Any]]:
        checks: dict[str, dict[str, Any]] = {}
        for name, definition in self.trusted_inputs.items():
            relative_path = str(definition["relative_path"])
            candidate = Path(relative_path)
            resolved = (self.project_root / candidate).resolve()
            safe = (
                not candidate.is_absolute()
                and (resolved == self.project_root or self.project_root in resolved.parents)
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
                    safe and exists and actual == definition["expected_sha256"]
                ),
            }
        return checks

    def _build_fixture(self, root: Path) -> dict[str, Any]:
        root.mkdir(parents=True, exist_ok=True)
        artifact_name = "aegissec-fedops-0.1.0.whl"
        artifact_path = root / "dist" / artifact_name
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(b"AEGISSEC-FEDOPS-CONTROLLED-RELEASE-V1\n")

        dependency_entries = []
        for name, version in (
            ("pandas", "2.3.3"),
            ("requests", "2.32.5"),
            ("PyYAML", "6.0.3"),
        ):
            normalized = normalize_package_name(name)
            relative = f"deps/{normalized}-{version}.whl"
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"CONTROLLED-{normalized}-{version}\n".encode("utf-8"))
            dependency_entries.append(
                {
                    "name": name,
                    "normalized_name": normalized,
                    "version": version,
                    "purl": f"pkg:pypi/{normalized}@{version}",
                    "artifact_path": relative,
                    "hashes": {"sha256": sha256_file(path)},
                    "source": {
                        "type": "registry",
                        "url": "https://pypi.org/simple",
                    },
                }
            )
        dependency_lock: dict[str, Any] = {
            "schema_version": "1.0.0",
            "dependencies": dependency_entries,
        }
        dependency_lock["lock_digest"] = compute_lock_digest(dependency_lock)

        model_path = root / "models" / "aegis-embedding.bin"
        model_path.parent.mkdir(parents=True, exist_ok=True)
        model_path.write_bytes(b"AEGIS-CONTROLLED-EMBEDDING-MODEL\n")
        model_manifest = {
            "schema_version": "1.0.0",
            "model_id": "aegissec/controlled-embedding-model",
            "source_uri": "https://huggingface.co/aegissec/controlled-embedding-model",
            "revision": "c" * 40,
            "trust_remote_code": False,
            "files": [
                {
                    "path": "models/aegis-embedding.bin",
                    "sha256": sha256_file(model_path),
                }
            ],
            "datasets": [
                {
                    "dataset_id": "AEGIS-CONTROLLED-DATASET-001",
                    "revision": "1.0.0",
                    "sha256": "d" * 64,
                    "origin_type": "observed",
                }
            ],
        }

        workflow_text = (
            "name: controlled-release\n"
            "on:\n  workflow_dispatch:\n"
            "jobs:\n  build:\n"
            "    runs-on: ubuntu-24.04\n"
            "    container: python@sha256:" + "1" * 64 + "\n"
            "    steps:\n"
            "      - uses: actions/checkout@" + "2" * 40 + "\n"
            "      - uses: actions/setup-python@" + "3" * 40 + "\n"
            "      - run: python -m build --no-isolation\n"
        )
        workflow_sha256 = sha256_bytes(workflow_text.encode("utf-8"))

        source_state = SourceState(
            revision=self.provenance_policy.expected_source_revision,
            tree_digest=self.provenance_policy.expected_source_digest,
            clean=True,
            committed_inputs_only=True,
        )

        artifact_sha256 = sha256_file(artifact_path)
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:aegissec-step11i-controlled-001",
            "version": 1,
            "metadata": {
                "timestamp": self.catalog["deterministic_clock"]["evaluation_time"],
                "component": {
                    "type": "application",
                    "name": artifact_name,
                    "version": "0.1.0",
                    "hashes": [
                        {"alg": "SHA-256", "content": artifact_sha256}
                    ],
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": entry["normalized_name"],
                    "version": entry["version"],
                    "purl": entry["purl"],
                    "hashes": [
                        {"alg": "SHA-256", "content": entry["hashes"]["sha256"]}
                    ],
                }
                for entry in dependency_entries
            ],
        }

        statement = {
            "_type": self.provenance_policy.statement_type,
            "subject": [
                {
                    "name": artifact_name,
                    "digest": {"sha256": artifact_sha256},
                }
            ],
            "predicateType": self.provenance_policy.predicate_type,
            "predicate": {
                "buildDefinition": {
                    "buildType": next(iter(self.provenance_policy.allowed_build_types)),
                    "externalParameters": {
                        "releaseVersion": "0.1.0",
                        "workflowSha256": workflow_sha256,
                    },
                    "internalParameters": {
                        "networkDisabled": True,
                        "hermetic": True,
                    },
                    "resolvedDependencies": [
                        {
                            "uri": self.provenance_policy.expected_source_uri,
                            "digest": {
                                "sha256": self.provenance_policy.expected_source_digest
                            },
                            "annotations": {
                                "revision": self.provenance_policy.expected_source_revision
                            },
                        }
                    ],
                },
                "runDetails": {
                    "builder": {
                        "id": next(iter(self.provenance_policy.allowed_builder_ids))
                    },
                    "metadata": {
                        "invocationId": "AEGIS-BUILD-INVOCATION-001",
                        "startedOn": "2026-07-15T11:58:00Z",
                        "finishedOn": "2026-07-15T11:59:00Z",
                        "completeness": {
                            "parameters": True,
                            "environment": True,
                            "materials": True,
                        },
                        "reproducible": True,
                    },
                    "byproducts": [
                        {
                            "name": "workflow",
                            "digest": {"sha256": workflow_sha256},
                        }
                    ],
                },
            },
        }

        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        key_id = next(iter(self.provenance_policy.allowed_key_fingerprints))
        envelope = build_dsse_envelope(
            statement,
            key_id=key_id,
            signer=private_key,
            payload_type=self.provenance_policy.payload_type,
        )

        evidence_documents = {
            "dependency_lock": dependency_lock,
            "sbom": sbom,
            "provenance": envelope,
            "model_manifest": model_manifest,
            "workflow": workflow_text,
        }
        release_manifest = {
            "schema_version": "1.0.0",
            "release_id": "AEGIS-RELEASE-STEP11I-001",
            "release_version": "0.1.0",
            "release_sequence": 7,
            "source": {
                "revision": source_state.revision,
                "tree_digest": source_state.tree_digest,
            },
            "artifacts": [
                {
                    "name": artifact_name,
                    "path": f"dist/{artifact_name}",
                    "media_type": "application/zip",
                    "size_bytes": artifact_path.stat().st_size,
                    "sha256": artifact_sha256,
                }
            ],
            "evidence": [
                {"role": role, "sha256": _document_sha256(document)}
                for role, document in evidence_documents.items()
            ],
            "authorized_exception": None,
        }
        release_manifest = finalize_release_manifest(release_manifest)

        return {
            "root": root,
            "artifact_name": artifact_name,
            "artifact_path": artifact_path,
            "artifact_sha256": artifact_sha256,
            "dependency_lock": dependency_lock,
            "model_manifest": model_manifest,
            "workflow_text": workflow_text,
            "workflow_sha256": workflow_sha256,
            "source_state": source_state,
            "sbom": sbom,
            "statement": statement,
            "envelope": envelope,
            "private_key": private_key,
            "public_keys": {key_id: public_key},
            "key_id": key_id,
            "release_manifest": release_manifest,
            "reproducible_first": {artifact_name: artifact_sha256},
            "reproducible_second": {artifact_name: artifact_sha256},
            "review_required": False,
        }

    def _resign(self, fixture: dict[str, Any]) -> None:
        fixture["envelope"] = build_dsse_envelope(
            fixture["statement"],
            key_id=fixture["key_id"],
            signer=fixture["private_key"],
            payload_type=self.provenance_policy.payload_type,
        )

    def _refresh_release_manifest(self, fixture: dict[str, Any]) -> None:
        documents = {
            "dependency_lock": fixture["dependency_lock"],
            "sbom": fixture["sbom"],
            "provenance": fixture["envelope"],
            "model_manifest": fixture["model_manifest"],
            "workflow": fixture["workflow_text"],
        }
        manifest = copy.deepcopy(fixture["release_manifest"])
        manifest["evidence"] = [
            {"role": role, "sha256": _document_sha256(document)}
            for role, document in documents.items()
        ]
        fixture["release_manifest"] = finalize_release_manifest(manifest)

    def _mutate(self, fixture: dict[str, Any], mutation: str) -> None:
        lock = fixture["dependency_lock"]
        statement = fixture["statement"]
        manifest = fixture["release_manifest"]
        model = fixture["model_manifest"]
        sbom = fixture["sbom"]
        refresh_manifest = True
        resign = False

        if mutation == "baseline_verified":
            return
        if mutation == "dependency_range":
            lock["dependencies"][0]["version"] = ">=2.0"
            lock["dependencies"][0]["purl"] = "pkg:pypi/pandas@>=2.0"
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "dependency_wildcard":
            lock["dependencies"][0]["version"] = "2.*"
            lock["dependencies"][0]["purl"] = "pkg:pypi/pandas@2.*"
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "dependency_missing_hash":
            lock["dependencies"][0]["hashes"] = {}
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "dependency_hash_mismatch":
            lock["dependencies"][0]["hashes"]["sha256"] = "0" * 64
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "dependency_direct_url":
            lock["dependencies"][0]["source"] = {
                "type": "direct_url",
                "url": "https://example.invalid/pandas.whl",
            }
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "dependency_bad_registry":
            lock["dependencies"][0]["source"]["url"] = "https://evil.invalid/simple"
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "dependency_lock_digest_tamper":
            lock["lock_digest"] = "f" * 64
        elif mutation == "dependency_normalization_conflict":
            duplicate = copy.deepcopy(lock["dependencies"][0])
            duplicate["name"] = "PANDAS"
            duplicate["normalized_name"] = "pandas"
            duplicate["version"] = "1.0.0"
            duplicate["purl"] = "pkg:pypi/pandas@1.0.0"
            lock["dependencies"].append(duplicate)
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "dependency_missing_artifact":
            lock["dependencies"][0]["artifact_path"] = "deps/missing.whl"
            lock["lock_digest"] = compute_lock_digest(lock)
        elif mutation == "provenance_missing":
            fixture["envelope"] = {}
        elif mutation == "provenance_predicate_type":
            statement["predicateType"] = "https://example.invalid/provenance/v0"
            resign = True
        elif mutation == "provenance_subject_mismatch":
            statement["subject"][0]["digest"]["sha256"] = "9" * 64
            resign = True
        elif mutation == "provenance_builder_mismatch":
            statement["predicate"]["runDetails"]["builder"]["id"] = "urn:evil:builder"
            resign = True
        elif mutation == "provenance_build_type_mismatch":
            statement["predicate"]["buildDefinition"]["buildType"] = "urn:evil:build"
            resign = True
        elif mutation == "provenance_source_revision_mismatch":
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["annotations"]["revision"] = "e" * 40
            resign = True
        elif mutation == "provenance_material_digest_mismatch":
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["sha256"] = "e" * 64
            resign = True
        elif mutation == "provenance_invocation_missing":
            statement["predicate"]["runDetails"]["metadata"]["invocationId"] = ""
            resign = True
        elif mutation == "signature_invalid":
            signature = fixture["envelope"]["signatures"][0]["sig"]
            raw = bytearray(base64.b64decode(signature))
            raw[0] ^= 1
            fixture["envelope"]["signatures"][0]["sig"] = base64.b64encode(bytes(raw)).decode("ascii")
        elif mutation == "signature_untrusted_key":
            fixture["envelope"]["signatures"][0]["keyid"] = "UNKNOWN-KEY"
        elif mutation == "workflow_mutable_action":
            fixture["workflow_text"] = fixture["workflow_text"].replace(
                "actions/checkout@" + "2" * 40,
                "actions/checkout@v4",
            )
        elif mutation == "workflow_mutable_container":
            fixture["workflow_text"] = fixture["workflow_text"].replace(
                "python@sha256:" + "1" * 64,
                "python:3.12",
            )
        elif mutation == "workflow_digest_tamper":
            fixture["workflow_text"] += "# unauthorized change\n"
        elif mutation == "workflow_forbidden_trigger":
            fixture["workflow_text"] = fixture["workflow_text"].replace(
                "workflow_dispatch:", "pull_request_target:"
            )
        elif mutation == "build_network_enabled":
            fixture["network_disabled"] = False
        elif mutation == "build_nonhermetic":
            fixture["hermetic"] = False
        elif mutation == "source_dirty":
            state = fixture["source_state"]
            fixture["source_state"] = SourceState(
                state.revision, state.tree_digest, False, state.committed_inputs_only
            )
        elif mutation == "source_uncommitted_input":
            state = fixture["source_state"]
            fixture["source_state"] = SourceState(
                state.revision, state.tree_digest, state.clean, False
            )
        elif mutation == "artifact_bytes_tamper":
            fixture["artifact_path"].write_bytes(b"TAMPERED-ARTIFACT\n")
            refresh_manifest = False
        elif mutation == "artifact_hash_missing":
            manifest["artifacts"][0]["sha256"] = None
            fixture["release_manifest"] = finalize_release_manifest(manifest)
            refresh_manifest = False
        elif mutation == "manifest_digest_tamper":
            fixture["release_manifest"]["manifest_digest"] = "0" * 64
            refresh_manifest = False
        elif mutation == "release_duplicate_artifact":
            manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))
            fixture["release_manifest"] = finalize_release_manifest(manifest)
            refresh_manifest = False
        elif mutation == "release_unauthorized_exception":
            manifest["authorized_exception"] = {
                "exception_id": "EXC-UNAUTHORIZED-001",
                "approved": True,
            }
            fixture["release_manifest"] = finalize_release_manifest(manifest)
            refresh_manifest = False
        elif mutation == "release_rollback":
            manifest["release_sequence"] = 6
            fixture["release_manifest"] = finalize_release_manifest(manifest)
            refresh_manifest = False
        elif mutation == "release_untrusted_media":
            manifest["artifacts"][0]["media_type"] = "application/x-executable"
            fixture["release_manifest"] = finalize_release_manifest(manifest)
            refresh_manifest = False
        elif mutation == "reproducibility_mismatch":
            fixture["reproducible_second"] = {fixture["artifact_name"]: "8" * 64}
        elif mutation == "sbom_missing_component":
            sbom["components"].pop()
        elif mutation == "sbom_unexpected_component":
            sbom["components"].append(
                {
                    "type": "library",
                    "name": "unexpected",
                    "version": "1.0.0",
                    "hashes": [{"alg": "SHA-256", "content": "7" * 64}],
                }
            )
        elif mutation == "sbom_version_mismatch":
            sbom["components"][0]["version"] = "1.0.0"
        elif mutation == "sbom_component_hash_mismatch":
            sbom["components"][0]["hashes"][0]["content"] = "7" * 64
        elif mutation == "sbom_subject_mismatch":
            sbom["metadata"]["component"]["hashes"][0]["content"] = "7" * 64
        elif mutation == "sbom_old_spec":
            sbom["specVersion"] = "1.3"
        elif mutation == "model_unpinned_revision":
            model["revision"] = "main"
        elif mutation == "model_hash_mismatch":
            model["files"][0]["sha256"] = "7" * 64
        elif mutation == "model_remote_code":
            model["trust_remote_code"] = True
        elif mutation == "model_missing_dataset":
            model["datasets"] = []
        elif mutation == "model_bad_registry":
            model["source_uri"] = "https://evil.invalid/model"
        elif mutation == "model_synthetic_dataset_review":
            model["datasets"][0]["origin_type"] = "synthetic"
            fixture["review_required"] = True
        else:
            raise SupplyChainAssuranceError(f"Unknown mutation: {mutation}")

        if resign:
            self._resign(fixture)
        if refresh_manifest:
            self._refresh_release_manifest(fixture)

    def _evaluate_fixture(self, fixture: dict[str, Any]) -> dict[str, Any]:
        network_disabled = fixture.get("network_disabled", True)
        hermetic = fixture.get("hermetic", True)
        source_result = verify_source_state(
            fixture["source_state"],
            self.provenance_policy.expected_source_revision,
            self.provenance_policy.expected_source_digest,
        )
        dependency_result = verify_dependency_lock(
            fixture["dependency_lock"], fixture["root"], self.dependency_policy
        )
        workflow_result = verify_workflow_text(
            fixture["workflow_text"],
            fixture["workflow_sha256"],
            self.workflow_policy,
            runner_labels=["ubuntu-24.04"],
            network_disabled=network_disabled,
            hermetic=hermetic,
        )
        release_result = verify_release_manifest(
            fixture["release_manifest"], fixture["root"], self.release_policy
        )
        provenance = verify_dsse_provenance(
            fixture["envelope"],
            public_keys=fixture["public_keys"],
            policy=self.provenance_policy,
            expected_subject_name=fixture["artifact_name"],
            expected_subject_sha256=fixture["artifact_sha256"],
        )
        provenance_result = provenance.to_result()
        sbom_result = reconcile_cyclonedx_sbom(
            fixture["dependency_lock"],
            fixture["sbom"],
            expected_subject_name=fixture["artifact_name"],
            expected_subject_sha256=fixture["artifact_sha256"],
        ).to_result()
        model_result = verify_model_manifest(
            fixture["model_manifest"], fixture["root"], self.model_policy
        )
        reproducibility_result = verify_reproducible_artifact_sets(
            fixture["reproducible_first"], fixture["reproducible_second"]
        )

        results = {
            "source": source_result,
            "dependency": dependency_result,
            "workflow": workflow_result,
            "release": release_result,
            "provenance": provenance_result,
            "sbom": sbom_result,
            "model": model_result,
            "reproducibility": reproducibility_result,
        }
        all_codes = {
            code
            for result in results.values()
            for code in _finding_codes(result)
        }

        if not source_result.passed or not workflow_result.passed:
            outcome = "BLOCKED_BUILD_POLICY_VIOLATION"
        elif not dependency_result.passed:
            outcome = (
                "BLOCKED_UNPINNED_DEPENDENCY"
                if all_codes & UNPINNED_FINDING_CODES
                else "BLOCKED_DEPENDENCY_HASH_FAILURE"
            )
        elif not release_result.passed:
            release_codes = _finding_codes(release_result)
            if release_codes & RELEASE_CONFLICT_CODES:
                outcome = "QUARANTINED_RELEASE_CONFLICT"
            elif release_codes & UNTRUSTED_ARTIFACT_CODES:
                outcome = "QUARANTINED_UNTRUSTED_ARTIFACT"
            elif release_codes & REPRODUCIBILITY_CODES:
                outcome = "BLOCKED_REPRODUCIBILITY_FAILURE"
            else:
                outcome = "BLOCKED_ARTIFACT_DIGEST_FAILURE"
        elif not provenance_result.passed:
            if provenance.statement is None and not fixture["envelope"]:
                outcome = "BLOCKED_PROVENANCE_FAILURE"
            else:
                outcome = (
                    "BLOCKED_SIGNATURE_FAILURE"
                    if all_codes & SIGNATURE_FINDING_CODES
                    else "BLOCKED_PROVENANCE_FAILURE"
                )
        elif not sbom_result.passed:
            outcome = "BLOCKED_SBOM_RECONCILIATION_FAILURE"
        elif not model_result.passed:
            outcome = "BLOCKED_MODEL_PROVENANCE_FAILURE"
        elif not reproducibility_result.passed:
            outcome = "BLOCKED_REPRODUCIBILITY_FAILURE"
        elif fixture["review_required"]:
            outcome = "RELEASE_VERIFIED_WITH_REVIEW"
        else:
            outcome = "RELEASE_VERIFIED"

        automated_release = outcome == "RELEASE_VERIFIED"
        human_review_required = outcome == "RELEASE_VERIFIED_WITH_REVIEW"
        unsafe_release = outcome == "UNSAFE_RELEASE"
        unverified_release = automated_release and not all(
            result.passed for result in results.values()
        )

        return {
            "outcome": outcome,
            "verification_results": {
                name: result.to_dict() for name, result in results.items()
            },
            "finding_codes": sorted(all_codes),
            "automated_release": automated_release,
            "human_review_required": human_review_required,
            "prohibit_closure": human_review_required,
            "unsafe_release": unsafe_release,
            "unverified_artifact_release": unverified_release,
            "signature_verified": provenance.signature_verified,
        }

    def _run_scenario(self, scenario: Mapping[str, Any]) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="aegis-step11i-") as temporary:
            fixture = self._build_fixture(Path(temporary))
            mutation = scenario["parameters"]["mutation"]
            self._mutate(fixture, mutation)
            evaluation = self._evaluate_fixture(fixture)

        expected = list(scenario["expected_outcomes"])
        defended = (
            evaluation["outcome"] in expected
            and not evaluation["unsafe_release"]
            and not evaluation["unverified_artifact_release"]
        )
        return {
            "scenario_id": scenario["scenario_id"],
            "family": scenario["family"],
            "handler": scenario["handler"],
            "severity": scenario["severity"],
            "description": scenario["description"],
            "mutation": mutation,
            "control_tags": list(scenario["control_tags"]),
            "expected_outcomes": expected,
            "outcome": evaluation["outcome"],
            "defended": defended,
            "automated_release": evaluation["automated_release"],
            "human_review_required": evaluation["human_review_required"],
            "prohibit_closure": evaluation["prohibit_closure"],
            "unsafe_release": evaluation["unsafe_release"],
            "unverified_artifact_release": evaluation[
                "unverified_artifact_release"
            ],
            "signature_verified": evaluation["signature_verified"],
            "finding_codes": evaluation["finding_codes"],
            "verification_results": evaluation["verification_results"],
        }

    def run(self) -> dict[str, Any]:
        integrity_before = self.input_integrity_checks()
        results: list[dict[str, Any]] = []
        harness_errors: list[str] = []

        for scenario in self.catalog["scenarios"]:
            try:
                results.append(self._run_scenario(scenario))
            except Exception as exc:  # assurance boundary records, never swallows
                harness_errors.append(str(scenario.get("scenario_id")))
                results.append(
                    {
                        "scenario_id": scenario.get("scenario_id"),
                        "family": scenario.get("family"),
                        "handler": scenario.get("handler"),
                        "severity": scenario.get("severity"),
                        "description": scenario.get("description"),
                        "mutation": scenario.get("parameters", {}).get("mutation"),
                        "control_tags": list(scenario.get("control_tags", [])),
                        "expected_outcomes": list(scenario.get("expected_outcomes", [])),
                        "outcome": "HARNESS_ERROR",
                        "defended": False,
                        "automated_release": False,
                        "human_review_required": True,
                        "prohibit_closure": True,
                        "unsafe_release": False,
                        "unverified_artifact_release": False,
                        "signature_verified": False,
                        "finding_codes": [f"HARNESS_ERROR:{type(exc).__name__}"],
                        "verification_results": {},
                    }
                )

        integrity_after = self.input_integrity_checks()
        trusted_integrity = bool(
            integrity_before
            and all(item["passed"] for item in integrity_before.values())
            and integrity_before == integrity_after
        )
        outcomes = Counter(result["outcome"] for result in results)
        defended_count = sum(result["defended"] for result in results)
        unsafe_ids = [
            result["scenario_id"] for result in results if result["unsafe_release"]
        ]
        unverified_ids = [
            result["scenario_id"]
            for result in results
            if result["unverified_artifact_release"]
        ]
        undetected_ids = [
            result["scenario_id"]
            for result in results
            if result["outcome"] == "UNDETECTED"
        ]
        harness_error_ids = [
            result["scenario_id"]
            for result in results
            if result["outcome"] == "HARNESS_ERROR"
        ]

        summary = {
            "scenario_count": len(results),
            "critical_scenario_count": sum(
                result["severity"] == "critical" for result in results
            ),
            "defended_critical_count": defended_count,
            "release_verified_count": outcomes["RELEASE_VERIFIED"],
            "release_verified_with_review_count": outcomes[
                "RELEASE_VERIFIED_WITH_REVIEW"
            ],
            "blocked_unpinned_dependency_count": outcomes[
                "BLOCKED_UNPINNED_DEPENDENCY"
            ],
            "blocked_dependency_hash_failure_count": outcomes[
                "BLOCKED_DEPENDENCY_HASH_FAILURE"
            ],
            "blocked_build_policy_violation_count": outcomes[
                "BLOCKED_BUILD_POLICY_VIOLATION"
            ],
            "blocked_provenance_failure_count": outcomes[
                "BLOCKED_PROVENANCE_FAILURE"
            ],
            "blocked_artifact_digest_failure_count": outcomes[
                "BLOCKED_ARTIFACT_DIGEST_FAILURE"
            ],
            "blocked_sbom_reconciliation_failure_count": outcomes[
                "BLOCKED_SBOM_RECONCILIATION_FAILURE"
            ],
            "blocked_signature_failure_count": outcomes[
                "BLOCKED_SIGNATURE_FAILURE"
            ],
            "blocked_reproducibility_failure_count": outcomes[
                "BLOCKED_REPRODUCIBILITY_FAILURE"
            ],
            "blocked_model_provenance_failure_count": outcomes[
                "BLOCKED_MODEL_PROVENANCE_FAILURE"
            ],
            "quarantined_untrusted_artifact_count": outcomes[
                "QUARANTINED_UNTRUSTED_ARTIFACT"
            ],
            "quarantined_release_conflict_count": outcomes[
                "QUARANTINED_RELEASE_CONFLICT"
            ],
            "unsafe_release_count": len(unsafe_ids),
            "unverified_artifact_release_count": len(unverified_ids),
            "undetected_count": len(undetected_ids),
            "harness_error_count": len(harness_error_ids),
            "critical_supply_chain_scenario_defence_rate": (
                defended_count / len(results) if results else 0.0
            ),
            "artifact_digest_verification_rate": _rate(results, "artifact_digest"),
            "dependency_integrity_enforcement_rate": _rate(
                results, "dependency_integrity"
            ),
            "build_provenance_verification_rate": _rate(results, "provenance"),
            "builder_identity_enforcement_rate": _rate(results, "builder_identity"),
            "source_to_artifact_binding_rate": _rate(results, "source_binding"),
            "sbom_to_build_reconciliation_rate": _rate(results, "sbom"),
            "ci_workflow_integrity_rate": _rate(results, "workflow_integrity"),
            "model_data_provenance_enforcement_rate": _rate(
                results, "model_provenance"
            ),
            "release_manifest_atomicity_rate": _rate(
                results, "manifest_atomicity"
            ),
            "rollback_protection_rate": _rate(results, "rollback_protection"),
            "reproducibility_consistency_rate": _rate(results, "reproducibility"),
            "signature_enforcement_rate": _rate(results, "signature"),
            "release_conflict_containment_rate": _rate(
                results, "release_conflict"
            ),
            "trusted_input_integrity_passed": trusted_integrity,
        }

        gates = []
        for definition in self.catalog["quality_gates"]:
            metric = definition["metric"]
            observed = summary[metric]
            passed = _gate_passed(
                observed, definition["operator"], definition["threshold"]
            )
            gates.append(
                {
                    "gate_id": definition["gate_id"],
                    "metric": metric,
                    "operator": definition["operator"],
                    "threshold": definition["threshold"],
                    "observed": observed,
                    "passed": passed,
                }
            )
        overall_passed = all(gate["passed"] for gate in gates)
        summary["overall_passed"] = overall_passed

        readiness = self.catalog["production_readiness"]
        release_decision = {
            "stage_gate_status": "PASS" if overall_passed else "FAIL",
            "production_readiness_status": readiness["status"],
            "blocking_reasons": list(readiness["blocking_reasons"]),
        }
        generated_at = datetime.fromisoformat(
            self.catalog["deterministic_clock"]["evaluation_time"].replace(
                "Z", "+00:00"
            )
        ).astimezone(timezone.utc).isoformat()

        return {
            "report_id": "AEG-SUPPLY-CHAIN-STEP11I-001",
            "schema_version": "1.0.0",
            "generated_at": generated_at,
            "catalog": {
                "catalog_id": self.catalog["policy"]["catalog_id"],
                "version": self.catalog["policy"]["version"],
                "path": self.catalog_path.relative_to(self.project_root).as_posix(),
                "sha256": sha256_file(self.catalog_path),
            },
            "release_policy": {
                "policy_id": self.policy_document["policy"]["policy_id"],
                "version": self.policy_document["policy"]["version"],
                "path": self.catalog["release_policy_path"],
                "sha256": sha256_file(
                    self.project_root / self.catalog["release_policy_path"]
                ),
            },
            "deterministic_clock": {
                "evaluation_time": generated_at,
                "wall_clock_reads_used_for_scenarios": False,
                "network_requests_used_for_scenarios": False,
                "production_signing_keys_used": False,
            },
            "input_integrity_checks_before": integrity_before,
            "input_integrity_checks_after": integrity_after,
            "summary": summary,
            "quality_gates": gates,
            "unsafe_release_scenario_ids": unsafe_ids,
            "unverified_artifact_release_scenario_ids": unverified_ids,
            "undetected_scenario_ids": undetected_ids,
            "harness_error_scenario_ids": harness_error_ids,
            "results": results,
            "release_decision": release_decision,
            "limitations": list(self.catalog["limitations"]),
        }


def save_supply_chain_assurance_artifacts(
    report: Mapping[str, Any], output_dir: Path | str
) -> dict[str, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    report_path = directory / "step11i_supply_chain_assurance_report.json"
    csv_path = directory / "step11i_supply_chain_results.csv"
    unsafe_path = directory / "step11i_unsafe_releases.json"
    evidence_path = directory / "step11i_release_evidence_summary.json"
    integrity_path = directory / "step11i_trusted_baseline_integrity.sha256"

    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    fieldnames = [
        "scenario_id",
        "family",
        "handler",
        "severity",
        "mutation",
        "outcome",
        "defended",
        "automated_release",
        "human_review_required",
        "unsafe_release",
        "unverified_artifact_release",
        "signature_verified",
        "finding_codes",
    ]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for result in report["results"]:
        writer.writerow(
            {
                field: (
                    "|".join(result[field])
                    if field == "finding_codes"
                    else result[field]
                )
                for field in fieldnames
            }
        )
    csv_path.write_text(buffer.getvalue(), encoding="utf-8")

    unsafe_path.write_text(
        json.dumps(
            {
                "report_id": report["report_id"],
                "unsafe_release_scenario_ids": report[
                    "unsafe_release_scenario_ids"
                ],
                "unverified_artifact_release_scenario_ids": report[
                    "unverified_artifact_release_scenario_ids"
                ],
                "unsafe_releases": [
                    result
                    for result in report["results"]
                    if result["unsafe_release"]
                    or result["unverified_artifact_release"]
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    evidence_path.write_text(
        json.dumps(
            {
                "report_id": report["report_id"],
                "verified_release_count": report["summary"][
                    "release_verified_count"
                ],
                "review_required_release_count": report["summary"][
                    "release_verified_with_review_count"
                ],
                "blocked_or_quarantined_count": (
                    report["summary"]["scenario_count"]
                    - report["summary"]["release_verified_count"]
                    - report["summary"]["release_verified_with_review_count"]
                ),
                "signature_enforcement_rate": report["summary"][
                    "signature_enforcement_rate"
                ],
                "source_to_artifact_binding_rate": report["summary"][
                    "source_to_artifact_binding_rate"
                ],
                "sbom_to_build_reconciliation_rate": report["summary"][
                    "sbom_to_build_reconciliation_rate"
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    integrity_lines = []
    for name, path in (
        ("report", report_path),
        ("results", csv_path),
        ("unsafe", unsafe_path),
        ("evidence", evidence_path),
    ):
        integrity_lines.append(f"{sha256_file(path)}  {path.name}")
    integrity_path.write_text("\n".join(integrity_lines) + "\n", encoding="utf-8")

    return {
        "report": report_path,
        "csv": csv_path,
        "unsafe": unsafe_path,
        "evidence": evidence_path,
        "integrity": integrity_path,
    }

from __future__ import annotations

import copy
import json
from pathlib import Path

from src.governance.release_integrity import (
    ReleasePolicy,
    finalize_release_manifest,
    reconcile_cyclonedx_sbom,
    verify_release_manifest,
    verify_reproducible_artifact_sets,
    write_release_manifest_atomic,
)
from src.governance.supply_chain_guard import compute_lock_digest, sha256_file


def fixture(tmp_path: Path):
    artifact = tmp_path / "dist" / "a.whl"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"artifact")
    policy = ReleasePolicy(
        minimum_release_sequence=6,
        allowed_artifact_media_types=frozenset({"application/zip"}),
        required_evidence_roles=frozenset({"dependency_lock", "sbom", "provenance", "model_manifest", "workflow"}),
    )
    manifest = finalize_release_manifest(
        {
            "release_id": "R-1",
            "release_version": "1.0.0",
            "release_sequence": 7,
            "artifacts": [{"name": "a.whl", "path": "dist/a.whl", "media_type": "application/zip", "size_bytes": artifact.stat().st_size, "sha256": sha256_file(artifact)}],
            "evidence": [{"role": role, "sha256": "1" * 64} for role in policy.required_evidence_roles],
            "authorized_exception": None,
        }
    )
    return artifact, policy, manifest


def test_release_manifest_passes(tmp_path: Path) -> None:
    _, policy, manifest = fixture(tmp_path)
    assert verify_release_manifest(manifest, tmp_path, policy).passed is True


def test_artifact_tamper_fails(tmp_path: Path) -> None:
    artifact, policy, manifest = fixture(tmp_path)
    artifact.write_bytes(b"tampered")
    result = verify_release_manifest(manifest, tmp_path, policy)
    assert "RELEASE_ARTIFACT_DIGEST_MISMATCH" in {x.code for x in result.findings}


def test_manifest_digest_tamper_fails(tmp_path: Path) -> None:
    _, policy, manifest = fixture(tmp_path)
    manifest["release_id"] = "changed"
    result = verify_release_manifest(manifest, tmp_path, policy)
    assert "RELEASE_MANIFEST_DIGEST_MISMATCH" in {x.code for x in result.findings}


def test_rollback_and_duplicate_are_detected(tmp_path: Path) -> None:
    _, policy, manifest = fixture(tmp_path)
    manifest["release_sequence"] = 6
    manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))
    manifest = finalize_release_manifest(manifest)
    codes = {x.code for x in verify_release_manifest(manifest, tmp_path, policy).findings}
    assert "RELEASE_ROLLBACK_DETECTED" in codes
    assert "RELEASE_ARTIFACT_DUPLICATE" in codes


def test_atomic_manifest_writer_produces_verified_document(tmp_path: Path) -> None:
    _, policy, manifest = fixture(tmp_path)
    target = tmp_path / "release.json"
    write_release_manifest_atomic(target, manifest)
    stored = json.loads(target.read_text())
    assert verify_release_manifest(stored, tmp_path, policy).passed is True


def lock_and_sbom():
    lock = {
        "dependencies": [{"name": "requests", "version": "2.32.5", "hashes": {"sha256": "a" * 64}}]
    }
    lock["lock_digest"] = compute_lock_digest(lock)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "a.whl", "hashes": [{"alg": "SHA-256", "content": "b" * 64}]}},
        "components": [{"name": "requests", "version": "2.32.5", "hashes": [{"alg": "SHA-256", "content": "a" * 64}]}],
    }
    return lock, sbom


def test_sbom_reconciliation_passes() -> None:
    lock, sbom = lock_and_sbom()
    result = reconcile_cyclonedx_sbom(lock, sbom, expected_subject_name="a.whl", expected_subject_sha256="b" * 64)
    assert result.passed is True
    assert result.matched_components == 1


def test_sbom_missing_and_unexpected_components_fail() -> None:
    lock, sbom = lock_and_sbom()
    sbom["components"] = [{"name": "evil", "version": "1.0.0", "hashes": [{"alg": "SHA-256", "content": "c" * 64}]}]
    result = reconcile_cyclonedx_sbom(lock, sbom, expected_subject_name="a.whl", expected_subject_sha256="b" * 64)
    codes = {x.code for x in result.findings}
    assert "SBOM_DEPENDENCY_MISSING" in codes
    assert "SBOM_UNEXPECTED_COMPONENT" in codes


def test_reproducibility_mismatch_fails() -> None:
    result = verify_reproducible_artifact_sets({"a": "1" * 64}, {"a": "2" * 64})
    assert result.passed is False

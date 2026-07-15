from __future__ import annotations

import copy
from pathlib import Path

from src.governance.supply_chain_guard import (
    DependencyPolicy,
    ModelPolicy,
    SourceState,
    WorkflowPolicy,
    compute_lock_digest,
    normalize_package_name,
    sha256_bytes,
    sha256_file,
    verify_dependency_lock,
    verify_model_manifest,
    verify_source_state,
    verify_workflow_text,
)


def dependency_fixture(tmp_path: Path) -> dict:
    artifact = tmp_path / "deps" / "requests-2.32.5.whl"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"controlled dependency")
    lock = {
        "schema_version": "1.0.0",
        "dependencies": [
            {
                "name": "Requests",
                "normalized_name": "requests",
                "version": "2.32.5",
                "purl": "pkg:pypi/requests@2.32.5",
                "artifact_path": "deps/requests-2.32.5.whl",
                "hashes": {"sha256": sha256_file(artifact)},
                "source": {"type": "registry", "url": "https://pypi.org/simple"},
            }
        ],
    }
    lock["lock_digest"] = compute_lock_digest(lock)
    return lock


def test_package_normalization_is_pep503_style() -> None:
    assert normalize_package_name("My_Package.Name") == "my-package-name"


def test_verified_dependency_lock_passes(tmp_path: Path) -> None:
    result = verify_dependency_lock(
        dependency_fixture(tmp_path), tmp_path, DependencyPolicy()
    )
    assert result.passed is True
    assert result.metadata["verified_artifact_count"] == 1


def test_unpinned_dependency_fails(tmp_path: Path) -> None:
    lock = dependency_fixture(tmp_path)
    lock["dependencies"][0]["version"] = ">=2"
    lock["lock_digest"] = compute_lock_digest(lock)
    result = verify_dependency_lock(lock, tmp_path, DependencyPolicy())
    assert "DEPENDENCY_NOT_EXACTLY_PINNED" in {
        item.code for item in result.findings
    }


def test_dependency_hash_mismatch_fails(tmp_path: Path) -> None:
    lock = dependency_fixture(tmp_path)
    lock["dependencies"][0]["hashes"]["sha256"] = "0" * 64
    lock["lock_digest"] = compute_lock_digest(lock)
    result = verify_dependency_lock(lock, tmp_path, DependencyPolicy())
    assert "DEPENDENCY_ARTIFACT_HASH_MISMATCH" in {
        item.code for item in result.findings
    }


def test_direct_reference_fails_closed(tmp_path: Path) -> None:
    lock = dependency_fixture(tmp_path)
    lock["dependencies"][0]["source"] = {
        "type": "direct_url",
        "url": "https://example.invalid/package.whl",
    }
    lock["lock_digest"] = compute_lock_digest(lock)
    result = verify_dependency_lock(lock, tmp_path, DependencyPolicy())
    assert "DEPENDENCY_DIRECT_REFERENCE_PROHIBITED" in {
        item.code for item in result.findings
    }


def test_normalized_name_conflict_is_detected(tmp_path: Path) -> None:
    lock = dependency_fixture(tmp_path)
    duplicate = copy.deepcopy(lock["dependencies"][0])
    duplicate["name"] = "REQUESTS"
    duplicate["version"] = "1.0.0"
    duplicate["purl"] = "pkg:pypi/requests@1.0.0"
    lock["dependencies"].append(duplicate)
    lock["lock_digest"] = compute_lock_digest(lock)
    result = verify_dependency_lock(lock, tmp_path, DependencyPolicy())
    assert "DEPENDENCY_NORMALIZED_NAME_CONFLICT" in {
        item.code for item in result.findings
    }


def valid_workflow() -> str:
    return (
        "on:\n  workflow_dispatch:\n"
        "jobs:\n  build:\n    runs-on: ubuntu-24.04\n"
        "    container: python@sha256:" + "1" * 64 + "\n"
        "    steps:\n      - uses: actions/checkout@" + "2" * 40 + "\n"
    )


def test_pinned_workflow_passes() -> None:
    text = valid_workflow()
    result = verify_workflow_text(
        text,
        sha256_bytes(text.encode()),
        WorkflowPolicy(),
        runner_labels=["ubuntu-24.04"],
        network_disabled=True,
        hermetic=True,
    )
    assert result.passed is True


def test_mutable_action_and_container_fail() -> None:
    text = valid_workflow().replace("actions/checkout@" + "2" * 40, "actions/checkout@v4")
    text = text.replace("python@sha256:" + "1" * 64, "python:3.12")
    result = verify_workflow_text(
        text,
        sha256_bytes(text.encode()),
        WorkflowPolicy(),
        runner_labels=["ubuntu-24.04"],
        network_disabled=True,
        hermetic=True,
    )
    codes = {item.code for item in result.findings}
    assert "WORKFLOW_ACTION_NOT_COMMIT_PINNED" in codes
    assert "WORKFLOW_CONTAINER_NOT_DIGEST_PINNED" in codes


def test_dirty_source_is_blocked() -> None:
    result = verify_source_state(
        SourceState("a" * 40, "b" * 64, False, True),
        "a" * 40,
        "b" * 64,
    )
    assert "SOURCE_WORKTREE_DIRTY" in {item.code for item in result.findings}


def model_fixture(tmp_path: Path) -> dict:
    path = tmp_path / "models" / "model.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"model")
    return {
        "model_id": "org/model",
        "source_uri": "https://huggingface.co/org/model",
        "revision": "c" * 40,
        "trust_remote_code": False,
        "files": [{"path": "models/model.bin", "sha256": sha256_file(path)}],
        "datasets": [{"dataset_id": "d", "sha256": "d" * 64}],
    }


def test_model_manifest_passes(tmp_path: Path) -> None:
    result = verify_model_manifest(
        model_fixture(tmp_path),
        tmp_path,
        ModelPolicy(frozenset({"huggingface.co"})),
    )
    assert result.passed is True


def test_remote_code_and_unpinned_model_fail(tmp_path: Path) -> None:
    manifest = model_fixture(tmp_path)
    manifest["revision"] = "main"
    manifest["trust_remote_code"] = True
    result = verify_model_manifest(
        manifest,
        tmp_path,
        ModelPolicy(frozenset({"huggingface.co"})),
    )
    codes = {item.code for item in result.findings}
    assert "MODEL_REVISION_NOT_IMMUTABLE" in codes
    assert "MODEL_REMOTE_CODE_PROHIBITED" in codes

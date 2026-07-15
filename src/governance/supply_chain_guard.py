from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from packaging.version import InvalidVersion, Version


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EXACT_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")
_MUTABLE_VERSION_TOKENS = ("*", "^", "~", ">", "<", "=", " ", ",")
_ACTION_RE = re.compile(r"\buses:\s*([^\s@]+)@([^\s#]+)")
_CONTAINER_RE = re.compile(r"\b(?:container:|image:)\s*([^\s#]+)")


class SupplyChainPolicyError(ValueError):
    """Raised when a supply-chain policy or input contract is invalid."""


@dataclass(frozen=True)
class SupplyChainFinding:
    code: str
    severity: str
    message: str
    field_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "field_path": self.field_path,
        }


@dataclass(frozen=True)
class VerificationResult:
    passed: bool
    findings: tuple[SupplyChainFinding, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DependencyPolicy:
    exact_pin_required: bool = True
    sha256_required: bool = True
    direct_references_permitted: bool = False
    allowed_registry_hosts: frozenset[str] = frozenset({"pypi.org"})
    normalized_name_uniqueness_required: bool = True
    artifact_verification_required: bool = True


@dataclass(frozen=True)
class WorkflowPolicy:
    action_commit_pin_required: bool = True
    container_digest_pin_required: bool = True
    allowed_runner_labels: frozenset[str] = frozenset({"ubuntu-24.04"})
    forbidden_triggers: frozenset[str] = frozenset({"pull_request_target"})
    forbidden_tokens: tuple[str, ...] = (
        "permissions: write-all",
        "curl | sh",
        "curl | bash",
        "wget | sh",
        "wget | bash",
    )
    network_disabled_required: bool = True
    hermetic_required: bool = True


@dataclass(frozen=True)
class ModelPolicy:
    allowed_registry_hosts: frozenset[str]
    revision_pattern: str = r"^[0-9a-f]{40}$"
    remote_code_permitted: bool = False
    dataset_provenance_required: bool = True
    file_hashes_required: bool = True


@dataclass(frozen=True)
class SourceState:
    revision: str
    tree_digest: str
    clean: bool
    committed_inputs_only: bool


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_package_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise SupplyChainPolicyError("Package name must be a non-empty string.")
    value = name.strip()
    if not _PACKAGE_NAME_RE.fullmatch(value):
        raise SupplyChainPolicyError(f"Invalid package name: {name!r}")
    return re.sub(r"[-_.]+", "-", value).lower()


def is_exact_version(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    candidate = value.strip()
    if any(token in candidate for token in _MUTABLE_VERSION_TOKENS):
        return False
    if not _EXACT_VERSION_RE.fullmatch(candidate):
        return False
    try:
        Version(candidate)
    except InvalidVersion:
        return False
    return True


def _safe_relative_file(root: Path, relative_path: Any) -> Path | None:
    if not isinstance(relative_path, str) or not relative_path.strip():
        return None
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    resolved = (root / candidate).resolve()
    if root != resolved and root not in resolved.parents:
        return None
    if not resolved.is_file():
        return None
    return resolved


def compute_lock_digest(lock: Mapping[str, Any]) -> str:
    value = dict(lock)
    value.pop("lock_digest", None)
    return sha256_bytes(canonical_json_bytes(value))


def verify_dependency_lock(
    lock: Mapping[str, Any],
    artifact_root: Path | str,
    policy: DependencyPolicy,
) -> VerificationResult:
    findings: list[SupplyChainFinding] = []
    root = Path(artifact_root).resolve()

    if not isinstance(lock, Mapping):
        raise SupplyChainPolicyError("Dependency lock must be a mapping.")

    entries = lock.get("dependencies")
    if not isinstance(entries, list) or not entries:
        findings.append(
            SupplyChainFinding(
                "DEPENDENCY_LOCK_EMPTY",
                "critical",
                "Dependency lock contains no dependency entries.",
                "dependencies",
            )
        )
        return VerificationResult(False, tuple(findings))

    stored_lock_digest = lock.get("lock_digest")
    actual_lock_digest = compute_lock_digest(lock)
    if stored_lock_digest != actual_lock_digest:
        findings.append(
            SupplyChainFinding(
                "DEPENDENCY_LOCK_DIGEST_MISMATCH",
                "critical",
                "Dependency lock canonical digest does not match its content.",
                "lock_digest",
            )
        )

    normalized_versions: dict[str, str] = {}
    verified_artifacts = 0

    for index, entry in enumerate(entries):
        field = f"dependencies[{index}]"
        if not isinstance(entry, Mapping):
            findings.append(
                SupplyChainFinding(
                    "DEPENDENCY_ENTRY_INVALID",
                    "critical",
                    "Dependency entry must be an object.",
                    field,
                )
            )
            continue

        name = entry.get("name")
        try:
            normalized_name = normalize_package_name(name)
        except SupplyChainPolicyError as exc:
            findings.append(
                SupplyChainFinding(
                    "DEPENDENCY_NAME_INVALID",
                    "critical",
                    str(exc),
                    f"{field}.name",
                )
            )
            continue

        declared_normalized = entry.get("normalized_name")
        if declared_normalized != normalized_name:
            findings.append(
                SupplyChainFinding(
                    "DEPENDENCY_NORMALIZATION_MISMATCH",
                    "critical",
                    "Declared normalized dependency name does not match canonical normalization.",
                    f"{field}.normalized_name",
                )
            )

        version = entry.get("version")
        if policy.exact_pin_required and not is_exact_version(version):
            findings.append(
                SupplyChainFinding(
                    "DEPENDENCY_NOT_EXACTLY_PINNED",
                    "critical",
                    "Dependency version is not an immutable exact version.",
                    f"{field}.version",
                )
            )

        if isinstance(version, str):
            previous = normalized_versions.get(normalized_name)
            if previous is not None and previous != version:
                findings.append(
                    SupplyChainFinding(
                        "DEPENDENCY_NORMALIZED_NAME_CONFLICT",
                        "critical",
                        "Equivalent normalized package names resolve to conflicting versions.",
                        f"{field}.name",
                    )
                )
            normalized_versions[normalized_name] = version

        source = entry.get("source")
        if not isinstance(source, Mapping):
            findings.append(
                SupplyChainFinding(
                    "DEPENDENCY_SOURCE_MISSING",
                    "critical",
                    "Dependency source metadata is required.",
                    f"{field}.source",
                )
            )
        else:
            source_type = source.get("type")
            source_url = source.get("url")
            if source_type in {"direct_url", "vcs", "local_path"} and not policy.direct_references_permitted:
                findings.append(
                    SupplyChainFinding(
                        "DEPENDENCY_DIRECT_REFERENCE_PROHIBITED",
                        "critical",
                        "Direct URL, VCS, and local-path dependencies are prohibited by policy.",
                        f"{field}.source.type",
                    )
                )
            if source_type == "registry":
                host = urlparse(str(source_url)).hostname
                if host not in policy.allowed_registry_hosts:
                    findings.append(
                        SupplyChainFinding(
                            "DEPENDENCY_REGISTRY_NOT_ALLOWED",
                            "critical",
                            f"Dependency registry host is not allowlisted: {host!r}.",
                            f"{field}.source.url",
                        )
                    )

        hashes = entry.get("hashes")
        expected_sha256 = hashes.get("sha256") if isinstance(hashes, Mapping) else None
        if policy.sha256_required and (
            not isinstance(expected_sha256, str)
            or not _SHA256_RE.fullmatch(expected_sha256)
        ):
            findings.append(
                SupplyChainFinding(
                    "DEPENDENCY_SHA256_MISSING_OR_INVALID",
                    "critical",
                    "Dependency artifact requires a lowercase SHA-256 digest.",
                    f"{field}.hashes.sha256",
                )
            )

        artifact = _safe_relative_file(root, entry.get("artifact_path"))
        if policy.artifact_verification_required and artifact is None:
            findings.append(
                SupplyChainFinding(
                    "DEPENDENCY_ARTIFACT_MISSING_OR_UNSAFE",
                    "critical",
                    "Dependency artifact path is missing, unsafe, or does not exist.",
                    f"{field}.artifact_path",
                )
            )
        elif artifact is not None and isinstance(expected_sha256, str):
            actual_sha256 = sha256_file(artifact)
            if actual_sha256 != expected_sha256:
                findings.append(
                    SupplyChainFinding(
                        "DEPENDENCY_ARTIFACT_HASH_MISMATCH",
                        "critical",
                        "Dependency artifact digest does not match the lock entry.",
                        f"{field}.hashes.sha256",
                    )
                )
            else:
                verified_artifacts += 1

        purl = entry.get("purl")
        if isinstance(version, str):
            expected_purl = f"pkg:pypi/{normalized_name}@{version}"
            if purl != expected_purl:
                findings.append(
                    SupplyChainFinding(
                        "DEPENDENCY_PURL_MISMATCH",
                        "high",
                        "Dependency purl does not bind the canonical name and exact version.",
                        f"{field}.purl",
                    )
                )

    return VerificationResult(
        passed=not findings,
        findings=tuple(findings),
        metadata={
            "dependency_count": len(entries),
            "verified_artifact_count": verified_artifacts,
            "actual_lock_digest": actual_lock_digest,
        },
    )


def verify_source_state(
    state: SourceState,
    expected_revision: str,
    expected_tree_digest: str,
) -> VerificationResult:
    findings: list[SupplyChainFinding] = []
    if state.revision != expected_revision:
        findings.append(
            SupplyChainFinding(
                "SOURCE_REVISION_MISMATCH",
                "critical",
                "Build source revision does not match the authorized revision.",
                "source.revision",
            )
        )
    if state.tree_digest != expected_tree_digest:
        findings.append(
            SupplyChainFinding(
                "SOURCE_TREE_MISMATCH",
                "critical",
                "Build source tree digest does not match the authorized tree.",
                "source.tree_digest",
            )
        )
    if not state.clean:
        findings.append(
            SupplyChainFinding(
                "SOURCE_WORKTREE_DIRTY",
                "critical",
                "Uncommitted source changes are prohibited build inputs.",
                "source.clean",
            )
        )
    if not state.committed_inputs_only:
        findings.append(
            SupplyChainFinding(
                "UNCOMMITTED_BUILD_INPUT",
                "critical",
                "Build consumed inputs not bound to the source revision.",
                "source.committed_inputs_only",
            )
        )
    return VerificationResult(not findings, tuple(findings))


def verify_workflow_text(
    workflow_text: str,
    expected_sha256: str,
    policy: WorkflowPolicy,
    *,
    runner_labels: Iterable[str],
    network_disabled: bool,
    hermetic: bool,
) -> VerificationResult:
    findings: list[SupplyChainFinding] = []
    actual_sha256 = sha256_bytes(workflow_text.encode("utf-8"))
    if actual_sha256 != expected_sha256:
        findings.append(
            SupplyChainFinding(
                "WORKFLOW_DIGEST_MISMATCH",
                "critical",
                "Build workflow digest differs from the authorized workflow.",
                "workflow.sha256",
            )
        )

    lower = workflow_text.casefold()
    for trigger in policy.forbidden_triggers:
        if re.search(rf"(?m)^\s*{re.escape(trigger.casefold())}\s*:", lower):
            findings.append(
                SupplyChainFinding(
                    "WORKFLOW_FORBIDDEN_TRIGGER",
                    "critical",
                    f"Forbidden workflow trigger detected: {trigger}.",
                    "workflow.trigger",
                )
            )
    for token in policy.forbidden_tokens:
        if token.casefold() in lower:
            findings.append(
                SupplyChainFinding(
                    "WORKFLOW_FORBIDDEN_TOKEN",
                    "critical",
                    f"Forbidden workflow construct detected: {token}.",
                    "workflow",
                )
            )

    for match in _ACTION_RE.finditer(workflow_text):
        reference = match.group(2)
        if policy.action_commit_pin_required and not re.fullmatch(r"[0-9a-fA-F]{40}", reference):
            findings.append(
                SupplyChainFinding(
                    "WORKFLOW_ACTION_NOT_COMMIT_PINNED",
                    "critical",
                    "Third-party action reference must be pinned to a full commit SHA.",
                    "workflow.uses",
                )
            )

    for match in _CONTAINER_RE.finditer(workflow_text):
        image = match.group(1)
        if image.startswith("$"):
            continue
        if policy.container_digest_pin_required and not re.search(r"@sha256:[0-9a-fA-F]{64}$", image):
            findings.append(
                SupplyChainFinding(
                    "WORKFLOW_CONTAINER_NOT_DIGEST_PINNED",
                    "critical",
                    "Container image must be pinned by SHA-256 digest.",
                    "workflow.container",
                )
            )

    labels = set(runner_labels)
    if not labels or not labels.issubset(policy.allowed_runner_labels):
        findings.append(
            SupplyChainFinding(
                "WORKFLOW_RUNNER_NOT_ALLOWED",
                "critical",
                "Workflow runner label is not allowlisted.",
                "workflow.runner_labels",
            )
        )
    if policy.network_disabled_required and not network_disabled:
        findings.append(
            SupplyChainFinding(
                "BUILD_NETWORK_POLICY_VIOLATION",
                "critical",
                "Build network access was enabled contrary to policy.",
                "workflow.network_disabled",
            )
        )
    if policy.hermetic_required and not hermetic:
        findings.append(
            SupplyChainFinding(
                "BUILD_NOT_HERMETIC",
                "critical",
                "Build environment was not hermetic.",
                "workflow.hermetic",
            )
        )

    return VerificationResult(
        not findings,
        tuple(findings),
        {"actual_workflow_sha256": actual_sha256},
    )


def verify_model_manifest(
    manifest: Mapping[str, Any],
    artifact_root: Path | str,
    policy: ModelPolicy,
) -> VerificationResult:
    findings: list[SupplyChainFinding] = []
    root = Path(artifact_root).resolve()

    model_id = manifest.get("model_id")
    if not isinstance(model_id, str) or not model_id.strip():
        findings.append(
            SupplyChainFinding(
                "MODEL_ID_MISSING",
                "critical",
                "Model identity is required.",
                "model_id",
            )
        )

    revision = manifest.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(policy.revision_pattern, revision):
        findings.append(
            SupplyChainFinding(
                "MODEL_REVISION_NOT_IMMUTABLE",
                "critical",
                "Model revision must be an immutable commit-like identifier.",
                "revision",
            )
        )

    source_uri = manifest.get("source_uri")
    host = urlparse(str(source_uri)).hostname
    if host not in policy.allowed_registry_hosts:
        findings.append(
            SupplyChainFinding(
                "MODEL_REGISTRY_NOT_ALLOWED",
                "critical",
                f"Model registry host is not allowlisted: {host!r}.",
                "source_uri",
            )
        )

    if not policy.remote_code_permitted and manifest.get("trust_remote_code") is not False:
        findings.append(
            SupplyChainFinding(
                "MODEL_REMOTE_CODE_PROHIBITED",
                "critical",
                "Remote model code execution is prohibited.",
                "trust_remote_code",
            )
        )

    files = manifest.get("files")
    verified_files = 0
    if not isinstance(files, list) or not files:
        findings.append(
            SupplyChainFinding(
                "MODEL_FILES_MISSING",
                "critical",
                "Model file inventory is required.",
                "files",
            )
        )
    else:
        for index, item in enumerate(files):
            field = f"files[{index}]"
            if not isinstance(item, Mapping):
                findings.append(
                    SupplyChainFinding(
                        "MODEL_FILE_ENTRY_INVALID",
                        "critical",
                        "Model file entry must be an object.",
                        field,
                    )
                )
                continue
            expected = item.get("sha256")
            if policy.file_hashes_required and (
                not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected)
            ):
                findings.append(
                    SupplyChainFinding(
                        "MODEL_FILE_HASH_MISSING",
                        "critical",
                        "Model file requires a SHA-256 digest.",
                        f"{field}.sha256",
                    )
                )
                continue
            path = _safe_relative_file(root, item.get("path"))
            if path is None:
                findings.append(
                    SupplyChainFinding(
                        "MODEL_FILE_MISSING_OR_UNSAFE",
                        "critical",
                        "Model file path is missing, unsafe, or does not exist.",
                        f"{field}.path",
                    )
                )
                continue
            if sha256_file(path) != expected:
                findings.append(
                    SupplyChainFinding(
                        "MODEL_FILE_HASH_MISMATCH",
                        "critical",
                        "Model file digest does not match its manifest.",
                        f"{field}.sha256",
                    )
                )
            else:
                verified_files += 1

    datasets = manifest.get("datasets")
    if policy.dataset_provenance_required:
        if not isinstance(datasets, list) or not datasets:
            findings.append(
                SupplyChainFinding(
                    "MODEL_DATASET_PROVENANCE_MISSING",
                    "critical",
                    "Model dataset provenance is required.",
                    "datasets",
                )
            )
        else:
            for index, dataset in enumerate(datasets):
                if not isinstance(dataset, Mapping):
                    findings.append(
                        SupplyChainFinding(
                            "MODEL_DATASET_ENTRY_INVALID",
                            "critical",
                            "Dataset provenance entry must be an object.",
                            f"datasets[{index}]",
                        )
                    )
                    continue
                digest = dataset.get("sha256")
                if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                    findings.append(
                        SupplyChainFinding(
                            "MODEL_DATASET_HASH_MISSING",
                            "critical",
                            "Dataset provenance requires a SHA-256 digest.",
                            f"datasets[{index}].sha256",
                        )
                    )

    return VerificationResult(
        not findings,
        tuple(findings),
        {"verified_model_file_count": verified_files},
    )

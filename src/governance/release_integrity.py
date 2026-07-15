from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from packaging.version import InvalidVersion, Version

from src.governance.recovery_checkpoint import atomic_write_json
from src.governance.supply_chain_guard import (
    SupplyChainFinding,
    VerificationResult,
    canonical_json_bytes,
    normalize_package_name,
    sha256_bytes,
    sha256_file,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReleaseIntegrityError(ValueError):
    """Raised when a release-integrity contract is structurally invalid."""


@dataclass(frozen=True)
class ReleasePolicy:
    minimum_release_sequence: int
    allowed_artifact_media_types: frozenset[str]
    required_evidence_roles: frozenset[str]
    authorized_exception_ids: frozenset[str] = frozenset()
    atomic_manifest_required: bool = True
    rollback_protection_required: bool = True


@dataclass(frozen=True)
class ReconciliationResult:
    passed: bool
    findings: tuple[SupplyChainFinding, ...] = field(default_factory=tuple)
    matched_components: int = 0
    missing_components: tuple[str, ...] = field(default_factory=tuple)
    unexpected_components: tuple[str, ...] = field(default_factory=tuple)

    def to_result(self) -> VerificationResult:
        return VerificationResult(
            self.passed,
            self.findings,
            {
                "matched_components": self.matched_components,
                "missing_components": list(self.missing_components),
                "unexpected_components": list(self.unexpected_components),
            },
        )


def compute_release_manifest_digest(manifest: Mapping[str, Any]) -> str:
    value = copy.deepcopy(dict(manifest))
    value.pop("manifest_digest", None)
    return sha256_bytes(canonical_json_bytes(value))


def finalize_release_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(manifest))
    value["manifest_digest"] = compute_release_manifest_digest(value)
    return value


def write_release_manifest_atomic(path: Path | str, manifest: Mapping[str, Any]) -> None:
    atomic_write_json(path, finalize_release_manifest(manifest))


def _safe_file(root: Path, relative_path: Any) -> Path | None:
    if not isinstance(relative_path, str) or not relative_path:
        return None
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    resolved = (root / candidate).resolve()
    if root != resolved and root not in resolved.parents:
        return None
    return resolved if resolved.is_file() else None


def verify_release_manifest(
    manifest: Mapping[str, Any],
    artifact_root: Path | str,
    policy: ReleasePolicy,
) -> VerificationResult:
    findings: list[SupplyChainFinding] = []
    root = Path(artifact_root).resolve()

    if not isinstance(manifest, Mapping):
        raise ReleaseIntegrityError("Release manifest must be an object.")

    release_id = manifest.get("release_id")
    release_version = manifest.get("release_version")
    if not isinstance(release_id, str) or not release_id:
        findings.append(
            SupplyChainFinding(
                "RELEASE_ID_MISSING",
                "critical",
                "Release identity is required.",
                "release_id",
            )
        )
    try:
        Version(str(release_version))
    except InvalidVersion:
        findings.append(
            SupplyChainFinding(
                "RELEASE_VERSION_INVALID",
                "critical",
                "Release version is not a valid immutable version.",
                "release_version",
            )
        )

    sequence = manifest.get("release_sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        findings.append(
            SupplyChainFinding(
                "RELEASE_SEQUENCE_INVALID",
                "critical",
                "Release sequence must be an integer.",
                "release_sequence",
            )
        )
    elif policy.rollback_protection_required and sequence <= policy.minimum_release_sequence:
        findings.append(
            SupplyChainFinding(
                "RELEASE_ROLLBACK_DETECTED",
                "critical",
                "Release sequence does not advance beyond the trusted baseline.",
                "release_sequence",
            )
        )

    stored_digest = manifest.get("manifest_digest")
    actual_digest = compute_release_manifest_digest(manifest)
    if stored_digest != actual_digest:
        findings.append(
            SupplyChainFinding(
                "RELEASE_MANIFEST_DIGEST_MISMATCH",
                "critical",
                "Release manifest canonical digest does not match its content.",
                "manifest_digest",
            )
        )

    artifacts = manifest.get("artifacts")
    seen_names: set[str] = set()
    verified_artifacts = 0
    if not isinstance(artifacts, list) or not artifacts:
        findings.append(
            SupplyChainFinding(
                "RELEASE_ARTIFACTS_MISSING",
                "critical",
                "Release manifest requires at least one artifact.",
                "artifacts",
            )
        )
    else:
        for index, artifact in enumerate(artifacts):
            field = f"artifacts[{index}]"
            if not isinstance(artifact, Mapping):
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_ENTRY_INVALID",
                        "critical",
                        "Release artifact entry must be an object.",
                        field,
                    )
                )
                continue
            name = artifact.get("name")
            if not isinstance(name, str) or not name:
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_NAME_MISSING",
                        "critical",
                        "Release artifact name is required.",
                        f"{field}.name",
                    )
                )
            elif name in seen_names:
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_DUPLICATE",
                        "critical",
                        "Duplicate artifact identity creates a release conflict.",
                        f"{field}.name",
                    )
                )
            else:
                seen_names.add(name)

            media_type = artifact.get("media_type")
            if media_type not in policy.allowed_artifact_media_types:
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_MEDIA_TYPE_NOT_ALLOWED",
                        "critical",
                        "Release artifact media type is not allowlisted.",
                        f"{field}.media_type",
                    )
                )

            expected = artifact.get("sha256")
            if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected):
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_HASH_MISSING",
                        "critical",
                        "Release artifact requires a SHA-256 digest.",
                        f"{field}.sha256",
                    )
                )
                continue
            path = _safe_file(root, artifact.get("path"))
            if path is None:
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_MISSING_OR_UNSAFE",
                        "critical",
                        "Release artifact path is missing, unsafe, or absent.",
                        f"{field}.path",
                    )
                )
                continue
            actual_size = path.stat().st_size
            if artifact.get("size_bytes") != actual_size:
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_SIZE_MISMATCH",
                        "critical",
                        "Release artifact size does not match the manifest.",
                        f"{field}.size_bytes",
                    )
                )
            if sha256_file(path) != expected:
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_ARTIFACT_DIGEST_MISMATCH",
                        "critical",
                        "Release artifact bytes do not match the manifest digest.",
                        f"{field}.sha256",
                    )
                )
            else:
                verified_artifacts += 1

    evidence = manifest.get("evidence")
    observed_roles: set[str] = set()
    if not isinstance(evidence, list):
        findings.append(
            SupplyChainFinding(
                "RELEASE_EVIDENCE_MISSING",
                "critical",
                "Release evidence inventory is required.",
                "evidence",
            )
        )
    else:
        for index, record in enumerate(evidence):
            field = f"evidence[{index}]"
            if not isinstance(record, Mapping):
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_EVIDENCE_ENTRY_INVALID",
                        "critical",
                        "Release evidence entry must be an object.",
                        field,
                    )
                )
                continue
            role = record.get("role")
            if isinstance(role, str):
                observed_roles.add(role)
            digest = record.get("sha256")
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                findings.append(
                    SupplyChainFinding(
                        "RELEASE_EVIDENCE_HASH_INVALID",
                        "critical",
                        "Release evidence requires a SHA-256 digest.",
                        f"{field}.sha256",
                    )
                )

        missing_roles = policy.required_evidence_roles - observed_roles
        if missing_roles:
            findings.append(
                SupplyChainFinding(
                    "RELEASE_EVIDENCE_ROLE_MISSING",
                    "critical",
                    f"Release evidence roles are missing: {sorted(missing_roles)}.",
                    "evidence",
                )
            )

    exception = manifest.get("authorized_exception")
    if exception is not None:
        exception_id = exception.get("exception_id") if isinstance(exception, Mapping) else None
        approved = exception.get("approved") if isinstance(exception, Mapping) else False
        if exception_id not in policy.authorized_exception_ids or approved is not True:
            findings.append(
                SupplyChainFinding(
                    "UNAUTHORIZED_RELEASE_EXCEPTION",
                    "critical",
                    "Release exception is absent from the authorized exception policy.",
                    "authorized_exception",
                )
            )

    return VerificationResult(
        not findings,
        tuple(findings),
        {
            "actual_manifest_digest": actual_digest,
            "verified_artifact_count": verified_artifacts,
            "observed_evidence_roles": sorted(observed_roles),
        },
    )


def _component_key(name: Any, version: Any) -> str | None:
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    try:
        normalized = normalize_package_name(name)
    except ValueError:
        return None
    return f"{normalized}@{version}"


def reconcile_cyclonedx_sbom(
    dependency_lock: Mapping[str, Any],
    sbom: Mapping[str, Any],
    *,
    expected_subject_name: str,
    expected_subject_sha256: str,
) -> ReconciliationResult:
    findings: list[SupplyChainFinding] = []

    if sbom.get("bomFormat") != "CycloneDX":
        findings.append(
            SupplyChainFinding(
                "SBOM_FORMAT_INVALID",
                "critical",
                "SBOM must use CycloneDX format.",
                "bomFormat",
            )
        )
    spec_version = sbom.get("specVersion")
    try:
        if Version(str(spec_version)) < Version("1.5"):
            raise InvalidVersion
    except InvalidVersion:
        findings.append(
            SupplyChainFinding(
                "SBOM_SPEC_VERSION_UNSUPPORTED",
                "critical",
                "CycloneDX specification version must be 1.5 or newer.",
                "specVersion",
            )
        )

    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, Mapping) else None
    subject_digest = None
    subject_name = component.get("name") if isinstance(component, Mapping) else None
    hashes = component.get("hashes") if isinstance(component, Mapping) else None
    if isinstance(hashes, list):
        for item in hashes:
            if isinstance(item, Mapping) and item.get("alg") == "SHA-256":
                subject_digest = item.get("content")
                break
    if subject_name != expected_subject_name or subject_digest != expected_subject_sha256:
        findings.append(
            SupplyChainFinding(
                "SBOM_SUBJECT_BINDING_MISMATCH",
                "critical",
                "SBOM metadata does not bind the expected release artifact.",
                "metadata.component",
            )
        )

    dependencies = dependency_lock.get("dependencies")
    expected: dict[str, str] = {}
    if isinstance(dependencies, list):
        for entry in dependencies:
            if not isinstance(entry, Mapping):
                continue
            key = _component_key(entry.get("name"), entry.get("version"))
            digest = entry.get("hashes", {}).get("sha256") if isinstance(entry.get("hashes"), Mapping) else None
            if key and isinstance(digest, str):
                expected[key] = digest

    actual: dict[str, str | None] = {}
    components = sbom.get("components")
    if isinstance(components, list):
        for index, item in enumerate(components):
            if not isinstance(item, Mapping):
                findings.append(
                    SupplyChainFinding(
                        "SBOM_COMPONENT_INVALID",
                        "critical",
                        "SBOM component entry must be an object.",
                        f"components[{index}]",
                    )
                )
                continue
            key = _component_key(item.get("name"), item.get("version"))
            if key is None:
                findings.append(
                    SupplyChainFinding(
                        "SBOM_COMPONENT_IDENTITY_INCOMPLETE",
                        "critical",
                        "SBOM component requires a canonical name and exact version.",
                        f"components[{index}]",
                    )
                )
                continue
            digest_value = None
            item_hashes = item.get("hashes")
            if isinstance(item_hashes, list):
                for hash_record in item_hashes:
                    if isinstance(hash_record, Mapping) and hash_record.get("alg") == "SHA-256":
                        digest_value = hash_record.get("content")
                        break
            actual[key] = digest_value
    else:
        findings.append(
            SupplyChainFinding(
                "SBOM_COMPONENTS_MISSING",
                "critical",
                "SBOM component inventory is required.",
                "components",
            )
        )

    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing:
        findings.append(
            SupplyChainFinding(
                "SBOM_DEPENDENCY_MISSING",
                "critical",
                f"Locked dependencies are absent from the SBOM: {missing}.",
                "components",
            )
        )
    if unexpected:
        findings.append(
            SupplyChainFinding(
                "SBOM_UNEXPECTED_COMPONENT",
                "critical",
                f"SBOM contains components absent from the dependency lock: {unexpected}.",
                "components",
            )
        )

    matched = 0
    for key in set(expected) & set(actual):
        if actual[key] != expected[key]:
            findings.append(
                SupplyChainFinding(
                    "SBOM_COMPONENT_HASH_MISMATCH",
                    "critical",
                    f"SBOM digest does not match locked artifact for {key}.",
                    "components",
                )
            )
        else:
            matched += 1

    return ReconciliationResult(
        passed=not findings,
        findings=tuple(findings),
        matched_components=matched,
        missing_components=tuple(missing),
        unexpected_components=tuple(unexpected),
    )


def verify_reproducible_artifact_sets(
    first: Mapping[str, str],
    second: Mapping[str, str],
) -> VerificationResult:
    findings: list[SupplyChainFinding] = []
    if dict(first) != dict(second):
        findings.append(
            SupplyChainFinding(
                "REPRODUCIBLE_BUILD_DIGEST_MISMATCH",
                "critical",
                "Independent deterministic builds produced different artifact digests.",
                "reproducibility",
            )
        )
    return VerificationResult(not findings, tuple(findings))

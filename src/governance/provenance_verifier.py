from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.governance.supply_chain_guard import (
    SupplyChainFinding,
    VerificationResult,
    canonical_json_bytes,
)


IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class ProvenanceVerificationError(ValueError):
    """Raised when provenance verification inputs are structurally invalid."""


@dataclass(frozen=True)
class ProvenancePolicy:
    allowed_builder_ids: frozenset[str]
    allowed_build_types: frozenset[str]
    allowed_key_fingerprints: Mapping[str, str]
    expected_source_uri: str
    expected_source_revision: str
    expected_source_digest: str
    predicate_type: str = SLSA_PROVENANCE_V1
    statement_type: str = IN_TOTO_STATEMENT_V1
    payload_type: str = DSSE_PAYLOAD_TYPE
    require_material_completeness: bool = True
    require_parameter_completeness: bool = True
    require_environment_completeness: bool = True
    require_reproducible: bool = True
    require_network_disabled: bool = True


@dataclass(frozen=True)
class ProvenanceVerification:
    passed: bool
    signature_verified: bool
    statement: Mapping[str, Any] | None
    findings: tuple[SupplyChainFinding, ...] = field(default_factory=tuple)

    def to_result(self) -> VerificationResult:
        return VerificationResult(
            passed=self.passed,
            findings=self.findings,
            metadata={
                "signature_verified": self.signature_verified,
                "statement_present": self.statement is not None,
            },
        )


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    if not isinstance(payload_type, str) or not payload_type:
        raise ProvenanceVerificationError("DSSE payload type is required.")
    return (
        b"DSSEv1 "
        + str(len(payload_type.encode("utf-8"))).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def public_key_fingerprint(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()


def build_dsse_envelope(
    statement: Mapping[str, Any],
    *,
    key_id: str,
    signer: Any,
    payload_type: str = DSSE_PAYLOAD_TYPE,
) -> dict[str, Any]:
    payload = canonical_json_bytes(statement)
    signature = signer.sign(dsse_pae(payload_type, payload))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": key_id,
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }


def _decode_base64(value: Any, field_path: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProvenanceVerificationError(f"{field_path} must be base64 text.")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProvenanceVerificationError(
            f"{field_path} is not valid base64."
        ) from exc


def _parse_timestamp(value: Any, field_path: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _subject_digest(statement: Mapping[str, Any], subject_name: str) -> str | None:
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return None
    for subject in subjects:
        if not isinstance(subject, Mapping):
            continue
        if subject.get("name") != subject_name:
            continue
        digest = subject.get("digest")
        if isinstance(digest, Mapping):
            value = digest.get("sha256")
            if isinstance(value, str):
                return value
    return None


def verify_dsse_provenance(
    envelope: Mapping[str, Any],
    *,
    public_keys: Mapping[str, bytes],
    policy: ProvenancePolicy,
    expected_subject_name: str,
    expected_subject_sha256: str,
) -> ProvenanceVerification:
    findings: list[SupplyChainFinding] = []
    signature_verified = False
    statement: Mapping[str, Any] | None = None

    if not isinstance(envelope, Mapping):
        raise ProvenanceVerificationError("DSSE envelope must be an object.")

    payload_type = envelope.get("payloadType")
    if payload_type != policy.payload_type:
        findings.append(
            SupplyChainFinding(
                "DSSE_PAYLOAD_TYPE_MISMATCH",
                "critical",
                "DSSE payload type is not the authorized in-toto media type.",
                "payloadType",
            )
        )

    try:
        payload = _decode_base64(envelope.get("payload"), "payload")
    except ProvenanceVerificationError as exc:
        findings.append(
            SupplyChainFinding(
                "DSSE_PAYLOAD_INVALID",
                "critical",
                str(exc),
                "payload",
            )
        )
        return ProvenanceVerification(False, False, None, tuple(findings))

    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        findings.append(
            SupplyChainFinding(
                "DSSE_SIGNATURE_COUNT_INVALID",
                "critical",
                "Exactly one authorized release signature is required.",
                "signatures",
            )
        )
    else:
        signature_record = signatures[0]
        if not isinstance(signature_record, Mapping):
            findings.append(
                SupplyChainFinding(
                    "DSSE_SIGNATURE_RECORD_INVALID",
                    "critical",
                    "DSSE signature record must be an object.",
                    "signatures[0]",
                )
            )
        else:
            key_id = signature_record.get("keyid")
            public_key_bytes = public_keys.get(str(key_id))
            expected_fingerprint = policy.allowed_key_fingerprints.get(str(key_id))
            if public_key_bytes is None or expected_fingerprint is None:
                findings.append(
                    SupplyChainFinding(
                        "SIGNING_KEY_NOT_TRUSTED",
                        "critical",
                        "Release signing key is not present in the trusted key policy.",
                        "signatures[0].keyid",
                    )
                )
            elif public_key_fingerprint(public_key_bytes) != expected_fingerprint:
                findings.append(
                    SupplyChainFinding(
                        "SIGNING_KEY_FINGERPRINT_MISMATCH",
                        "critical",
                        "Release signing public key does not match its trusted fingerprint.",
                        "signatures[0].keyid",
                    )
                )
            else:
                try:
                    signature = _decode_base64(
                        signature_record.get("sig"),
                        "signatures[0].sig",
                    )
                    Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                        signature,
                        dsse_pae(str(payload_type), payload),
                    )
                    signature_verified = True
                except (ProvenanceVerificationError, ValueError, InvalidSignature):
                    findings.append(
                        SupplyChainFinding(
                            "SIGNATURE_VERIFICATION_FAILED",
                            "critical",
                            "DSSE provenance signature verification failed.",
                            "signatures[0].sig",
                        )
                    )

    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_STATEMENT_INVALID_JSON",
                "critical",
                "Signed provenance payload is not valid UTF-8 JSON.",
                "payload",
            )
        )
        return ProvenanceVerification(False, signature_verified, None, tuple(findings))

    if not isinstance(decoded, Mapping):
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_STATEMENT_NOT_OBJECT",
                "critical",
                "Signed provenance statement must be a JSON object.",
                "payload",
            )
        )
        return ProvenanceVerification(False, signature_verified, None, tuple(findings))

    statement = decoded
    if statement.get("_type") != policy.statement_type:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_STATEMENT_TYPE_MISMATCH",
                "critical",
                "Provenance statement is not an in-toto Statement v1.",
                "_type",
            )
        )
    if statement.get("predicateType") != policy.predicate_type:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_PREDICATE_TYPE_MISMATCH",
                "critical",
                "Provenance predicate type does not match policy.",
                "predicateType",
            )
        )

    actual_subject_sha256 = _subject_digest(statement, expected_subject_name)
    if actual_subject_sha256 != expected_subject_sha256:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_SUBJECT_DIGEST_MISMATCH",
                "critical",
                "Provenance subject does not bind the expected artifact digest.",
                "subject",
            )
        )

    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_PREDICATE_MISSING",
                "critical",
                "SLSA provenance predicate is required.",
                "predicate",
            )
        )
        return ProvenanceVerification(False, signature_verified, statement, tuple(findings))

    build_definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if not isinstance(build_definition, Mapping):
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_BUILD_DEFINITION_MISSING",
                "critical",
                "SLSA buildDefinition is required.",
                "predicate.buildDefinition",
            )
        )
        build_definition = {}
    if not isinstance(run_details, Mapping):
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_RUN_DETAILS_MISSING",
                "critical",
                "SLSA runDetails is required.",
                "predicate.runDetails",
            )
        )
        run_details = {}

    build_type = build_definition.get("buildType")
    if build_type not in policy.allowed_build_types:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_BUILD_TYPE_NOT_ALLOWED",
                "critical",
                "Build type is not allowlisted.",
                "predicate.buildDefinition.buildType",
            )
        )

    internal_parameters = build_definition.get("internalParameters")
    if not isinstance(internal_parameters, Mapping):
        internal_parameters = {}
    if policy.require_network_disabled and internal_parameters.get("networkDisabled") is not True:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_NETWORK_POLICY_VIOLATION",
                "critical",
                "Provenance does not prove network-disabled build execution.",
                "predicate.buildDefinition.internalParameters.networkDisabled",
            )
        )

    resolved_dependencies = build_definition.get("resolvedDependencies")
    matched_source = False
    if isinstance(resolved_dependencies, list):
        for material in resolved_dependencies:
            if not isinstance(material, Mapping):
                continue
            if material.get("uri") != policy.expected_source_uri:
                continue
            digest = material.get("digest")
            annotations = material.get("annotations")
            revision = (
                annotations.get("revision")
                if isinstance(annotations, Mapping)
                else None
            )
            if (
                isinstance(digest, Mapping)
                and digest.get("sha256") == policy.expected_source_digest
                and revision == policy.expected_source_revision
            ):
                matched_source = True
                break
    if not matched_source:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_SOURCE_BINDING_MISMATCH",
                "critical",
                "Resolved source material does not match the authorized source URI, revision, and digest.",
                "predicate.buildDefinition.resolvedDependencies",
            )
        )

    builder = run_details.get("builder")
    builder_id = builder.get("id") if isinstance(builder, Mapping) else None
    if builder_id not in policy.allowed_builder_ids:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_BUILDER_NOT_ALLOWED",
                "critical",
                "Builder identity is not allowlisted.",
                "predicate.runDetails.builder.id",
            )
        )

    metadata = run_details.get("metadata")
    if not isinstance(metadata, Mapping):
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_RUN_METADATA_MISSING",
                "critical",
                "Build run metadata is required.",
                "predicate.runDetails.metadata",
            )
        )
        metadata = {}

    invocation_id = metadata.get("invocationId")
    if not isinstance(invocation_id, str) or not invocation_id:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_INVOCATION_ID_MISSING",
                "critical",
                "Unique build invocation identity is required.",
                "predicate.runDetails.metadata.invocationId",
            )
        )

    started = _parse_timestamp(metadata.get("startedOn"), "startedOn")
    finished = _parse_timestamp(metadata.get("finishedOn"), "finishedOn")
    if started is None or finished is None or finished < started:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_TIME_RANGE_INVALID",
                "critical",
                "Build timestamps are missing, malformed, or reversed.",
                "predicate.runDetails.metadata",
            )
        )

    completeness = metadata.get("completeness")
    if not isinstance(completeness, Mapping):
        completeness = {}
    completeness_requirements = (
        ("materials", policy.require_material_completeness),
        ("parameters", policy.require_parameter_completeness),
        ("environment", policy.require_environment_completeness),
    )
    for name, required in completeness_requirements:
        if required and completeness.get(name) is not True:
            findings.append(
                SupplyChainFinding(
                    "PROVENANCE_COMPLETENESS_FAILURE",
                    "critical",
                    f"Provenance completeness flag {name!r} is not true.",
                    f"predicate.runDetails.metadata.completeness.{name}",
                )
            )

    if policy.require_reproducible and metadata.get("reproducible") is not True:
        findings.append(
            SupplyChainFinding(
                "PROVENANCE_REPRODUCIBILITY_NOT_ASSERTED",
                "critical",
                "Provenance does not assert reproducible output.",
                "predicate.runDetails.metadata.reproducible",
            )
        )

    return ProvenanceVerification(
        passed=signature_verified and not findings,
        signature_verified=signature_verified,
        statement=statement,
        findings=tuple(findings),
    )

from __future__ import annotations

import base64
import copy
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.governance.provenance_verifier import (
    ProvenancePolicy,
    build_dsse_envelope,
    verify_dsse_provenance,
)


def fixture():
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = "KEY-1"
    policy = ProvenancePolicy(
        allowed_builder_ids=frozenset({"urn:builder:1"}),
        allowed_build_types=frozenset({"urn:build:1"}),
        allowed_key_fingerprints={key_id: hashlib.sha256(public).hexdigest()},
        expected_source_uri="git+https://example.invalid/repo",
        expected_source_revision="a" * 40,
        expected_source_digest="b" * 64,
    )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.whl", "digest": {"sha256": "c" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "urn:build:1",
                "externalParameters": {},
                "internalParameters": {"networkDisabled": True},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://example.invalid/repo",
                        "digest": {"sha256": "b" * 64},
                        "annotations": {"revision": "a" * 40},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": "urn:builder:1"},
                "metadata": {
                    "invocationId": "inv-1",
                    "startedOn": "2026-07-15T11:00:00Z",
                    "finishedOn": "2026-07-15T11:01:00Z",
                    "completeness": {"parameters": True, "environment": True, "materials": True},
                    "reproducible": True,
                },
            },
        },
    }
    envelope = build_dsse_envelope(statement, key_id=key_id, signer=private)
    return private, public, key_id, policy, statement, envelope


def test_valid_dsse_provenance_passes() -> None:
    _, public, key_id, policy, _, envelope = fixture()
    result = verify_dsse_provenance(
        envelope,
        public_keys={key_id: public},
        policy=policy,
        expected_subject_name="artifact.whl",
        expected_subject_sha256="c" * 64,
    )
    assert result.passed is True
    assert result.signature_verified is True


def test_signature_tamper_fails() -> None:
    _, public, key_id, policy, _, envelope = fixture()
    raw = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    raw[0] ^= 1
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(raw)).decode()
    result = verify_dsse_provenance(
        envelope,
        public_keys={key_id: public},
        policy=policy,
        expected_subject_name="artifact.whl",
        expected_subject_sha256="c" * 64,
    )
    assert "SIGNATURE_VERIFICATION_FAILED" in {x.code for x in result.findings}


def test_untrusted_key_fails() -> None:
    _, public, _, policy, _, envelope = fixture()
    envelope["signatures"][0]["keyid"] = "UNKNOWN"
    result = verify_dsse_provenance(
        envelope,
        public_keys={"KEY-1": public},
        policy=policy,
        expected_subject_name="artifact.whl",
        expected_subject_sha256="c" * 64,
    )
    assert "SIGNING_KEY_NOT_TRUSTED" in {x.code for x in result.findings}


def test_builder_and_subject_mismatch_fail() -> None:
    private, public, key_id, policy, statement, _ = fixture()
    changed = copy.deepcopy(statement)
    changed["subject"][0]["digest"]["sha256"] = "d" * 64
    changed["predicate"]["runDetails"]["builder"]["id"] = "urn:evil"
    envelope = build_dsse_envelope(changed, key_id=key_id, signer=private)
    result = verify_dsse_provenance(
        envelope,
        public_keys={key_id: public},
        policy=policy,
        expected_subject_name="artifact.whl",
        expected_subject_sha256="c" * 64,
    )
    codes = {x.code for x in result.findings}
    assert "PROVENANCE_SUBJECT_DIGEST_MISMATCH" in codes
    assert "PROVENANCE_BUILDER_NOT_ALLOWED" in codes


def test_source_binding_mismatch_fails() -> None:
    private, public, key_id, policy, statement, _ = fixture()
    statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["sha256"] = "e" * 64
    envelope = build_dsse_envelope(statement, key_id=key_id, signer=private)
    result = verify_dsse_provenance(
        envelope,
        public_keys={key_id: public},
        policy=policy,
        expected_subject_name="artifact.whl",
        expected_subject_sha256="c" * 64,
    )
    assert "PROVENANCE_SOURCE_BINDING_MISMATCH" in {x.code for x in result.findings}

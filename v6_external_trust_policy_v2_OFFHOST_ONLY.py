"""V6 External Trust Identity Policy V2 — OFFHOST policy precheck only.

This module deliberately DOES NOT perform Sigstore, Rekor, OIDC JWT, or drand BLS
cryptographic verification. It validates the *shape and binding policy* that a future
pinned cryptographic verifier must satisfy.

A PASS from this module is never a production-trust PASS and never increments Native 0/6.
"""

from __future__ import annotations
import hashlib
import json
import re
from typing import Any, Mapping

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._:/@+-]{1,256}$")
DRAND_CHAIN = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MAX_CHALLENGE_AGE_SECONDS = 120

class V2PolicyBlocked(ValueError):
    pass

def _deny(reason: str):
    raise V2PolicyBlocked(reason)

def _sha(s: Any, reason: str):
    if type(s) is not str or HEX64.fullmatch(s) is None:
        _deny(reason)

def _safe(s: Any, reason: str):
    if type(s) is not str or SAFE_ID.fullmatch(s) is None:
        _deny(reason)

def strict_json(raw: bytes, max_bytes: int = 65536) -> dict:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes or raw.startswith(b"\xef\xbb\xbf"):
        _deny("JSON_BYTES_INVALID")
    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d:
                _deny("DUPLICATE_JSON_KEY")
            d[k] = v
        return d
    try:
        obj = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _x: _deny("NONFINITE_NUMBER"),
        )
    except V2PolicyBlocked:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _deny("JSON_INVALID")
    if type(obj) is not dict:
        _deny("JSON_OBJECT_REQUIRED")
    return obj

def canonical_json_bytes(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(
        obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")

PUBLIC_ENVELOPE_FIELDS = {
    "schema", "raw_evidence_sha256", "drand_chain_hash", "drand_round",
    "drand_randomness", "observer_build_sha256", "subject_boot_identity_sha256",
    "subject_process_creation_id", "formal_gate_claims", "github_run_invocation_uri",
}
TRUST_FIELDS = {
    "schema", "oidc_issuer", "repository_id", "repository_owner_id",
    "repository_visibility", "runner_environment", "workflow_sha",
    "job_workflow_sha", "workflow_ref", "run_id", "run_number", "run_attempt",
}
CRYPTO_FIELDS = {
    "schema", "drand_bls_verified", "drand_chain_info_verified",
    "sigstore_bundle_verified", "fulcio_chain_verified", "rekor_inclusion_verified",
    "rekor_signed_entry_timestamp_verified", "sigstore_tuf_root_verified",
    "certificate_identity_exact", "certificate_oidc_issuer_exact",
    "artifact_digest_bound", "raw_tool_output_sha256",
}
WORKFLOW_FIELDS = {
    "schema", "repository_visibility", "runner_environment", "permissions",
    "dependency_mode", "workflow_commit_sha256", "workflow_file_sha256",
    "third_party_actions_fully_pinned", "secrets_required",
    "raw_evidence_uploaded", "paid_runner_allowed",
}

FORMAL_GATES = (
    "ALL_WRITERS_FENCED",
    "EXACT_JOBOBJECT_DESCENDANTS",
    "FINITE_NATIVE_ACK_WAIT",
    "KERNEL_BYTE_RANGE_LOCK_OWNER",
    "LOADED_EXECUTING_CODE",
    "OOB_PREVIOUS_GOOD_RECOVERY",
)

def verify_policy_precheck(*, envelope_raw: bytes, trust_raw: bytes,
                           crypto_raw: bytes, workflow_raw: bytes,
                           observed_challenge_age_seconds: int,
                           prior_accepted_drand_round: int | None = None) -> dict:
    e = strict_json(envelope_raw)
    t = strict_json(trust_raw)
    c = strict_json(crypto_raw)
    w = strict_json(workflow_raw)

    if set(e) != PUBLIC_ENVELOPE_FIELDS:
        _deny("ENVELOPE_FIELDS_MISMATCH")
    if set(t) != TRUST_FIELDS:
        _deny("TRUST_FIELDS_MISMATCH")
    if set(c) != CRYPTO_FIELDS:
        _deny("CRYPTO_FIELDS_MISMATCH")
    if set(w) != WORKFLOW_FIELDS:
        _deny("WORKFLOW_FIELDS_MISMATCH")

    if e["schema"] != "V6_EXTERNAL_TRUST_ENVELOPE_V2":
        _deny("ENVELOPE_SCHEMA")
    if t["schema"] != "V6_EXTERNAL_TRUST_GITHUB_IDENTITY_V2":
        _deny("TRUST_SCHEMA")
    if c["schema"] != "V6_EXTERNAL_TRUST_CRYPTO_RESULT_V2":
        _deny("CRYPTO_SCHEMA")
    if w["schema"] != "V6_EXTERNAL_TRUST_WORKFLOW_CONTRACT_V2":
        _deny("WORKFLOW_SCHEMA")

    for key in ("raw_evidence_sha256", "observer_build_sha256", "subject_boot_identity_sha256"):
        _sha(e[key], "ENVELOPE_SHA_INVALID")
    if e["drand_chain_hash"] != DRAND_CHAIN:
        _deny("DRAND_CHAIN_MISMATCH")
    if type(e["drand_round"]) is not int or e["drand_round"] <= 0:
        _deny("DRAND_ROUND_INVALID")
    _sha(e["drand_randomness"], "DRAND_RANDOMNESS_INVALID")
    _safe(e["subject_process_creation_id"], "PROCESS_CREATION_ID_INVALID")
    _safe(e["github_run_invocation_uri"], "RUN_INVOCATION_URI_INVALID")

    claims = e["formal_gate_claims"]
    if type(claims) is not dict or set(claims) != set(FORMAL_GATES):
        _deny("FORMAL_GATE_SET_MISMATCH")
    # Trust-domain proof cannot self-promote Native.
    if any(v not in ("UNPROVEN", "EVIDENCE_PRESENT_REVIEW_REQUIRED") for v in claims.values()):
        _deny("NATIVE_GATE_SELF_PROMOTION_FORBIDDEN")

    if t["oidc_issuer"] != OIDC_ISSUER:
        _deny("OIDC_ISSUER_MISMATCH")
    for key in ("repository_id", "repository_owner_id", "run_id", "run_number", "run_attempt"):
        if type(t[key]) is not str or not t[key].isdigit() or int(t[key]) <= 0:
            _deny("GITHUB_NUMERIC_ID_INVALID")
    if t["repository_visibility"] != "public":
        _deny("REPOSITORY_NOT_PUBLIC")
    if t["runner_environment"] != "github-hosted":
        _deny("RUNNER_NOT_GITHUB_HOSTED")
    _sha(t["workflow_sha"], "WORKFLOW_SHA_INVALID")
    _sha(t["job_workflow_sha"], "JOB_WORKFLOW_SHA_INVALID")
    _safe(t["workflow_ref"], "WORKFLOW_REF_INVALID")

    if type(observed_challenge_age_seconds) is not int or not (0 <= observed_challenge_age_seconds <= MAX_CHALLENGE_AGE_SECONDS):
        _deny("DRAND_CHALLENGE_STALE_OR_INVALID")
    if prior_accepted_drand_round is not None:
        if type(prior_accepted_drand_round) is not int or prior_accepted_drand_round < 0:
            _deny("PRIOR_DRAND_ROUND_INVALID")
        if e["drand_round"] <= prior_accepted_drand_round:
            _deny("DRAND_ROUND_NOT_MONOTONIC")

    required_true = (
        "drand_bls_verified", "drand_chain_info_verified", "sigstore_bundle_verified",
        "fulcio_chain_verified", "rekor_inclusion_verified",
        "rekor_signed_entry_timestamp_verified", "sigstore_tuf_root_verified",
        "certificate_identity_exact", "certificate_oidc_issuer_exact",
        "artifact_digest_bound",
    )
    if any(c[k] is not True for k in required_true):
        _deny("CRYPTO_VERIFICATION_INCOMPLETE")
    _sha(c["raw_tool_output_sha256"], "CRYPTO_RAW_OUTPUT_SHA_INVALID")

    if w["repository_visibility"] != "public" or w["runner_environment"] != "github-hosted":
        _deny("WORKFLOW_ENVIRONMENT_UNSAFE")
    if w["permissions"] != {"contents": "read", "id-token": "write"}:
        _deny("WORKFLOW_PERMISSIONS_NOT_MINIMAL")
    if w["dependency_mode"] not in ("WORKFLOW_DEPENDENCY_LOCKFILE", "FULL_COMMIT_SHA_ONLY"):
        _deny("WORKFLOW_DEPENDENCY_MODE_UNSAFE")
    _sha(w["workflow_commit_sha256"], "WORKFLOW_COMMIT_INVALID")
    _sha(w["workflow_file_sha256"], "WORKFLOW_FILE_SHA_INVALID")
    if w["third_party_actions_fully_pinned"] is not True:
        _deny("UNPINNED_ACTION_DEPENDENCY")
    if w["secrets_required"] is not False:
        _deny("LONG_LIVED_SECRET_FORBIDDEN")
    if w["raw_evidence_uploaded"] is not False:
        _deny("RAW_EVIDENCE_UPLOAD_FORBIDDEN")
    if w["paid_runner_allowed"] is not False:
        _deny("PAID_RUNNER_FORBIDDEN")

    evidence_id = hashlib.sha256(canonical_json_bytes(e)).hexdigest()
    return {
        "schema": "V6_EXTERNAL_TRUST_POLICY_PRECHECK_RESULT_V2",
        "status": "POLICY_PRECHECK_PASS_NOT_CRYPTO_VERIFIED_NOT_NATIVE",
        "evidence_id": evidence_id,
        "phase_a_gates_proven": 0,
        "native_security_gates_proven": 0,
        "guard_release_allowed": False,
        "safe_job_allowed": False,
        "canonical_promotion_allowed": False,
        "external_action_authorized": False,
    }

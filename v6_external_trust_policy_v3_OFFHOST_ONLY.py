"""V6 External Trust Policy V3 — OFFHOST policy gate only.

This module validates exact GitHub/Sigstore/drand bindings for a future external
trust run. It does not perform network or cryptographic verification itself.
A PASS is not Native proof and cannot authorize Guard, Safe Job, canonical
promotion, Windows mutation, commerce, or cost.
"""
from __future__ import annotations
import hashlib, json, re
from typing import Any, Mapping

REPO="1985550705a-sketch/v6-external-trust-verifier"
REPO_ID="1469695205"
OWNER_ID="360536248"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
DISPATCH_PATH=".github/workflows/v6-external-trust-dispatch-v3.yml"
REUSABLE_PATH=".github/workflows/v6-external-trust-reusable-v3.yml"
EXPECTED_WORKFLOW_REF=f"{REPO}/{DISPATCH_PATH}@refs/heads/main"
DRAND_CHAIN="8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
DRAND_VENDOR_MANIFEST_SHA256="6002364cb465a162321099e022add5da5ff900d5d777241bc619419c7bda917b"
CHECKOUT_SHA="11bd71901bbe5b1630ceea73d27597364c9af683"
COSIGN_INSTALLER_SHA="756fe2d284c7292c4e9b62c8a28f1e5629c59532"
UPLOAD_ARTIFACT_SHA="ea165f8d65b6e75b540449e92b4886f43607fa02"
COSIGN_RELEASE="v3.1.4"
HEX64=re.compile(r"^[0-9a-f]{64}$")
HEX40=re.compile(r"^[0-9a-f]{40}$")
SAFE_PROCESS_ID=re.compile(r"^[A-Za-z0-9._:@+-]{1,192}$")
FORMAL_GATES=(
 "ALL_WRITERS_FENCED","EXACT_JOBOBJECT_DESCENDANTS","FINITE_NATIVE_ACK_WAIT",
 "KERNEL_BYTE_RANGE_LOCK_OWNER","LOADED_EXECUTING_CODE","OOB_PREVIOUS_GOOD_RECOVERY",
)
class V3PolicyBlocked(ValueError): pass
def deny(x): raise V3PolicyBlocked(x)
def strict_json(raw: bytes, max_bytes=131072):
    if type(raw) is not bytes or not raw or len(raw)>max_bytes or raw.startswith(b"\xef\xbb\xbf"): deny("JSON_BYTES_INVALID")
    def pairs(ps):
        d={}
        for k,v in ps:
            if k in d: deny("DUPLICATE_JSON_KEY")
            d[k]=v
        return d
    try:
        x=json.loads(raw.decode("utf-8"),object_pairs_hook=pairs,parse_constant=lambda _x: deny("NONFINITE_NUMBER"))
    except V3PolicyBlocked: raise
    except Exception: deny("JSON_INVALID")
    if type(x) is not dict: deny("JSON_OBJECT_REQUIRED")
    return x
def canon(o: Mapping[str,Any])->bytes:
    return json.dumps(o,ensure_ascii=True,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
def h64(v,why):
    if type(v) is not str or HEX64.fullmatch(v) is None: deny(why)
def h40(v,why):
    if type(v) is not str or HEX40.fullmatch(v) is None: deny(why)

E_FIELDS={"schema","raw_evidence_sha256","drand_chain_hash","drand_round","drand_randomness","observer_build_sha256","subject_boot_identity_sha256","subject_process_creation_id","formal_gate_claims","github_run_invocation_uri"}
T_FIELDS={"schema","oidc_issuer","repository","repository_id","repository_owner_id","repository_visibility","runner_environment","event_name","ref","sha","workflow_ref","workflow_sha","job_workflow_ref","job_workflow_sha","run_id","run_number","run_attempt","certificate_identity"}
C_FIELDS={"schema","cosign_version","cosign_verify_exit_code","sigstore_bundle_verified","fulcio_chain_verified","rekor_inclusion_verified","rekor_signed_entry_timestamp_verified","sigstore_tuf_root_verified","certificate_identity_exact","certificate_oidc_issuer_exact","certificate_github_workflow_repository_exact","certificate_github_workflow_ref_exact","certificate_github_workflow_sha_exact","certificate_github_workflow_trigger_exact","artifact_digest_bound","envelope_sha256","sigstore_bundle_sha256","raw_tool_output_sha256"}
W_FIELDS={"schema","permissions","dependency_mode","checkout_action_sha","cosign_installer_action_sha","upload_artifact_action_sha","cosign_release","drand_vendor_manifest_sha256","secrets_required","raw_evidence_uploaded","paid_runner_allowed","reusable_call_pinned_to_full_sha"}

def verify_policy_v3(*, envelope_raw:bytes, trust_raw:bytes, crypto_raw:bytes, workflow_raw:bytes,
                     observed_challenge_age_seconds:int, prior_accepted_drand_round:int|None=None):
    e,t,c,w=(strict_json(envelope_raw),strict_json(trust_raw),strict_json(crypto_raw),strict_json(workflow_raw))
    if set(e)!=E_FIELDS: deny("ENVELOPE_FIELDS")
    if set(t)!=T_FIELDS: deny("TRUST_FIELDS")
    if set(c)!=C_FIELDS: deny("CRYPTO_FIELDS")
    if set(w)!=W_FIELDS: deny("WORKFLOW_FIELDS")
    if e["schema"]!="V6_EXTERNAL_TRUST_ENVELOPE_V3": deny("ENVELOPE_SCHEMA")
    if t["schema"]!="V6_EXTERNAL_TRUST_GITHUB_IDENTITY_V3": deny("TRUST_SCHEMA")
    if c["schema"]!="V6_EXTERNAL_TRUST_CRYPTO_RESULT_V3": deny("CRYPTO_SCHEMA")
    if w["schema"]!="V6_EXTERNAL_TRUST_WORKFLOW_CONTRACT_V3": deny("WORKFLOW_SCHEMA")

    for k in ("raw_evidence_sha256","observer_build_sha256","subject_boot_identity_sha256"): h64(e[k],"ENVELOPE_SHA")
    if e["drand_chain_hash"]!=DRAND_CHAIN: deny("DRAND_CHAIN")
    if type(e["drand_round"]) is not int or e["drand_round"]<=0: deny("DRAND_ROUND")
    h64(e["drand_randomness"],"DRAND_RANDOMNESS")
    if type(e["subject_process_creation_id"]) is not str or SAFE_PROCESS_ID.fullmatch(e["subject_process_creation_id"]) is None: deny("PROCESS_ID")
    if e["github_run_invocation_uri"] != f"https://github.com/{REPO}/actions/runs/{t['run_id']}/attempts/{t['run_attempt']}": deny("RUN_URI_BINDING")
    claims=e["formal_gate_claims"]
    if type(claims) is not dict or set(claims)!=set(FORMAL_GATES): deny("FORMAL_GATE_SET")
    if any(v not in ("UNPROVEN","EVIDENCE_PRESENT_REVIEW_REQUIRED") for v in claims.values()): deny("NATIVE_SELF_PROMOTION")

    if t["oidc_issuer"]!=OIDC_ISSUER or t["repository"]!=REPO or t["repository_id"]!=REPO_ID or t["repository_owner_id"]!=OWNER_ID: deny("GITHUB_IDENTITY")
    if t["repository_visibility"]!="public" or t["runner_environment"]!="github-hosted": deny("GITHUB_ENVIRONMENT")
    if t["event_name"]!="workflow_dispatch" or t["ref"]!="refs/heads/main": deny("GITHUB_TRIGGER")
    h40(t["sha"],"GITHUB_SHA")
    if t["workflow_ref"]!=EXPECTED_WORKFLOW_REF: deny("CALLER_WORKFLOW_REF")
    h40(t["workflow_sha"],"CALLER_WORKFLOW_SHA")
    expected_prefix=f"{REPO}/{REUSABLE_PATH}@"
    if type(t["job_workflow_ref"]) is not str or not t["job_workflow_ref"].startswith(expected_prefix): deny("JOB_WORKFLOW_REF")
    pinned=t["job_workflow_ref"][len(expected_prefix):]
    h40(pinned,"JOB_WORKFLOW_PIN")
    h40(t["job_workflow_sha"],"JOB_WORKFLOW_SHA")
    if pinned!=t["job_workflow_sha"]: deny("JOB_WORKFLOW_SHA_BINDING")
    if t["certificate_identity"]!="https://github.com/"+t["job_workflow_ref"]: deny("CERT_IDENTITY_BINDING")
    for k in ("run_id","run_number","run_attempt"):
        if type(t[k]) is not str or not t[k].isdigit() or int(t[k])<=0: deny("RUN_NUMERIC_ID")

    if type(observed_challenge_age_seconds) is not int or not 0<=observed_challenge_age_seconds<=120: deny("CHALLENGE_AGE")
    if prior_accepted_drand_round is not None:
        if type(prior_accepted_drand_round) is not int or prior_accepted_drand_round<0 or e["drand_round"]<=prior_accepted_drand_round: deny("DRAND_REPLAY")

    if c["cosign_version"]!=COSIGN_RELEASE or c["cosign_verify_exit_code"]!=0: deny("COSIGN_RESULT")
    for k in ("sigstore_bundle_verified","fulcio_chain_verified","rekor_inclusion_verified","rekor_signed_entry_timestamp_verified","sigstore_tuf_root_verified",
              "certificate_identity_exact","certificate_oidc_issuer_exact","certificate_github_workflow_repository_exact","certificate_github_workflow_ref_exact",
              "certificate_github_workflow_sha_exact","certificate_github_workflow_trigger_exact","artifact_digest_bound"):
        if c[k] is not True: deny("CRYPTO_INCOMPLETE")
    h64(c["envelope_sha256"],"ENVELOPE_SHA_BINDING")
    h64(c["sigstore_bundle_sha256"],"BUNDLE_SHA")
    h64(c["raw_tool_output_sha256"],"COSIGN_OUTPUT_SHA")

    if w["permissions"]!={"contents":"read","id-token":"write"}: deny("PERMISSIONS")
    if w["dependency_mode"]!="FULL_COMMIT_SHA_ONLY": deny("DEPENDENCY_MODE")
    if w["checkout_action_sha"]!=CHECKOUT_SHA or w["cosign_installer_action_sha"]!=COSIGN_INSTALLER_SHA or w["upload_artifact_action_sha"]!=UPLOAD_ARTIFACT_SHA: deny("ACTION_PIN")
    if w["cosign_release"]!=COSIGN_RELEASE or w["drand_vendor_manifest_sha256"]!=DRAND_VENDOR_MANIFEST_SHA256: deny("DEPENDENCY_BINDING")
    if w["secrets_required"] is not False or w["raw_evidence_uploaded"] is not False or w["paid_runner_allowed"] is not False or w["reusable_call_pinned_to_full_sha"] is not True: deny("WORKFLOW_SAFETY")

    eid=hashlib.sha256(canon({"e":e,"t":t,"c":c,"w":w})).hexdigest()
    return {"schema":"V6_EXTERNAL_TRUST_POLICY_PRECHECK_RESULT_V3","status":"POLICY_PRECHECK_PASS_NOT_NATIVE","evidence_id":eid,
            "phase_a_gates_proven":0,"native_security_gates_proven":0,"guard_release_allowed":False,"safe_job_allowed":False,
            "canonical_promotion_allowed":False,"external_action_authorized":False}

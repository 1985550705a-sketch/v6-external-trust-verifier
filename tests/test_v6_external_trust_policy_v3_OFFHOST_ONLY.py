import json, unittest
from v6_external_trust_policy_v3_OFFHOST_ONLY import *

def raw(x): return json.dumps(x,sort_keys=True,separators=(",",":")).encode()
def valid():
    jobsha="1"*40
    t={"schema":"V6_EXTERNAL_TRUST_GITHUB_IDENTITY_V3","oidc_issuer":OIDC_ISSUER,"repository":REPO,"repository_id":REPO_ID,"repository_owner_id":OWNER_ID,
       "repository_visibility":"public","runner_environment":"github-hosted","event_name":"workflow_dispatch","ref":"refs/heads/main","sha":"4"*40,"workflow_ref":EXPECTED_WORKFLOW_REF,
       "workflow_sha":"2"*40,"job_workflow_ref":f"{REPO}/{REUSABLE_PATH}@{jobsha}","job_workflow_sha":jobsha,"run_id":"3003","run_number":"7","run_attempt":"1",
       "certificate_identity":f"https://github.com/{REPO}/{REUSABLE_PATH}@{jobsha}"}
    e={"schema":"V6_EXTERNAL_TRUST_ENVELOPE_V3","raw_evidence_sha256":"a"*64,"drand_chain_hash":DRAND_CHAIN,"drand_round":123456,"drand_randomness":"b"*64,
       "observer_build_sha256":"c"*64,"subject_boot_identity_sha256":"d"*64,"subject_process_creation_id":"pid-1234-created-20261124T041300Z",
       "formal_gate_claims":{g:"UNPROVEN" for g in FORMAL_GATES},"github_run_invocation_uri":f"https://github.com/{REPO}/actions/runs/3003/attempts/1"}
    c={"schema":"V6_EXTERNAL_TRUST_CRYPTO_RESULT_V3","cosign_version":COSIGN_RELEASE,"cosign_verify_exit_code":0,"sigstore_bundle_verified":True,
       "fulcio_chain_verified":True,"rekor_inclusion_verified":True,"rekor_signed_entry_timestamp_verified":True,"sigstore_tuf_root_verified":True,
       "certificate_identity_exact":True,"certificate_oidc_issuer_exact":True,"certificate_github_workflow_repository_exact":True,
       "certificate_github_workflow_ref_exact":True,"certificate_github_workflow_sha_exact":True,"certificate_github_workflow_trigger_exact":True,
       "artifact_digest_bound":True,"envelope_sha256":hashlib.sha256(raw(e)).hexdigest(),"sigstore_bundle_sha256":"1"*64,"raw_tool_output_sha256":"e"*64}
    w={"schema":"V6_EXTERNAL_TRUST_WORKFLOW_CONTRACT_V3","permissions":{"contents":"read","id-token":"write"},"dependency_mode":"FULL_COMMIT_SHA_ONLY",
       "checkout_action_sha":CHECKOUT_SHA,"cosign_installer_action_sha":COSIGN_INSTALLER_SHA,"upload_artifact_action_sha":UPLOAD_ARTIFACT_SHA,
       "cosign_release":COSIGN_RELEASE,"drand_vendor_manifest_sha256":DRAND_VENDOR_MANIFEST_SHA256,"secrets_required":False,"raw_evidence_uploaded":False,
       "paid_runner_allowed":False,"reusable_call_pinned_to_full_sha":True}
    return e,t,c,w

class T(unittest.TestCase):
    def ok(self,e,t,c,w,age=10,prior=123455): return verify_policy_v3(envelope_raw=raw(e),trust_raw=raw(t),crypto_raw=raw(c),workflow_raw=raw(w),observed_challenge_age_seconds=age,prior_accepted_drand_round=prior)
    def block(self,mut):
        e,t,c,w=valid(); mut(e,t,c,w)
        with self.assertRaises(V3PolicyBlocked): self.ok(e,t,c,w)
    def test_positive(self):
        e,t,c,w=valid(); r=self.ok(e,t,c,w); self.assertEqual(r["status"],"POLICY_PRECHECK_PASS_NOT_NATIVE"); self.assertEqual(r["native_security_gates_proven"],0)
    def test_repo(self): self.block(lambda e,t,c,w:t.__setitem__("repository","evil/r"))
    def test_repo_id(self): self.block(lambda e,t,c,w:t.__setitem__("repository_id","1"))
    def test_owner_id(self): self.block(lambda e,t,c,w:t.__setitem__("repository_owner_id","1"))
    def test_private(self): self.block(lambda e,t,c,w:t.__setitem__("repository_visibility","private"))
    def test_self_hosted(self): self.block(lambda e,t,c,w:t.__setitem__("runner_environment","self-hosted"))
    def test_push_event(self): self.block(lambda e,t,c,w:t.__setitem__("event_name","push"))
    def test_wrong_ref(self): self.block(lambda e,t,c,w:t.__setitem__("ref","refs/heads/dev"))
    def test_bad_github_sha(self): self.block(lambda e,t,c,w:t.__setitem__("sha","x"))
    def test_wrong_dispatcher(self): self.block(lambda e,t,c,w:t.__setitem__("workflow_ref","x"))
    def test_bad_caller_sha(self): self.block(lambda e,t,c,w:t.__setitem__("workflow_sha","x"))
    def test_branch_reusable_ref(self): self.block(lambda e,t,c,w:t.__setitem__("job_workflow_ref",f"{REPO}/{REUSABLE_PATH}@main"))
    def test_job_sha_mismatch(self): self.block(lambda e,t,c,w:t.__setitem__("job_workflow_sha","3"*40))
    def test_cert_identity(self): self.block(lambda e,t,c,w:t.__setitem__("certificate_identity","https://github.com/evil"))
    def test_oidc(self): self.block(lambda e,t,c,w:t.__setitem__("oidc_issuer","https://evil"))
    def test_run_uri(self): self.block(lambda e,t,c,w:e.__setitem__("github_run_invocation_uri","https://evil"))
    def test_native_self_promotion(self): self.block(lambda e,t,c,w:e["formal_gate_claims"].__setitem__(FORMAL_GATES[0],"PASS"))
    def test_missing_gate(self): self.block(lambda e,t,c,w:e["formal_gate_claims"].pop(FORMAL_GATES[0]))
    def test_stale(self):
        e,t,c,w=valid()
        with self.assertRaises(V3PolicyBlocked): self.ok(e,t,c,w,age=121)
    def test_replay(self):
        e,t,c,w=valid()
        with self.assertRaises(V3PolicyBlocked): self.ok(e,t,c,w,prior=123456)
    def test_cosign_exit(self): self.block(lambda e,t,c,w:c.__setitem__("cosign_verify_exit_code",1))
    def test_cosign_version(self): self.block(lambda e,t,c,w:c.__setitem__("cosign_version","v0"))
    def test_rekor(self): self.block(lambda e,t,c,w:c.__setitem__("rekor_inclusion_verified",False))
    def test_set(self): self.block(lambda e,t,c,w:c.__setitem__("rekor_signed_entry_timestamp_verified",False))
    def test_fulcio(self): self.block(lambda e,t,c,w:c.__setitem__("fulcio_chain_verified",False))
    def test_tuf(self): self.block(lambda e,t,c,w:c.__setitem__("sigstore_tuf_root_verified",False))
    def test_cert_repo_ext(self): self.block(lambda e,t,c,w:c.__setitem__("certificate_github_workflow_repository_exact",False))
    def test_cert_ref_ext(self): self.block(lambda e,t,c,w:c.__setitem__("certificate_github_workflow_ref_exact",False))
    def test_cert_sha_ext(self): self.block(lambda e,t,c,w:c.__setitem__("certificate_github_workflow_sha_exact",False))
    def test_cert_trigger_ext(self): self.block(lambda e,t,c,w:c.__setitem__("certificate_github_workflow_trigger_exact",False))
    def test_artifact_digest(self): self.block(lambda e,t,c,w:c.__setitem__("artifact_digest_bound",False))
    def test_permissions(self): self.block(lambda e,t,c,w:w.__setitem__("permissions",{"contents":"write","id-token":"write"}))
    def test_unpinned_checkout(self): self.block(lambda e,t,c,w:w.__setitem__("checkout_action_sha","v4"))
    def test_wrong_vendor(self): self.block(lambda e,t,c,w:w.__setitem__("drand_vendor_manifest_sha256","0"*64))
    def test_secret(self): self.block(lambda e,t,c,w:w.__setitem__("secrets_required",True))
    def test_raw_upload(self): self.block(lambda e,t,c,w:w.__setitem__("raw_evidence_uploaded",True))
    def test_paid(self): self.block(lambda e,t,c,w:w.__setitem__("paid_runner_allowed",True))
    def test_unpinned_reusable(self): self.block(lambda e,t,c,w:w.__setitem__("reusable_call_pinned_to_full_sha",False))
    def test_duplicate_json(self):
        e,t,c,w=valid()
        with self.assertRaises(V3PolicyBlocked): verify_policy_v3(envelope_raw=b'{"schema":"x","schema":"y"}',trust_raw=raw(t),crypto_raw=raw(c),workflow_raw=raw(w),observed_challenge_age_seconds=1)
    def test_bom(self):
        e,t,c,w=valid()
        with self.assertRaises(V3PolicyBlocked): verify_policy_v3(envelope_raw=b"\xef\xbb\xbf"+raw(e),trust_raw=raw(t),crypto_raw=raw(c),workflow_raw=raw(w),observed_challenge_age_seconds=1)
    def test_envelope_sha_mismatch(self): self.block(lambda e,t,c,w:c.__setitem__("envelope_sha256","0"*64))
    def test_envelope_bytes_changed(self): self.block(lambda e,t,c,w:e.__setitem__("raw_evidence_sha256","9"*64))
    def test_deterministic(self):
        e,t,c,w=valid(); self.assertEqual(self.ok(e,t,c,w)["evidence_id"],self.ok(e,t,c,w)["evidence_id"])

if __name__=="__main__": unittest.main(verbosity=2)

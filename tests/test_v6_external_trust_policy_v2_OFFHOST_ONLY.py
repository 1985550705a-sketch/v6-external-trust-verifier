import copy, json, unittest
from v6_external_trust_policy_v2_OFFHOST_ONLY import (
    verify_policy_precheck, V2PolicyBlocked, DRAND_CHAIN, OIDC_ISSUER, FORMAL_GATES
)

S64 = "a"*64
B64 = "b"*64
C64 = "c"*64
D64 = "d"*64

def raw(x): return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()

def valid():
    e = {
        "schema":"V6_EXTERNAL_TRUST_ENVELOPE_V2",
        "raw_evidence_sha256":S64,
        "drand_chain_hash":DRAND_CHAIN,
        "drand_round":123456,
        "drand_randomness":B64,
        "observer_build_sha256":C64,
        "subject_boot_identity_sha256":D64,
        "subject_process_creation_id":"pid-1234-created-20261124T041300Z",
        "formal_gate_claims":{g:"UNPROVEN" for g in FORMAL_GATES},
        "github_run_invocation_uri":"https://github.com/o/r/actions/runs/123/attempts/1",
    }
    t = {
        "schema":"V6_EXTERNAL_TRUST_GITHUB_IDENTITY_V2",
        "oidc_issuer":OIDC_ISSUER,
        "repository_id":"1001",
        "repository_owner_id":"2002",
        "repository_visibility":"public",
        "runner_environment":"github-hosted",
        "workflow_sha":"1"*64,
        "job_workflow_sha":"2"*64,
        "workflow_ref":"o/r/.github/workflows/v6-trust.yml@refs/heads/main",
        "run_id":"3003","run_number":"7","run_attempt":"1",
    }
    c = {
        "schema":"V6_EXTERNAL_TRUST_CRYPTO_RESULT_V2",
        "drand_bls_verified":True,
        "drand_chain_info_verified":True,
        "sigstore_bundle_verified":True,
        "fulcio_chain_verified":True,
        "rekor_inclusion_verified":True,
        "rekor_signed_entry_timestamp_verified":True,
        "sigstore_tuf_root_verified":True,
        "certificate_identity_exact":True,
        "certificate_oidc_issuer_exact":True,
        "artifact_digest_bound":True,
        "raw_tool_output_sha256":"3"*64,
    }
    w = {
        "schema":"V6_EXTERNAL_TRUST_WORKFLOW_CONTRACT_V2",
        "repository_visibility":"public",
        "runner_environment":"github-hosted",
        "permissions":{"contents":"read","id-token":"write"},
        "dependency_mode":"FULL_COMMIT_SHA_ONLY",
        "workflow_commit_sha256":"4"*64,
        "workflow_file_sha256":"5"*64,
        "third_party_actions_fully_pinned":True,
        "secrets_required":False,
        "raw_evidence_uploaded":False,
        "paid_runner_allowed":False,
    }
    return e,t,c,w

class T(unittest.TestCase):
    def ok(self,e,t,c,w,age=10,prior=123455):
        return verify_policy_precheck(
            envelope_raw=raw(e), trust_raw=raw(t), crypto_raw=raw(c),
            workflow_raw=raw(w), observed_challenge_age_seconds=age,
            prior_accepted_drand_round=prior)

    def blocked(self,mut):
        e,t,c,w=valid()
        mut(e,t,c,w)
        with self.assertRaises(V2PolicyBlocked):
            self.ok(e,t,c,w)

    def test_positive_review_only(self):
        e,t,c,w=valid(); r=self.ok(e,t,c,w)
        self.assertEqual(r["status"],"POLICY_PRECHECK_PASS_NOT_CRYPTO_VERIFIED_NOT_NATIVE")
        self.assertEqual(r["phase_a_gates_proven"],0)
        self.assertEqual(r["native_security_gates_proven"],0)
        self.assertFalse(r["guard_release_allowed"])

    def test_wrong_chain(self): self.blocked(lambda e,t,c,w:e.__setitem__("drand_chain_hash","0"*64))
    def test_stale(self):
        e,t,c,w=valid()
        with self.assertRaises(V2PolicyBlocked): self.ok(e,t,c,w,age=121)
    def test_negative_age(self):
        e,t,c,w=valid()
        with self.assertRaises(V2PolicyBlocked): self.ok(e,t,c,w,age=-1)
    def test_round_replay(self):
        e,t,c,w=valid()
        with self.assertRaises(V2PolicyBlocked): self.ok(e,t,c,w,prior=e["drand_round"])
    def test_round_rollback(self):
        e,t,c,w=valid()
        with self.assertRaises(V2PolicyBlocked): self.ok(e,t,c,w,prior=e["drand_round"]+1)
    def test_wrong_oidc(self): self.blocked(lambda e,t,c,w:t.__setitem__("oidc_issuer","https://evil"))
    def test_private_repo(self): self.blocked(lambda e,t,c,w:t.__setitem__("repository_visibility","private"))
    def test_self_hosted(self): self.blocked(lambda e,t,c,w:t.__setitem__("runner_environment","self-hosted"))
    def test_bad_workflow_sha(self): self.blocked(lambda e,t,c,w:t.__setitem__("workflow_sha","bad"))
    def test_bad_job_workflow_sha(self): self.blocked(lambda e,t,c,w:t.__setitem__("job_workflow_sha","bad"))
    def test_zero_repo_id(self): self.blocked(lambda e,t,c,w:t.__setitem__("repository_id","0"))
    def test_non_numeric_owner_id(self): self.blocked(lambda e,t,c,w:t.__setitem__("repository_owner_id","x"))
    def test_missing_rekor(self): self.blocked(lambda e,t,c,w:c.__setitem__("rekor_inclusion_verified",False))
    def test_missing_set(self): self.blocked(lambda e,t,c,w:c.__setitem__("rekor_signed_entry_timestamp_verified",False))
    def test_missing_tuf(self): self.blocked(lambda e,t,c,w:c.__setitem__("sigstore_tuf_root_verified",False))
    def test_missing_fulcio(self): self.blocked(lambda e,t,c,w:c.__setitem__("fulcio_chain_verified",False))
    def test_missing_drand_bls(self): self.blocked(lambda e,t,c,w:c.__setitem__("drand_bls_verified",False))
    def test_missing_chain_info(self): self.blocked(lambda e,t,c,w:c.__setitem__("drand_chain_info_verified",False))
    def test_identity_not_exact(self): self.blocked(lambda e,t,c,w:c.__setitem__("certificate_identity_exact",False))
    def test_issuer_not_exact(self): self.blocked(lambda e,t,c,w:c.__setitem__("certificate_oidc_issuer_exact",False))
    def test_digest_not_bound(self): self.blocked(lambda e,t,c,w:c.__setitem__("artifact_digest_bound",False))
    def test_extra_envelope_field(self): self.blocked(lambda e,t,c,w:e.__setitem__("raw_path","C:/secret"))
    def test_missing_gate(self): self.blocked(lambda e,t,c,w:e["formal_gate_claims"].pop(FORMAL_GATES[0]))
    def test_fake_native_pass(self): self.blocked(lambda e,t,c,w:e["formal_gate_claims"].__setitem__(FORMAL_GATES[0],"PASS"))
    def test_long_lived_secret(self): self.blocked(lambda e,t,c,w:w.__setitem__("secrets_required",True))
    def test_raw_upload(self): self.blocked(lambda e,t,c,w:w.__setitem__("raw_evidence_uploaded",True))
    def test_paid_runner(self): self.blocked(lambda e,t,c,w:w.__setitem__("paid_runner_allowed",True))
    def test_unpinned_action(self): self.blocked(lambda e,t,c,w:w.__setitem__("third_party_actions_fully_pinned",False))
    def test_bad_permissions_write_all(self): self.blocked(lambda e,t,c,w:w.__setitem__("permissions",{"contents":"write","id-token":"write"}))
    def test_bad_dependency_mode(self): self.blocked(lambda e,t,c,w:w.__setitem__("dependency_mode","TAG"))
    def test_workflow_private(self): self.blocked(lambda e,t,c,w:w.__setitem__("repository_visibility","private"))
    def test_workflow_self_hosted(self): self.blocked(lambda e,t,c,w:w.__setitem__("runner_environment","self-hosted"))
    def test_bad_raw_sha(self): self.blocked(lambda e,t,c,w:e.__setitem__("raw_evidence_sha256","A"*64))
    def test_bad_randomness(self): self.blocked(lambda e,t,c,w:e.__setitem__("drand_randomness","xyz"))
    def test_duplicate_json_key_rejected(self):
        e,t,c,w=valid()
        bad = b'{"schema":"V6_EXTERNAL_TRUST_ENVELOPE_V2","schema":"x"}'
        with self.assertRaises(V2PolicyBlocked):
            verify_policy_precheck(
                envelope_raw=bad, trust_raw=raw(t), crypto_raw=raw(c), workflow_raw=raw(w),
                observed_challenge_age_seconds=10, prior_accepted_drand_round=1)
    def test_bom_rejected(self):
        e,t,c,w=valid()
        with self.assertRaises(V2PolicyBlocked):
            verify_policy_precheck(
                envelope_raw=b"\xef\xbb\xbf"+raw(e), trust_raw=raw(t), crypto_raw=raw(c), workflow_raw=raw(w),
                observed_challenge_age_seconds=10, prior_accepted_drand_round=1)
    def test_nonfinite_rejected(self):
        e,t,c,w=valid()
        bad=raw(e).replace(b'"drand_round":123456',b'"drand_round":NaN')
        with self.assertRaises(V2PolicyBlocked):
            verify_policy_precheck(
                envelope_raw=bad, trust_raw=raw(t), crypto_raw=raw(c), workflow_raw=raw(w),
                observed_challenge_age_seconds=10, prior_accepted_drand_round=1)
    def test_evidence_id_deterministic(self):
        e,t,c,w=valid()
        a=self.ok(e,t,c,w)["evidence_id"]
        b=self.ok(e,t,c,w)["evidence_id"]
        self.assertEqual(a,b)
    def test_identical_review_claim_allowed(self):
        e,t,c,w=valid()
        e["formal_gate_claims"][FORMAL_GATES[0]]="EVIDENCE_PRESENT_REVIEW_REQUIRED"
        r=self.ok(e,t,c,w)
        self.assertEqual(r["native_security_gates_proven"],0)

if __name__=="__main__":
    unittest.main(verbosity=2)

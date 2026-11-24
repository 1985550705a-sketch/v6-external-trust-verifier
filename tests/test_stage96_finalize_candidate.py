import json, pathlib, tempfile, types, unittest, subprocess
from unittest.mock import patch
from test_v6_external_trust_policy_v3_OFFHOST_ONLY import valid,raw
from tools import stage53_runtime_v3 as rt

class FinalizeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.out=pathlib.Path(self.temp.name); self.e,self.t,self.c,self.w=valid()
        self.e['drand_randomness']=rt.sha256_bytes(bytes.fromhex('a'*192))
        self.bundle=self.out/'bundle.json'; self.bundle.write_bytes(b'{"synthetic":true}')
        for name,o in [('envelope.json',self.e),('trust.json',self.t),('workflow-contract.json',self.w)]: (self.out/name).write_bytes(raw(o))
        self.a=types.SimpleNamespace(out_dir=str(self.out),bundle=str(self.bundle),cosign_verify_output=str(self.out/'verify.log'),drand_signature='a'*192,prior_accepted_drand_round=123455)
        self.calls=[]; self.fail=None
        self.addCleanup(patch.stopall)
        patch.object(rt,'runtime_identity',return_value=self.t).start();patch.object(rt,'verify_vendor').start()
        patch.object(rt.subprocess,'run',side_effect=self.run_fake).start()
    def run_fake(self,argv,**kwargs):
        self.calls.append(argv); self.assertFalse(kwargs['shell']); self.assertTrue(kwargs['check']); self.assertEqual(kwargs['timeout'],120)
        phase=argv[1]; code=0; data=b'Verified OK\n'
        if phase.endswith('.mjs'):
            capture={'status':'PASS','round':self.e['drand_round'],'age_seconds':10,'chain_hash':rt.DRAND_CHAIN,'beacon':{'round':self.e['drand_round'],'randomness':self.e['drand_randomness'],'signature':self.a.drand_signature,'previous_signature':'b'*192}}
            if self.fail=='wrong_chain': capture['chain_hash']='0'*64
            if self.fail=='stale': capture['age_seconds']=121
            if self.fail=='missing_beacon': del capture['beacon']
            if self.fail=='wrong_beacon_round': capture['beacon']['round']+=1
            if self.fail=='wrong_beacon_signature': capture['beacon']['signature']='c'*192
            if self.fail=='wrong_previous_signature': capture['beacon']['previous_signature']='x'
            if self.fail=='extra_beacon_field': capture['beacon']['extra']=True
            data=raw(capture)
        if phase=='version': data=raw({'gitVersion':rt.COSIGN_RELEASE})
        if self.fail==phase: raise subprocess.CalledProcessError(1,argv)
        if self.fail=='timeout' and phase=='verify-blob': raise subprocess.TimeoutExpired(argv,120)
        if self.fail=='wrong_version' and phase=='version': data=raw({'gitVersion':'v0'})
        if phase=='verify-blob':
            self.assertEqual(pathlib.Path(argv[2]).read_bytes(),raw(self.e)); self.assertEqual(pathlib.Path(argv[4]).read_bytes(),self.bundle.read_bytes())
            for key,val in [('--certificate-identity',self.t['certificate_identity']),('--certificate-oidc-issuer',rt.OIDC_ISSUER),('--certificate-github-workflow-repository',rt.REPO),('--certificate-github-workflow-ref',self.t['ref']),('--certificate-github-workflow-sha',self.t['sha']),('--certificate-github-workflow-trigger',self.t['event_name'])]: self.assertEqual(argv[argv.index(key)+1],val)
            if self.fail=='mutate_snapshot': pathlib.Path(argv[2]).write_bytes(b'bad')
            if self.fail=='mutate_source': self.bundle.write_bytes(b'bad')
            if self.fail=='empty_log': data=b''
        return subprocess.CompletedProcess(argv,code,data,b'')
    def rejected(self,reason):
        with self.assertRaisesRegex(SystemExit,reason): rt.cmd_finalize(self.a)
        self.assertFalse((self.out/'policy-result.json').exists())
    def test_valid_mocked_verifier(self):
        rt.cmd_finalize(self.a); self.assertEqual(len(self.calls),3)
        p=json.loads((self.out/'policy-result.json').read_bytes()); self.assertEqual(p['native_security_gates_proven'],0); self.assertFalse(p['external_action_authorized'])
        c=json.loads((self.out/'crypto.json').read_bytes()); self.assertEqual(c['envelope_sha256'],rt.sha256_bytes(raw(self.e))); self.assertEqual(c['sigstore_bundle_sha256'],rt.sha256_file(self.bundle)); self.assertEqual(c['raw_tool_output_sha256'],rt.sha256_file(self.out/'verify.log')); self.assertEqual(json.loads((self.out/'drand-finalize-verify.json').read_bytes())['round'],self.e['drand_round'])
    def test_finalize_elapsed_limit(self):
        with patch.object(rt.time,'monotonic',side_effect=[100,209]):
            rt.cmd_finalize(self.a)
        d=json.loads((self.out/'finalize-timing.json').read_bytes()); self.assertEqual(d['conservative_age_seconds'],120); self.assertFalse(d['production_authority'])
    def test_finalize_elapsed_expired(self):
        with patch.object(rt.time,'monotonic',side_effect=[100,209.01]): self.rejected('FINALIZE_FRESHNESS_EXPIRED')
    def test_finalize_clock_rollback(self):
        with patch.object(rt.time,'monotonic',side_effect=[100,99]): self.rejected('FINALIZE_CLOCK_INVALID')
    def test_finalize_clock_nan(self):
        with patch.object(rt.time,'monotonic',side_effect=[100,float('nan')]): self.rejected('FINALIZE_CLOCK_INVALID')
    def test_timing_output_reuse(self):
        (self.out/'finalize-timing.json').write_text('PASS'); self.rejected('OUTPUT_ALREADY_EXISTS'); self.assertEqual(self.calls,[])
    def test_forged_old_log(self): (self.out/'verify.log').write_text('PASS'); self.rejected('OUTPUT_ALREADY_EXISTS'); self.assertEqual(self.calls,[])
    def test_cosign_failure(self): self.fail='verify-blob'; self.rejected('VERIFIER_EXECUTION_FAILED')
    def test_drand_failure(self): self.fail='tools/stage98_drand_evidence.mjs'; self.rejected('VERIFIER_EXECUTION_FAILED')
    def test_timeout(self): self.fail='timeout'; self.rejected('VERIFIER_EXECUTION_FAILED')
    def test_wrong_version(self): self.fail='wrong_version'; self.rejected('COSIGN_VERSION')
    def test_wrong_chain(self): self.fail='wrong_chain'; self.rejected('DRAND_RESULT')
    def test_stale(self): self.fail='stale'; self.rejected('DRAND_AGE')
    def test_snapshot_mutation(self): self.fail='mutate_snapshot'; self.rejected('VERIFY_INPUT_CHANGED')
    def test_source_mutation(self): self.fail='mutate_source'; self.rejected('SOURCE_INPUT_CHANGED')
    def test_empty_log(self): self.fail='empty_log'; self.rejected('VERIFIER_OUTPUT_EMPTY')
    def test_identity_mismatch(self): rt.runtime_identity.return_value={}; self.rejected('FINALIZE_RUNTIME_IDENTITY_MISMATCH'); self.assertEqual(self.calls,[])
    def test_replay(self): self.a.prior_accepted_drand_round=self.e['drand_round']; self.rejected('DRAND_REPLAY')
    def test_missing_bundle(self): self.bundle.unlink(); self.rejected('INPUT_NOT_REGULAR_FILE')
    def test_symlink_bundle(self): self.bundle.unlink(); self.bundle.symlink_to(self.out/'envelope.json'); self.rejected('INPUT_NOT_REGULAR_FILE')
    def test_bad_signature_format(self): self.a.drand_signature='x'; self.rejected('DRAND_SIGNATURE')
    def test_stale_crypto(self): (self.out/'crypto.json').write_text('PASS'); self.rejected('OUTPUT_ALREADY_EXISTS')
    def test_evidence_readback(self):
        rt.cmd_finalize(self.a)
        d=json.loads((self.out/'drand-beacon-evidence.json').read_bytes())
        self.assertEqual(d['beacon']['signature'],self.a.drand_signature)
        self.assertEqual(d['beacon']['previous_signature'],'b'*192)
        self.assertEqual(d['envelope_sha256'],rt.sha256_file(self.out/'envelope.json'))
        self.assertEqual(d['sigstore_bundle_sha256'],rt.sha256_file(self.bundle))
        self.assertFalse(d['production_authority'])
        self.assertEqual(d['verifier_output_sha256'],rt.sha256_file(self.out/'drand-finalize-capture.json'))
    def test_missing_beacon(self): self.fail='missing_beacon'; self.rejected('DRAND_EVIDENCE_FIELDS')
    def test_wrong_beacon_round(self): self.fail='wrong_beacon_round'; self.rejected('DRAND_EVIDENCE_BINDING')
    def test_wrong_beacon_signature(self): self.fail='wrong_beacon_signature'; self.rejected('DRAND_EVIDENCE_BINDING')
    def test_wrong_previous_signature(self): self.fail='wrong_previous_signature'; self.rejected('DRAND_EVIDENCE_PREVIOUS_SIGNATURE')
    def test_extra_beacon_field(self): self.fail='extra_beacon_field'; self.rejected('DRAND_EVIDENCE_FIELDS')
    def test_randomness_hash(self):
        self.e['drand_randomness']='0'*64; (self.out/'envelope.json').write_bytes(raw(self.e)); self.rejected('DRAND_EVIDENCE_RANDOMNESS_HASH')
    def test_old_beacon_evidence(self): (self.out/'drand-beacon-evidence.json').write_text('PASS'); self.rejected('OUTPUT_ALREADY_EXISTS'); self.assertEqual(self.calls,[])
    def test_old_capture_output(self): (self.out/'drand-finalize-capture.json').write_text('PASS'); self.rejected('OUTPUT_ALREADY_EXISTS'); self.assertEqual(self.calls,[])

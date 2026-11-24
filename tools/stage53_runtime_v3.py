from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, sys, subprocess, tempfile, math, time

REPO="1985550705a-sketch/v6-external-trust-verifier"
REPO_ID="1469695205"
OWNER_ID="360536248"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
DISPATCH_PATH=".github/workflows/v6-external-trust-dispatch-v3.yml"
REUSABLE_PATH=".github/workflows/v6-external-trust-reusable-v3.yml"
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

def die(x): raise SystemExit(x)
def sha256_bytes(b:bytes)->str: return hashlib.sha256(b).hexdigest()
def sha256_file(p:pathlib.Path)->str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()
def write_json(p:pathlib.Path,o):
    p.write_text(json.dumps(o,ensure_ascii=True,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n",encoding="utf-8")
def need64(x,n):
    if not HEX64.fullmatch(x or ""): die(n)
def need40(x,n):
    if not HEX40.fullmatch(x or ""): die(n)
def env(n):
    v=os.environ.get(n)
    if not v: die("ENV_"+n)
    return v

def verify_vendor():
    mpath=pathlib.Path("vendor/drand/V6_VENDOR_MANIFEST.json")
    if not mpath.is_file(): die("VENDOR_MANIFEST_MISSING")
    if sha256_file(mpath)!=DRAND_VENDOR_MANIFEST_SHA256: die("VENDOR_MANIFEST_SHA_MISMATCH")
    m=json.loads(mpath.read_text(encoding="utf-8"))
    if m.get("schema")!="V6_STAGE52_DRAND_VENDOR_MANIFEST_V1": die("VENDOR_MANIFEST_SCHEMA")
    if m.get("github_repository_id")!=REPO_ID or m.get("github_repository_owner_id")!=OWNER_ID: die("VENDOR_IDENTITY")
    for item in m.get("files",[]):
        p=pathlib.Path("vendor/drand")/item["name"]
        if not p.is_file() or p.is_symlink(): die("VENDOR_FILE_MISSING")
        if p.stat().st_size!=item["bytes"] or sha256_file(p)!=item["sha256"]: die("VENDOR_FILE_SHA_MISMATCH")

def runtime_identity():
    t={
      "schema":"V6_EXTERNAL_TRUST_GITHUB_IDENTITY_V3",
      "oidc_issuer":OIDC_ISSUER,
      "repository":env("V6_REPOSITORY"),
      "repository_id":env("V6_REPOSITORY_ID"),
      "repository_owner_id":env("V6_REPOSITORY_OWNER_ID"),
      "repository_visibility":env("V6_REPOSITORY_VISIBILITY"),
      "runner_environment":env("V6_RUNNER_ENVIRONMENT"),
      "event_name":env("V6_EVENT_NAME"),
      "ref":env("V6_REF"),
      "sha":env("V6_SHA"),
      "workflow_ref":env("V6_WORKFLOW_REF"),
      "workflow_sha":env("V6_WORKFLOW_SHA"),
      "job_workflow_ref":env("V6_JOB_WORKFLOW_REF"),
      "job_workflow_sha":env("V6_JOB_WORKFLOW_SHA"),
      "run_id":env("V6_RUN_ID"),
      "run_number":env("V6_RUN_NUMBER"),
      "run_attempt":env("V6_RUN_ATTEMPT"),
      "certificate_identity":"https://github.com/"+env("V6_JOB_WORKFLOW_REF"),
    }
    if t["repository"]!=REPO or t["repository_id"]!=REPO_ID or t["repository_owner_id"]!=OWNER_ID: die("REPOSITORY_BINDING")
    if t["repository_visibility"]!="public" or t["runner_environment"]!="github-hosted": die("RUNNER_BINDING")
    if t["event_name"]!="workflow_dispatch" or t["ref"]!="refs/heads/main": die("TRIGGER_BINDING")
    if t["workflow_ref"]!=f"{REPO}/{DISPATCH_PATH}@refs/heads/main": die("DISPATCH_BINDING")
    need40(t["sha"],"GITHUB_SHA"); need40(t["workflow_sha"],"WORKFLOW_SHA"); need40(t["job_workflow_sha"],"JOB_WORKFLOW_SHA")
    prefix=f"{REPO}/{REUSABLE_PATH}@"
    if not t["job_workflow_ref"].startswith(prefix): die("REUSABLE_REF")
    if t["job_workflow_ref"][len(prefix):]!=t["job_workflow_sha"]: die("REUSABLE_SHA_BINDING")
    for k in ("run_id","run_number","run_attempt"):
        if not t[k].isdigit() or int(t[k])<=0: die("RUN_ID")
    return t

def cmd_preflight(a):
    out=pathlib.Path(a.out_dir); out.mkdir(parents=True,exist_ok=True)
    need64(a.raw_evidence_sha256,"RAW_SHA")
    need64(a.drand_randomness,"DRAND_RANDOMNESS")
    need64(a.observer_build_sha256,"OBSERVER_SHA")
    need64(a.subject_boot_identity_sha256,"BOOT_SHA")
    if a.drand_round<=0 or a.prior_accepted_drand_round<0 or a.drand_round<=a.prior_accepted_drand_round: die("DRAND_REPLAY")
    if SAFE_PROCESS_ID.fullmatch(a.subject_process_creation_id) is None: die("PROCESS_ID")
    verify_vendor()
    t=runtime_identity()
    e={
      "schema":"V6_EXTERNAL_TRUST_ENVELOPE_V3",
      "raw_evidence_sha256":a.raw_evidence_sha256,
      "drand_chain_hash":DRAND_CHAIN,
      "drand_round":a.drand_round,
      "drand_randomness":a.drand_randomness,
      "observer_build_sha256":a.observer_build_sha256,
      "subject_boot_identity_sha256":a.subject_boot_identity_sha256,
      "subject_process_creation_id":a.subject_process_creation_id,
      "formal_gate_claims":{g:"UNPROVEN" for g in FORMAL_GATES},
      "github_run_invocation_uri":f"https://github.com/{REPO}/actions/runs/{t['run_id']}/attempts/{t['run_attempt']}",
    }
    w={
      "schema":"V6_EXTERNAL_TRUST_WORKFLOW_CONTRACT_V3",
      "permissions":{"contents":"read","id-token":"write"},
      "dependency_mode":"FULL_COMMIT_SHA_ONLY",
      "checkout_action_sha":CHECKOUT_SHA,
      "cosign_installer_action_sha":COSIGN_INSTALLER_SHA,
      "upload_artifact_action_sha":UPLOAD_ARTIFACT_SHA,
      "cosign_release":COSIGN_RELEASE,
      "drand_vendor_manifest_sha256":DRAND_VENDOR_MANIFEST_SHA256,
      "secrets_required":False,"raw_evidence_uploaded":False,"paid_runner_allowed":False,
      "reusable_call_pinned_to_full_sha":True,
    }
    write_json(out/"envelope.json",e); write_json(out/"trust.json",t); write_json(out/"workflow-contract.json",w)

def read_bounded(p, limit=1024*1024):
    if p.is_symlink() or not p.is_file(): die("INPUT_NOT_REGULAR_FILE")
    with p.open("rb") as f: raw=f.read(limit+1)
    if not raw or len(raw)>limit: die("INPUT_SIZE")
    return raw

def checked_command(argv):
    # Review-only: assumes a trusted, pinned runner and installed executable.
    try:
        r=subprocess.run(argv, shell=False, check=True, timeout=120,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.SubprocessError): die("VERIFIER_EXECUTION_FAILED")
    if r.returncode!=0: die("VERIFIER_EXECUTION_FAILED")
    if len(r.stdout)+len(r.stderr)>1024*1024: die("VERIFIER_OUTPUT_SIZE")
    return r

def cmd_finalize(a):
    out=pathlib.Path(a.out_dir)
    # Never reuse old receipts or overwrite existing files.
    paths=[out/"crypto.json",out/"policy-result.json",pathlib.Path(a.cosign_verify_output),out/"drand-finalize-verify.json",out/"finalize-timing.json"]
    if len(set(x.resolve() for x in paths))!=len(paths) or any(x.exists() or x.is_symlink() for x in paths): die("OUTPUT_ALREADY_EXISTS")
    sys.path.insert(0,str(pathlib.Path(".").resolve()))
    from v6_external_trust_policy_v3_OFFHOST_ONLY import verify_policy_v3, strict_json
    envelope=out/"envelope.json"; trust=out/"trust.json"; workflow=out/"workflow-contract.json"
    bundle=pathlib.Path(a.bundle)
    inputs={p:read_bounded(p) for p in (envelope,trust,workflow,bundle)}
    e,t,w=(strict_json(inputs[p]) for p in (envelope,trust,workflow))
    if t!=runtime_identity(): die("FINALIZE_RUNTIME_IDENTITY_MISMATCH")
    if e.get("drand_chain_hash")!=DRAND_CHAIN: die("DRAND_CHAIN")
    if type(e.get("drand_round")) is not int or e["drand_round"]<=a.prior_accepted_drand_round or a.prior_accepted_drand_round<0: die("DRAND_REPLAY")
    need64(e.get("drand_randomness"),"DRAND_RANDOMNESS")
    if not re.fullmatch(r"[0-9a-f]{192}",a.drand_signature): die("DRAND_SIGNATURE")
    verify_vendor()
    # Recheck using the existing pinned verifier, not a caller-authored PASS file.
    freshness_start=time.monotonic()
    dr=checked_command(["node","vendor/drand/verify-beacon.mjs","--round",str(e["drand_round"]),
                        "--randomness",e["drand_randomness"],"--signature",a.drand_signature,"--max-age-seconds","120"])
    d=strict_json(dr.stdout)
    if set(d)!={"status","round","age_seconds","chain_hash"} or d["status"]!="PASS" or type(d["round"]) is not int or d["round"]!=e["drand_round"] or d["chain_hash"]!=DRAND_CHAIN: die("DRAND_RESULT")
    age=d["age_seconds"]
    if type(age) is not int or not 0<=age<=120: die("DRAND_AGE")
    v=checked_command(["cosign","version","--json"])
    if strict_json(v.stdout).get("gitVersion")!=COSIGN_RELEASE: die("COSIGN_VERSION")
    # Verify private copies of the exact bytes used by the policy.
    with tempfile.TemporaryDirectory(prefix="v6-finalize-") as tmp:
        ep=pathlib.Path(tmp)/"envelope.json"; bp=pathlib.Path(tmp)/"bundle.json"
        ep.write_bytes(inputs[envelope]); bp.write_bytes(inputs[bundle])
        r=checked_command(["cosign","verify-blob",str(ep),"--bundle",str(bp),
          "--certificate-identity",t["certificate_identity"],"--certificate-oidc-issuer",OIDC_ISSUER,
          "--certificate-github-workflow-repository",REPO,"--certificate-github-workflow-ref",t["ref"],
          "--certificate-github-workflow-sha",t["sha"],"--certificate-github-workflow-trigger",t["event_name"]])
        if ep.read_bytes()!=inputs[envelope] or bp.read_bytes()!=inputs[bundle]: die("VERIFY_INPUT_CHANGED")
    log=r.stdout+r.stderr
    if not log: die("VERIFIER_OUTPUT_EMPTY")
    if any(read_bounded(p)!=b for p,b in inputs.items()): die("SOURCE_INPUT_CHANGED")
    c={
      "schema":"V6_EXTERNAL_TRUST_CRYPTO_RESULT_V3",
      "cosign_version":COSIGN_RELEASE,"cosign_verify_exit_code":0,
      "sigstore_bundle_verified":True,"fulcio_chain_verified":True,"rekor_inclusion_verified":True,
      "rekor_signed_entry_timestamp_verified":True,"sigstore_tuf_root_verified":True,
      "certificate_identity_exact":True,"certificate_oidc_issuer_exact":True,
      "certificate_github_workflow_repository_exact":True,"certificate_github_workflow_ref_exact":True,
      "certificate_github_workflow_sha_exact":True,"certificate_github_workflow_trigger_exact":True,
      "artifact_digest_bound":True,"envelope_sha256":sha256_bytes(inputs[envelope]),
      "sigstore_bundle_sha256":sha256_bytes(inputs[bundle]),"raw_tool_output_sha256":sha256_bytes(log),
    }
    def serialized(o): return (json.dumps(o,ensure_ascii=True,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
    # The Node verifier reports a floored age at some point inside its call.
    # Measuring from before that call and rounding up with an additional second
    # is conservative; verification completion cannot silently extend freshness.
    elapsed=time.monotonic()-freshness_start
    if not math.isfinite(elapsed) or elapsed<0: die("FINALIZE_CLOCK_INVALID")
    upper_age=age+math.ceil(elapsed)+1
    if upper_age>120: die("FINALIZE_FRESHNESS_EXPIRED")
    timing={"schema":"V6_FINALIZE_FRESHNESS_REVIEW_V1","reported_age_seconds":age,
            "elapsed_upper_seconds":math.ceil(elapsed),"conservative_age_seconds":upper_age,
            "limit_seconds":120,"production_authority":False}
    result=verify_policy_v3(envelope_raw=inputs[envelope],trust_raw=inputs[trust],crypto_raw=serialized(c),workflow_raw=inputs[workflow],observed_challenge_age_seconds=upper_age,prior_accepted_drand_round=a.prior_accepted_drand_round)
    # Policy result is last; incomplete output is not an accepted receipt.
    for path,raw in [(paths[2],log),(paths[3],dr.stdout),(paths[4],serialized(timing)),(paths[0],serialized(c)),(paths[1],serialized(result))]:
        with path.open("xb") as f: f.write(raw)

def main():
    p=argparse.ArgumentParser(); sp=p.add_subparsers(dest="cmd",required=True)
    q=sp.add_parser("preflight")
    q.add_argument("--raw-evidence-sha256",required=True); q.add_argument("--drand-round",type=int,required=True)
    q.add_argument("--drand-randomness",required=True); q.add_argument("--observer-build-sha256",required=True)
    q.add_argument("--subject-boot-identity-sha256",required=True); q.add_argument("--subject-process-creation-id",required=True)
    q.add_argument("--prior-accepted-drand-round",type=int,required=True); q.add_argument("--out-dir",required=True)
    q.set_defaults(fn=cmd_preflight)
    q=sp.add_parser("finalize")
    q.add_argument("--out-dir",required=True); q.add_argument("--drand-signature",required=True)
    q.add_argument("--cosign-verify-output",required=True); q.add_argument("--bundle",required=True)
    q.add_argument("--prior-accepted-drand-round",type=int,required=True); q.set_defaults(fn=cmd_finalize)
    a=p.parse_args(); a.fn(a)
if __name__=="__main__": main()

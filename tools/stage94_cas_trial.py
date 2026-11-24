from __future__ import annotations
import argparse,hashlib,json,pathlib

REPO="1985550705a-sketch/v6-external-trust-verifier"
REPO_ID="1469695205"
LEDGER_BRANCH="v6-n64-replay-ledger-trial-v1"
WORKFLOW_PATH=".github/workflows/v6-n64-replay-cas-trial-v1.yml"
CHAIN_HASH="8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
BASELINE_COMMIT="f8508197692722ca974e86efd7a5b88abf04c0c7"
GENESIS="0"*64
ENTRY_DOMAIN=b"V6:N64:STAGE69:ANCHOR_ENTRY:V1\0"
CHALLENGE_DOMAIN=b"V6:N64:STAGE94:ONE_CLICK_CAS_TRIAL:V1\0"
SYNTHETIC_CAPSULE_SHA256=hashlib.sha256(b"V6 N64 Stage94 synthetic capsule v1").hexdigest()
SYNTHETIC_ATTESTOR_RECEIPT_SHA256=hashlib.sha256(b"V6 N64 Stage94 synthetic attestor receipt v1").hexdigest()

class Reject(ValueError):pass
def need(v,w):
    if not v: raise Reject(w)
def hx(v,n=64):
    return isinstance(v,str) and len(v)==n and all(c in "0123456789abcdef" for c in v)
def sha1hex(v):
    return isinstance(v,str) and len(v)==40 and all(c in "0123456789abcdef" for c in v)
def canon(o):
    return json.dumps(o,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def sha(b):return hashlib.sha256(b).hexdigest()

def logical_head(sequence,previous_head_sha256,capsule_sha256,challenge_sha256):
    need(type(sequence) is int and sequence>=1,"SEQUENCE")
    need(hx(previous_head_sha256) and hx(capsule_sha256) and hx(challenge_sha256),"HEAD_INPUT")
    return sha(ENTRY_DOMAIN+canon({"sequence":sequence,"previous_head_sha256":previous_head_sha256,
                                  "capsule_sha256":capsule_sha256,"nonce_sha256":challenge_sha256}))

def make_precommit(*,observed_round,target_round,workflow_commit_sha1,run_id,run_attempt,parent_commit_sha1):
    need(type(observed_round) is int and observed_round>=1,"OBSERVED_ROUND")
    need(type(target_round) is int and observed_round<target_round<=observed_round+4,"TARGET_ROUND")
    need(sha1hex(workflow_commit_sha1) and sha1hex(parent_commit_sha1),"COMMIT")
    need(parent_commit_sha1==BASELINE_COMMIT,"TRIAL_PARENT")
    need(isinstance(run_id,str) and run_id.isdigit(),"RUN_ID")
    need(run_attempt=="1","RUN_ATTEMPT")
    request_id=sha(CHALLENGE_DOMAIN+b"REQUEST\0"+run_id.encode()+b"\0"+workflow_commit_sha1.encode())
    intent={
      "schema":"V6_N64_STAGE94_SYNTHETIC_INTENT_V1",
      "classification":"SYNTHETIC_TRANSPORT_TRIAL_ONLY",
      "request_id":request_id,
      "workflow_commit_sha1":workflow_commit_sha1,
      "run_id":run_id,
      "run_attempt":1,
      "expected_parent_commit_sha1":parent_commit_sha1,
      "capsule_sha256":SYNTHETIC_CAPSULE_SHA256,
      "attestor_receipt_sha256":SYNTHETIC_ATTESTOR_RECEIPT_SHA256,
      "production_authority":False
    }
    return {"schema":"V6_N64_STAGE94_DRAND_PRECOMMIT_V1","chain_hash":CHAIN_HASH,
            "observed_round":observed_round,"target_round":target_round,
            "intent_sha256":sha(canon(intent)),"intent":intent}

def bind_beacon(precommit,beacon):
    need(precommit.get("schema")=="V6_N64_STAGE94_DRAND_PRECOMMIT_V1","PRECOMMIT")
    need(precommit.get("chain_hash")==CHAIN_HASH,"CHAIN")
    need(precommit["intent_sha256"]==sha(canon(precommit["intent"])),"INTENT_TAMPER")
    need(type(beacon) is dict and type(beacon.get("round")) is int,"BEACON")
    need(beacon["round"]==precommit["target_round"],"ROUND")
    sig=beacon.get("signature");rnd=beacon.get("randomness")
    need(isinstance(sig,str) and len(sig)%2==0 and all(c in "0123456789abcdef" for c in sig),"SIG")
    need(hx(rnd),"RANDOMNESS")
    need(sha(bytes.fromhex(sig))==rnd,"RANDOMNESS_HASH")
    raw={"round":beacon["round"],"signature":sig,"randomness":rnd}
    challenge=sha(CHALLENGE_DOMAIN+canon(precommit)+canon(raw))
    i=precommit["intent"]
    head=logical_head(1,GENESIS,i["capsule_sha256"],challenge)
    witness={
      "schema":"V6_N64_STAGE89_GITHUB_SIGSTORE_CAS_WITNESS_V1",
      "classification":"EXTERNAL_GITHUB_SIGSTORE_CAS_WITNESS_REVIEW_ONLY",
      "repository":REPO,"repository_id":REPO_ID,"ledger_branch":LEDGER_BRANCH,
      "workflow_path":WORKFLOW_PATH,"workflow_commit_sha1":i["workflow_commit_sha1"],
      "sequence":1,"expected_parent_commit_sha1":i["expected_parent_commit_sha1"],
      "previous_head_sha256":GENESIS,"head_sha256":head,
      "capsule_sha256":i["capsule_sha256"],"challene_sha256":challenge,
      "nonce_sha256":challenge,"drand_chain_hash":CHAIN_HASH,"drand_round":beacon["round"],
      "attestor_receipt_sha256":i["attestor_receipt_sha256"],
      "previous_witness_sha256":GENESIS,"production_authority":False
    }
    return {"challenge_sha256":challenge,"witness":witness}

def main():
    p=argparse.ArgumentParser();sp=p.add_subparsers(dest="cmd",required=True)
    q=sp.add_parser("precommit")
    q.add_argument("--observed-round",type=int,required=True);q.add_argument("--target-round",type=int,required=True)
    q.add_argument("--workflow-commit-sha1",required=True);q.add_argument("--run-id",required=True)
    q.add_argument("--run-attempt",required=True);q.add_argument("--parent-commit-sha1",required=True);q.add_argument("--out",required=True)
    q=sp.add_parser("bind")
    q.add_argument("--precommit",required=True);q.add_argument("--beacon",required=True)
    q.add_argument("--witness-out", required=True);q.add_argument("--challenge-out",required=True)
    a=p.parse_args()
    if a.cmd=="precommit":
        o=make_precommit(observed_round=a.observed_round,target_round=a.target_round,
          workflow_commit_sha1=a.workflow_commit_sha1,run_id=a.run_id,run_attempt=a.run_attempt,
          parent_commit_sha1=a.parent_commit_sha1)
        pathlib.Path(a.out).write_bytes(canon(o))
    else:
        pre=json.loads(pathlib.Path(a.precommit).read_text("ascii"))
        beacon=json.loads(pathlib.Path(a.beacon).read_text("ascii"))
        o=bind_beacon(pre,beacon)
        pathlib.Path(a.witness_out).write_bytes(canon(o["witness"]))
        pathlib.Path(a.challenge_out).write_text(o["challenge_sha256"],encoding="ascii")
if __name__=="__main__":main()

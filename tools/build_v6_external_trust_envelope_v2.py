from __future__ import annotations
import argparse, hashlib, json, pathlib, sys

FORMAL_GATES = (
    "ALL_WRITERS_FENCED",
    "EXACT_JOBOBJECT_DESCENDANTS",
    "FINITE_NATIVE_ACK_WAIT",
    "KERNEL_BYTE_RANGE_LOCK_OWNER",
    "LOADED_EXECUTING_CODE",
    "OOB_PREVIOUS_GOOD_RECOVERY",
)

def sha256_file(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--raw-evidence", required=True)
    p.add_argument("--drand-chain-hash", required=True)
    p.add_argument("--drand-round", required=True, type=int)
    p.add_argument("--drand-randomness", required=True)
    p.add_argument("--observer-build-sha256", required=True)
    p.add_argument("--subject-boot-identity-sha256", required=True)
    p.add_argument("--subject-process-creation-id", required=True)
    p.add_argument("--github-run-invocation-uri", required=True)
    a=p.parse_args()
    raw=pathlib.Path(a.raw_evidence)
    if not raw.is_file():
        raise SystemExit("RAW_EVIDENCE_MISSING")
    env={
        "schema":"V6_EXTERNAL_TRUST_ENVELOPE_V2",
        "raw_evidence_sha256":sha256_file(raw),
        "drand_chain_hash":a.drand_chain_hash,
        "drand_round":a.drand_round,
        "drand_randomness":a.drand_randomness,
        "observer_build_sha256":a.observer_build_sha256,
        "subject_boot_identity_sha256":a.subject_boot_identity_sha256,
        "subject_process_creation_id":a.subject_process_creation_id,
        "formal_gate_claims":{g:"UNPROVEN" for g in FORMAL_GATES},
        "github_run_invocation_uri":a.github_run_invocation_uri,
    }
    sys.stdout.write(json.dumps(env,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n")

if __name__=="__main__":
    main()

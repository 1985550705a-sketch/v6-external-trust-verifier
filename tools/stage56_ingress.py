"""OFFHOST candidate: untrusted expressions are environment data, never shell code.
No command execution on import. Future approved runner entrypoint uses argv only.
"""
import json, os, re, subprocess, sys

FIELDS={'raw_evidence_sha256','drand_round','drand_randomness','drand_signature','observer_build_sha256','subject_boot_identity_sha256','subject_process_creation_id','prior_accepted_drand_round'}
HASH_FIELDS=FIELDS-{'drand_round','prior_accepted_drand_round','drand_signature'}
MAX_ROUND=2**53-1  # GitHub expression number exact integer range
REPO='1985550705a-sketch/v6-external-trust-verifier'
class Rejected(ValueError): pass

def reject(code): raise Rejected(code)
def strict_object(raw):
    if type(raw) is not bytes or not 0<len(raw)<=16384 or raw.startswith(b'\xef\xbb\xbf'): reject('JSON_BYTES')
    def pairs(xs):
        d={}
        for k,v in xs:
            if k in d: reject('DUPLICATE_KEY')
            d[k]=v
        return d
    try:
        x=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pairs,parse_constant=lambda _:reject('NONFINITE'))
        if type(x) is not dict: reject('JSON_OBJECT')
        # Reject unpaired surrogates including escaped ones.
        json.dumps(x,ensure_ascii=False,allow_nan=False).encode('utf-8','strict')
        return x
    except Rejected: raise
    except (ValueError,UnicodeError,RecursionError,OverflowError): reject('JSON_INVALID')

def validhex(v,n): return type(v) is str and len(v)==n and re.fullmatch('[0-9a-f]+',v) is not None

def uint(v,lo=0):
    if type(v) is str:
        if len(v)>16 or re.fullmatch(r'0|[1-9][0-9]{0,15}',v) is None: reject('NUMERIC_FORMAT')
        v=int(v)
    if type(v) is not int or not lo<=v<=MAX_ROUND: reject('NUMERIC_RANGE')
    return v

def validate(x):
    if type(x) is not dict or set(x)!=FIELDS: reject('INPUT_FIELDS')
    for k in HASH_FIELDS:
        if not validhex(x[k],64): reject('SHA_OR_OPAQUE_ID_FORMAT')
    if not validhex(x['drand_signature'],192): reject('DRAND_SIGNATURE_FORMAT')
    r,p=uint(x['drand_round'],1),uint(x['prior_accepted_drand_round'])
    if r<=p: reject('DRAND_REPLAY')
    return dict(x,drand_round=r,prior_accepted_drand_round=p)

def from_env(env):
    prefix='V6_INPUT_'
    keys={k for k in env if k.startswith(prefix)}
    if keys!={prefix+k.upper() for k in FIELDS}: reject('INPUT_ENV_FIELDS')
    return validate({k:env[prefix+k.upper()] for k in FIELDS})

def identity(env):
    expected={'V6_REPOSITORY':REPO,'V6_REPOSITORY_ID':'1469695205','V6_REPOSITORY_OWNER_ID':'360536248','V6_REPOSITORY_VISIBILITY':'public','V6_RUNNER_ENVIRONMENT':'github-hosted','V6_EVENT_NAME':'workflow_dispatch','V6_REF':'refs/heads/main','V6_WORKFLOW_REF':REPO+'/.github/workflows/v6-external-trust-dispatch-v3.yml@refs/heads/main'}
    if any(env.get(k)!=v for k,v in expected.items()): reject('RUN_IDENTITY')
    for k in ('V6_SHA','V6_WORKFLOW_SHA','V6_JOB_WORKFLOW_SHA'):
        if not validhex(env.get(k),40): reject('WORKFLOW_SHA')
    if env['V6_SHA']!=env['V6_WORKFLOW_SHA']: reject('CALLER_SHA')
    ref=REPO+'/.github/workflows/v6-external-trust-reusable-v3.yml@'+env['V6_JOB_WORKFLOW_SHA']
    if env.get('V6_JOB_WORKFLOW_REF')!=ref: reject('REUSABLE_REF')
    for k in ('V6_RUN_ID','V6_RUN_NUMBER','V6_RUN_ATTEMPT'): uint(env.get(k),1)
    return ref

def plan(mode,env):
    x=from_env(env); ref=identity(env)
    if mode=='preflight':
        args=['python3','tools/stage53_runtime_v3.py','preflight']
        for k in ('raw_evidence_sha256','drand_round','drand_randomness','observer_build_sha256','subject_boot_identity_sha256','subject_process_creation_id','prior_accepted_drand_round'):
            args.extend(['--'+k.replace('_','-'),str(x[k])])
        return args+['--out-dir','stage53-out'],None
    if mode=='drand': return ['node','vendor/drand/verify-beacon.mjs','--round',str(x['drand_round']),'--randomness',x['drand_randomness'],'--signature',x['drand_signature'],'--max-age-seconds','120'],'stage53-out/drand-verify.json'
    if mode=='verify': return ['cosign','verify-blob','stage53-out/envelope.json','--bundle','stage53-out/envelope.sigstore.json','--certificate-identity','https://github.com/'+ref,'--certificate-oidc-issuer','https://token.actions.githubusercontent.com','--certificate-github-workflow-repository',REPO,'--certificate-github-workflow-ref','refs/heads/main','--certificate-github-workflow-sha',env['V6_SHA'],'--certificate-github-workflow-trigger','workflow_dispatch'],'stage53-out/cosign-verify.txt'
    if mode=='finalize': return ['python3','tools/stage53_runtime_v3.py','finalize','--out-dir','stage53-out','--drand-result','stage53-out/drand-verify.json','--cosign-verify-output','stage53-out/cosign-verify.txt','--bundle','stage53-out/envelope.sigstore.json','--prior-accepted-drand-round',str(x['prior_accepted_drand_round'])],None
    reject('MODE')

def execute(mode,env,runner=subprocess.run):
    argv,out=plan(mode,env)  # no shell or output file opened before validation
    clean={k:v for k,v in env.items() if not k.startswith('V6_INPUT_')}
    if out:
        with open(out,'xb') as f: runner(argv,check=True,shell=False,env=clean,stdout=f,stderr=subprocess.STDOUT if mode=='verify' else None,timeout=120)
    else: runner(argv,check=True,shell=False,env=clean,timeout=120)

if __name__=='__main__':
    try:
        if len(sys.argv)!=2: reject('MODE')
        execute(sys.argv[1],os.environ)
    except Rejected as e: raise SystemExit(str(e)) from None

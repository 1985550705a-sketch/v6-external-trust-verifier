"""Inactive digest-only synthetic link candidate. No Windows/native authority.
Only fixed argv; verified historical drand vendor is required by future runner.
No network performed by importing this module or by local tests.
"""
import hashlib,json,os,subprocess,sys
from pathlib import Path
from stage56_ingress import strict_object,validhex,uint,Rejected,REPO
HISTORICAL_SHA='0d46838c481621cbaf291e27aca7120e7c4e9007'
CHAIN='8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce'
CALLER='.github/workflows/v6-n64-link-dispatch-v1.yml'
WORKFLOW='.github/workflows/v6-n64-link-reusable-v1.yml'
ISSUER='https://token.actions.githubusercontent.com'
DIGESTS=set('challenge_sha256 observation_commitment_sha256 observer_signature_sha256 raw_evidence_sha256 generation_sha256 observer_build_sha256 subject_boot_identity_sha256 subject_process_creation_id drand_randomness'.split())
FIELDS=DIGESTS|{'drand_round','drand_signature','prior_accepted_drand_round'}
def need(v,c):
    if not v: raise Rejected(c)
def sha(x):return hashlib.sha256(x).hexdigest()
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def validate_inputs(x):
    need(type(x) is dict and set(x)==FIELDS,'LINK_INPUT_FIELDS')
    need(all(validhex(x[k],64) for k in DIGESTS),'LINK_INPUT_SHA')
    need(validhex(x['drand_signature'],192),'LINK_DRAND_SIGNATURE')
    r,p=uint(x['drand_round'],1),uint(x['prior_accepted_drand_round'])
    need(r>p,'LINK_ROUND_REPLAY')
    need(x['raw_evidence_sha256']!=x['observation_commitment_sha256'],'DISTINCT_RAW_COMMITMENT')
    return dict(x,drand_round=r,prior_accepted_drand_round=p)
def synthetic_inputs(round_,randomness,signature):
    """Known public fixture; not a real observer or Windows receipt."""
    r=uint(round_,1)
    need(validhex(randomness,64) and validhex(signature,192),'SMOKE_CHALLENGE_FORMAT')
    base={k:sha(('V6:N64:STAGE58:PUBLIC_SYNTHETIC:'+k).encode()) for k in DIGESTS-{'drand_randomness','challenge_sha256','observation_commitment_sha256'}}
    ch=sha(canon({'schema':'PUBLIC_SYNTHETIC_DRAND_CHALLENGE_V1','round':r,'randomness':randomness,'chain':CHAIN}))
    commitment=sha(canon({'schema':'PUBLIC_SYNTHETIC_FIXTURE_NOT_OBSERVATION_V1','challenge_sha256':ch,**base}))
    return validate_inputs(dict(base,drand_randomness=randomness,challenge_sha256=ch,observation_commitment_sha256=commitment,drand_round=r,drand_signature=signature,prior_accepted_drand_round=6669087))
def identity(env):
    fixed={'V6_REPOSITORY':REPO,'V6_REPOSITORY_ID':'1469695205','V6_OWNER_ID':'360536248','V6_VISIBILITY':'public','V6_RUNNER':'github-hosted','V6_EVENT':'workflow_dispatch','V6_REF':'refs/heads/main','V6_CALLER_REF':REPO+'/'+CALLER+'@refs/heads/main'}
    need(all(env.get(k)==v for k,v in fixed.items()),'LINK_RUN_IDENTITY')
    caller,workflow=env.get('V6_CALLER_SHA'),env.get('V6_WORKFLOW_SHA')
    need(validhex(caller,40) and validhex(workflow,40) and workflow!=HISTORICAL_SHA,'LINK_WORKFLOW_PIN')
    need(env.get('V6_HEAD_SHA')==caller and env.get('V6_WORKFLOW_REF')==REPO+'/'+WORKFLOW+'@'+workflow,'LINK_REF_BINDING')
    r,a=env.get('V6_RUN_ID'),env.get('V6_RUN_ATTEMPT')
    uint(r,1); need(a=='1','LINK_NO_RERUN')
    return dict(repository=REPO,repository_id='1469695205',owner_id='360536248',caller_sha=caller,reusable_workflow_sha=workflow,run_id=r,run_attempt=a,oidc_issuer=ISSUER)
def envelope(x,i):
    x=validate_inputs(x)
    return dict(schema='V6_N64_EXTERNAL_DIGEST_LINK_V1',classification='SYNTHETIC_OFFHOST_ONLY',smoke_profile='PUBLIC_SYNTHETIC_FIXTURE_NOT_WINDOWS_OBSERVATION',**{k:x[k] for k in DIGESTS|{'drand_round'}},drand_chain_hash=CHAIN,drand_signature_sha256=sha(bytes.fromhex(x['drand_signature'])),prior_accepted_drand_round=x['prior_accepted_drand_round'],**i)
def prepare(env):
    p='V6_LINK_'; need({k for k in env if k.startswith(p)}=={p+k.upper() for k in FIELDS},'LINK_ENV_FIELDS')
    x=validate_inputs({k:env[p+k.upper()] for k in FIELDS}); i=identity(env)
    return envelope(x,i),['node','vendor/drand/verify-beacon.mjs','--round',str(x['drand_round']),'--randomness',x['drand_randomness'],'--signature',x['drand_signature'],'--max-age-seconds','120']
def verify_argv(i):
    return ['cosign','verify-blob','link-out/envelope.json','--bundle','link-out/envelope.sigstore.json','--certificate-identity','https://github.com/'+REPO+'/'+WORKFLOW+'@'+i['reusable_workflow_sha'],'--certificate-oidc-issuer',ISSUER,'--certificate-github-workflow-repository',REPO,'--certificate-github-workflow-ref','refs/heads/main','--certificate-github-workflow-sha',i['caller_sha'],'--certificate-github-workflow-trigger','workflow_dispatch']
def run(env,runner=subprocess.run):
    e,argv=prepare(env) # validates before any subprocess/output
    actual=validate_inputs({k:env['V6_LINK_'+k.upper()] for k in FIELDS})
    need(actual==synthetic_inputs(actual['drand_round'],actual['drand_randomness'],actual['drand_signature']),'NONPUBLIC_FIXTURE_DENIED')
    clean={k:v for k,v in env.items() if not k.startswith('V6_LINK_')}
    # Vendor exact manifest/files must be verified before executing Node.
    from stage53_runtime_v3 import verify_vendor
    verify_vendor()
    out=Path('link-out');out.mkdir(exist_ok=False)
    with (out/'drand.json').open('xb') as f: runner(argv,env=clean,shell=False,check=True,timeout=120,stdout=f)
    d=strict_object((out/'drand.json').read_bytes())
    need(set(d)=={'status','round','age_seconds','chain_hash'} and d['status']=='PASS' and type(d['round']) is int and d['round']==e['drand_round'] and d['chain_hash']==CHAIN and type(d['age_seconds']) is int and 0<=d['age_seconds']<=120,'LINK_DRAND_RESULT')
    (out/'envelope.json').write_bytes(canon(e))
    runner(['cosign','sign-blob','--yes','--bundle','link-out/envelope.sigstore.json','link-out/envelope.json'],env=clean,shell=False,check=True,timeout=120)
    runner(verify_argv(e),env=clean,shell=False,check=True,timeout=120)
if __name__=='__main__':run(os.environ)

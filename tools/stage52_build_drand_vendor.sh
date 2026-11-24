#!/usr/bin/env bash
set -euo pipefail

EXPECTED_REPO="1985550705a-sketch/v6-external-trust-verifier"
EXPECTED_REPO_ID="1469695205"
EXPECTED_OWNER_ID="360536248"
UPSTREAM_REPO="https://github.com/drand/drand-client.git"
UPSTREAM_COMMIT="ef8c9260294f8699b5e8c27a6b764f8f0d768bea"
UPSTREAM_LOCK_BLOB="f5a4f7ccbcd51d35e23fef45f8323769c4312d71"
CHAIN_HASH="8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
PUBLIC_KEY="868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"

test "${GITHUB_REPOSITORY:-}" = "$EXPECTED_REPO"
test "${GITHUB_REPOSITORY_ID:-}" = "$EXPECTED_REPO_ID"
test "${GITHUB_REPOSITORY_OWNER_ID:-}" = "$EXPECTED_OWNER_ID"

rm -rf upstream stage
git clone --quiet "$UPSTREAM_REPO" upstream
cd upstream
git checkout --quiet --detach "$UPSTREAM_COMMIT"
test "$(git rev-parse HEAD)" = "$UPSTREAM_COMMIT"
test "$(git hash-object package-lock.json)" = "$UPSTREAM_LOCK_BLOB"
python3 - <<'PY'
import json
p=json.load(open("package.json",encoding="utf-8"))
assert p["name"]=="drand-client"
assert p["version"]=="1.4.2"
PY
npm ci --no-audit --no-fund
npm run build
cd "$GITHUB_WORKSPACE"

mkdir -p stage/vendor/drand
cp upstream/build/esm/index.mjs stage/vendor/drand/index.mjs
cp upstream/build/esm/index.mjs.map stage/vendor/drand/index.mjs.map
cp upstream/package.json upstream/package-lock.json stage/vendor/drand/
cp upstream/LICENSE* stage/vendor/drand/ 2>/dev/null || true
node --version > stage/vendor/drand/node-version.txt
npm --version > stage/vendor/drand/npm-version.txt

cat > stage/vendor/drand/verify-beacon.mjs <<'JS'
import { HttpCachingChain, HttpChainClient, fetchBeacon } from './index.mjs'

const CHAIN_HASH = '8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce'
const PUBLIC_KEY = '868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31'

function arg(name) {
  const i = process.argv.indexOf(name)
  if (i < 0 || i + 1 >= process.argv.length) throw new Error('MISSING_' + name.replace(/^--/, '').toUpperCase())
  return process.argv[i + 1]
}

const round = Number(arg('--round'))
const expectedRandomness = arg('--randomness').toLowerCase()
const expectedSignature = arg('--signature').toLowerCase()
const maxAgeSeconds = Number(arg('--max-age-seconds'))
if (!Number.isSafeInteger(round) || round <= 0) throw new Error('ROUND_INVALID')
if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0 || maxAgeSeconds > 120) throw new Error('MAX_AGE_INVALID')

const options = {
  disableBeaconVerification: false,
  noCache: true,
  chainVerificationParams: { chainHash: CHAIN_HASH, publicKey: PUBLIC_KEY }
}
const chain = new HttpCachingChain('https://api.drand.sh/' + CHAIN_HASH, options)
const client = new HttpChainClient(chain, options)
const beacon = await fetchBeacon(client, round)
if (beacon.round !== round) throw new Error('ROUND_MISMATCH')
if (String(beacon.randomness).toLowerCase() !== expectedRandomness) throw new Error('RANDOMNESS_MISMATCH')
if (String(beacon.signature).toLowerCase() !== expectedSignature) throw new Error('SIGNATURE_MISMATCH')

const genesis = 1595431050
const period = 30
const roundUnix = genesis + (round - 1) * period
const age = Math.floor(Date.now() / 1000) - roundUnix
if (age < 0 || age > maxAgeSeconds) throw new Error('ROUND_STALE_OR_FUTURE')
process.stdout.write(JSON.stringify({status:'PASS',round,age_seconds:age,chain_hash:CHAIN_HASH}) + '\n')
JS

node --input-type=module <<'JS'
import { HttpCachingChain, HttpChainClient, fetchBeacon } from './stage/vendor/drand/index.mjs'
const chainHash='8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce'
const publicKey='868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31'
const options={disableBeaconVerification:false,noCache:true,chainVerificationParams:{chainHash,publicKey}}
const chain=new HttpCachingChain('https://api.drand.sh/'+chainHash,options)
const client=new HttpChainClient(chain,options)
const b=await fetchBeacon(client)
if (!b || !Number.isSafeInteger(b.round) || b.round<=0) throw new Error('SMOKE_BEACON_INVALID')
console.log('DRAND_SMOKE_VERIFIED_ROUND='+b.round)
JS

python3 - <<'PY'
import hashlib,json,pathlib,datetime,os
root=pathlib.Path("stage/vendor/drand")
files=[]
for p in sorted(root.iterdir()):
    if p.is_file():
        files.append({"name":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"bytes":p.stat().st_size})
obj={
  "schema":"V6_STAGE52_DRAND_VENDOR_MANIFEST_V1",
  "status":"BUILT_ON_GITHUB_HOSTED_RUNNER",
  "upstream_repository":"drand/drand-client",
  "upstream_tag":"v1.4.2",
  "upstream_commit":"ef8c9260294f8699b5e8c27a6b764f8f0d768bea",
  "upstream_package_lock_git_blob_sha1":"f5a4f7ccbcd51d35e23fef45f8323769c4312d71",
  "drand_chain_hash":"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
  "drand_public_key":"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31",
  "github_repository_id":os.environ["GITHUB_REPOSITORY_ID"],
  "github_repository_owner_id":os.environ["GITHUB_REPOSITORY_OWNER_ID"],
  "run_id":os.environ["GITHUB_RUN_ID"],
  "run_attempt":os.environ["GITHUB_RUN_ATTEMPT"],
  "files":files,
  "generated_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat()
}
(root/"V6_VENDOR_MANIFEST.json").write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n",encoding="utf-8")
PY

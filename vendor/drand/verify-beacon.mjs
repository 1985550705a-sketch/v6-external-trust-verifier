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

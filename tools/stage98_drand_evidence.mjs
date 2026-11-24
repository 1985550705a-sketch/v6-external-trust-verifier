// Review-only evidence adapter. Reuse the pinned Stage52 vendor BLS verifier.
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {HttpCachingChain, HttpChainClient, fetchBeacon} from '../vendor/drand/index.mjs';
const CHAIN_HASH='8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce';
const PUBLIC_KEY='868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31';
const GENESIS=1595431050, PERIOD=30;
const need=(ok,msg)=>{if(!ok)throw Error(msg)};
const hex=(x,n)=>typeof x==='string'&&x.length===n&&/^[0-9a-f]+$/.test(x);
const sha=x=>createHash('sha256').update(x).digest('hex');
function validate(round,randomness,signature,maxAge){
  need(Number.isSafeInteger(round)&&round>1,'ROUND_INVALID');
  need(hex(randomness,64)&&hex(signature,192),'HEX_INVALID');
  need(Number.isSafeInteger(maxAge)&&maxAge>=0&&maxAge<=120,'MAX_AGE_INVALID');
  need(sha(Buffer.from(signature,'hex'))===randomness,'RANDOMNESS_HASH');
}
// Injected client and clock are exclusively for offline tests; CLI uses fixed live settings.
export async function verifyAndCapture({round,randomness,signature,maxAge,client,now=Date.now}){
  validate(round,randomness,signature,maxAge);
  const info=await client.chain().info();
  need(info.hash===CHAIN_HASH&&info.public_key===PUBLIC_KEY&&info.schemeID==='pedersen-bls-chained'&&info.period===PERIOD&&info.genesis_time===GENESIS,'CHAIN_INFO');
  need(client.options?.disableBeaconVerification===false,'VERIFICATION_REQUIRED');
  const b=await fetchBeacon(client,round);
  need(b.round===round&&b.randomness===randomness&&b.signature===signature,'BEACON_MISMATCH');
  need(hex(b.previous_signature,192),'PREVIOUS_SIGNATURE');
  const age=Math.floor(now()/1000)-(GENESIS+(round-1)*PERIOD);
  need(Number.isSafeInteger(age)&&age>=0&&age<=maxAge,'ROUND_STALE_OR_FUTURE');
  return {status:'PASS',round,age_seconds:age,chain_hash:CHAIN_HASH,beacon:{round,randomness,signature,previous_signature:b.previous_signature}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const names=['--round','--randomness','--signature','--max-age-seconds'];
  const args=process.argv.slice(2), vals={};
  need(args.length===8,'ARGUMENTS');
  for(let i=0;i<args.length;i+=2){need(names.includes(args[i])&&!(args[i] in vals),'ARGUMENTS');vals[args[i]]=args[i+1];}
  const round=Number(vals['--round']), randomness=vals['--randomness'],signature=vals['--signature'],maxAge=Number(vals['--max-age-seconds']);
  validate(round,randomness,signature,maxAge);
  const opts={disableBeaconVerification:false,noCache:true,chainVerificationParams:{chainHash:CHAIN_HASH,publicKey:PUBLIC_KEY}};
  const chain=new HttpCachingChain('https://api.drand.sh/'+CHAIN_HASH,opts);
  const client=new HttpChainClient(chain,opts);
  process.stdout.write(JSON.stringify(await verifyAndCapture({round,randomness,signature,maxAge,client}))+'\n');
}

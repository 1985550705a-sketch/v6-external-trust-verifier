"""Inactive future runner; network only from explicitly authorized invocation."""
import os,urllib.request
import stage58_external as x
from stage56_ingress import strict_object

def project(raw):
    d=strict_object(raw)
    x.need(set(d) in ({'round','randomness','signature'},{'round','randomness','signature','previous_signature'}),'BEACON_FIELDS')
    x.need(type(d['round']) is int,'BEACON_ROUND_TYPE')
    if 'previous_signature' in d:x.need(x.validhex(d['previous_signature'],192),'BEACON_PREVIOUS_SIGNATURE')
    z=x.synthetic_inputs(d['round'],d['randomness'],d['signature'])
    return {k:str(v) for k,v in z.items()}

def main():
    url='https://api.drand.sh/'+x.CHAIN+'/public/latest'
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'V6-N64-PUBLIC-SYNTHETIC/1'}),timeout=10) as r:
        x.need(r.status==200 and r.geturl()==url,'BEACON_HTTP');raw=r.read(16385)
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as f:f.write('json='+x.canon(project(raw)).decode('ascii')+'\n')
if __name__=='__main__':main()

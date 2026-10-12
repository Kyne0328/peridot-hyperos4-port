"""Acquire byte-identical transport mirror of an already hashed official release; never execute it."""
import hashlib,json,pathlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[2]
OUT=ROOT/'downloads/recovery-audit'
NAME='OrangeFox-R12.0_7_crypto-peridot.zip'
PIN='f0f04589b68fe096b6ff1fb522bc1b3598d1cb15d3692615b5e9607de30e62b0'
SIZE=56565915
URL='https://sourceforge.net/projects/recovery-for-xiaomi-devices/files/peridot/OrangeFox-R12.0_7_crypto-peridot.zip/download'
OFFICIAL='https://orangefox.download/release/6ab06b4434d647462e0f116d'
OUT.mkdir(parents=True,exist_ok=True); dest=OUT/NAME;temp=OUT/(NAME+'.partial')
assert not dest.exists() and not temp.exists(),'Refuse overwrite or duplicate transfer'
req=urllib.request.Request(URL,headers={'User-Agent':'Mozilla/5.0'})
h=hashlib.sha256();n=0
with urllib.request.urlopen(req,timeout=60) as response,temp.open('xb') as f:
    final=response.url
    while True:
        b=response.read(1024*1024)
        if not b:break
        n+=len(b)
        assert n<=SIZE,'Response exceeds expected artifact size'
        h.update(b);f.write(b)
assert n==SIZE and h.hexdigest()==PIN,'Official artifact identity mismatch; partial retained'
temp.rename(dest)
receipt=dict(official_release=OFFICIAL,transport_mirror=URL,resolved_transport_url=final,path=str(dest),size=n,sha256=h.hexdigest(),executed=False,provenance='Identity independently obtained from official browser download; mirror accepted only after exact size/SHA256 match.')
(ROOT/'00-manifest/official-orangefox-r12_0_7.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))

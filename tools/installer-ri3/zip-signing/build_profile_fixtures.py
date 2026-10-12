#!/usr/bin/env python3
"""Generate small malformed-CMS fixtures without reading any private key."""
import pathlib,json,struct,hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from verify_zip import DER,certificate,envelope,extract_signature,verify_zip,VerificationError
from sign_zip import der_tlv,make_cms
ROOT=pathlib.Path(__file__).resolve().parents[3]
R=ROOT/"09-reports/installer-ri3/zip-signing"
small=json.loads((R/"small-tests.json").read_text())
original=ROOT/small["signed_fixture"]
out=original.parent/"cms-profile";out.mkdir(exist_ok=True)
certpath=ROOT/"builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem"
env,cms=envelope(original);raw=original.read_bytes();prefix=raw[:env["signed_bytes"]]
ci=DER(cms).body(0x30);oid=ci.item(6)[2];sd=ci.body(0xa0).body(0x30)
fields=[]
while sd.peek() is not None:fields.append(sd.item()[2])
signers=DER(fields[-1]).body(0x31);signer=signers.item(0x30)[2]
si=DER(signer).body(0x30);parts=[]
while si.peek() is not None:parts.append(si.item()[2])
def build(sf=None,sp=None,multiple=False):
    sf=list(fields if sf is None else sf)
    if sp is not None:sf[-1]=der_tlv(0x31,der_tlv(0x30,b"".join(sp)))
    if multiple:sf[-1]=der_tlv(0x31,signer+signer)
    return der_tlv(0x30,oid+der_tlv(0xa0,der_tlv(0x30,b"".join(sf))))
def pack(name,data):
    comment=b"CMS negative fixture\0"+data
    count=len(comment)+6
    path=out/(name+".zip")
    path.write_bytes(prefix+struct.pack("<H",count)+comment+struct.pack("<HHH",len(data)+6,65535,count))
    try:verify_zip(path,certpath)
    except VerificationError as e:return {"name":name,"path":str(path.relative_to(ROOT)),"rejected":True,"reason":str(e)}
    return {"name":name,"path":str(path.relative_to(ROOT)),"rejected":False}
wrong=x509.load_pem_x509_certificate((ROOT/"builder/work/installer-ri3-zipsign/sources/testkey.x509.pem").read_bytes())
_,der,*_=certificate(certpath)
sig=extract_signature(cms,der)
variants={
"signed_attrs":build(sp=parts[:3]+[b"\xa0\0"]+parts[3:]),
"unsigned_attrs":build(sp=parts+[b"\xa1\0"]),
"multiple_signers":build(multiple=True),
"trailing_der":cms+b"\0",
"indefinite_length":b"\x30\x80"+DER(cms).item(0x30)[1]+b"\0\0",
"wrong_digest_oid":cms.replace(bytes.fromhex("608648016503040201"),bytes.fromhex("608648016503040202")),
"wrong_rsa_oid":build(sp=parts[:3]+[parts[3].replace(bytes.fromhex("2a864886f70d010101"),bytes.fromhex("2a864886f70d010105"))]+parts[4:]),
"wrong_embedded_certificate":make_cms(wrong,wrong.public_bytes(serialization.Encoding.DER),sig)}
body=DER(cms).item(0x30)[1]
n=len(body);variants["nonminimal_length"]=b"\x30\x83\0"+n.to_bytes(2,"big")+body
sf=list(fields);sf[2]=der_tlv(0x30,bytes.fromhex("06092a864886f70d010701")+b"\xa0\x02\x04\0")
variants["attached_content"]=build(sf=sf)
results=[pack(name,data) for name,data in variants.items()]
(R/"cms-profile-fixtures.json").write_text(json.dumps({"count":len(results),"all_python_rejected":all(x["rejected"] for x in results),"fixtures":results},indent=2)+"\n")
print(json.dumps(results,indent=2))

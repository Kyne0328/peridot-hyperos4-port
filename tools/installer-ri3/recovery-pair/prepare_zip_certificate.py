#!/usr/bin/env python3
"""Generate or reuse one approved offline ZIP-signing key and public certificate."""
import datetime,hashlib,io,json,pathlib,zipfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.x509.oid import NameOID
from build_pair import ROOT,WORK,REPORT,key,write_exact
from pair_format import *
OUT=WORK/'images-ziptrust';OUT.mkdir(parents=True,exist_ok=True)
k=key(2048,'development-zip-rsa2048.pem')
subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'RI3 Offline Development ZIP Signing')])
pub=k.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
serial=int.from_bytes(hashlib.sha256(pub).digest()[:19],'big') or 1
cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key()).serial_number(serial).not_valid_before(datetime.datetime(2026,10,3,tzinfo=datetime.timezone.utc)).not_valid_after(datetime.datetime(2036,10,3,tzinfo=datetime.timezone.utc)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(k,hashes.SHA256()))
pem=cert.public_bytes(serialization.Encoding.PEM);der=cert.public_bytes(serialization.Encoding.DER)
write_exact(OUT/'development-zip.x509.pem',pem);write_exact(OUT/'development-zip.x509.der',der)
image=(WORK/'images/recovery.img').read_bytes();_,blocks=unpack_boot(image);raw=b''.join(x[1] for x in blocks);e=next(e for e in cpio_entries(raw) if e['name']=='system/etc/security/otacerts.zip');old=raw[e['offset']:e['offset']+e['size']]
require(sha(old)=='07d1291f830b7f6a97c0e7396fc99c250e8789a47b58ef843cbaf087ed1e335c','unexpected existing certificate store')
with zipfile.ZipFile(io.BytesIO(old)) as z:
 originals={i.filename:z.read(i) for i in z.infolist()};infos=z.infolist();require(len(originals)==len(infos),'duplicate source certificate entries')
 for n,b in originals.items():x509.load_pem_x509_certificate(b)
stream=io.BytesIO(old)
with zipfile.ZipFile(stream,'a',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 name='ri3-development-zip.x509.pem';require(name not in originals,'certificate name collision');i=zipfile.ZipInfo(name,(2026,10,3,0,0,0));i.create_system=3;i.external_attr=0o100644<<16;i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,pem,compresslevel=9)
new=stream.getvalue()
with zipfile.ZipFile(io.BytesIO(new)) as z:
 require(set(z.namelist())==set(originals)|{name},'unexpected certificate-store entries')
 for n,b in originals.items():require(z.read(n)==b,'existing trusted certificate changed')
 require(z.read(name)==pem,'new certificate mismatch')
write_exact(WORK/'otacerts-ziptrust.zip',new)
r={'trust_store':'/system/etc/security/otacerts.zip','source_store_sha256':sha(old),'candidate_store_sha256':sha(new),'source_size':len(old),'candidate_size':len(new),'original_certificates':{n:{'sha256':sha(b),'subject':x509.load_pem_x509_certificate(b).subject.rfc4514_string()} for n,b in originals.items()},'added_certificate':{'name':name,'pem_path':(OUT/'development-zip.x509.pem').relative_to(ROOT).as_posix(),'pem_sha256':sha(pem),'der_sha256':sha(der),'public_key_spki_sha256':sha(pub),'subject':subject.rfc4514_string(),'key_bits':2048,'digest':'sha256'},'preserves_all_original_certificate_bytes':True,'private_key_excluded':True,'scope':'offline candidate trust store only; no device trust or settings changed'}
(REPORT/'zip-certificate.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))

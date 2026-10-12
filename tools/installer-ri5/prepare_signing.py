"""Create a dedicated ZIP-only development identity outside disposable build caches."""
from pathlib import Path
import datetime, hashlib, json, os, subprocess, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'builder/work/installer-ri5-recoveryfix-20261004'
PRIVATE=ROOT/'.private/zip-signing/ri5-recoveryfix-20261004'
PRIVATE.mkdir(parents=True,exist_ok=True)
if os.name=='nt':
    owner=subprocess.run(['whoami'],capture_output=True,text=True,check=True).stdout.strip()
    subprocess.run(['icacls',str(PRIVATE),'/inheritance:r','/grant:r',owner+':(OI)(CI)F'],capture_output=True,check=True)
key_path=PRIVATE/'private.pem';cert_path=PRIVATE/'certificate.pem'
assert key_path.exists()==cert_path.exists(),'Incomplete signing identity'
if not key_path.exists():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.datetime.now(datetime.timezone.utc)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'RI5 Recovery Fix Development ZIP Signing')])
    cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(key,hashes.SHA256())
    with key_path.open('xb') as f:f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
    with cert_path.open('xb') as f:f.write(cert.public_bytes(serialization.Encoding.PEM))
else:
    key=serialization.load_pem_private_key(key_path.read_bytes(),None)
    cert=x509.load_pem_x509_certificate(cert_path.read_bytes())
assert key.public_key().public_numbers()==cert.public_key().public_numbers()
der=cert.public_bytes(serialization.Encoding.DER);fingerprint=hashlib.sha256(der).hexdigest()
sys.path.insert(0,str(ROOT/'tools/installer-ri3/zip-signing'))
from sign_zip import der_tlv,der_integer
sid=der_tlv(0x30,cert.issuer.public_bytes()+der_integer(cert.serial_number))
header='#pragma once\n#include <cstdint>\nnamespace ri3zip {\n'+''.join('inline constexpr uint8_t '+name+'[]={'+','.join('0x'+format(b,'02x') for b in data)+'};\n' for name,data in [('kTrustedCertDer',der),('kTrustedSignerId',sid)])+'}\n'
(WORK/'trusted_cert_der.h').write_text(header,encoding='utf-8')
public={'certificate_der_sha256':fingerprint,'rsa_modulus_hex':format(cert.public_key().public_numbers().n,'x'),
    'certificate_path':str(cert_path.relative_to(ROOT)),'private_key_path':str(key_path.relative_to(ROOT)),
    'purpose':'ZIP-only experimental development signing; all partition AVB images and phone trust unchanged',
    'prior_build_signing_directory_missing':True,'private_material_in_distributed_artifacts':False}
(WORK/'signing-public.json').write_text(json.dumps(public,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'certificate_der_sha256':fingerprint,'purpose':public['purpose'],'private_material_printed':False}))

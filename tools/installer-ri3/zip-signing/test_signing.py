#!/usr/bin/env python3
"""Bounded small positive/negative host fixtures for RI3 ZIP signing."""
import hashlib, json, pathlib, shutil, struct, sys, time, zipfile
from sign_zip import sign_generated_zip, OTACERT
from verify_zip import verify_zip, envelope, certificate, VerificationError

ROOT=pathlib.Path(__file__).resolve().parents[3]
WORK=ROOT/"builder/work/installer-ri3-zipsign"
CERT=ROOT/"builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem"
KEY=ROOT/"builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem"
REPORT=ROOT/"09-reports/installer-ri3/zip-signing"
def main():
    run=WORK/("fixtures-"+time.strftime("%Y%m%dT%H%M%SZ",time.gmtime()))
    run.mkdir(parents=True,exist_ok=False); REPORT.mkdir(parents=True,exist_ok=True)
    tests=[]
    def expect(name,fn,success=True):
        try:
            result=fn()
            if not success: raise AssertionError("Accepted negative fixture")
            tests.append({"name":name,"passed":True})
            return result
        except (VerificationError,ValueError,zipfile.BadZipFile) as ex:
            if success: raise
            tests.append({"name":name,"passed":True,"rejection":str(ex)})
    def make(name="unsigned.zip",cert=True,comment=b"",duplicate=False):
        p=run/name
        with zipfile.ZipFile(p,"w",allowZip64=True) as z:
            z.writestr("hello.txt",b"RI3 small fixture\n")
            if cert: z.writestr(OTACERT,CERT.read_bytes())
            if duplicate: z.writestr("hello.txt",b"duplicate")
            z.comment=comment
        return p
    def sign(p):
        return sign_generated_zip(p,CERT,KEY,generated_root=run,work_dir=WORK)
    p=make(); unsigned=p.read_bytes(); r=expect("positive_sign_and_independent_verify",lambda:sign(p))
    expect("positive_public_verify",lambda:verify_zip(p,CERT))
    signed=p.read_bytes(); env,cms=envelope(p)
    assert signed[:len(unsigned)-2]==unsigned[:-2]
    tests.append({"name":"original_signed_range_unchanged","passed":True})
    expect("already_signed_rejected",lambda:sign(p),False)
    for name,offset,delta in [("payload_tamper",40,1),("footer_marker",-4,1),
        ("signature_start_zero",-6,signed[-6]),("footer_comment_length",-1,1),
        ("EOCD_comment_mismatch",len(unsigned)-2,1),("CMS_signature_tamper",-7,1)]:
        data=bytearray(signed)
        if name=="signature_start_zero": data[-6:-4]=b"\0\0"
        else: data[offset]^=delta
        q=run/(name+".zip"); q.write_bytes(data)
        expect(name,lambda q=q:verify_zip(q,CERT),False)
    q=run/"truncated.zip"; q.write_bytes(signed[:-1])
    expect("truncated",lambda:verify_zip(q,CERT),False)
    q=run/"extra_eocd.zip"; data=bytearray(signed)
    comment_start=len(unsigned); data[comment_start:comment_start+4]=b"PK\x05\x06"; q.write_bytes(data)
    expect("spurious_eocd",lambda:verify_zip(q,CERT),False)
    expect("wrong_expected_trust_pin",lambda:verify_zip(p,CERT,"0"*64),False)
    expect("missing_otacert",lambda:sign(make("missing.zip",cert=False)),False)
    expect("preexisting_comment",lambda:sign(make("comment.zip",comment=b"hello")),False)
    expect("duplicate_members",lambda:sign(make("duplicate.zip",duplicate=True)),False)
    q=make("reserve.zip"); before=q.read_bytes()
    expect("disk_reserve_guard",lambda:sign_generated_zip(q,CERT,KEY,generated_root=run,
                    work_dir=WORK,reserve_bytes=shutil.disk_usage(WORK).total+1),False)
    assert q.read_bytes()==before
    # Another existing trusted cert is public evidence, never create an extra private key.
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    original=ROOT/"builder/work/installer-ri3-recovery"
    wrong=None
    for candidate in original.rglob("*.pem"):
        if ".private" in candidate.parts or candidate==CERT: continue
        try:
            x=x509.load_pem_x509_certificate(candidate.read_bytes())
            der=x.public_bytes(serialization.Encoding.DER)
            fp=hashlib.sha256(der).hexdigest()
            if fp != r["certificate_der_sha256"]: wrong=(candidate,fp); break
        except (ValueError, OSError): pass
    if wrong:
        expect("wrong_public_certificate",lambda:verify_zip(p,wrong[0],wrong[1]),False)
    out={"passed":True,"count":len(tests),"tests":tests,"positive":r,
         "fixture_dir":str(run.relative_to(ROOT)),"signed_fixture":str(p.relative_to(ROOT)),
         "wrong_public_certificate_fixture":bool(wrong)}
    (REPORT/"small-tests.json").write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps(out,indent=2))
if __name__=="__main__": main()

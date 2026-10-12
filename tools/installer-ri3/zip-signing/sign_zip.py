#!/usr/bin/env python3
"""Append a reviewed Android direct-CMS footer to a GENERATED, commentless ZIP.
Never pass a source ROM. No member rewrite, APK/JAR v1 signing, or device action.
Private key is consumed by OpenSSL from its existing path, never copied or logged.
"""
import argparse, hashlib, json, os, pathlib, shutil, struct, subprocess, tempfile, time, zipfile
from verify_zip import (TRUSTED_CERT_SHA256, certificate, extract_signature,
                        verify_rsa, verify_zip, need, EOCD, CHUNK)
from cryptography import x509
from cryptography.hazmat.primitives import serialization

OTACERT = "META-INF/com/android/otacert"
COMMENT_MESSAGE = b"signed by RI3 development\0"
RESERVE_BYTES = 12 * 1024**3

def der_tlv(tag,body):
    n=len(body)
    length=bytes([n]) if n<128 else bytes([0x80+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,"big")
    return bytes([tag])+length+body

def der_integer(n):
    b=n.to_bytes(max(1,(n.bit_length()+7)//8),"big")
    if b[0]&128:b=b"\0"+b
    return der_tlv(2,b)

def make_cms(cert,der,signature):
    # RFC5652 SignedData with the same direct-signature contract as SignApk.
    oid=lambda h:der_tlv(6,bytes.fromhex(h))
    seq=lambda b:der_tlv(0x30,b)
    sha256=seq(oid("608648016503040201")+b"\x05\0")
    rsa=seq(oid("2a864886f70d010101")+b"\x05\0")
    sid=seq(cert.issuer.public_bytes()+der_integer(cert.serial_number))
    signer=seq(der_integer(1)+sid+sha256+rsa+der_tlv(4,signature))
    sd=seq(der_integer(1)+der_tlv(0x31,sha256)+seq(oid("2a864886f70d010701"))+
           der_tlv(0xa0,der)+der_tlv(0x31,signer))
    return seq(oid("2a864886f70d010702")+der_tlv(0xa0,sd))

def process_peak_rss(proc):
    if os.name!="nt":return None
    import ctypes
    from ctypes import wintypes
    class PM(ctypes.Structure):
        _fields_=[("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD)]+[
         (name,ctypes.c_size_t) for name in ("PeakWorkingSetSize","WorkingSetSize",
          "QuotaPeakPagedPoolUsage","QuotaPagedPoolUsage","QuotaPeakNonPagedPoolUsage",
          "QuotaNonPagedPoolUsage","PagefileUsage","PeakPagefileUsage")]
    info=PM();info.cb=ctypes.sizeof(info)
    fn=ctypes.WinDLL("psapi").GetProcessMemoryInfo
    fn.argtypes=[wintypes.HANDLE,ctypes.POINTER(PM),wintypes.DWORD]
    fn.restype=wintypes.BOOL
    need(bool(fn(int(proc._handle),ctypes.byref(info),info.cb)),"Cannot measure OpenSSL memory")
    return info.PeakWorkingSetSize

def check_generated_path(path, generated_root, generated_parent=None):
    path=pathlib.Path(path).resolve(strict=True)
    root=pathlib.Path(generated_root).resolve(strict=True)
    workspace=pathlib.Path(__file__).resolve().parents[3]
    parent=(pathlib.Path(generated_parent).resolve(strict=True) if generated_parent is not None else workspace/"builder/work")
    need(root.is_relative_to(parent) and root!=parent, "Generated root must be below the explicitly selected generated parent")
    need(path.is_relative_to(root) and path != root, "ZIP outside generated root")
    need(path.is_file() and path.suffix.lower()==".zip", "Generated path must be regular .zip")
    # The caller must name the generated tree; this API intentionally has no generic in-place mode.
    return path,root

def unsigned_contract(path, trusted_der):
    size=path.stat().st_size
    need(size>=22,"Unsigned ZIP too small")
    with path.open("rb") as f:
        f.seek(-22,2); end=f.read(22)
    need(end[:4]==EOCD and end[-2:]==b"\0\0","Unsigned ZIP must end in commentless EOCD")
    need(EOCD not in end[4:],"Ambiguous EOCD in header")
    # Bound metadata allocations before allowing zipfile to read its central directory.
    cd_size=struct.unpack_from("<I",end,12)[0]
    if cd_size==0xffffffff:
        with path.open("rb") as f:
            f.seek(size-42); loc=f.read(20)
            need(loc[:4]==b"PK\x06\x07","Missing ZIP64 locator")
            disk,off,disks=struct.unpack_from("<IQI",loc,4)
            need(disk==0 and disks==1,"Split ZIP64 not supported")
            need(off <= size-98, "ZIP64 EOCD offset outside file")
            f.seek(off); z64=f.read(56)
        need(z64[:4]==b"PK\x06\x06","Missing ZIP64 EOCD")
        cd_size=struct.unpack_from("<Q",z64,40)[0]
    need(cd_size<=32*1024**2,"Central directory exceeds bounded 32 MiB metadata limit")
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        need(len(names)<=100000,"Too many ZIP members")
        need(len(names)==len(set(names)),"Duplicate ZIP member names")
        need(names.count(OTACERT)==1,"Exactly one public otacert member required")
        inf=z.getinfo(OTACERT)
        need(inf.file_size<=65536,"otacert too large")
        member=x509.load_pem_x509_certificate(z.read(inf))
        need(member.public_bytes(serialization.Encoding.DER)==trusted_der,
             "otacert member differs from signing certificate")
    return size,end,{"members":len(names),"central_directory_bytes":cd_size,
                     "zip64":b"PK\x06\x07" == read_at(path,size-42,4),
                     "otacert":OTACERT}

def read_at(path, off, size):
    with pathlib.Path(path).open("rb") as f:
        f.seek(off); return f.read(size)

def sign_generated_zip(path, cert_path, private_key_path, *, generated_root, work_dir,
                       openssl="C:/Program Files/Git/usr/bin/openssl.exe",
                       expected_cert_sha256=TRUSTED_CERT_SHA256,
                       reserve_bytes=RESERVE_BYTES, generated_parent=None):
    """Sign a caller-owned generated ZIP in place, then independently verify.
    Input must already contain exactly one matching public otacert and no comment.
    This writes only the last two EOCD bytes plus an appended <=65535-byte comment.
    On synchronous failure the original tail is restored; interrupted candidates
    must be discarded/rebuilt. Report is returned only after independent verify.
    """
    started=time.monotonic()
    path,root=check_generated_path(path,generated_root,generated_parent)
    work=pathlib.Path(work_dir).resolve(strict=True)
    need(work.is_dir() and work.is_relative_to(pathlib.Path(__file__).resolve().parents[3]),
         "Workspace-local work directory required")
    need(pathlib.Path(private_key_path).resolve(strict=True)!=path,"Invalid private-key path")
    cert,der,fp,n,e=certificate(cert_path,expected_cert_sha256)
    size,end,zipinfo=unsigned_contract(path,der)
    need(shutil.disk_usage(work).free>=reserve_bytes+1024**2,"Disk reserve below signing threshold")
    before=path.stat()
    env=os.environ.copy()
    env.update(TEMP=str(work),TMP=str(work),TMPDIR=str(work))
    with tempfile.TemporaryDirectory(prefix="cms-",dir=work) as td:
        td=pathlib.Path(td); sig_path=td/"signature.bin"; digest_path=td/"sha256.bin"
        whole,signed=hashlib.sha256(),hashlib.sha256()
        remaining=size-2
        with path.open("rb") as src:
            while remaining:
                block=src.read(min(CHUNK,remaining))
                need(bool(block),"ZIP shortened during hashing")
                signed.update(block); whole.update(block); remaining-=len(block)
            whole.update(src.read(2))
            need(src.read(1)==b"","ZIP grew during hashing")
        digest_path.write_bytes(signed.digest())
        # Only a 32-byte prehash enters OpenSSL. No payload-sized CMS buffering.
        cmd=[str(openssl),"pkeyutl","-sign",
             "-inkey",str(pathlib.Path(private_key_path).resolve()),
             "-pkeyopt","rsa_padding_mode:pkcs1","-pkeyopt","digest:sha256",
             "-in",str(digest_path),"-out",str(sig_path)]
        proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,env=env)
        try:
            stdout,stderr=proc.communicate(timeout=60)
            openssl_peak=process_peak_rss(proc)
            need(proc.returncode==0,"OpenSSL prehashed RSA signing failed")
        except BaseException:
            proc.kill(); proc.wait(); raise
        rawsig=sig_path.read_bytes()
        need(len(rawsig)==256,"Expected RSA2048 signature")
        cms=make_cms(cert,der,rawsig)
        # Independently prove the signature and trust before changing a ZIP byte.
        signature=extract_signature(cms,der)
        verify_rsa(signature,signed.digest(),n,e)
        total=len(COMMENT_MESSAGE)+len(cms)+6
        need(total<=65535,"ZIP comment overflow")
        footer=struct.pack("<HHH",len(cms)+6,65535,total)
        newtail=struct.pack("<H",total)+COMMENT_MESSAGE+cms+footer
        need(EOCD not in end[4:-2]+newtail,"Spurious EOCD in final footer")
        now=path.stat()
        need((before.st_size,before.st_mtime_ns,before.st_ino)==
             (now.st_size,now.st_mtime_ns,now.st_ino),"ZIP identity changed during signing")
        try:
            with path.open("r+b") as dst:
                dst.seek(size-2); need(dst.write(newtail)==len(newtail),"Short footer write")
                dst.flush(); os.fsync(dst.fileno())
            verified=verify_zip(path,cert_path,expected_cert_sha256)
            need(verified["signed_sha256"]==signed.hexdigest(),"Signed bytes changed after signing")
        except BaseException:
            with path.open("r+b") as dst:
                dst.seek(size-2); dst.write(b"\0\0"); dst.truncate(size)
                dst.flush(); os.fsync(dst.fileno())
            raise
    verified.update(zipinfo)
    verified.update({"unsigned_bytes":size,"unsigned_sha256":whole.hexdigest(),
        "added_bytes":total,"seconds":round(time.monotonic()-started,3),
        "disk_reserve_bytes":reserve_bytes,"private_key_material_in_artifacts":False,
        "method":"Streaming SHA256; OpenSSL pkeyutl signs 32-byte prehash; canonical detached DER CMS without attributes",
        "openssl_input_bytes":32,"openssl_peak_working_set_bytes":openssl_peak})
    return verified

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--generated-zip",required=True)
    p.add_argument("--generated-root",required=True)
    p.add_argument("--cert",required=True); p.add_argument("--private-key",required=True)
    p.add_argument("--work-dir",required=True); p.add_argument("--report",required=True)
    p.add_argument("--openssl",default="C:/Program Files/Git/usr/bin/openssl.exe")
    a=p.parse_args()
    r=sign_generated_zip(a.generated_zip,a.cert,a.private_key,
                        generated_root=a.generated_root,work_dir=a.work_dir,openssl=a.openssl)
    pathlib.Path(a.report).write_text(json.dumps(r,indent=2)+"\n")
    print(json.dumps(r,indent=2))

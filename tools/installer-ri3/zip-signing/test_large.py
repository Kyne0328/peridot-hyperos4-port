#!/usr/bin/env python3
"""Create one NTFS-sparse regular >10 GiB ZIP64 fixture, sign and verify it.
No large copy; no source archives or devices. Requires 12 GiB physical free reserve.
"""
import ctypes,hashlib,json,msvcrt,os,pathlib,shutil,struct,time,zlib
from ctypes import wintypes
from sign_zip import sign_generated_zip,OTACERT,RESERVE_BYTES
ROOT=pathlib.Path(__file__).resolve().parents[3]
WORK=ROOT/"builder/work/installer-ri3-zipsign"
REPORT=ROOT/"09-reports/installer-ri3/zip-signing/large-prehashed-test.json"
CERT=ROOT/"builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem"
KEY=ROOT/"builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem"
SIZE=10*1024**3+1024**2
def make_sparse(f):
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    k.DeviceIoControl.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,
                              ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
    k.DeviceIoControl.restype=wintypes.BOOL
    n=wintypes.DWORD()
    if not k.DeviceIoControl(msvcrt.get_osfhandle(f.fileno()),0x900c4,None,0,None,0,ctypes.byref(n),None):
        raise ctypes.WinError(ctypes.get_last_error())
def physical(path):
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    k.GetCompressedFileSizeW.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(wintypes.DWORD)]
    k.GetCompressedFileSizeW.restype=wintypes.DWORD
    high=wintypes.DWORD()
    low=k.GetCompressedFileSizeW(str(path),ctypes.byref(high))
    if low==0xffffffff and ctypes.get_last_error():raise ctypes.WinError(ctypes.get_last_error())
    return low+(high.value<<32)
def peak_rss():
    from ctypes import c_size_t
    class PM(ctypes.Structure):
        _fields_=[("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD)]+[
           (n,c_size_t) for n in ["PeakWorkingSetSize","WorkingSetSize","QuotaPeakPagedPoolUsage",
              "QuotaPagedPoolUsage","QuotaPeakNonPagedPoolUsage","QuotaNonPagedPoolUsage",
              "PagefileUsage","PeakPagefileUsage"]]
    p=PM();p.cb=ctypes.sizeof(p)
    fn=ctypes.WinDLL("psapi").GetProcessMemoryInfo
    fn.argtypes=[wintypes.HANDLE,ctypes.POINTER(PM),wintypes.DWORD]
    fn.restype=wintypes.BOOL
    if not fn(wintypes.HANDLE(-1),ctypes.byref(p),p.cb):raise ctypes.WinError()
    return p.PeakWorkingSetSize
def main():
    free_before=shutil.disk_usage(WORK).free
    if free_before<RESERVE_BYTES+16*1024**2:raise RuntimeError("Insufficient free reserve")
    path=WORK/"sparse-10gib-prehashed-fixture.zip"
    if path.exists():raise RuntimeError("Fixture already exists; inspect previous run, do not overwrite")
    started=time.monotonic()
    zeros=b"\0"*1024**2; crc=0
    for _ in range(SIZE//len(zeros)):crc=zlib.crc32(zeros,crc)
    cert=CERT.read_bytes()
    records=[]
    with path.open("x+b") as f:
        make_sparse(f)
        for name,data,length,crc32 in [("payload.zero",None,SIZE,crc),
                    (OTACERT,cert,len(cert),zlib.crc32(cert))]:
            name=name.encode();off=f.tell();extra=struct.pack("<HHQQ",1,16,length,length)
            f.write(struct.pack("<IHHHHHIIIHH",0x04034b50,45,0,0,0,33,crc32,
                         0xffffffff,0xffffffff,len(name),len(extra))+name+extra)
            if data is None:f.seek(length,1)
            else:f.write(data)
            records.append((name,off,length,crc32))
        cdoff=f.tell()
        for name,off,length,crc32 in records:
            extra=struct.pack("<HHQQQ",1,24,length,length,off)
            f.write(struct.pack("<IHHHHHHIIIHHHHHII",0x02014b50,45,45,0,0,0,33,crc32,
              0xffffffff,0xffffffff,len(name),len(extra),0,0,0,0,0xffffffff)+name+extra)
        cdsize=f.tell()-cdoff;z64off=f.tell()
        f.write(struct.pack("<IQHHIIQQQQ",0x06064b50,44,45,45,0,0,2,2,cdsize,cdoff))
        f.write(struct.pack("<IIQI",0x07064b50,0,z64off,1))
        f.write(struct.pack("<IHHHHIIH",0x06054b50,0,0,65535,65535,0xffffffff,0xffffffff,0))
        f.flush();os.fsync(f.fileno())
    allocated_before=physical(path)
    if allocated_before>16*1024**2:raise RuntimeError("Sparse fixture unexpectedly materialized")
    # zipfile parses the independent ZIP64 structure and cert; signer enforces contract.
    result=sign_generated_zip(path,CERT,KEY,generated_root=WORK,work_dir=WORK)
    allocated_after=physical(path);free_after=shutil.disk_usage(WORK).free
    out={"passed":True,"regular_host_fixture":str(path.relative_to(ROOT)),
         "logical_payload_bytes":SIZE,"physical_bytes_before":allocated_before,
         "physical_bytes_after":allocated_after,"free_disk_before":free_before,
         "free_disk_after":free_after,"reserve_bytes":RESERVE_BYTES,
         "python_peak_working_set_bytes":peak_rss(),"seconds":time.monotonic()-started,
         "signed":result}
    if free_after<RESERVE_BYTES:raise RuntimeError("Reserve violated")
    REPORT.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps(out,indent=2))
if __name__=="__main__":main()

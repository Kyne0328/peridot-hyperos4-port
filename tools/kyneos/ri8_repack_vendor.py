"""RI8 stage 1: reproduce Qualcomm minijail-policy correction in the stock peridot vendor EROFS.

This script NEVER flashes the phone or edits the original image. It requires two
pinned original policy byte sequences, adds only the denied lseek syscall to
each policy, preserves every original path/UID/GID/mode/SELinux xattr and
hardlink, and independently re-reads all output EROFS entries.
"""
from __future__ import annotations
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/"tools/postboot"), str(ROOT/"tools/kyneos")]
from image import Image
from repack_system_call_audio import Reader, small, image_hash, sha

TOOLS = ROOT/"builder/tools/bin/windows"
SOURCE = ROOT/"builder/work/kyneos-ri7-20261005/vendor.img"
EXPECTED_SHA = "42b6e24e3ee5a665535621920d77a88ffd6d99ec2359522bc8a8e82cc6a5a9a7"
WORK = Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")
PATHS = (
    "/etc/seccomp_policy/atfwd@2.0.policy",
    "/etc/seccomp_policy/qesdksec.policy",
)
EXPECTED_BYTES = (1545, 1482)

def prepare_patch(original: bytes) -> bytes:
    if b"\r" in original or b"lseek:" in original or not original.endswith(b"\n"):
        raise ValueError("Unexpected source policy format or lseek already present")
    if original.count(b"\npread64: 1\n") != 1:
        raise ValueError("Source does not have unique pread64 insertion anchor")
    new = original.replace(b"\npread64: 1\n", b"\npread64: 1\nlseek: 1\n", 1)
    if new.replace(b"lseek: 1\n", b"", 1) != original:
        raise ValueError("Policy patch changed unrelated bytes")
    return new

def run():
    if sha(SOURCE) != EXPECTED_SHA:
        raise ValueError("Exact source vendor image changed; refusing to patch")
    WORK.mkdir(parents=True, exist_ok=True)
    tar = WORK/"vendor-ri8.tar"
    fs = WORK/"vendor-ri8-filesystem.img"
    receipt_path = WORK/"vendor-ri8-repack.json"
    if any(x.exists() for x in (tar, fs, receipt_path)):
        raise FileExistsError("RI8 outputs already exist; refuse overwrite")
    original = Image(SOURCE)
    rows = original.inventory()
    by = {r["path"]:r for r in rows}
    if len(by) != len(rows) or len(rows) < 2000:
        raise ValueError("Unexpected vendor inventory")
    replacements = {}
    changes = []
    for path, n in zip(PATHS, EXPECTED_BYTES):
        row = by[path]
        if row["size"] != n or not stat.S_ISREG(row["mode"]):
            raise ValueError("Vendor source policy shape drift")
        before = small(SOURCE, row["nid"], n)
        after = prepare_patch(before)
        replacements[path] = after
        changes.append({"path":path,"old_sha256":hashlib.sha256(before).hexdigest(),
                        "new_sha256":hashlib.sha256(after).hexdigest(),
                        "old_bytes":len(before),"new_bytes":len(after),
                        "sole_added_rule":"lseek: 1"})
    seen = {}
    hashes = {}
    expected = []
    print("Writing immutable-source-derived vendor tar", flush=True)
    with tarfile.open(tar, "x", format=tarfile.PAX_FORMAT) as archive:
        for index,row in enumerate(sorted(rows,key=lambda x:(x["path"].count("/"),x["path"]))):
            path=row["path"]
            entry=tarfile.TarInfo(path.lstrip("/") or ".")
            entry.mode=row["mode"]&0o7777
            entry.uid=row["uid"]
            entry.gid=row["gid"]
            entry.mtime=1230768000
            entry.pax_headers={"LIBARCHIVE.xattr."+key:base64.b64encode(bytes.fromhex(value)).decode()
                              for key,value in row["xattrs"].items()}
            rec={key:row[key] for key in ("path","mode","uid","gid","xattrs")}
            if stat.S_ISDIR(row["mode"]):
                entry.type=tarfile.DIRTYPE
                archive.addfile(entry)
            elif stat.S_ISLNK(row["mode"]):
                raw=small(SOURCE,row["nid"],row["size"])
                entry.type=tarfile.SYMTYPE
                entry.linkname=raw.decode()
                archive.addfile(entry)
                rec.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            elif stat.S_ISREG(row["mode"]):
                if path in replacements:
                    raw=replacements[path]
                    entry.size=len(raw)
                    archive.addfile(entry,io.BytesIO(raw))
                    digest=hashlib.sha256(raw).hexdigest()
                elif row["nid"] in seen:
                    entry.type=tarfile.LNKTYPE
                    entry.linkname=seen[row["nid"]]
                    entry.size=row["size"]
                    archive.addfile(entry)
                    digest=hashes[row["nid"]]
                else:
                    entry.size=row["size"]
                    process=subprocess.Popen([str(TOOLS/"dump.erofs.exe"),"--cat",
                        "--nid="+str(row["nid"]),str(SOURCE)],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    reader=Reader(process.stdout)
                    archive.addfile(entry,reader)
                    if reader.count!=entry.size or process.stdout.read(1):
                        raise ValueError("Bad streamed file "+path)
                    err=process.stderr.read()
                    if process.wait():
                        raise RuntimeError("EROFS cat failed "+path+" "+err.decode(errors="replace"))
                    digest=reader.hash.hexdigest()
                if row["nid"] not in seen:
                    seen[row["nid"]]=entry.name
                    hashes[row["nid"]]=digest
                rec.update(size=entry.size,sha256=digest)
            else:
                raise ValueError("Unexpected special inode "+path)
            expected.append(rec)
            if index%500==0:
                print("Prepared",index,"of",len(rows),flush=True)
    original.close()
    with SOURCE.open("rb") as input:
        input.seek(1072)
        ident=uuid.UUID(bytes=input.read(16))
    env=os.environ.copy()
    temp=WORK/"temp"
    temp.mkdir(exist_ok=True)
    env.update(TEMP=str(temp),TMP=str(temp),TMPDIR=str(temp))
    subprocess.run([str(TOOLS/"mkfs.erofs.exe"),"-d0","-T1230768000","-U",str(ident),
                    "-zlz4hc,level=12","--tar=f",str(fs),str(tar)],
                   env=env,check=True)
    if fs.stat().st_size > SOURCE.stat().st_size-8*1024**2:
        raise ValueError("No guaranteed room for AVB footer in fixed vendor image")
    subprocess.run([str(TOOLS/"fsck.erofs.exe"),str(fs)],check=True)
    rebuilt=Image(fs)
    actual={row["path"]:row for row in rebuilt.inventory()}
    by_expected={row["path"]:row for row in expected}
    if len(actual)!=len(expected) or set(actual)!=set(by_expected):
        raise ValueError("Authored vendor path set differs from original")
    for index,(path,row) in enumerate(by_expected.items()):
        got=actual[path]
        for field in ("mode","uid","gid","xattrs"):
            if got[field]!=row[field]:
                raise ValueError("Vendor metadata changed: "+path+" "+field)
        if "sha256" in row and image_hash(fs,got["nid"],row["size"]) != row["sha256"]:
            raise ValueError("Vendor file changed: "+path)
        if index%500==0:
            print("Verified",index,"of",len(expected),flush=True)
    rebuilt.close()
    receipt={
        "base":"KYNEOS-RI7.3-20261007",
        "source_vendor_sha256":EXPECTED_SHA,
        "filesystem_path":str(fs),
        "filesystem_sha256":sha(fs),
        "filesystem_bytes":fs.stat().st_size,
        "allocation_bytes":SOURCE.stat().st_size,
        "all_original_paths_unchanged":True,
        "all_file_contents_and_metadata_verified":True,
        "changes":changes,
        "phone_kernel_or_root_addon_changed":False,
        "vendor_image_AVB_footer_authored":False,
        "ROM_ZIP_signed":False,
        "phone_flash_or_reboot":False
    }
    receipt_path.write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":"vendor_filesystem_verified","changes":changes,
        "vendor_filesystem_bytes":fs.stat().st_size},indent=2),flush=True)

if __name__=="__main__":
    run()

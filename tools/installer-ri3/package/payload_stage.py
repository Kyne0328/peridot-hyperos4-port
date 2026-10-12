#!/usr/bin/env python3
"""Build and independently verify a non-installable RI3 payload-only .partial archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import zipfile
import sparse_super as sparse
from estimate_layout import estimate_stored_zip
from plan_sources import checked_json, checked_hash, FROZEN_CONTRACT, FROZEN_CONTRACT_SHA

FORBIDDEN = {"META-INF/com/google/android/update-binary", "META-INF/com/google/android/updater-script"}
FINALIZATION_BUDGET = 64 * 1024**2
SIGNING_BUDGET = 1024**2
TRANSIENT_BUDGET = 11 * 1024**3


def own_process_memory():
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_=[("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD)] + [
            (name,ctypes.c_size_t) for name in ("PeakWorkingSetSize","WorkingSetSize",
            "QuotaPeakPagedPoolUsage","QuotaPagedPoolUsage","QuotaPeakNonPagedPoolUsage",
            "QuotaNonPagedPoolUsage","PagefileUsage","PeakPagefileUsage")]
    data=Counters(); data.cb=ctypes.sizeof(data)
    process=ctypes.windll.kernel32.GetCurrentProcess
    process.restype=wintypes.HANDLE
    call=ctypes.windll.psapi.GetProcessMemoryInfo
    call.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
    call.restype=wintypes.BOOL
    if not call(process(),ctypes.byref(data),data.cb):
        return {"available":False}
    return {"available":True,"peak_working_set_bytes":data.PeakWorkingSetSize,
            "working_set_bytes":data.WorkingSetSize,"peak_pagefile_usage_bytes":data.PeakPagefileUsage}

def info_for(member):
    info = zipfile.ZipInfo(member["zip_path"], (1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o100644 << 16
    info.file_size = member["encoded_size"]
    return info

def require_free(root, remaining, system_headroom):
    free = shutil.disk_usage(root).free
    sparse.check(free >= max(0, remaining) + system_headroom + FINALIZATION_BUDGET + SIGNING_BUDGET,
                 "disk budget changed: insufficient remaining-output/transient/system headroom")
    return free

def image_record(root, source, name, sha):
    p = sparse.regular(root/source)
    identity = checked_hash(p, p.stat().st_size, sha)
    return {"zip_path": name, "source_path": source, "raw_size": p.stat().st_size,
            "encoded_size": p.stat().st_size, "raw_sha256": sha, "encoded_sha256": sha,
            "encoding": "raw", "zip_method": "ZIP_STORED", "source_identity": identity}

class ReadHash:
    def __init__(self, source):
        self.source, self.digest, self.count = source, hashlib.sha256(), 0
    def read(self, length=-1):
        data = self.source.read(length)
        self.digest.update(data); self.count += len(data)
        return data

def verify_archive(path, members, emitted_super_sha):
    expected = {x["zip_path"]:x for x in members}
    findings = []
    with zipfile.ZipFile(path, "r", allowZip64=True) as archive:
        sparse.check(archive.comment == b"", "partial archive must be unsigned/commentless")
        sparse.check(archive.namelist() == sorted(expected), "entry list or deterministic order mismatch")
        sparse.check(not FORBIDDEN.intersection(archive.namelist()), "installer entry in payload-only archive")
        sparse.check(archive.namelist().count("META-INF/com/android/otacert") == 1,
                     "exactly one public certificate required")
        for info in archive.infolist():
            member = expected[info.filename]
            sparse.check(info.compress_type == zipfile.ZIP_STORED and
                         info.file_size == member["encoded_size"] and
                         info.compress_size == member["encoded_size"],
                         "ZIP member encoded size/method mismatch")
            sparse.check(not (info.flag_bits & (1 | 8)), "encryption/data-descriptor not permitted")
            with archive.open(info, "r") as source:
                read = ReadHash(source)
                if member["encoding"].startswith("android_sparse"):
                    decoded = sparse.validate_stream(read, expected_bytes=member["raw_size"],
                                 expected_sha256=member["raw_sha256"], capacity_bytes=member["raw_size"])
                    sparse.check(read.digest.hexdigest() == emitted_super_sha,
                                 "encoded sparse SHA changed in ZIP")
                else:
                    for unused in iter(lambda: read.read(sparse.IO_BYTES), b""):
                        pass
                    sparse.check(read.digest.hexdigest() == member["encoded_sha256"],
                                 "ordinary ZIP member hash mismatch")
                    decoded = None
                sparse.check(read.count == member["encoded_size"], "encoded readback byte mismatch")
            findings.append({"zip_path": info.filename, "raw_size": member["raw_size"],
                "raw_sha256": member["raw_sha256"], "encoded_size": read.count,
                "encoded_sha256": read.digest.hexdigest(), "zip_crc32": f"{info.CRC:08x}",
                "header_offset": info.header_offset, "expanded_validation": decoded})
    return findings

def build(root, plan_path, plan_sha, output, *, system_headroom):
    started = time.monotonic()
    plan = checked_json(plan_path, plan_sha)
    sparse.check(plan["phase"] == "verified_sources_and_exact_sparse_plan" and not plan["archive_created"],
                 "invalid source plan state")
    checked_json(root/FROZEN_CONTRACT, FROZEN_CONTRACT_SHA)
    members = list(plan["members"])
    members.append(image_record(root, FROZEN_CONTRACT, "RI3-RECOVERY-CONTRACT.json", FROZEN_CONTRACT_SHA))
    members.sort(key=lambda x:x["zip_path"])
    sparse.check(len({m["zip_path"] for m in members}) == len(members), "duplicate payload names")
    sparse.check(not FORBIDDEN.intersection(m["zip_path"] for m in members), "installer entries forbidden")
    sparse.check(len(members) == 34, "expected 32 images, one certificate, one frozen contract")
    layout = estimate_stored_zip(members)
    sparse.check(output.suffix == ".partial" and "NOT-INSTALLABLE" in output.name,
                 "payload archive must be clearly named non-installable .partial")
    sparse.check(output.is_relative_to(root/"builder/work/installer-ri3-package"),
                 "output outside owned staging directory")
    sparse.check(not output.exists() and not output.is_symlink(), "output exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    before = require_free(root, layout["unsigned_zip_bytes"] + TRANSIENT_BUDGET, system_headroom)
    print(json.dumps({"phase":"payload_stream_start","predicted_zip_bytes":layout["unsigned_zip_bytes"],
                      "free_bytes":before,"system_headroom_bytes":system_headroom}), flush=True)
    super_sha = None
    with output.open("xb") as outer:
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for member in members:
                require_free(root, layout["unsigned_zip_bytes"]-outer.tell(), system_headroom)
                p = sparse.regular(root/member["source_path"])
                sparse.check(list(sparse.fingerprint(p.stat())) == member["source_identity"],
                             "source identity changed after planning")
                with archive.open(info_for(member), "w", force_zip64=True) as destination:
                    class GuardedSink:
                        def write(self, data):
                            require_free(root, layout["unsigned_zip_bytes"]-outer.tell(), system_headroom)
                            return destination.write(data)
                    sink = GuardedSink()
                    if member["encoding"].startswith("android_sparse"):
                        result = sparse.emit_stream(p, sink, plan["super_plan"],
                                    expected_bytes=member["raw_size"], expected_sha256=member["raw_sha256"],
                                    capacity_bytes=member["raw_size"], allow_large_output=True)
                        super_sha = result["sparse_sha256"]
                    else:
                        digest, count = hashlib.sha256(), 0
                        with p.open("rb") as source:
                            identity = sparse.fingerprint(os.fstat(source.fileno()))
                            sparse.check(list(identity) == member["source_identity"], "source changed before open")
                            for block in iter(lambda:source.read(sparse.IO_BYTES), b""):
                                sparse.check(sink.write(block) == len(block), "short ZIP write")
                                digest.update(block); count += len(block)
                            sparse.check(identity == sparse.fingerprint(os.fstat(source.fileno())),
                                         "source changed during ZIP emission")
                        sparse.check(count == member["encoded_size"] and digest.hexdigest() == member["encoded_sha256"],
                                     "source payload hash or length changed")
        outer.flush(); os.fsync(outer.fileno())
    sparse.check(output.stat().st_size == layout["unsigned_zip_bytes"], "actual ZIP size differs from exact layout")
    sparse.check(super_sha is not None, "missing sparse super")
    verified_identity = sparse.fingerprint(output.stat())
    print(json.dumps({"phase":"payload_stream_complete","zip_bytes":output.stat().st_size,
                      "super_encoded_sha256":super_sha}), flush=True)
    require_free(root, 0, system_headroom)
    findings = verify_archive(output, members, super_sha)
    digest = hashlib.sha256()
    with output.open("rb") as source:
        for block in iter(lambda:source.read(sparse.IO_BYTES), b""):
            digest.update(block)
    sparse.check(sparse.fingerprint(output.stat()) == verified_identity,
                 "partial archive changed during independent readback/hash")
    after = require_free(root, 0, system_headroom)
    return {"schema_version":1,"phase":"payload_only_verified","installable":False,"signed":False,
            "updater_entries_absent":True,"archive_comment_empty":True,"private_keys_in_archive":False,
            "archive_path":str(output.relative_to(root)).replace("\\","/"),
            "archive_bytes":output.stat().st_size,"archive_sha256":digest.hexdigest(),
            "plan_path":str(plan_path.relative_to(root)).replace("\\","/"),"plan_sha256":plan_sha,
            "frozen_contract_sha256":FROZEN_CONTRACT_SHA,"exact_layout":layout,"members":findings,
            "free_bytes_before":before,"free_bytes_after":after,"system_headroom_bytes":system_headroom,
            "finalization_budget_bytes":FINALIZATION_BUDGET,"signing_budget_bytes":SIGNING_BUDGET,
            "upfront_external_transient_allowance_bytes":TRANSIENT_BUDGET,
            "elapsed_seconds":time.monotonic()-started,"no_intermediate_raw_or_sparse_file":True,
            "own_process_memory":own_process_memory(),
            "pending":["Final native updater/script pins","Final metadata and reproducible append validation",
                       "Whole-file ZIP signing by separate authorized signer","Final independent verification"]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan",type=Path,required=True)
    p.add_argument("--plan-sha256",required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--system-headroom-bytes",type=int,required=True)
    p.add_argument("--allow-large-payload-only",action="store_true")
    a=p.parse_args()
    sparse.check(a.allow_large_payload_only,"explicit large payload-only authorization required")
    sparse.check(a.system_headroom_bytes >= 4*1024**3,"at least 4 GiB explicit system headroom required")
    root=Path(__file__).resolve().parents[3]
    report=a.report.resolve()
    sparse.check(report.is_relative_to(root/"09-reports/installer-ri3/package") and not report.exists(),
                 "invalid or existing report destination")
    result=build(root,a.plan.resolve(),a.plan_sha256,a.output.resolve(),system_headroom=a.system_headroom_bytes)
    with report.open("x",encoding="utf-8",newline="\n") as f:
        json.dump(result,f,sort_keys=True,indent=2);f.write("\n")
    print(json.dumps({k:result[k] for k in ("phase","archive_path","archive_bytes","archive_sha256",
                                          "free_bytes_after","elapsed_seconds")}),flush=True)

if __name__=="__main__":
    main()

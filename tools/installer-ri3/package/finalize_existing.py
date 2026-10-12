#!/usr/bin/env python3
"""Finalize the already verified RI3 payload in place; no image copy or device access."""
import argparse, hashlib, json, os, pathlib, shutil, struct, sys, time, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"tools/installer-ri3/package"))
import sparse_super as sparse
from payload_stage import ReadHash, own_process_memory
CHUNK=1024*1024
OWN=ROOT/"builder/work/installer-ri3-package"
RECEIPT=ROOT/"09-reports/installer-ri3/package/payload-stage-20261003T0410.json"
RECEIPT_SHA="ed651e31ce596eb25283588252f159fd9a6bca5021d7fc1c92f5b2d61abcd5bb"
PARTIAL=OWN/"F6-Global-HyperOS4-DEV2-RI3-PAYLOAD-ONLY-NOT-INSTALLABLE.partial"
PAYLOAD_SHA="9a852aa71090f4aeecc9fb0c859099f69d5ff1ca566b58fb20826a587fb12cfd"
BASENAME="F6-Global-HyperOS4-DEV2-RI3-20261003"
UPDATER="builder/work/installer-ri3-native/runtime-integration/android-release-20261003T1018/update-binary"
UPDATER_SHA="04eb94933170c8d5de0345860ffa18b3d8c0a677ad32eeebcdb770fefffb871c"
SCRIPT="tools/installer-ri3/native-updater/runtime/updater-script"
SCRIPT_SHA="4d485206947acf128a0d418d74010376ea6604e0396330222ab49aa762c7f64c"
CERT="builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem"
CERT_SHA="099a2c2261110568ef1e48b4929a8d3f4e76ffd71b49ee9bf7fe5074987f31d8"
SOURCE=".cache/global-single-recovery-ri2/source-images/MANIFEST.json"
SOURCE_SHA="bc5f9e4f415e2910667aae20935e3130a1bfa99acb46c1131c170b31a325c38b"
CONTRACT="09-reports/installer-ri3/recovery-pair/FROZEN-CONTRACT.json"
CONTRACT_SHA="76b6b839b320fd4796808fe9fa7ab4c03cc4e81bbd275a7617f26a80930515c0"
CODE_PINS={
 "tools/installer-ri3/package/sparse_super.py":"0f689fe48c984fae0a1cecaa62da59ab74200ebca5bd823b5c8681d7f537bdfc",
 "tools/installer-ri3/package/payload_stage.py":"028fef283925790e86ad9d53a5811ccf7892e74a80cad60f184ee0df0f070d39",
 "tools/installer-ri3/zip-signing/sign_zip.py":"db8dad37ef7f2560cea9d15dfb68ead65958551b52587c6bc84d8a635753b875",
 "tools/installer-ri3/zip-signing/verify_zip.py":"5a3c91dfaccbd345d39c04f21a506b7fd4843338660b4c3a948c19b46c80f9fc"}
def need(ok,msg):
 if not ok: raise RuntimeError(msg)
def fingerprint(p):
 s=p.stat(); return [s.st_size,s.st_mtime_ns,s.st_dev,s.st_ino]
def digest(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(CHUNK),b""): h.update(b)
 return h.hexdigest()
def canonical(obj):
 return (json.dumps(obj,sort_keys=True,indent=2)+"\n").encode("utf-8")
def exclusive(p,data):
 need(not p.exists() and not p.is_symlink(),"Destination already exists: "+str(p))
 with p.open("xb") as f:
  need(f.write(data)==len(data),"Short write"); f.flush(); os.fsync(f.fileno())
def pinned(p,sha,size=None):
 need(p.is_file() and not p.is_symlink(),"Expected regular input: "+str(p))
 need(p.stat().st_size<=32*1024**2,"Small input exceeds bound")
 before=fingerprint(p); b=p.read_bytes()
 need(fingerprint(p)==before and hashlib.sha256(b).hexdigest()==sha,"Input pin changed: "+str(p))
 need(size is None or len(b)==size,"Input length changed: "+str(p))
 return b
def safe_name(name):
 return bool(name) and name.isascii() and not name.startswith("/") and not any(c in name for c in ("\0","\\",":")) and all(x not in ("",".","..") for x in name.split("/"))
def zip_info(name,n):
 need(safe_name(name),"Unsafe member name")
 z=zipfile.ZipInfo(name,(1980,1,1,0,0,0)); z.create_system=3
 z.external_attr=(0o100755 if name.endswith("/update-binary") else 0o100644)<<16
 z.compress_type=zipfile.ZIP_STORED; z.file_size=n
 return z
def append_entries(path,entries):
 with zipfile.ZipFile(path,"a",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
  need(z.comment==b"","Append requires unsigned ZIP")
  names=z.namelist()
  need(len(set(names))==len(names),"Duplicate existing names")
  need(not set(names).intersection(n for n,b in entries),"Append member already exists")
  for name,body in entries:
   with z.open(zip_info(name,len(body)),"w",force_zip64=True) as f:
    for off in range(0,len(body),CHUNK):
     b=body[off:off+CHUNK]; need(f.write(b)==len(b),"Short ZIP write")
 with path.open("r+b") as f: f.flush(); os.fsync(f.fileno())
def check_headers(path,expected,comment_expected):
 findings=[]
 with zipfile.ZipFile(path) as z, path.open("rb") as f:
  infos=z.infolist()
  need(len(infos)==len(expected) and [i.filename for i in infos]==list(expected),"Member list/order differs")
  need(bool(z.comment)==comment_expected,"Unexpected signature comment state")
  need(len(infos)<=100000 and len({i.filename for i in infos})==len(infos),"Invalid entry count")
  off=0
  for i in infos:
   row=expected[i.filename]
   need(safe_name(i.filename) and not i.is_dir(),"Invalid member name")
   need(i.header_offset==off,"Non-contiguous, hidden, or overlapping local member")
   need(i.compress_type==zipfile.ZIP_STORED and not(i.flag_bits&(1|8)),"Encrypted, compressed, or descriptor member")
   need(i.file_size==row["encoded_size"] and i.compress_size==row["encoded_size"],"Encoded size mismatch")
   f.seek(off); h=f.read(30); need(len(h)==30,"Truncated local header")
   v=struct.unpack("<IHHHHHIIIHH",h)
   need(v[0]==0x04034b50 and v[2]==i.flag_bits and v[3]==i.compress_type and v[6]==i.CRC,"Local/central header mismatch")
   name=f.read(v[9]); extra=f.read(v[10])
   need(name==i.filename.encode("ascii"),"Local name mismatch")
   need(v[7]==v[8]==0xffffffff and len(extra)==20,"Canonical local ZIP64 required")
   tag,n,usize,csize=struct.unpack("<HHQQ",extra)
   need(tag==1 and n==16 and usize==i.file_size and csize==i.compress_size,"Local ZIP64 size mismatch")
   off=f.tell()+i.compress_size
   findings.append({"zip_path":i.filename,"header_offset":i.header_offset,"data_offset":f.tell(),
                    "encoded_size":i.file_size,"zip_crc32":f"{i.CRC:08x}","data_descriptor":False})
  need(off==z.start_dir,"Unexpected gap before central directory")
 return findings
def verify_members(path,expected):
 out=[]
 with zipfile.ZipFile(path) as z:
  for name,row in expected.items():
   inf=z.getinfo(name)
   with z.open(inf) as f:
    r=ReadHash(f)
    if name=="images/super.img":
     expanded=sparse.validate_stream(r,expected_bytes=row["raw_size"],expected_sha256=row["raw_sha256"],capacity_bytes=row["raw_size"])
    else:
     for b in iter(lambda:r.read(CHUNK),b""): pass
     expanded=None
    need(r.count==row["encoded_size"] and r.digest.hexdigest()==row["encoded_sha256"],"Final member digest mismatch: "+name)
   out.append({"zip_path":name,"encoded_size":r.count,"encoded_sha256":r.digest.hexdigest(),
               "raw_size":row["raw_size"],"raw_sha256":row["raw_sha256"],
               "zip_crc32":f"{inf.CRC:08x}","expanded_validation":expanded})
 return out
def original_scan(path,cut):
 full=hashlib.sha256(); prefix=hashlib.sha256(); total=0
 with path.open("rb") as f:
  for b in iter(lambda:f.read(CHUNK),b""):
   full.update(b)
   if total<cut: prefix.update(b[:cut-total])
   total+=len(b)
 return total,full.hexdigest(),prefix.hexdigest()
def self_test():
 test=OWN/"finalization-selftest-20261003"
 test.mkdir()
 entries=[("META-INF/com/android/otacert",b"fixture"),("images/tiny.img",b"A\0B")]
 extra=[("META-INF/com/google/android/update-binary",b"fixture executable"),("audit.json",b"{}")]
 a=test/"append.zip"; b=test/"oneshot.zip"
 for path in (a,b):
  with zipfile.ZipFile(path,"x",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
   for n,body in entries+(extra if path==b else []):
    with z.open(zip_info(n,len(body)),"w",force_zip64=True) as f: f.write(body)
 append_entries(a,extra)
 need(a.read_bytes()==b.read_bytes(),"Append differs from one-shot")
 rows={}
 for n,body in entries+extra:
  rows[n]={"encoded_size":len(body),"encoded_sha256":hashlib.sha256(body).hexdigest(),
           "raw_size":len(body),"raw_sha256":hashlib.sha256(body).hexdigest()}
 check_headers(a,rows,False); verify_members(a,rows)
 before=a.read_bytes()
 try: append_entries(a,extra)
 except RuntimeError: pass
 else: raise AssertionError("Duplicate append accepted")
 need(a.read_bytes()==before,"Rejected append changed file")
 try: exclusive(a,b"bad")
 except RuntimeError: pass
 else: raise AssertionError("Overwrite accepted")
 need(a.read_bytes()==before,"Exclusive rejection changed file")
 bad=test/"bad-local.zip"; data=bytearray(before); data[6]|=8; exclusive(bad,data)
 try: check_headers(bad,rows,False)
 except RuntimeError: pass
 else: raise AssertionError("Local descriptor flag mismatch accepted")
 result={"passed":True,"checks":5,"coverage":["deterministic append equals one-shot","all CRC and SHA readbacks","duplicate append preserves bytes","exclusive output rejects overwrite","local descriptor mismatch rejected"]}
 exclusive(test/"receipt.json",canonical(result)); return result
def finalize():
 started=time.monotonic()
 need(os.name=="nt","Finalization is scoped to the approved Windows workspace")
 for path,sha in CODE_PINS.items(): pinned(ROOT/path,sha)
 receipt=json.loads(pinned(RECEIPT,RECEIPT_SHA))
 need(receipt["archive_sha256"]==PAYLOAD_SHA and receipt["archive_bytes"]==9695680045 and len(receipt["members"])==34,"Payload receipt contract mismatch")
 source_bytes=pinned(ROOT/SOURCE,SOURCE_SHA); source=json.loads(source_bytes)
 pinned(ROOT/CONTRACT,CONTRACT_SHA,5015)
 cert=pinned(ROOT/CERT,CERT_SHA,1094)
 updater=pinned(ROOT/UPDATER,UPDATER_SHA,14288592)
 script=pinned(ROOT/SCRIPT,SCRIPT_SHA,308)
 orig={x["path"]:x for x in source["images"]}
 need(len(orig)==32,"Original source manifest image count")
 expected={x["zip_path"]:dict(x) for x in receipt["members"]}
 images=[]; changed=[]
 for name,row in expected.items():
  if not name.startswith("images/"): continue
  old=orig[name]
  same=(old["size"]==row["raw_size"] and old["sha256"]==row["raw_sha256"])
  if not same: changed.append(name)
  images.append({"zip_path":name,"raw_size":row["raw_size"],"raw_sha256":row["raw_sha256"],
                 "encoded_size":row["encoded_size"],"encoded_sha256":row["encoded_sha256"],
                 "encoding":"android_sparse_RAW_zero_FILL_terminal_CRC" if name=="images/super.img" else "raw",
                 "unchanged_from_original":same,"original_raw_size":old["size"],"original_raw_sha256":old["sha256"]})
 need(sorted(changed)==["images/recovery.img","images/vbmeta.img"],"Only recovery/vbmeta may differ")
 manifest={"schema_version":1,"purpose":"Derived package byte audit; native policy is compiled and does not trust this JSON",
 "source_manifest":{"member":"RI3-ORIGINAL-SOURCE-MANIFEST.json","sha256":SOURCE_SHA},
 "frozen_recovery_contract":{"member":"RI3-RECOVERY-CONTRACT.json","sha256":CONTRACT_SHA},
 "raw_images_unchanged":30,"raw_images_replaced":changed,"images":images,
 "updater":{"member":"META-INF/com/google/android/update-binary","size":len(updater),"sha256":UPDATER_SHA},
 "edify_script":{"member":"META-INF/com/google/android/updater-script","size":len(script),"sha256":SCRIPT_SHA},
 "public_certificate":{"member":"META-INF/com/android/otacert","pem_sha256":CERT_SHA,"der_sha256":"24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf"},
 "avb_replacement_provenance":{"images":["images/recovery.img","images/vbmeta.img"],"frozen_contract_sha256":CONTRACT_SHA},
 "super_expanded_validation":expected["images/super.img"]["expanded_validation"],
 "native_write_targets":["super","boot_a","dtbo_a","init_boot_a","vendor_boot_a","vbmeta_system_a","vbmeta_a"],
 "recovery_a":"verified and preserved; recovery_b is not written","firmware":"verified as preconditions, not written",
 "gui_user_checks":["Fresh exact paired recovery boot","Stock theme","Ordinary flash_confirm with exactly this single ROM ZIP","ZIP signature verification ON","Settings ext_general: Reflash OrangeFox after flashing a ROM OFF"],
 "hardware_installation_tested":False}
 entries=[("META-INF/com/google/android/update-binary",updater),("META-INF/com/google/android/updater-script",script),
          ("RI3-ORIGINAL-SOURCE-MANIFEST.json",source_bytes),("RI3-PACKAGE-MANIFEST.json",canonical(manifest))]
 for n,body in entries:
  need(n not in expected,"New member collision")
  expected[n]={"zip_path":n,"encoded_size":len(body),"encoded_sha256":hashlib.sha256(body).hexdigest(),
               "raw_size":len(body),"raw_sha256":hashlib.sha256(body).hexdigest()}
 final=OWN/(BASENAME+".zip"); candidate=OWN/(BASENAME+"-UNVERIFIED.zip")
 report=OWN/(BASENAME+".validation.json"); readme=OWN/(BASENAME+".README.txt"); pem=OWN/(BASENAME+".x509.pem")
 journal=OWN/"finalization-journal-20261003"
 need(all(not p.exists() and not p.is_symlink() for p in (final,candidate,report,readme,pem,journal)),"Finalization output exists; reconcile, do not rerun")
 need(PARTIAL.is_file() and not PARTIAL.is_symlink(),"Expected generated partial")
 free_before=shutil.disk_usage(OWN).free
 needed=12*1024**3+sum(len(b) for n,b in entries)+32*1024**2
 need(free_before>=needed,"Insufficient current headroom before append")
 before=fingerprint(PARTIAL); need(before[0]==9695680045,"Payload size changed")
 cut=receipt["exact_layout"]["central_directory_offset"]
 size,whole,prefix=original_scan(PARTIAL,cut)
 need(size==before[0] and whole==PAYLOAD_SHA and fingerprint(PARTIAL)==before,"Payload identity/hash changed")
 check_headers(PARTIAL,{x["zip_path"]:x for x in receipt["members"]},False)
 with PARTIAL.open("rb") as f: f.seek(cut); tail=f.read(1024*1024)
 need(len(tail)==size-cut and len(tail)<1024*1024,"Tail journal exceeds bound")
 journal.mkdir(); exclusive(journal/"original-tail.bin",tail)
 journal_record={"phase":"before_append","original_path":str(PARTIAL.relative_to(ROOT)),"original_size":size,"original_sha256":whole,
 "original_identity":before,"prefix_bytes":cut,"prefix_sha256":prefix,"tail_bytes":len(tail),"tail_sha256":hashlib.sha256(tail).hexdigest(),
 "candidate_path":str(candidate.relative_to(ROOT)),"final_path":str(final.relative_to(ROOT)),
 "restoration_policy":"No automatic interrupted-write restoration. Reconcile identity and prefix hash, then restore only this exact tail/length if specifically needed.",
 "new_members":[n for n,b in entries]}
 exclusive(journal/"before-append.json",canonical(journal_record))
 print(json.dumps({"phase":"append_start","free_bytes":free_before,"extra_member_bytes":sum(len(b) for n,b in entries)}),flush=True)
 append_entries(PARTIAL,entries)
 descriptors=check_headers(PARTIAL,expected,False)
 with zipfile.ZipFile(PARTIAL) as z:
  for n,body in entries: need(z.read(n)==body,"Appended member readback changed")
 exclusive(journal/"append-complete.json",canonical({"phase":"append_complete","size":PARTIAL.stat().st_size,"descriptors":descriptors}))
 PARTIAL.rename(candidate)
 sys.path.insert(0,str(ROOT/"tools/installer-ri3/zip-signing"))
 from sign_zip import sign_generated_zip
 signing=sign_generated_zip(candidate,ROOT/CERT,ROOT/"builder/work/installer-ri3-recovery/.private/development-zip-rsa2048.pem",
                           generated_root=OWN,work_dir=journal)
 exclusive(journal/"signing.json",canonical(signing))
 signed_identity=fingerprint(candidate)
 descriptors=check_headers(candidate,expected,True)
 findings=verify_members(candidate,expected)
 need(fingerprint(candidate)==signed_identity,"Signed candidate changed during member verification")
 need(signing["verified"] and signing["size"]==signed_identity[0],"Signing verification mismatch")
 candidate.rename(final)
 need(fingerprint(final)==signed_identity,"Final rename changed artifact")
 summary={"schema_version":1,"phase":"signed_package_verified_pending_exact_ARM_readonly_verification","archive_path":str(final.relative_to(ROOT)),
 "archive_bytes":final.stat().st_size,"archive_sha256":signing["sha256"],"member_count":len(expected),"all_member_crc_sha_checks_passed":True,
 "raw_image_count":32,"unchanged_original_raw_images":30,"replaced_raw_images":changed,"members":findings,
 "local_central_headers_and_no_data_descriptors_verified":True,"descriptors":descriptors,"signing":signing,
 "payload_receipt_sha256":RECEIPT_SHA,"original_payload_sha256":PAYLOAD_SHA,"original_source_manifest_sha256":SOURCE_SHA,
 "frozen_recovery_contract_sha256":CONTRACT_SHA,"tool_pins":CODE_PINS,"finalizer_sha256":digest(pathlib.Path(__file__)),
 "free_bytes_before":free_before,"free_bytes_after":shutil.disk_usage(OWN).free,"own_process_memory":own_process_memory(),
 "elapsed_seconds":round(time.monotonic()-started,3),"private_key_material_in_artifacts":False,"no_payload_copy_or_expansion_file":True,
 "exact_ARM_real_ZIP_verification":"pending separate read-only core verification","device_actions_performed":False,"hardware_installation_tested":False}
 readme_text=f"""RI3 files-only candidate: {final.name}

ZIP size: {summary['archive_bytes']} bytes
ZIP SHA-256: {summary['archive_sha256']}
Validation report: {report.name}
Public ZIP-signing certificate: {pem.name}
Certificate DER SHA-256: 24adea378cba169a0852bce0ffd5ee1874940f16b73c873efc75d57129f080cf

This signed single ROM ZIP uses the compiled ARM64 Edify updater. It requires the exact paired recovery image:
builder/work/installer-ri3-recovery/images-ziptrust/recovery.img
Recovery bytes: 104857600
Recovery SHA-256: 8ba7e1e077f31e1a345397fca9842ed1bdf39e69d1003b7bbbcde0830b65e52a
Paired vbmeta: builder/work/installer-ri3-recovery/images-ziptrust/vbmeta.img
vbmeta bytes: 12288
vbmeta SHA-256: 2c3ad5c1ebdf271a6c2363d5367791e52bf119683091100254143f476587777c

Required user checks in the paired recovery:
- Fresh boot of that exact paired recovery, using the stock theme.
- Ordinary flash_confirm flow with this one ROM ZIP.
- ZIP signature verification ON.
- Settings > ext_general > Reflash OrangeFox after flashing a ROM OFF.
These GUI checks are declared prerequisites; native code does not attest the GUI route.

The updater verifies and preserves recovery_a. It writes only super, boot_a, dtbo_a, init_boot_a, vendor_boot_a, vbmeta_system_a, and vbmeta_a; it verifies firmware preconditions and selects slot A last.
All original 32 raw image identities are documented inside the ZIP. Thirty remain unchanged; only recovery and vbmeta are replaced by the approved pair.
Super ZIP member is a standard complete Android sparse stream with RAW and explicit zero-FILL chunks plus terminal CRC, without DONT_CARE. Encoded bytes 8912997308; SHA-256 88bbf9a453d3e75023c3862d5205022260fa59ed91e31e1f4e0e58a4aea30ad0.
Expanded super bytes 9126805504; SHA-256 04842fd6988f96e6e9784adab37d71ec1602ffe35a966f7043658fb84feefd9b.

Completed: all ZIP member CRC/SHA checks, expanded sparse-super validation, local/central ZIP64 and no-descriptor checks, and independent whole-file RSA-SHA256 signature verification.
Pending: separate exact final ARM executable verification against this actual ZIP. Consult its separate final receipt before release.
No phone or device actions were performed. Hardware installation/boot behavior has not been validated.
The private development signing key is not included.
"""
 exclusive(pem,cert); exclusive(readme,readme_text.encode("utf-8")); exclusive(report,canonical(summary))
 exclusive(journal/"complete.json",canonical({"archive_path":summary["archive_path"],"archive_sha256":summary["archive_sha256"],"archive_bytes":summary["archive_bytes"]}))
 print(json.dumps({k:summary[k] for k in ("phase","archive_path","archive_bytes","archive_sha256","member_count","free_bytes_before","free_bytes_after","elapsed_seconds")}),flush=True)
 return summary
if __name__=="__main__":
 p=argparse.ArgumentParser(); p.add_argument("--self-test",action="store_true");p.add_argument("--finalize-approved-existing",action="store_true");a=p.parse_args()
 need(a.self_test or a.finalize_approved_existing,"Explicit action required")
 if a.self_test: print(json.dumps(self_test()),flush=True)
 if a.finalize_approved_existing: finalize()

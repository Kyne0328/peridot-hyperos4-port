#!/usr/bin/env python3
"""Small regular-file tests for payload-only staging, exact ZIP sizes and append reproducibility."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch
import zipfile

import sparse_super as sparse
import payload_stage as stage
from estimate_layout import estimate_stored_zip

ROOT = Path.cwd()
RUN = ROOT/"09-reports/installer-ri3/package/fixtures"/("stage-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
RUN.mkdir(parents=True,exist_ok=False)
BLOCK=4096

def sha(data):
    return hashlib.sha256(data).hexdigest()

class StageTests(unittest.TestCase):
    def setUp(self):
        self.root=RUN/self.id().split(".")[-1]
        self.root.mkdir()
        (self.root/"source").mkdir()
        self.raw=bytes(range(256))*16+bytes(BLOCK)+bytes(range(256))*16
        raw_path=self.root/"source/super.raw"
        raw_path.write_bytes(self.raw)
        raw_plan=sparse.analyze_file(raw_path,expected_bytes=len(self.raw),expected_sha256=sha(self.raw),
                                    capacity_bytes=len(self.raw))
        names=["images/super.img","images/recovery.img","images/vbmeta.img"]
        names += ["images/fixture%02d.img"%i for i in range(29)]
        members=[]
        for index,name in enumerate(names):
            if name=="images/super.img":
                p=raw_path
                encoded, encoded_sha, encoding=raw_plan["sparse_bytes"],None,"android_sparse_v1_raw_zero_fill_crc"
                data=self.raw
            else:
                p=self.root/("source/fixture%02d.raw"%index)
                data=bytes([index])*512
                p.write_bytes(data)
                encoded,encoded_sha,encoding=len(data),sha(data),"raw"
            members.append(dict(zip_path=name,source_path=p.relative_to(self.root).as_posix(),
                  raw_size=len(data),raw_sha256=sha(data),encoded_size=encoded,encoded_sha256=encoded_sha,
                  encoding=encoding,zip_method="ZIP_STORED",source_identity=list(sparse.fingerprint(p.stat()))))
        cert=self.root/"source/public.pem"; cert.write_bytes(b"fixture public certificate")
        members.append(dict(zip_path="META-INF/com/android/otacert",source_path="source/public.pem",
              raw_size=cert.stat().st_size,raw_sha256=sha(cert.read_bytes()),encoded_size=cert.stat().st_size,
              encoded_sha256=sha(cert.read_bytes()),encoding="raw",zip_method="ZIP_STORED",
              source_identity=list(sparse.fingerprint(cert.stat()))))
        self.plan=dict(phase="verified_sources_and_exact_sparse_plan",archive_created=False,
                       super_plan=raw_plan,members=members)
        self.contract=self.root/"frozen.json"; self.contract.write_bytes(b'{"fixture":true}\n')
        self.planfile=self.root/"plan.json"
        self.planfile.write_text(json.dumps(self.plan),encoding="utf-8")
        self.plan_sha=sha(self.planfile.read_bytes())
        self.output=self.root/"builder/work/installer-ri3-package/fixture-NOT-INSTALLABLE.partial"
        self.patches=[patch("payload_stage.FROZEN_CONTRACT","frozen.json"),
                      patch("payload_stage.FROZEN_CONTRACT_SHA",sha(self.contract.read_bytes())),
                      patch("payload_stage.require_free",return_value=30*1024**3)]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
    def build(self):
        return stage.build(self.root,self.planfile,self.plan_sha,self.output,system_headroom=4*1024**3)

    def test_payload_only_exact_layout_and_raw_encoded_separation(self):
        result=self.build()
        self.assertEqual(result["archive_bytes"],result["exact_layout"]["unsigned_zip_bytes"])
        self.assertTrue(result["updater_entries_absent"])
        self.assertFalse(result["installable"])
        member=next(x for x in result["members"] if x["zip_path"]=="images/super.img")
        self.assertEqual(member["raw_size"],len(self.raw))
        self.assertNotEqual(member["encoded_size"],member["raw_size"])
        self.assertEqual(member["raw_sha256"],sha(self.raw))
        with zipfile.ZipFile(self.output) as z:
            self.assertEqual(z.comment,b"")
            self.assertEqual(z.namelist().count("META-INF/com/android/otacert"),1)
            self.assertFalse(stage.FORBIDDEN.intersection(z.namelist()))
            self.assertEqual(z.read("RI3-RECOVERY-CONTRACT.json"),self.contract.read_bytes())

    def test_append_is_byte_identical_to_same_order_one_shot(self):
        self.build()
        appended=self.output.parent/"append-fixture.zip"
        shutil.copyfile(self.output,appended)
        extras=[("META-INF/com/google/android/update-binary",b"fixture executable never run"),
                ("META-INF/com/google/android/updater-script",b'assert("fixture");\n')]
        with zipfile.ZipFile(self.output) as original:
            original_entries=[(x.filename,original.read(x.filename)) for x in original.infolist()]
        with zipfile.ZipFile(appended,"a",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
            for name,data in extras:
                with z.open(stage.info_for(dict(zip_path=name,encoded_size=len(data))),"w",force_zip64=True) as f:f.write(data)
        oneshot=self.output.parent/"one-shot-fixture.zip"
        with zipfile.ZipFile(oneshot,"w",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
            for name,data in original_entries+extras:
                with z.open(stage.info_for(dict(zip_path=name,encoded_size=len(data))),"w",force_zip64=True) as f:f.write(data)
        self.assertEqual(appended.read_bytes(),oneshot.read_bytes())
        self.assertEqual(len(appended.read_bytes()),estimate_stored_zip(
            [dict(zip_path=n,encoded_size=len(b)) for n,b in original_entries+extras])["unsigned_zip_bytes"])

    def test_existing_output_rejected(self):
        self.build()
        before=self.output.read_bytes()
        with self.assertRaises(sparse.SparseError):self.build()
        self.assertEqual(self.output.read_bytes(),before)

    def test_large_layout_arithmetic_without_large_files(self):
        result=estimate_stored_zip([{"zip_path":"images/super.img","encoded_size":8912997308},
                                   {"zip_path":"images/vbmeta.img","encoded_size":12288}])
        self.assertTrue(result["zip64_end_records"])
        self.assertGreater(result["members"][1]["header_offset"],0xffffffff)
        self.assertEqual(result["members"][0]["encoded_size"],8912997308)
        self.assertEqual(result["members"][0]["data_offset"],30+len("images/super.img")+20)


    def test_layout_zip64_central_branches_on_small_fixture(self):
        entries=[("images/one.img",bytes(4096)),("images/two.img",bytes(512))]
        path=self.root/"forced-central-zip64.zip"
        with patch("zipfile.ZIP64_LIMIT",1024):
            prediction=estimate_stored_zip([dict(zip_path=n,encoded_size=len(b)) for n,b in entries])
            with zipfile.ZipFile(path,"w",compression=zipfile.ZIP_STORED,allowZip64=True) as z:
                for name,data in entries:
                    with z.open(stage.info_for(dict(zip_path=name,encoded_size=len(data))),"w",force_zip64=True) as f:f.write(data)
        self.assertEqual(path.stat().st_size,prediction["unsigned_zip_bytes"])
        self.assertTrue(prediction["zip64_end_records"])
        with zipfile.ZipFile(path) as z:
            self.assertEqual(z.read("images/one.img"),bytes(4096))
            self.assertEqual(z.read("images/two.img"),bytes(512))

if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(StageTests))
    receipt={"passed":result.wasSuccessful(),"tests_run":result.testsRun,
             "failures":[(str(t),s) for t,s in result.failures],
             "errors":[(str(t),s) for t,s in result.errors],"run_directory":str(RUN),
             "large_file_created":False,"append_reproducibility_fixture_only":True}
    (RUN/"test-results.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(receipt,indent=2))
    raise SystemExit(not result.wasSuccessful())

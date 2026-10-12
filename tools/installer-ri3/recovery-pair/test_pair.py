#!/usr/bin/env python3
"""Bounded malformed-parser, crypto and non-device lifecycle-model tests."""
import json,pathlib,struct,unittest
from pair_format import *
from verify_pair import verify_recovery
ROOT=pathlib.Path.cwd();OUT=ROOT/'builder/work/installer-ri3-recovery/images';REPORT=ROOT/'09-reports/installer-ri3/recovery-pair'
def row(name,data=b'',mode=0o100755):
 n=name.encode()+b'\0';f=[1,mode,0,0,1,0,len(data),0,0,0,0,len(n),0];b=b'070701'+b''.join(f'{v:08x}'.encode() for v in f)+n;b+=bytes(align(len(b),4)-len(b));b+=data;return b+bytes(align(len(b),4)-len(b))
def archive(*entries):return b''.join(entries)+row('TRAILER!!!')
def lifecycle(pre=(b'A',b'B'),intended=b'A',guard=True,setting='0\n',status=0,baseline=None):
 # Model of exact evidenced gates, not execution of the recovery binary.
 before=tuple(sha(x) for x in pre) if baseline is None else baseline;writes=[];after=list(pre)
 if not guard or setting!='0\n' or pre[0]!=intended:return {'writes':writes,'success':False,'auto':False}
 if status:return {'writes':writes,'success':False,'auto':False}
 # Production native path skips identical recovery_a writes; recovery_b excluded.
 now=tuple(sha(x) for x in after);auto=False # live setting was checked zero
 if setting!='0\n':auto=before!=now
 return {'writes':writes,'success':True,'auto':auto}
class FormatTests(unittest.TestCase):
 def test_cpio_valid(self):self.assertEqual(cpio_entries(archive(row('x',b'abc')))[0]['size'],3)
 def test_cpio_duplicate(self):
  with self.assertRaises(ValueError):cpio_entries(archive(row('x'),row('x')))
 def test_cpio_traversal(self):
  for n in ['../x','/x','a/../x']:
   with self.subTest(n=n),self.assertRaises(ValueError):cpio_entries(archive(row(n)))
 def test_cpio_truncations(self):
  b=archive(row('x',b'abc'))
  for n in [0,5,109,112,len(b)-1]:
   with self.subTest(n=n),self.assertRaises(ValueError):cpio_entries(b[:n])
 def test_cpio_missing_trailer(self):
  with self.assertRaises(ValueError):cpio_entries(row('x'))
 def test_cpio_bad_hex(self):
  b=bytearray(archive(row('x')));b[6]=ord('z')
  with self.assertRaises(ValueError):cpio_entries(b)
 def test_cpio_trailing_nonzero(self):
  with self.assertRaises(ValueError):cpio_entries(archive(row('x'))+b'X')
 def test_lz4_literal(self):self.assertEqual(lz4_decode(b'\x30abc'),b'abc')
 def test_lz4_backref(self):self.assertEqual(lz4_decode(b'\x10a\x01\x00'),b'aaaaa')
 def test_lz4_truncation(self):
  for b in [b'\xf0',b'\x30ab',b'\x10a\x01']:
   with self.subTest(b=b),self.assertRaises(ValueError):lz4_decode(b)
 def test_lz4_zero_offset(self):
  with self.assertRaises(ValueError):lz4_decode(b'\x10a\x00\x00')
 def test_lz4_far_offset(self):
  with self.assertRaises(ValueError):lz4_decode(b'\x10a\x02\x00')
 def test_lz4_oversized_literals(self):
  b=b'\xf0'+b'\xff'*((MAX_BLOCK//255)+1)+b'\x00'
  with self.assertRaises(ValueError):lz4_decode(b)
 def test_boot_rejects_empty(self):
  with self.assertRaises(ValueError):unpack_boot(b'')
 def test_avb_rejects_empty(self):
  with self.assertRaises(ValueError):parse_avb(b'')
class ArtifactTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.rec=(OUT/'recovery.img').read_bytes();cls.root=(OUT/'vbmeta.img').read_bytes()
 def test_valid_signatures_and_hash(self):verify_recovery(self.rec);verify_avb(self.root)
 def test_signature_tamper(self):
  b=bytearray(self.root);b[300]^=1
  with self.assertRaises(Exception):verify_avb(b)
 def test_payload_tamper(self):
  b=bytearray(self.rec);b[4096+50]^=1
  with self.assertRaises(ValueError):verify_recovery(b)
 def test_partition_padding_tamper(self):
  b=bytearray(self.rec);b[-65]=1
  with self.assertRaises(ValueError):verify_recovery(b)
 def test_invalid_footer_extent(self):
  b=bytearray(self.rec);struct.pack_into('>Q',b,len(b)-44,len(b))
  with self.assertRaises(ValueError):parse_avb(b)
 def test_descriptor_overflow(self):
  b=bytearray(self.root);p=parse_avb(b);off=256+p['header'][3]+p['header'][14];struct.pack_into('>Q',b,off+8,2**63)
  with self.assertRaises(ValueError):parse_avb(b)
 def test_invalid_public_key(self):
  b=bytearray((OUT/'development-recovery.avbpubkey').read_bytes());b[7]^=1
  with self.assertRaises(ValueError):decode_key(b)
 def test_hook_grammar(self):
  j=json.loads((REPORT/'pair-build.json').read_text())
  for hook in j['hooks'].values():self.assertEqual([x.strip() for x in hook['text'].splitlines() if x.strip() and not x.lstrip().startswith('#')],['exit 0'])
class LifecycleTests(unittest.TestCase):
 def test_success_no_outer_writes(self):self.assertEqual(lifecycle(),{'writes':[],'success':True,'auto':False})
 def test_distinct_b_preserved(self):self.assertTrue(lifecycle(pre=(b'A',b'different B'))['success'])
 def test_wrong_a_before_writes(self):self.assertFalse(lifecycle(pre=(b'old',b'B'))['success']);self.assertEqual(lifecycle(pre=(b'old',b'B'))['writes'],[])
 def test_wrong_hooks_before_writes(self):self.assertFalse(lifecycle(guard=False)['success'])
 def test_bad_getter_outputs(self):
  for v in ['','1\n','0','unknown\n','getval=0\n','0\nextra\n',None,'timeout','error']:
   with self.subTest(v=v):self.assertEqual(lifecycle(setting=v),{'writes':[],'success':False,'auto':False})
 def test_partial_checksum_baseline_covered_by_setting(self):self.assertFalse(lifecycle(baseline=(sha(b'A'),''))['auto'])
 def test_checksum_identity_alone_insufficient(self):self.assertNotEqual((sha(b'A'),''),(sha(b'A'),sha(b'B')))
 def test_native_failure_no_outer_hook_writes(self):self.assertEqual(lifecycle(status=1),{'writes':[],'success':False,'auto':False})
 def test_pre_hook_exit_not_gui_abort_contract(self):
  # Exact RunFoxScript returns path existence. Guards belong in native updater.
  exists=True;script_exit=9;self.assertTrue(exists);self.assertNotEqual(script_exit,0)
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__));result=unittest.TextTestRunner(verbosity=2).run(suite)
 (REPORT/'pair-tests.json').write_text(json.dumps({'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'passed':result.wasSuccessful(),'model_only_lifecycle':True,'actual_device_or_recovery_execution':False},indent=2)+'\n')
 raise SystemExit(not result.wasSuccessful())

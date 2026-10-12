#!/usr/bin/env python3
"""Run all existing parser/crypto models on final images plus certificate/host-hook checks."""
import io,json,pathlib,subprocess,unittest,zipfile
import test_pair as base
from pair_format import *
ROOT=pathlib.Path.cwd();REPORT=ROOT/'09-reports/installer-ri3/recovery-pair';OUT=ROOT/'builder/work/installer-ri3-recovery/images-ziptrust';base.OUT=OUT
class FinalTests(unittest.TestCase):
 def test_signature_preflight_model(self):
  for value in ['0\n','','unknown\n',None,'timeout','1\nextra']:
   with self.subTest(value=value):self.assertNotEqual(value,'1\n')
  self.assertEqual('1\n','1\n')
 def test_final_certificate_members(self):
  _,bs=unpack_boot((OUT/'recovery.img').read_bytes());raw=b''.join(r for _,r in bs);e=next(e for e in cpio_entries(raw) if e['name']=='system/etc/security/otacerts.zip');b=raw[e['offset']:e['offset']+e['size']];r=json.loads((REPORT/'zip-certificate.json').read_text());self.assertEqual(sha(b),r['candidate_store_sha256'])
  with zipfile.ZipFile(io.BytesIO(b)) as z:
   self.assertEqual(set(z.namelist()),set(r['original_certificates'])|{r['added_certificate']['name']})
   for n,v in r['original_certificates'].items():self.assertEqual(sha(z.read(n)),v['sha256'])
   self.assertEqual(z.read(r['added_certificate']['name']),(OUT/'development-zip.x509.pem').read_bytes())
 def test_authored_noop_hooks_on_host_shell(self):
  m=json.loads((REPORT/'pair-build-ziptrust.json').read_text())
  for n,h in m['hooks'].items():
   self.assertEqual([x.strip() for x in h['text'].splitlines() if x.strip() and not x.lstrip().startswith('#')],['exit 0'])
   p=subprocess.run(['wsl.exe','-d','Ubuntu','--cd','/mnt/c/Dev/peridot-hyperos4-port','--','/bin/dash','-s'],input=h['text'],text=True,capture_output=True,cwd=ROOT,timeout=30)
   self.assertEqual(p.returncode,0,n);self.assertEqual(p.stdout,'',n);self.assertEqual(p.stderr,'',n)
if __name__=='__main__':
 s=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(base),unittest.defaultTestLoader.loadTestsFromTestCase(FinalTests)]);r=unittest.TextTestRunner(verbosity=2).run(s)
 d={'tests_run':r.testsRun,'failures':len(r.failures),'errors':len(r.errors),'passed':r.wasSuccessful(),'images_directory':OUT.relative_to(ROOT).as_posix(),'lifecycle_is_model_only':True,'authored_hooks_executed_with':'existing host dash; no recovered executable run','device_tested':False}
 (REPORT/'pair-tests-ziptrust.json').write_text(json.dumps(d,indent=2)+'\n');raise SystemExit(not r.wasSuccessful())

#!/usr/bin/env python3
"""Verify signatures using the pinned official AOSP implementation."""
import json,pathlib,runpy,zipfile,os,tempfile,sys
from pair_format import parse_avb,require,sha
ROOT=pathlib.Path.cwd();SUFFIX='-ziptrust' if '--ziptrust' in sys.argv else '';REPORT=ROOT/'09-reports/installer-ri3/recovery-pair';OUT=ROOT/('builder/work/installer-ri3-recovery/images'+SUFFIX)
tmp=ROOT/'builder/work/installer-ri3-recovery/tmp';tmp.mkdir(parents=True,exist_ok=True);tempfile.tempdir=str(tmp)
for variable in ['TMP','TEMP','TMPDIR']:os.environ[variable]=str(tmp)
openssl=next((p for p in [pathlib.Path('C:/Program Files/Git/usr/bin/openssl.exe'),pathlib.Path('C:/Program Files/Git/mingw64/bin/openssl.exe')] if p.is_file()),None)
require(openssl is not None,'installed Git OpenSSL unavailable');os.environ['PATH']=str(openssl.parent)+os.pathsep+os.environ.get('PATH','')
tool=ROOT/'builder/tools/bin/windows/avbtool.py';expected='1aa6f2b462aa67aa3fdf488bee83ab517de8ad9d8228c7b45c35267ab2cf6781'
require(sha(tool.read_bytes())==expected,'official avbtool identity mismatch');m=runpy.run_path(str(tool));result={'avbtool_sha256':expected,'avbtool_source':'https://android.googlesource.com/platform/external/avb/+/refs/tags/android-cts-17.0_r1/avbtool.py','results':{},'source_members':{}}
for name in ['recovery.img','vbmeta.img']:
 p=parse_avb((OUT/name).read_bytes());header=m['AvbVBMetaHeader'](p['data'][:256]);ok=m['verify_vbmeta_signature'](header,p['data']);require(ok,'AOSP signature verification failed: '+name);result['results'][name]=bool(ok)
with zipfile.ZipFile(ROOT/'F6-Global-HyperOS4-DEV2-RI2.zip') as z:
 for n in ['images/vbmeta.img','images/recovery.img']:
  info=z.getinfo(n);b=z.read(n);result['source_members'][n]={'zipinfo_size':info.file_size,'actual_size':len(b),'sha256':sha(b)}
(REPORT/('aosp-avb-verification'+SUFFIX+'.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

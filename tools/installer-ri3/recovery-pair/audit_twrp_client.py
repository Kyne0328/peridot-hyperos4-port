#!/usr/bin/env python3
"""Exact read-only CLI client/channel protocol audit."""
import ast,json,pathlib,re,runpy,zipfile
ROOT=pathlib.Path.cwd();OUT=ROOT/'09-reports/installer-ri3/recovery-pair';p=ROOT/'tools/install-readiness-launcher/audit_launcher.py';t=ast.parse(p.read_text());env={};exec(compile(ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),str(p),'exec'),env)
env['rx']=re.compile('main|Channel|command|Command|client|Client');env['sha_rx']=re.compile('.*')
m=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'))
with zipfile.ZipFile(ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip') as z:h,files=m['ramdisk'](z.read('recovery.img'))
b=files['system/bin/twrp'];r=env['analyze'](b);r['client_strings']=[s.decode() for s in re.findall(rb'[ -~]{4,}',b) if len(s)<200];(OUT/'twrp-client-evidence.json').write_text(json.dumps(r,indent=2)+'\n')
print('FUNCTIONS',[(k,hex(v['address']),v['size']) for k,v in r['functions'].items()]);print('STRINGS',[s for s in r['client_strings'] if not s.startswith('_Z')]);print('MAIN_CALLS',[(k,v['calls']) for k,v in r['functions'].items() if k=='main'])

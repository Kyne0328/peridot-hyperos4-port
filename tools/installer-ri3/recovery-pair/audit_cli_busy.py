#!/usr/bin/env python3
"""Exact-binary CLI busy-state audit; no recovered program execution."""
import ast,json,pathlib,re,runpy,zipfile
ROOT=pathlib.Path.cwd();OUT=ROOT/'09-reports/installer-ri3/recovery-pair';p=ROOT/'tools/install-readiness-launcher/audit_launcher.py';t=ast.parse(p.read_text());env={};exec(compile(ast.Module(body=[n for n in t.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),str(p),'exec'),env)
env['rx']=re.compile('ors_command_read|runPages|gui_startPage|gui_start|operation_start|operation_end|GUIAction.*flash|GUIAction.*twcmd');env['sha_rx']=re.compile('read|write|open|fputs|pthread|busy')
m=runpy.run_path(str(ROOT/'tools/local-recovery/inspect_recovery.py'))
with zipfile.ZipFile(ROOT/'OrangeFox-R12.0_202610011528_crypto-Unofficial-peridot.zip') as z:h,files=m['ramdisk'](z.read('recovery.img'))
b=files['system/bin/recovery'];r=env['analyze'](b);e,ss,ns=env['sections'](b);r['busy_literals']=[]
for mt in re.finditer(rb'[ -~]{4,}',b):
 s=mt[0].decode()
 if any(x in s for x in ['tw_busy','operation in progress','orsin','orsout','twcmd']):
  for sec in ss:
   if sec[1]!=8 and sec[4]<=mt.start()<sec[4]+sec[5]:r['busy_literals'].append({'address':hex(sec[3]+mt.start()-sec[4]),'text':s});break
(OUT/'cli-busy-evidence.json').write_text(json.dumps(r,indent=2)+'\n');print('LITERALS',r['busy_literals']);print('FUNCTIONS',[(k,hex(v['address']),v['size']) for k,v in r['functions'].items()])
for k,v in r['functions'].items():
 if 'ors_command_read' in k:print(k);print('\n'.join(v['disassembly']))

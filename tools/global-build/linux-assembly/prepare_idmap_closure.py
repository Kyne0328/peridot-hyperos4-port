"""Extract exact donor idmap2 dependency inputs, never execute Android code."""
import hashlib,json,pathlib,re,stat,subprocess,sys
sys.path.insert(0,'/workspace/shared/peridot-global-assembly/compatibility')
from extract_inputs import Payload,SelectiveReader,DONOR,SHA
R=pathlib.Path('/workspace/shared/peridot-global-assembly/idmap-inputs');sysroot=R/'sysroot';sysroot.mkdir(exist_ok=True)
p=Payload(DONOR,SHA[DONOR]);reader=SelectiveReader(p,'system');rows={i['path']:i for i in reader.e.inventory()};done={};missing=[];todo=['/system/bin/idmap2','/system/bin/linker64','/system/apex/com.android.runtime.apex']
while todo:
 name=todo.pop(0)
 if name in done or name in missing:continue
 if name not in rows:missing.append(name);continue
 i=rows[name];data=reader.read(i);dest=sysroot/name.lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True)
 rec={'source_path':name,'mode':i['mode'],'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'source_archive_sha256':p.sha256}
 if stat.S_ISLNK(i['mode']):
  rec['symlink_target']=data.decode();rec['not_materialized_as_host_absolute_symlink']=True
 else:
  dest.write_bytes(data);rec['output']=str(dest)
  if data.startswith(b'\x7fELF'):
   text=subprocess.run(['readelf','-d',str(dest)],capture_output=True,text=True,check=True).stdout;needs=re.findall(r'Shared library: \[(.*?)\]',text);rec['elf_needed']=needs;todo.extend('/system/lib64/'+lib for lib in needs)
 done[name]=rec
reader.close();p.close();report={'status':'system_dependency_extraction_complete_runtime_apex_unpack_pending','inputs':list(done.values()),'missing_system_paths':missing,'android_code_executed':False};(R/'dependency-extraction.json').write_text(json.dumps(report,indent=2));print(json.dumps({'files':len(done),'missing':missing,'symlinks':{k:v.get('symlink_target') for k,v in done.items() if 'symlink_target'in v}},indent=2))

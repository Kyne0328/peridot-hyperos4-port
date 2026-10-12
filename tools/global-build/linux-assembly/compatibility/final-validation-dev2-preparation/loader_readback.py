"""Fresh static loader byte/ramdisk binding; no ROM executable is run."""
import ast,ctypes,ctypes.util,hashlib,json,pathlib,stat
from final_image_reader import digest_file,Invalid
A=pathlib.Path('/workspace/shared/peridot-global-assembly');H=A/'compatibility'
def check(root,erofs,inventories,init_boot,run):
 expected_image='faa65e685c4f82c592eaa898238c485985b3f46b2f03d59bed1f24ec1fd79273'
 if digest_file(init_boot)!=expected_image:raise Invalid('packaged init_boot differs from reviewed normal ramdisk')
 summary=json.loads((H/'policy-delta/load-selection/summary.json').read_text());sysrow=next(x for x in inventories['system'] if x['path']=='/system/bin/init');data=erofs['system'].file_bytes(sysrow);init_sha=hashlib.sha256(data).hexdigest()
 if init_sha!=summary['final_init_sha256']:raise Invalid('actual final init binary differs from static control-flow proof')
 tmp=root/'loader-ramdisk-scratch';tmp.mkdir();tool=pathlib.Path('/workspace/shared/peridot-cloud/tools/otatools-minimal/bin/unpack_bootimg');r=run(root,'unpack-final-init-boot',[tool,'--boot_img',init_boot,'--out',tmp])
 if r['returncode']:raise Invalid('final init_boot unpack failed')
 import struct
 lib=ctypes.CDLL(ctypes.util.find_library('lz4'));lib.LZ4_decompress_safe.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_int];lib.LZ4_decompress_safe.restype=ctypes.c_int
 namespace={'ctypes':ctypes,'struct':struct,'lib':lib,'sha':lambda b:hashlib.sha256(b).hexdigest()};source=pathlib.Path('/workspace/shared/peridot-global-base/scan_stock_property_guards.py');tree=ast.parse(source.read_text())
 for name in ['decode_legacy','cpio']:
  n=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name==name);exec(compile(ast.Module(body=[n],type_ignores=[]),'bounded-ramdisk-data-reader','exec'),namespace)
 raw,blocks=namespace['decode_legacy']((tmp/'ramdisk').read_bytes());entries,archives=namespace['cpio'](raw);first=next(x for x in entries if x['path']=='init')
 if first['sha256']!='ad2c28bfba0cc112759277d89a710c509a5099f4b3ea1936d439a869aa32058b':raise Invalid('normal first-stage init changed')
 markers=[x['path'] for x in entries if pathlib.PurePosixPath(x['path']).name in ['force_debuggable','adb_debug.prop','userdebug_plat_sepolicy.cil']]
 if markers:raise Invalid('unreviewed packaged debug marker/policy')
 regular=[{k:v for k,v in x.items() if k!='data'} for x in entries]
 report={'status':'ACTUAL_FINAL_LOADER_CHAIN_BYTE_IDENTICAL_TO_REVIEWED_CONTROL_FLOW','packaged_init_boot_sha256':expected_image,'actual_first_stage_init_sha256':first['sha256'],'actual_system_init_sha256':init_sha,'normal_ramdisk_entry_count':len(entries),'newc_archives':archives,'debug_markers':markers,'ramdisk_inventory':regular,'actual_control_flow_report':{'path':str(H/'policy-delta/load-selection/REPORT.md'),'sha256':digest_file(H/'policy-delta/load-selection/REPORT.md')},'normal_selection':'ODM precompiled selected, first-line mismatch rejects it, split CIL fallback selected','condition':'Normal packaged mounts/files; live DSU/debug/remount/bootloader state and kernel acceptance are unobserved','rom_code_executed':False}
 (root/'fresh-loader-byte-proof.json').write_text(json.dumps(report,indent=2));import shutil;shutil.rmtree(tmp);return report

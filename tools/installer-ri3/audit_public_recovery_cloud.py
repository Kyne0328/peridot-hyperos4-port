import zipfile,struct,hashlib,ctypes,ctypes.util,json,pathlib
root=pathlib.Path('/workspace/shared/peridot_recovery_audit'); path=root/'OrangeFox-R12.0_7_crypto-peridot.zip'
zbytes=path.read_bytes(); z=zipfile.ZipFile(path); img=z.read('recovery.img')
magic,kernel_sz,ramdisk_sz,osver,header_sz=struct.unpack_from('<8s4I',img)
version=struct.unpack_from('<I',img,40)[0]; off=4096+((kernel_sz+4095)//4096)*4096
rd=img[off:off+ramdisk_sz]; assert rd[:4]==bytes.fromhex('02214c18')
lib=ctypes.CDLL(ctypes.util.find_library('lz4')); fn=lib.LZ4_decompress_safe; fn.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_int]; fn.restype=ctypes.c_int
p=4; out=bytearray(); blocks=[]
while p+4<=len(rd):
 n=struct.unpack_from('<I',rd,p)[0];p+=4
 if n==0:break
 assert n<=len(rd)-p,(n,p,len(rd))
 src=ctypes.create_string_buffer(rd[p:p+n]);dst=ctypes.create_string_buffer(8*1024*1024);size=fn(src,dst,n,len(dst));assert size>=0,size
 blocks.append({'compressed_offset':p,'compressed_size':n,'decompressed_size':size});out.extend(dst.raw[:size]);p+=n
p=0; entries=[]; scripts={}
while p+110<=len(out):
 assert out[p:p+6] in (b'070701',b'070702'),(p,out[p:p+6])
 fields=[int(out[p+6+i*8:p+14+i*8],16) for i in range(13)]
 size=fields[6]; namesz=fields[11]; name=bytes(out[p+110:p+110+namesz-1]).decode(errors='replace'); dataoff=(p+110+namesz+3)&~3; data=bytes(out[dataoff:dataoff+size]);p=(dataoff+size+3)&~3
 if name=='TRAILER!!!':break
 entries.append({'name':name,'cpio_data_offset':dataoff,'size':size,'sha256':hashlib.sha256(data).hexdigest()})
 if name.endswith('.sh') or ('rom_flash' in name) or name.endswith('default.prop'):
  scripts[name]=data.decode(errors='replace')
(root/'ramdisk_inventory.json').write_text(json.dumps(entries,indent=2));(root/'ramdisk_scripts.json').write_text(json.dumps(scripts,indent=2))
meta={'source_url':'https://orangefox.download/release/6ab06b4434d647462e0f116d','zip_size':len(zbytes),'zip_sha256':hashlib.sha256(zbytes).hexdigest(),'recovery_size':len(img),'recovery_sha256':hashlib.sha256(img).hexdigest(),'boot_header_version':version,'header_size':header_sz,'kernel_size':kernel_sz,'ramdisk_offset':off,'ramdisk_size':ramdisk_sz,'ramdisk_sha256':hashlib.sha256(rd).hexdigest(),'cpio_size':len(out),'cpio_sha256':hashlib.sha256(out).hexdigest(),'lz4_blocks':blocks,'method':'Python boot/cpio parsing and system liblz4 decompression. No downloaded executable run.'}
(root/'audit_metadata.json').write_text(json.dumps(meta,indent=2));print(json.dumps(meta,indent=2)); print('\nHOOK SCRIPTS:')
for name,data in scripts.items():
 if 'rom_flash' in name or '/metadata/ota' in data or ('recovery_a' in data and 'recovery_b' in data):print('\nFILE',name,'\n',data)

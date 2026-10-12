#!/usr/bin/env python3
"""Decode a local SELinux binary with existing host libsepol; no policy installation."""
import ctypes,hashlib,json,pathlib,sys
lib=ctypes.CDLL('/workspace/shared/peridot-global-assembly/compatibility/policy-delta/host-libsepol-3.11/extracted/usr/lib/x86_64-linux-gnu/libsepol.so.2');c=ctypes.CDLL(None);P=ctypes.c_void_p
for name,args,result in [('sepol_policydb_create',[ctypes.POINTER(P)],ctypes.c_int),('sepol_policy_file_create',[ctypes.POINTER(P)],ctypes.c_int),('sepol_policy_file_set_mem',[P,P,ctypes.c_size_t],None),('sepol_policydb_read',[P,P],ctypes.c_int),('sepol_kernel_policydb_to_cil',[P,P],ctypes.c_int),('sepol_policy_file_free',[P],None),('sepol_policydb_free',[P],None)]:
 fn=getattr(lib,name);fn.argtypes=args;fn.restype=result
c.fopen.argtypes=[ctypes.c_char_p,ctypes.c_char_p];c.fopen.restype=P;c.fclose.argtypes=[P];c.fclose.restype=ctypes.c_int
source=pathlib.Path(sys.argv[1]);output=pathlib.Path(sys.argv[2]);raw=source.read_bytes();buf=ctypes.create_string_buffer(raw);db=P();pf=P();assert lib.sepol_policydb_create(ctypes.byref(db))==0;assert lib.sepol_policy_file_create(ctypes.byref(pf))==0;lib.sepol_policy_file_set_mem(pf,buf,len(raw));assert lib.sepol_policydb_read(db,pf)==0
# Official libsepol's struct sepol_policydb has policydb_t p as its first field.
# The opaque wrapper pointer thus equals &wrapper->p; no other struct offsets used.
f=c.fopen(str(output).encode(),b'wx');assert f;code=lib.sepol_kernel_policydb_to_cil(f,db);assert c.fclose(f)==0;lib.sepol_policy_file_free(pf);lib.sepol_policydb_free(db);assert code==0
print(json.dumps({'source':str(source),'source_sha256':hashlib.sha256(raw).hexdigest(),'output':str(output),'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'existing_host_libsepol_sha256':hashlib.sha256(pathlib.Path('/workspace/shared/peridot-global-assembly/compatibility/policy-delta/host-libsepol-3.11/extracted/usr/lib/x86_64-linux-gnu/libsepol.so.2').read_bytes()).hexdigest()}))

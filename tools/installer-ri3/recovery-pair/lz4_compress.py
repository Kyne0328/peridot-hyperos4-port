#!/usr/bin/env python3
"""Deterministic one-block compression with Ubuntu's installed liblz4; no installation."""
import ctypes, hashlib, json, pathlib, sys
c=ctypes.CDLL('liblz4.so.1')
c.LZ4_versionString.restype=ctypes.c_char_p
c.LZ4_compressBound.argtypes=[ctypes.c_int]
c.LZ4_compress_default.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_int]
src=pathlib.Path(sys.argv[1]);dst=pathlib.Path(sys.argv[2]);data=src.read_bytes()
if not 0<len(data)<=8*1024*1024:raise ValueError('legacy LZ4 block size limit')
a=ctypes.create_string_buffer(data);bound=c.LZ4_compressBound(len(data));b=ctypes.create_string_buffer(bound)
n=c.LZ4_compress_default(a,b,len(data),bound)
if n<=0:raise ValueError('LZ4 compression failed')
result=b.raw[:n]
if dst.exists() and dst.read_bytes()!=result:raise ValueError('non-reproducible existing compressed block')
if not dst.exists():dst.write_bytes(result)
print(json.dumps({'version':c.LZ4_versionString().decode(),'input_size':len(data),'output_size':n,'sha256':hashlib.sha256(result).hexdigest()}))

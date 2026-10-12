#!/usr/bin/env python3
"""Bounded full-OTA extraction to new image files, with operation and image hashes.

No device access or flashing. Only stored ZIP payloads and REPLACE/BZ2/XZ
operations are supported. Manifest hashes provide integrity, not OEM trust.
"""
from __future__ import annotations
import argparse, base64, bz2, dataclasses, datetime, hashlib, json, lzma, os
from pathlib import Path
import re, stat, struct, sys, zipfile

class Invalid(ValueError): pass
MAX_MANIFEST = 64 * 1024**2
MAX_OPERATION = 64 * 1024**2
CHUNK = 4 * 1024**2

def fields(data):
    def varint(p):
        v = 0
        for n in range(10):
            if p >= len(data): raise Invalid('truncated protobuf varint')
            b = data[p]; p += 1
            if n == 9 and b > 1: raise Invalid('protobuf uint64 overflow')
            v |= (b & 127) << (n * 7)
            if not b & 128:
                if n and b == 0: raise Invalid('noncanonical protobuf varint')
                return v, p
        raise Invalid('unterminated protobuf varint')
    p = 0
    while p < len(data):
        k,p = varint(p); n,w = k>>3,k&7
        if not 1 <= n <= 536870911: raise Invalid('invalid protobuf field number')
        if w == 0: v,p = varint(p)
        elif w in (1,2,5):
            if w == 2: sz,p = varint(p)
            else: sz = 8 if w == 1 else 4
            if sz > len(data)-p: raise Invalid('truncated protobuf field')
            v = data[p:p+sz];p += sz
        else: raise Invalid('unsupported protobuf wire type')
        yield n,w,v

def one(fs,n,w,default=None,required=True):
    vs=[(fw,v) for fn,fw,v in fs if fn==n]
    if not vs and not required:return default
    if len(vs)!=1 or vs[0][0]!=w:raise Invalid(f'field {n} duplicate, missing or wrong wire type')
    return vs[0][1]

def exact(f,n):
    b=f.read(n)
    if len(b)!=n:raise Invalid('truncated input')
    return b

def fingerprint(f):
    s=os.fstat(f.fileno())
    if not stat.S_ISREG(s.st_mode):raise Invalid('input must be a regular file')
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))

def hash_range(f,offset,size):
    f.seek(offset);h=hashlib.sha256()
    while size:
        b=exact(f,min(CHUNK,size));h.update(b);size-=len(b)
    return h.hexdigest()

@dataclasses.dataclass(frozen=True)
class Op:
    kind:int
    offset:int
    length:int
    digest:bytes
    extents:tuple

@dataclasses.dataclass(frozen=True)
class Partition:
    name:str
    size:int
    digest:bytes
    ops:tuple

class Payload:
    def __init__(self,path,sha256, verify_archive=True):
        self.path=Path(path).resolve()
        if self.path.name.endswith('.partial'):raise Invalid('partial archive cannot be a source')
        if not re.fullmatch('[a-fA-F0-9]{64}',sha256):raise Invalid('archive SHA256 required')
        self.f=self.path.open('rb');self.identity=fingerprint(self.f)
        self.sha256=sha256.lower()
        if verify_archive and hash_range(self.f,0,self.identity[2]) != self.sha256:raise Invalid('archive SHA256 mismatch')
        with zipfile.ZipFile(self.f) as z:
            entries=[x for x in z.infolist() if x.filename=='payload.bin']
            if len(entries)!=1:raise Invalid('requires unique root payload.bin')
            e=entries[0]
            if e.compress_type!=zipfile.ZIP_STORED or e.flag_bits&1:raise Invalid('requires unencrypted stored payload')
            props_entries=[x for x in z.infolist() if x.filename=='payload_properties.txt']
            if len(props_entries)!=1:raise Invalid('requires payload properties')
            props=dict(l.split('=',1) for l in z.read(props_entries[0]).decode('ascii').splitlines() if '=' in l)
            meta_entries=[x for x in z.infolist() if x.filename=='META-INF/com/android/metadata']
            self.metadata=dict(l.split('=',1) for l in z.read(meta_entries[0]).decode().splitlines() if '=' in l) if len(meta_entries)==1 else {}
            self.f.seek(e.header_offset)
            h=struct.unpack('<IHHHHHIIIHH',exact(self.f,30))
            if h[0]!=0x04034b50 or h[3]!=zipfile.ZIP_STORED or h[2]&1:raise Invalid('invalid payload local ZIP header')
            local_name=exact(self.f,h[-2]);exact(self.f,h[-1])
            if local_name!=b'payload.bin':raise Invalid('local ZIP filename mismatch')
            self.payload_start=self.f.tell();self.payload_size=e.file_size
            magic,major,mflen,siglen=struct.unpack('>4sQQI',exact(self.f,24))
            if magic!=b'CrAU' or major!=2 or not 0<mflen<=MAX_MANIFEST:raise Invalid('unsupported payload header')
            if 24+mflen+siglen>e.file_size:raise Invalid('metadata outside payload')
            self.manifest=exact(self.f,mflen)
            self.data_start=self.payload_start+24+mflen+siglen
            if int(props['FILE_SIZE'])!=self.payload_size:raise Invalid('payload properties file size mismatch')
            metalen=int(props['METADATA_SIZE'])
            if metalen not in (24+mflen,24+mflen+siglen):raise Invalid('unsupported metadata hash range')
            mh=hash_range(self.f,self.payload_start,metalen)
            if bytes.fromhex(mh)!=base64.b64decode(props['METADATA_HASH'],validate=True):raise Invalid('metadata hash mismatch')
        fs=list(fields(self.manifest));self.block_size=one(fs,3,0,4096,False)
        if self.block_size!=4096:raise Invalid('only 4096-byte payload blocks supported')
        self.partitions={}
        for n,w,pb in fs:
            if n!=13:continue
            if w!=2:raise Invalid('bad partition wire type')
            pf=list(fields(pb));name=one(pf,1,2).decode('ascii')
            if not re.fullmatch('[a-zA-Z0-9_][a-zA-Z0-9_-]*',name) or name in self.partitions:raise Invalid('invalid/duplicate partition name')
            if any(n==6 for n,w,v in pf):raise Invalid('delta partition unsupported')
            info=list(fields(one(pf,7,2)));size=one(info,1,0);digest=one(info,2,2)
            if size<=0 or size%4096 or len(digest)!=32:raise Invalid('invalid partition size/hash')
            ops=[];coverage=[]
            for n,w,ob in pf:
                if n!=8:continue
                if w!=2:raise Invalid('bad operation wire type')
                of=list(fields(ob));kind=one(of,1,0);offset=one(of,2,0,0,False);length=one(of,3,0);odh=one(of,8,2)
                if kind not in (0,1,8) or not 0<length<=MAX_OPERATION or len(odh)!=32:raise Invalid('unsupported operation kind/size/hash')
                if offset<0 or self.data_start+offset+length>self.payload_start+self.payload_size:raise Invalid('operation outside payload')
                ex=[]
                for en,ew,eb in of:
                    if en!=6:continue
                    if ew!=2:raise Invalid('bad destination extent')
                    ef=list(fields(eb));start=one(ef,1,0,0,False)*4096;sz=one(ef,2,0)*4096
                    if sz<=0 or start+sz>size:raise Invalid('destination extent outside partition')
                    ex.append((start,sz));coverage.append((start,sz))
                if not ex or sum(x[1] for x in ex)>MAX_OPERATION:raise Invalid('operation expanded size exceeds bound')
                ops.append(Op(kind,offset,length,odh,tuple(ex)))
            cursor=0
            for start,sz in sorted(coverage):
                if start!=cursor:raise Invalid(f'{name} has overlapping or missing extent at {cursor}')
                cursor+=sz
            if cursor!=size:raise Invalid(f'{name} incomplete operation coverage')
            self.partitions[name]=Partition(name,size,digest,tuple(ops))
        if fingerprint(self.f)!=self.identity:raise Invalid('archive changed while reading')

    def __del__(self):
        if hasattr(self,'f'):self.f.close()
    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
    def close(self):self.f.close()
    def raw(self,op):
        self.f.seek(self.data_start+op.offset);b=exact(self.f,op.length)
        if hashlib.sha256(b).digest()!=op.digest:raise Invalid('operation compressed hash mismatch')
        limit=sum(n for _,n in op.extents)
        if op.kind==0:raw=b
        else:
            d=bz2.BZ2Decompressor() if op.kind==1 else lzma.LZMADecompressor(memlimit=256*1024**2)
            raw=d.decompress(b,max_length=limit+1)
            if not d.eof or d.unused_data:raise Invalid('compressed operation length/trailing data mismatch')
        if len(raw)!=limit:raise Invalid('decompressed operation size mismatch')
        return raw

    def stream(self,name,out,physical_extents=None):
        p=self.partitions[name]
        extents=physical_extents or [(0,p.size)]
        if sum(n for _,n in extents)!=p.size:raise Invalid('physical extent size mismatch')
        def mapped_write(logical,b):
            cursor=0;pos=0
            for off,sz in extents:
                if logical<cursor+sz and pos<len(b):
                    rel=max(0,logical-cursor);take=min(sz-rel,len(b)-pos)
                    out.seek(off+rel);written=out.write(b[pos:pos+take])
                    if written!=take:raise Invalid('short output write')
                    pos+=take;logical+=take
                cursor+=sz
            if pos!=len(b):raise Invalid('physical extents exhausted')
        for i,op in enumerate(p.ops):
            raw=self.raw(op);pos=0
            for off,sz in op.extents:mapped_write(off,raw[pos:pos+sz]);pos+=sz
        out.flush();os.fsync(out.fileno());h=hashlib.sha256()
        for off,sz in extents:
            out.seek(off)
            while sz:
                b=exact(out,min(CHUNK,sz));h.update(b);sz-=len(b)
        if h.digest()!=p.digest:raise Invalid(f'{name} full partition hash mismatch')
        if fingerprint(self.f)!=self.identity:raise Invalid('archive changed during extraction')
        return {'partition':name,'size':p.size,'sha256':h.hexdigest(),'operation_count':len(p.ops),'operation_sha256_verified':True,'manifest_partition_sha256_verified':True,'source_archive':str(self.path),'source_archive_sha256':self.sha256,'physical_extents':[{'offset':o,'size':s} for o,s in extents]}


def extract(archive,sha256,names,directory):
    outdir=Path(directory);outdir.mkdir(parents=True,exist_ok=True)
    src=Payload(archive,sha256);records=[]
    for name in names:
        if name not in src.partitions:raise Invalid(f'partition absent: {name}')
        final=outdir/(name+'.img');partial=outdir/(name+'.img.partial')
        if final.exists() or partial.exists():raise Invalid('refusing output overwrite')
        with partial.open('x+b') as out:
            out.truncate(src.partitions[name].size)
            rec=src.stream(name,out)
        partial.rename(final);rec['output']=str(final.resolve());records.append(rec)
        report=outdir/(name+'.integrity.json')
        with report.open('x') as f:json.dump(rec,f,indent=2)
        print(json.dumps(rec),flush=True)
    src.close();return records

if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--archive',required=True);a.add_argument('--sha256',required=True);a.add_argument('--partition',action='append',required=True);a.add_argument('--out',required=True)
    args=a.parse_args();extract(args.archive,args.sha256,args.partition,args.out)

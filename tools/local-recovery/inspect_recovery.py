#!/usr/bin/env python3
"""Read-only boot-image/CPIO inspection. Never executes supplied ROM binaries."""
import hashlib, json, struct, zipfile
from pathlib import Path

def sha(b): return hashlib.sha256(b).hexdigest()
def require(ok, message):
    if not ok: raise ValueError(message)

def lz4_block(data):
    out=bytearray(); i=0
    def length(base):
        nonlocal i
        if base==15:
            while True:
                require(i<len(data), 'truncated LZ4 length')
                v=data[i]; i+=1; base+=v
                if v!=255: break
        return base
    while i<len(data):
        token=data[i]; i+=1
        count=length(token>>4)
        require(i+count<=len(data), 'truncated LZ4 literals')
        out+=data[i:i+count]; i+=count
        if i==len(data): break
        require(i+2<=len(data), 'truncated LZ4 offset')
        offset=data[i]|(data[i+1]<<8); i+=2
        require(0<offset<=len(out), 'invalid LZ4 offset')
        count=length(token&15)+4
        chunk=bytes(out[-offset:])
        out+=(chunk*((count+offset-1)//offset))[:count]
        require(len(out)<=8*1024*1024,'oversized legacy LZ4 block')
    return bytes(out)

def ramdisk(image):
    require(image[:8]==b'ANDROID!', 'not Android boot image')
    version=struct.unpack_from('<I',image,40)[0]
    require(version in (3,4), 'unsupported boot header')
    kernel_size, size=struct.unpack_from('<II',image,8)
    off=4096+((kernel_size+4095)//4096)*4096
    data=image[off:off+size]
    require(len(data)==size and data[:4]==b'\x02\x21\x4c\x18','not legacy LZ4 ramdisk')
    pos=4; blocks=[]
    while pos<len(data):
        require(pos+4<=len(data),'truncated legacy block size')
        count=struct.unpack_from('<I',data,pos)[0];pos+=4
        require(0<count<=len(data)-pos,'invalid legacy block size')
        blocks.append(lz4_block(data[pos:pos+count]));pos+=count
    raw=b''.join(blocks); entries={}; pos=0
    while pos+110<=len(raw) and raw[pos:pos+6] in (b'070701',b'070702'):
        fields=[int(raw[pos+6+j*8:pos+14+j*8],16) for j in range(13)]
        size,namesize=fields[6],fields[11]
        name=raw[pos+110:pos+110+namesize-1].decode()
        pos=(pos+110+namesize+3)&~3
        require(pos+size<=len(raw),'truncated CPIO file')
        payload=raw[pos:pos+size];pos=(pos+size+3)&~3
        if name=='TRAILER!!!': break
        require(name not in entries,'duplicate CPIO path')
        entries[name]=payload
    return {'header_version':version,'kernel_size':kernel_size,'ramdisk_bytes':len(raw)},entries

def avb(image):
    if image[-64:-60]==b'AVBf':
        original,off,size=struct.unpack_from('>QQQ',image,len(image)-64+12)
        data=image[off:off+size]
    else: off=0; original=None;data=image
    require(data[:4]==b'AVB0','missing AVB header')
    vals=struct.unpack('!4s2L2QL2Q2Q2Q2Q2QQLL47sx80x',data[:256])
    auth,aux,algorithm=vals[3:6]
    pko,pks=vals[10:12]; do,ds=vals[14:16]
    base=256+auth
    require(base+aux<=len(data),'truncated AVB auxiliary data')
    pk=data[base+pko:base+pko+pks]
    descriptors=[];pos=base+do;end=pos+ds
    while pos<end:
        tag,length=struct.unpack_from('>QQ',data,pos)
        require(length%8==0 and pos+16+length<=end,'malformed AVB descriptor')
        body=data[pos:pos+16+length]
        entry={'tag':tag}
        if tag==4:
            loc,n,k,flags=struct.unpack_from('>IIII',body,16)
            name=body[92:92+n].decode();key=body[92+n:92+n+k]
            entry.update(partition=name,rollback_index_location=loc,flags=flags,public_key_sha256=sha(key))
        descriptors.append(entry);pos+=16+length
    return {'offset':off,'original_image_size':original,'algorithm':algorithm,'flags':vals[17],
            'rollback_index':vals[16],'rollback_index_location':vals[18],
            'public_key_bytes':len(pk),'public_key_sha256':sha(pk),'descriptors':descriptors}

def inspect_fox(path):
    with zipfile.ZipFile(path) as z:
        image=z.read('recovery.img');head,files=ramdisk(image)
        report={'archive':str(path),'archive_size':path.stat().st_size,
                'archive_sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest(),
                'recovery_sha256':sha(image),'recovery_size':len(image),'boot':head,'avb':avb(image),
                'members':[{'name':i.filename,'size':i.file_size} for i in z.infolist()],
                'configs':{},'commands':{},'untrusted_code_executed':False}
        for name,b in files.items():
            if 'fstab' in name or name in ('prop.default','system/etc/fox.cfg','system/etc/twrp.flags','sbin/foxstart.sh'):
                report['configs'][name]={'sha256':sha(b),'text':b.decode('utf-8','replace')}
            if name.rsplit('/',1)[-1] in ('bootctl','blockdev','sha256sum','unzip','busybox','toybox','dd','sync','sh','bash'):
                report['commands'][name]={'size':len(b),'sha256':sha(b)}
        return report

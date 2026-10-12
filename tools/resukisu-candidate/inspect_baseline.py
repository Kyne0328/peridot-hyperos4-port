#!/usr/bin/env python3
"""Offline read-only RI2 kernel/AVB/module inventory. Never executes ROM code."""
import argparse, gzip, hashlib, json, re, struct, sys
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/local-recovery'))
from inspect_recovery import ramdisk, require
from build_local import MappedErofs

def sha(b): return hashlib.sha256(b).hexdigest()
def digest(p):
    with p.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()
def avb(b):
    original = None
    if b[-64:-60] == b'AVBf':
        original, off, size = struct.unpack_from('>QQQ', b, len(b)-52)
        require(off+size <= len(b)-64, 'AVB footer bounds')
        v = b[off:off+size]
    else: off=0; v=b
    require(v[:4] == b'AVB0', 'AVB magic')
    a, x = struct.unpack_from('>QQ', v, 12)
    alg = struct.unpack_from('>I', v, 28)[0]
    ho, hs, so, ss, po, ps, pmo, pms, do, ds = struct.unpack_from('>10Q', v, 32)
    require(256+a+x <= len(v), 'AVB blocks truncated')
    aux=v[256+a:256+a+x]; auth=v[256:256+a]; key=aux[po:po+ps]
    result={'offset':off,'original_image_size':original,'algorithm':alg,'flags':struct.unpack_from('>I',v,120)[0], 'rollback_index':struct.unpack_from('>Q',v,112)[0], 'public_key_sha256':sha(key),'signature_verified':False,'descriptors':[]}
    if alg:
        require(alg in range(1,7), 'Unsupported AVB algorithm')
        name='sha256' if alg<=3 else 'sha512'
        h=hashlib.new(name,v[:256]+aux).digest()
        require(auth[ho:ho+hs]==h, 'AVB authentication hash mismatch')
        bits=struct.unpack_from('>I',key)[0]; n=int.from_bytes(key[8:8+bits//8],'big')
        signature=auth[so:so+ss]
        require(len(signature)==bits//8 and int.from_bytes(signature,'big')<n, 'AVB RSA bounds')
        em=pow(int.from_bytes(signature,'big'),65537,n).to_bytes(bits//8,'big')
        prefix=bytes.fromhex('3031300d060960864801650304020105000420' if name=='sha256' else '3051300d060960864801650304020305000440')
        tail=prefix+h; expected=b'\x00\x01'+b'\xff'*(len(em)-len(tail)-3)+b'\x00'+tail
        require(em==expected, 'AVB RSA signature mismatch')
        result['signature_verified']=True
    pos=do
    while pos<do+ds:
        tag,length=struct.unpack_from('>QQ',aux,pos); body=aux[pos:pos+16+length]
        require(length%8==0 and len(body)==16+length and pos+16+length<=do+ds,'AVB descriptor bounds')
        d={'tag':tag}
        if tag==2:
            image_size=struct.unpack_from('>Q',body,16)[0]; name=body[24:56].split(b'\0')[0].decode()
            pn,sl,dl,flags=struct.unpack_from('>IIII',body,56); part=body[132:132+pn].decode(); salt=body[132+pn:132+pn+sl]; dh=body[132+pn+sl:132+pn+sl+dl]
            d.update(partition=part,image_size=image_size,hash_algorithm=name,salt=salt.hex(),digest=dh.hex(),flags=flags)
            if original is not None:
                require(image_size<=off,'AVB content overlap'); require(hashlib.new(name,salt+b[:image_size]).digest()==dh,'AVB image hash mismatch');d['image_hash_verified']=True
        elif tag==4:
            loc,pn,kl,flags=struct.unpack_from('>IIII',body,16); part=body[92:92+pn].decode(); ck=body[92+pn:92+pn+kl]
            d.update(partition=part,rollback_index_location=loc,public_key_sha256=sha(ck),flags=flags)
        result['descriptors'].append(d);pos+=16+length
    return result

def module(b,path,origin):
    m=re.search(rb'vermagic=([^\0]+)',b)
    return {'path':path,'origin':origin,'bytes':len(b),'sha256':sha(b),'vermagic':m.group(1).decode() if m else None,'signed_marker':b.endswith(b'~Module signature appended~\n')}

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    require(not args.output.exists(),'Refuse output overwrite');args.output.mkdir(parents=True)
    src=ROOT/'.cache/global-single-recovery-ri2/source-images';manifest=json.loads((src/'MANIFEST.json').read_text())
    checked={}; metadata={}
    for name in ['boot','init_boot','vendor_boot','dtbo','recovery','vbmeta','vbmeta_system']:
        pin=next(x for x in manifest['images'] if x['path']=='images/'+name+'.img');image=src/pin['path'];b=image.read_bytes()
        require(len(b)==pin['size'] and sha(b)==pin['sha256'],'Source hash mismatch: '+name)
        checked[name]={'bytes':len(b),'sha256':sha(b)};metadata[name]=avb(b)
    b=(src/'images/boot.img').read_bytes();ks,rs=struct.unpack_from('<II',b,8);hv=struct.unpack_from('<I',b,40)[0]
    require(b[:8]==b'ANDROID!' and hv==4 and rs==0 and ks+4096<=len(b),'Unexpected boot layout');k=b[4096:4096+ks]
    pos=k.find(b'IKCFG_ST');end=k.find(b'IKCFG_ED',pos+8);require(pos>=0 and end>pos,'Missing embedded config');config=gzip.decompress(k[pos+8:end])
    (args.output/'stock.config').write_bytes(config)
    versions=sorted(set(x.decode() for x in re.findall(rb'Linux version [ -~]+',k)))
    kernel={'version_banners':versions,'sha256':sha(k),'bytes':ks,'header_version':hv,'ramdisk_size':rs,'signature_size':struct.unpack_from('<I',b,1580)[0],'config_sha256':sha(config)}
    vb=(src/'images/vendor_boot.img').read_bytes();require(vb[:8]==b'VNDRBOOT','vendor boot header');size=struct.unpack_from('<I',vb,24)[0]
    synthetic=bytearray(4096);synthetic[:8]=b'ANDROID!';struct.pack_into('<II',synthetic,8,0,size);struct.pack_into('<I',synthetic,40,4)
    _,files=ramdisk(bytes(synthetic)+vb[4096:4096+size]);modules=[module(data,name,'vendor_boot') for name,data in files.items() if name.endswith('.ko')]
    ramdisk_meta={name:{'bytes':len(data),'sha256':sha(data),'text':data.decode(errors='replace')} for name,data in files.items() if name.endswith(('modules.load','modules.dep','fstab.qcom'))}
    logical=[];unread=[]
    with (src/'images/super.img').open('rb') as f:
        for part in ['system_dlkm','vendor_dlkm']:
            pin=next(x for x in manifest['logical_inputs'] if x['partition']==part);e=MappedErofs(f,pin['physical_extents'],pin['size_bytes']);inventory=e.inventory();h=hashlib.sha256()
            for offset,size in pin['physical_extents']:
                f.seek(offset)
                while size:
                    b=f.read(min(size,8*1024**2));require(b,'Short logical span');h.update(b);size-=len(b)
            require(h.hexdigest()==pin['sha256'],'Logical partition hash mismatch')
            logical.append({'partition':part,'sha256':h.hexdigest(),'size':pin['size_bytes'],'entries':len(inventory),'module_count':sum(i['path'].endswith('.ko') for i in inventory)})
            for i in inventory:
                if i['path'].endswith('.ko'):
                    try: modules.append(module(e.data(i),i['path'],part))
                    except ValueError as ex: unread.append({'origin':part,'path':i['path'],'reason':str(ex)})
    chain=[]
    for d in metadata['vbmeta']['descriptors']:
        part=d.get('partition')
        if d['tag']==4 and part in metadata:
            require(d['public_key_sha256']==metadata[part]['public_key_sha256'],'AVB child key mismatch');chain.append(part)
    report={'status':'baseline_inspected_candidate_not_built','physical_images_verified':checked,'kernel':kernel,'avb':metadata,'child_keys_matched':chain,'vendor_boot_configs':ramdisk_meta,'logical_partitions':logical,'modules':modules,'unread_modules':unread,'all_module_bytes_inspected':not unread,'changed_images':[],'source_images_modified':False,'device_tested':False,'production_trust_verified':False}
    (args.output/'baseline-inspection.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'kernel':kernel,'images_verified':len(checked),'module_count':len(modules),'unread_module_count':len(unread),'logical':logical,'avb_signatures_verified':[n for n,v in metadata.items() if v['signature_verified']],'vermagics':sorted(set(m['vermagic'] or '<missing>' for m in modules))},indent=2))
if __name__=='__main__':main()

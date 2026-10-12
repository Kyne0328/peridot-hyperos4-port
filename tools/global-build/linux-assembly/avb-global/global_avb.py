#!/usr/bin/env python3
"""Offline Global AVB authoring and bounded mapped-image verification.

No device interface is used. Public AOSP test signing does not establish OEM
trust. All source image bodies and OEM boot/recovery chain keys are preserved.
"""
from __future__ import annotations
import argparse, copy, hashlib, importlib.util, json, os, pathlib, struct, subprocess, sys

ROOT=pathlib.Path(__file__).resolve().parent
TOOL=pathlib.Path('/workspace/shared/peridot-cloud/tools/otatools-minimal/bin/avbtool')
LIBDIR=TOOL.parent.parent/'lib64'
KEY=ROOT/'external/avb/test/data/testkey_rsa4096.pem'
KEY_SHA='6a224754880a57ab9cbd308267cd157d94cf05a1c8cb851aec4090e045d24121'
KEY_PUBLIC_SHA1='2597c218aae470a130f61162feaae70afd97f011'
OEM_SHA1='cb646ab4d06eb30d6b9602b8ea0148e9bf354dd5'
SOURCE_REVISION='ba2dec4b035b0a3b61c5f8f8a74d86bcd450b1ee'
BASE=pathlib.Path('/workspace/shared/peridot-global-base/images')
DONOR=ROOT.parent/'donor-avb'
BASE_ARCHIVE_SHA='13958bfdfcbaf72709302b6d4806a39e55ed9bd72e23d5a53dbf5606c52340b5'
DONOR_ARCHIVE_SHA='b6bc69ddddc7750a4e453c514fd945ca22d166c5ab0704d955b0e6ab81ac5dbd'

class Invalid(ValueError): pass

def require(test,message):
    if not test:raise Invalid(message)

def digest_file(path):
    with pathlib.Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def write_json(path,obj):
    with pathlib.Path(path).open('x') as f:json.dump(obj,f,indent=2);f.write('\n')

def record(path):
    p=pathlib.Path(path);return {'path':str(p.resolve()),'size':p.stat().st_size,'sha256':digest_file(p)}

AVB_SOURCE_SHA256='1aa6f2b462aa67aa3fdf488bee83ab517de8ad9d8228c7b45c35267ab2cf6781'

def load_avb():
    require(digest_file(ROOT/'avbtool_source.py')==AVB_SOURCE_SHA256,'official avbtool source hash mismatch')
    spec=importlib.util.spec_from_file_location('official_avbtool',ROOT/'avbtool_source.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
A=load_avb()

def command(args):
    env=os.environ.copy();env['PATH']=str(ROOT/'bin')+os.pathsep+env.get('PATH','')
    env['LD_LIBRARY_PATH']=str(ROOT/'lib64')+os.pathsep+str(LIBDIR)+os.pathsep+env.get('LD_LIBRARY_PATH','')
    result=subprocess.run([str(TOOL),*map(str,args)],check=True,text=True,capture_output=True,env=env)
    return {'argv':[str(TOOL),*map(str,args)],'stdout':result.stdout,'stderr':result.stderr,'exit_code':result.returncode}

class MappedReader:
    """Read-only logical image backed by bounded nonoverlapping physical ranges."""
    def __init__(self,entry):
        self.filename=str(pathlib.Path(entry['path']).resolve());self.f=open(self.filename,'rb')
        actual=os.fstat(self.f.fileno()).st_size
        self.extents=[(int(x['offset']),int(x['size'])) for x in entry.get('extents',[{'offset':0,'size':actual}])]
        require(self.extents and all(o>=0 and s>0 and o+s<=actual for o,s in self.extents),'invalid mapped extents')
        spans=sorted(self.extents)
        require(all(x[0]+x[1]<=y[0] for x,y in zip(spans,spans[1:])),'overlapping mapped extents')
        self.image_size=sum(s for _,s in self.extents)
        require(entry.get('size',self.image_size)==self.image_size,'mapped size mismatch')
        self.pos=0;self.identity=self._identity()
    def _identity(self):
        s=os.fstat(self.f.fileno());return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    def seek(self,offset):
        require(isinstance(offset,int) and 0<=offset<=self.image_size,'seek outside image');self.pos=offset
    def read(self,n):
        require(0<=n<=self.image_size-self.pos,'read outside mapped image')
        logical=0;out=bytearray();remaining=n
        for off,sz in self.extents:
            if remaining and self.pos<logical+sz:
                rel=max(0,self.pos-logical);take=min(sz-rel,remaining)
                self.f.seek(off+rel);b=self.f.read(take);require(len(b)==take,'short image read')
                out.extend(b);self.pos+=take;remaining-=take
            logical+=sz
        require(not remaining,'incomplete mapped read');return bytes(out)
    def sha256(self):
        self.seek(0);h=hashlib.sha256()
        while self.pos<self.image_size:h.update(self.read(min(4*1024**2,self.image_size-self.pos)))
        return h.hexdigest()
    def stable(self):require(self.identity==self._identity(),'image changed during verification')
    def close(self):self.f.close()
    def __del__(self):
        if hasattr(self,'f'):self.f.close()

def parse_image(reader):
    require(reader.image_size>=256,'image too small')
    reader.seek(reader.image_size-64);tail=reader.read(64);footer=None;off=0
    if tail[:4]==b'AVBf':
        footer=A.AvbFooter(tail);off=footer.vbmeta_offset
        require(0<=footer.original_image_size<=off and off+footer.vbmeta_size<=reader.image_size-64,'invalid footer bounds')
    reader.seek(off);header=A.AvbVBMetaHeader(reader.read(256))
    total=256+header.authentication_data_block_size+header.auxiliary_data_block_size
    require(total<=16*1024**2 and off+total<=reader.image_size,'invalid vbmeta size')
    if footer:require(total==footer.vbmeta_size,'vbmeta footer size mismatch')
    for pos,sz in [(header.descriptors_offset,header.descriptors_size),(header.public_key_offset,header.public_key_size),(header.public_key_metadata_offset,header.public_key_metadata_size)]:
        require(pos+sz<=header.auxiliary_data_block_size,'auxiliary field outside block')
    require(header.hash_offset+header.hash_size<=header.authentication_data_block_size,'auth hash outside block')
    require(header.signature_offset+header.signature_size<=header.authentication_data_block_size,'signature outside block')
    reader.seek(off);blob=reader.read(total);aux=256+header.authentication_data_block_size
    enc=blob[aux+header.descriptors_offset:aux+header.descriptors_offset+header.descriptors_size]
    p=0
    while p<len(enc):
        require(p+16<=len(enc),'short descriptor header');tag,n=struct.unpack('!QQ',enc[p:p+16]);require(n%8==0 and p+16+n<=len(enc),'invalid descriptor bounds');p+=16+n
    descriptors=A.parse_descriptors(enc)
    require(b''.join(d.encode() for d in descriptors)==enc,'noncanonical descriptors')
    pub=blob[aux+header.public_key_offset:aux+header.public_key_offset+header.public_key_size]
    return footer,header,descriptors,blob,pub

def load_meta(path):
    r=MappedReader({'path':str(path)})
    try:
        v=parse_image(r);require(v[1].flags==0,'AVB flags must be 0');require(A.verify_vbmeta_signature(v[1],v[3]),'vbmeta signature invalid');r.stable();return v
    finally:r.close()

def belongs(desc,name):
    return getattr(desc,'partition_name',None)==name or getattr(desc,'key','').startswith(f'com.android.build.{name}.')

def desc_record(d):
    values={}
    for k,v in vars(d).items():
        if k in ('tag','data'):continue
        values[k]=v.hex() if isinstance(v,(bytes,bytearray)) else v
    return {'type':type(d).__name__,'encoded_sha256':hashlib.sha256(d.encode()).hexdigest(),**values}

def source_meta():
    sources={}
    for origin,directory in [('base',BASE),('donor',DONOR)]:
        for name in ['vbmeta','vbmeta_system']:
            p=directory/(name+'.img');v=load_meta(p)
            require(v[1].rollback_index==({'base/vbmeta':0,'base/vbmeta_system':1769904000,'donor/vbmeta':0,'donor/vbmeta_system':1788220800}[origin+'/'+name]),'unexpected Global rollback metadata')
            sources[origin+'/'+name]=(p,v)
    require(hashlib.sha1(sources['base/vbmeta'][1][4]).hexdigest()==OEM_SHA1,'unexpected base OEM key')
    return sources

def get_descriptors(sources,product_descriptors=None):
    top=[copy.deepcopy(d) for d in sources['base/vbmeta'][1][2] if not belongs(d,'mi_ext')]
    top += [copy.deepcopy(d) for d in sources['donor/vbmeta'][1][2] if belongs(d,'mi_ext')]
    pub=(ROOT/'development.avbpubkey').read_bytes()
    chains={}
    for d in top:
        if isinstance(d,A.AvbChainPartitionDescriptor):
            require(d.partition_name not in chains,'duplicate chain');chains[d.partition_name]=d
            if d.partition_name=='vbmeta_system':d.public_key=pub
    require({n:d.rollback_index_location for n,d in chains.items()}=={'boot':3,'recovery':1,'vbmeta_system':2},'unexpected chain layout')
    for n in ['boot','recovery']:require(hashlib.sha1(chains[n].public_key).hexdigest()==OEM_SHA1,'stock chain key changed')
    system=[copy.deepcopy(d) for d in sources['donor/vbmeta_system'][1][2] if not belongs(d,'product')]
    if product_descriptors is not None:system.extend(copy.deepcopy(product_descriptors))
    for d in top+system:require(getattr(d,'flags',0)==0,'descriptor flags must stay 0')
    return top,system

def prepare():
    require(digest_file(KEY)==KEY_SHA,'test key hash mismatch')
    require(hashlib.sha1((ROOT/'development.avbpubkey').read_bytes()).hexdigest()==KEY_PUBLIC_SHA1,'test public key mismatch')
    sources=source_meta();top,system=get_descriptors(sources)
    expected_top=['countrycode','dtbo','init_boot','vendor_boot','mi_ext','odm','system_dlkm','vendor','vendor_dlkm']
    require(sorted(d.partition_name for d in top if isinstance(d,(A.AvbHashDescriptor,A.AvbHashtreeDescriptor)))==sorted(expected_top),'top descriptor provenance mismatch')
    profile={'schema':1,'mode':'development_aosp_public_testkey','production_trust':False,'phone_actions':False,'verification_flags':0,'hashtree_disabled':False,'verification_disabled':False,'fbe_changes':False,'boot_and_recovery':'unchanged source bytes and OEM keys','testkey_sha256':KEY_SHA,'test_public_key_sha1':KEY_PUBLIC_SHA1,'base_archive_sha256':BASE_ARCHIVE_SHA,'donor_archive_sha256':DONOR_ARCHIVE_SHA,'avb_source_revision':SOURCE_REVISION,'avb_source':record(ROOT/'avbtool_source.py'),'avbtool':record(TOOL),'sources':{},'top_descriptors':[desc_record(d) for d in top],'system_retained_descriptors':[desc_record(d) for d in system],'rollback':{'top':0,'boot':1769904000,'recovery':1,'system':1788220800,'system_location':2,'base_system':1769904000},'product':{'status':'awaiting reviewed final filesystem hash and size','hash_algorithm':'sha256','data_block_size':4096,'fec_num_roots':2,'footer_algorithm':'NONE; authenticated by signed vbmeta_system','preferred_partition_size':3936165888,'max_partition_size':4099854336},'limits':['No hardware boot compatibility established','Device stored rollback values unknown','Top vbmeta raw minimum 8448 bytes; padded to 12288; verified physical capacity 131072 bytes per slot','FEC generated with official helper; avbtool does not independently check FEC parity']}
    for label,(path,v) in sources.items():
        profile['sources'][label]={**record(path),'signature_valid':True,'public_key_sha1':hashlib.sha1(v[4]).hexdigest(),'rollback_index':v[1].rollback_index,'flags':v[1].flags,'descriptors':[desc_record(d) for d in v[2]]}
    profile['preserved_sources']=preserved_sources()
    profile['physical_capacity']={'bytes':131072,'source':'/workspace/shared/peridot-global-base/geometry/vbmeta_physical_capacity.json'}
    write_json(ROOT/'global-avb-profile.json',profile);return profile

def preserved_sources():
    base=json.loads((BASE.parent/'partition_manifest.json').read_text())['partitions']
    base={x['name']:x for x in base}
    donor=json.loads(pathlib.Path('/workspace/shared/peridot-regional-research/partition_hashes.json').read_text())['global']
    result={}
    for name in ['countrycode','dtbo','init_boot','vendor_boot','odm','system_dlkm','vendor','vendor_dlkm','boot','recovery']:
        x=base[name];result[name]={'sha256':x['sha256'],'size':x['size'],'origin':'base'}
    for name in ['system','system_ext','mi_ext']:
        x=donor[name];result[name]={'sha256':x['sha256'],'size':x['size'],'origin':'donor'}
    return result

def product_properties(sources,props_file,partition='product'):
    origin='donor/vbmeta_system' if partition=='product' else 'donor/vbmeta'
    defaults={d.key:d.value.decode() for d in sources[origin][1][2] if isinstance(d,A.AvbPropertyDescriptor) and belongs(d,partition)}
    props=json.loads(pathlib.Path(props_file).read_text()) if props_file else defaults
    require(set(props)==set(defaults),'require exactly donor product AVB property names')
    require(all(isinstance(v,str) and v and '\0' not in v for v in props.values()),'invalid property value')
    return props

def sign_product(path,expected_sha,expected_size,partition_size,props_file,partition='product'):
    require(partition in ('product','mi_ext'),'unsupported rebuilt filesystem partition')
    path=pathlib.Path(path).resolve();require(path.stat().st_size==expected_size,'product filesystem size mismatch')
    require(expected_size%4096==0,'product image must be block aligned')
    require(digest_file(path)==expected_sha,'product filesystem hash mismatch')
    with path.open('rb') as f:f.seek(-64,2);require(f.read(4)!=b'AVBf','refusing to overwrite existing AVB footer')
    maximum=4099854336 if partition=='product' else 1142345728
    require(0<partition_size<=maximum and partition_size%4096==0,'rebuilt partition exceeds Global budget or is unaligned')
    sources=source_meta();props=product_properties(sources,props_file,partition)
    origin='donor/vbmeta_system' if partition=='product' else 'donor/vbmeta'
    src=[d for d in sources[origin][1][2] if isinstance(d,A.AvbHashtreeDescriptor) and d.partition_name==partition][0]
    sizing=command(['add_hashtree_footer','--partition_size',partition_size,'--hash_algorithm','sha256','--block_size',4096,'--fec_num_roots',2,'--calc_max_image_size'])
    require(expected_size<=int(sizing['stdout'].strip()),'product filesystem + AVB/FEC does not fit')
    args=['add_hashtree_footer','--image',path,'--partition_name',partition,'--partition_size',partition_size,'--hash_algorithm','sha256','--block_size',4096,'--fec_num_roots',2,'--salt',src.salt.hex(),'--algorithm','NONE','--flags',0]
    for k,v in props.items():args+=['--prop',f'{k}:{v}']
    invocation=command(args);v=load_meta(path);ht=[d for d in v[2] if isinstance(d,A.AvbHashtreeDescriptor)]
    require(len(ht)==1 and ht[0].partition_name==partition and ht[0].fec_num_roots==2 and ht[0].fec_size>0,'invalid product AVB/FEC')
    require(v[0].original_image_size==expected_size,'product body size changed')
    r=MappedReader({'path':str(path)});r.seek(0);h=hashlib.sha256();remaining=expected_size
    while remaining:b=r.read(min(4*1024**2,remaining));h.update(b);remaining-=len(b)
    r.close();require(h.hexdigest()==expected_sha,'product body changed during footer creation')
    report={'composition_review_approved':True,'input_sha256':expected_sha,'input_size':expected_size,'output':record(path),'properties':props,'sizing':sizing,'command':invocation,'hashtree':desc_record(ht[0]),'filesystem_bytes_unchanged':True,'fec_generated_with_official_helper':True,'fec_parity_independently_verified':False}
    write_json(ROOT/(partition+'-signing-report.json'),report);return report

def unsigned_capsule(path,descriptors):
    blob=A.Avb()._generate_vbmeta_blob(algorithm_name='NONE',key_path=None,public_key_metadata_path=None,descriptors=descriptors,chain_partitions_use_ab=None,chain_partitions_do_not_use_ab=None,rollback_index=0,flags=0,rollback_index_location=0,props=None,props_from_file=None,kernel_cmdlines=None,setup_rootfs_from_kernel=None,ht_desc_to_setup=None,include_descriptors_from_image=None,signing_helper=None,signing_helper_with_files=None,release_string=None,append_to_release_string=None,required_libavb_version_minor=0)
    with pathlib.Path(path).open('xb') as f:f.write(blob)

def sign_metadata(product_path,expected_product_sha,out_dir,mi_ext_path=None,mi_ext_sha=None):
    require(digest_file(KEY)==KEY_SHA,'test key hash mismatch')
    require(digest_file(product_path)==expected_product_sha,'final product hash mismatch')
    current_product_report=json.loads((ROOT/'product-signing-report.json').read_text())
    require(current_product_report.get('composition_review_approved') is True,'product composition approval missing or withdrawn')
    require(current_product_report['output']['sha256']==expected_product_sha,'product does not match current reviewed authoring report')
    profile=json.loads((ROOT/'global-avb-profile.json').read_text())
    for label,expected in profile['sources'].items():require(digest_file(expected['path'])==expected['sha256'],'source metadata changed')
    product=load_meta(product_path);require(all(belongs(d,'product') for d in product[2]),'foreign descriptor in product footer')
    ht=[d for d in product[2] if isinstance(d,A.AvbHashtreeDescriptor)];require(len(ht)==1 and ht[0].fec_num_roots==2 and ht[0].flags==0,'product missing enabled hashtree/FEC')
    top,system=get_descriptors(source_meta(),product[2])
    if mi_ext_path:
        require(mi_ext_sha and digest_file(mi_ext_path)==mi_ext_sha,'rebuilt mi_ext hash mismatch')
        mi_report=json.loads((ROOT/'mi_ext-signing-report.json').read_text())
        require(mi_report.get('composition_review_approved') is True and mi_report['output']['sha256']==mi_ext_sha,'mi_ext does not match approved authoring report')
        v=load_meta(mi_ext_path);require(all(belongs(d,'mi_ext') for d in v[2]),'foreign descriptor in rebuilt mi_ext')
        ht=[d for d in v[2] if isinstance(d,A.AvbHashtreeDescriptor)];require(len(ht)==1 and ht[0].fec_num_roots==2 and ht[0].flags==0,'rebuilt mi_ext missing hashtree/FEC')
        top=[d for d in top if not belongs(d,'mi_ext')]+v[2]
    else:require(not mi_ext_sha,'mi_ext hash requires its path')
    out=pathlib.Path(out_dir);out.mkdir(parents=True,exist_ok=True);reports={}
    for name,descs,rollback in [('vbmeta_system',system,1788220800),('vbmeta',top,0)]:
        capsule=out/(name+'.descriptor-capsule.img');dest=out/(name+'.img');require(not dest.exists(),'refusing metadata overwrite');unsigned_capsule(capsule,descs)
        cmd=command(['make_vbmeta_image','--output',dest,'--padding_size',4096,'--algorithm','SHA256_RSA4096','--key',KEY,'--rollback_index',rollback,'--rollback_index_location',0,'--flags',0,'--include_descriptors_from_image',capsule])
        v=load_meta(dest);require(hashlib.sha1(v[4]).hexdigest()==KEY_PUBLIC_SHA1,'signed key mismatch')
        require(dest.stat().st_size<=131072,'signed metadata exceeds proven physical capacity')
        require(sorted(d.encode() for d in v[2])==sorted(d.encode() for d in descs),'signed descriptors changed')
        reports[name]={'output':record(dest),'raw_vbmeta_size':len(v[3]),'rollback_index':v[1].rollback_index,'flags':v[1].flags,'command':cmd,'signature_valid':True,'public_key_sha1':KEY_PUBLIC_SHA1}
    write_json(out/'metadata-signing-report.json',reports);return reports

def verify_mapped(map_path,report_path):
    spec=json.loads(pathlib.Path(map_path).read_text());entries=spec['images'];readers={n:MappedReader(e) for n,e in entries.items()};report={'images':{},'descriptors':[],'fec_parity_independently_verified':False,'hardware_boot_verified':False}
    try:
        profile=json.loads((ROOT/'global-avb-profile.json').read_text())
        pinned=profile['preserved_sources']
        for name,value in pinned.items():
            if name=='mi_ext' and (ROOT/'mi_ext-signing-report.json').exists():
                value=json.loads((ROOT/'mi_ext-signing-report.json').read_text())['output']
            require(name in entries and entries[name].get('expected_sha256')==value['sha256'],'source partition hash is not pinned: '+name)
            require(readers[name].image_size==value['size'],'source partition size changed: '+name)
        metadata_records=json.loads((ROOT.parent/'final-avb/metadata-signing-report.json').read_text())
        for name,record in metadata_records.items():
            expected=record['output']
            require(name in entries and entries[name].get('expected_sha256')==expected['sha256'],'signed metadata hash not pinned: '+name)
            require(readers[name].image_size==expected['size'],'signed metadata size changed: '+name)
        product_record=json.loads((ROOT/'product-signing-report.json').read_text())['output']
        require(entries.get('product',{}).get('expected_sha256')==product_record['sha256'],'rebuilt product hash not pinned to authoring report')
        for n,r in readers.items():
            e=entries[n];got=r.sha256();require('expected_sha256' in e,'expected full-image SHA256 required: '+n);require(got==e['expected_sha256'],'full image hash mismatch: '+n);report['images'][n]={'size':r.image_size,'sha256':got,'full_image_sha256_verified':True}
        metas={n:parse_image(readers[n]) for n in ['vbmeta','vbmeta_system','boot','recovery']}
        expected_pub=(ROOT/'development.avbpubkey').read_bytes();require(metas['vbmeta'][4]==expected_pub and metas['vbmeta_system'][4]==expected_pub,'unexpected development key')
        require(metas['vbmeta'][1].rollback_index==0 and metas['vbmeta_system'][1].rollback_index==1788220800,'unexpected Global rollback')
        for n,v in metas.items():
            require(v[1].flags==0 and A.verify_vbmeta_signature(v[1],v[3]),'bad metadata signature/flags: '+n)
            report['images'][n].update({'signature_valid':True,'rollback_index':v[1].rollback_index,'public_key_sha1':hashlib.sha1(v[4]).hexdigest(),'flags':v[1].flags})
        chains=[d for d in metas['vbmeta'][2] if isinstance(d,A.AvbChainPartitionDescriptor)]
        require({d.partition_name:d.rollback_index_location for d in chains}=={'boot':3,'recovery':1,'vbmeta_system':2},'chain locations changed')
        for d in chains:require(d.public_key==metas[d.partition_name][4] and d.flags==0,'chain key mismatch')
        for n in ['boot','recovery']:require(hashlib.sha1(metas[n][4]).hexdigest()==OEM_SHA1,'OEM chain key changed')
        seen=set()
        for source,v in metas.items():
            for d in v[2]:
                if not isinstance(d,(A.AvbHashDescriptor,A.AvbHashtreeDescriptor)):continue
                n=d.partition_name;require(n not in seen,'duplicate partition authentication: '+n);seen.add(n);r=readers[n]
                require(d.flags==0 and 0<d.image_size<=r.image_size,'invalid descriptor flags/size')
                if isinstance(d,A.AvbHashDescriptor):
                    h=hashlib.new(d.hash_algorithm);h.update(d.salt);r.seek(0);remaining=d.image_size
                    while remaining:b=r.read(min(4*1024**2,remaining));h.update(b);remaining-=len(b)
                    require(h.digest()==d.digest,'AVB hash mismatch: '+n)
                else:
                    require(d.data_block_size==4096 and d.hash_block_size==4096 and d.dm_verity_version==1,'unsupported hashtree geometry')
                    require(d.tree_offset>=d.image_size and d.tree_offset%4096==0 and d.tree_offset+d.tree_size<=r.image_size,'hashtree outside legal range')
                    digest_size=len(hashlib.new(d.hash_algorithm).digest());padding=A.round_to_pow2(digest_size)-digest_size
                    offsets,size=A.calc_hash_level_offsets(d.image_size,4096,digest_size+padding);require(size==d.tree_size,'hashtree size mismatch')
                    root,tree=A.generate_hash_tree(r,d.image_size,4096,d.hash_algorithm,d.salt,padding,offsets,size)
                    require(root==d.root_digest,'AVB root mismatch: '+n);r.seek(d.tree_offset);require(r.read(d.tree_size)==tree,'stored hashtree mismatch: '+n)
                    require(d.fec_num_roots==2 and d.fec_size>0 and d.fec_offset>=d.tree_offset+d.tree_size and d.fec_offset+d.fec_size<=r.image_size,'invalid FEC bounds')
                report['descriptors'].append({'partition':n,'authenticated_by':source,'type':type(d).__name__,'verified':True})
        expected={'countrycode','dtbo','init_boot','vendor_boot','mi_ext','odm','system_dlkm','vendor','vendor_dlkm','product','system','system_ext','boot','recovery'}
        require(seen==expected,'authentication coverage mismatch')
        for r in readers.values():r.stable()
        report['full_chain_verified']=True;write_json(report_path,report);return report
    finally:
        for r in readers.values():r.close()

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='action',required=True);s.add_parser('prepare')
    x=s.add_parser('sign-product');x.add_argument('--image',required=True);x.add_argument('--sha256',required=True);x.add_argument('--size',required=True,type=int);x.add_argument('--partition-size',required=True,type=int);x.add_argument('--properties-json');x.add_argument('--partition',choices=['product','mi_ext'],default='product')
    x=s.add_parser('sign-metadata');x.add_argument('--product',required=True);x.add_argument('--product-sha256',required=True);x.add_argument('--out',required=True);x.add_argument('--mi-ext');x.add_argument('--mi-ext-sha256')
    x=s.add_parser('verify');x.add_argument('--image-map',required=True);x.add_argument('--report',required=True)
    args=p.parse_args()
    if args.action=='prepare':result=prepare()
    elif args.action=='sign-product':result=sign_product(args.image,args.sha256,args.size,args.partition_size,args.properties_json,args.partition)
    elif args.action=='sign-metadata':result=sign_metadata(args.product,args.product_sha256,args.out,args.mi_ext,args.mi_ext_sha256)
    else:result=verify_mapped(args.image_map,args.report)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()

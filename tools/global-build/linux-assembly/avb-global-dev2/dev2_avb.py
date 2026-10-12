#!/usr/bin/env python3
"""Explicit report-pinned DEV2 AVB support; DEV1 files remain immutable.

Only an approved, source-pinned vendor authoring report can replace the stock
vendor hash. Product and mi_ext stay byte-identical to reviewed DEV1 outputs.
No phone actions and no verification or FEC disabling are implemented.
"""
from __future__ import annotations
import argparse, copy, hashlib, importlib.util, json, pathlib, re, sys
ROOT=pathlib.Path(__file__).resolve().parent
LOCK_SHA256='3ed7ca04f2898800745bdb268f1e93810d079d9ead8c6d81e2332587041d5a76'

def require(test,message):
    if not test:raise ValueError(message)

def sha(path):
    with pathlib.Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def ref(path):
    p=pathlib.Path(path).resolve();return {'path':str(p),'size':p.stat().st_size,'sha256':sha(p)}

def checked(ref,decode=True):
    require(isinstance(ref,dict) and set(('path','size','sha256'))<=set(ref),'incomplete pinned reference')
    require(isinstance(ref['sha256'],str) and re.fullmatch('[0-9a-f]{64}',ref['sha256']),'invalid reference SHA256')
    p=pathlib.Path(ref['path']);require(p.is_file() and p.stat().st_size==ref['size'],'reference size mismatch: '+str(p))
    require(sha(p)==ref['sha256'],'reference SHA256 mismatch: '+str(p))
    return json.loads(p.read_text()) if decode else p

require(sha(ROOT/'dev1-lock.json')==LOCK_SHA256,'DEV1 lock changed')
LOCK=json.loads((ROOT/'dev1-lock.json').read_text())
checked(LOCK['dev1_verifier'],False);checked(LOCK['official_avb_source'],False)
spec=importlib.util.spec_from_file_location('frozen_dev1_avb',LOCK['dev1_verifier']['path']);G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
A=G.A
AUTHENTICATED={'countrycode','dtbo','init_boot','vendor_boot','mi_ext','odm','system_dlkm','vendor','vendor_dlkm','product','system','system_ext','boot','recovery'}
IMAGES=AUTHENTICATED|{'vbmeta','vbmeta_system'}

def write(path,value):
    with pathlib.Path(path).open('x') as f:json.dump(value,f,indent=2);f.write('\n')

def same_ref(a,b):return all(a.get(k)==b.get(k) for k in ('path','size','sha256'))

def load_spec(path,expected_sha=None):
    if expected_sha:require(sha(path)==expected_sha,'map SHA256 mismatch')
    d=json.loads(pathlib.Path(path).read_text());require(d.get('schema')==2 and d.get('build_id') in ('DEV1','DEV2'),'unsupported explicit map schema/build')
    require(set(d.get('images',{}))==IMAGES,'map must contain exactly the 16 AVB images')
    require(same_ref(d.get('source_profile',{}),LOCK['source_profile']),'source profile is not frozen Global profile')
    return d

POLICY_SOURCE_LOCK_SHA256='11d114e6977373e5f1606888b47ffe8134f4a9b823f693c2f826f21e130e803a'

def source_file_inventory(partition):
    require(sha(ROOT/'policy-source-inventory-lock.json')==POLICY_SOURCE_LOCK_SHA256,'policy source inventory lock changed')
    references=json.loads((ROOT/'policy-source-inventory-lock.json').read_text());require(partition in references,'unsupported source inventory')
    value=checked(references[partition]);expected=checked(LOCK['source_profile'])['preserved_sources'][partition]
    require(value['source_sha256']==expected['sha256'],'source inventory image binding mismatch')
    entries=value['entries'];rows={x['path']:x for x in entries if x['mode'] & 0o170000==0o100000}
    require(len(rows)==sum(x['mode'] & 0o170000==0o100000 for x in entries),'duplicate regular source path');return rows

def _evidence(item,label):
    value=checked(item['reference']);assertions=item.get('assertions')
    require(isinstance(assertions,list) and assertions,'review must pin successful assertions: '+label)
    for assertion in assertions:
        current=value
        for field in assertion['path']:
            require(isinstance(current,dict) and field in current,'review assertion path missing: '+label);current=current[field]
        require(current==assertion['equals'],'review assertion failed: '+label)
    return value

DERIVED_SOURCE_LOCK_SHA256='69002dc7ce2a8414f6f58a5f2d3c5501ce9412aa9885156fa5b5c5b6b2079e5f'
PLAT_PATH='/system/etc/selinux/plat_sepolicy.cil'
MAPPING_PATH='/system/etc/selinux/mapping/202604.cil'
CACHE_PATH='/system/etc/selinux/plat_sepolicy_and_mapping.sha256'

def validate_derived_metadata(approval,patches,readbacks):
    derived=approval.get('derived_files',[]);require(isinstance(derived,list),'derived_files must be a list')
    platform=[p for p in patches if p['partition']=='system' and p['path']==PLAT_PATH]
    if 'system' not in readbacks:
        require(not derived,'derived metadata outside authored system scope');return
    require(sha(ROOT/'derived-source-lock.json')==DERIVED_SOURCE_LOCK_SHA256,'derived source lock changed')
    frozen=json.loads((ROOT/'derived-source-lock.json').read_text())['files']
    rows={name:[r for r in readbacks['system'].get('files',[]) if r.get('path')==name] for name in (PLAT_PATH,MAPPING_PATH,CACHE_PATH)}
    require(all(len(x)==1 for x in rows.values()),'derived metadata/input missing or duplicate in system readback')
    require(rows[MAPPING_PATH][0]['sha256']==frozen[MAPPING_PATH]['sha256'] and rows[MAPPING_PATH][0]['size']==frozen[MAPPING_PATH]['size'],'derived mapping input changed from exact donor')
    if not platform:
        require(not derived and rows[CACHE_PATH][0]['sha256']==frozen[CACHE_PATH]['sha256'],'unaccounted derived digest change');return
    require(len(platform)==1 and len(derived)==1,'platform policy edit requires exactly one explicit derived digest')
    item=derived[0];require(set(item)=={'partition','path','before_sha256','after_sha256','derivation_report'} and item['partition']=='system' and item['path']==CACHE_PATH,'only the exact platform-policy cache digest is permitted')
    proposal=checked(item['derivation_report']);require(item['before_sha256']==frozen[CACHE_PATH]['sha256']==proposal.get('source_sha256'),'derived original file identity mismatch')
    require(item['after_sha256']==proposal.get('output_sha256'),'derived output hash not bound to proposal')
    require(proposal.get('system_as_root_readback_path')==CACHE_PATH and proposal.get('original_size_bytes')==65 and proposal.get('output_size_bytes')==65,'derived path/size contract mismatch')
    inputs=proposal.get('ordered_inputs',[])
    require(len(inputs)==2 and [x.get('semantic_path') for x in inputs]==[PLAT_PATH,MAPPING_PATH],'derived concatenation input order/path changed')
    require(inputs[0].get('reviewed_changed_input') is True and inputs[1].get('reviewed_changed_input') is False,'derived input mutation scope changed')
    require(inputs[0]['sha256']==platform[0]['after_sha256'],'derived platform input differs from semantic review')
    require(inputs[1]['sha256']==frozen[MAPPING_PATH]['sha256'] and inputs[1]['size']==frozen[MAPPING_PATH]['size'],'derived mapping is not exact original Global donor input')
    hasher=hashlib.sha256()
    for source in inputs:
        path=checked({k:source[k] for k in ('path','size','sha256')},False)
        row=rows[source['semantic_path']][0];require(row['sha256']==source['sha256'] and row['size']==source['size'],'derived input differs from final filesystem readback')
        with path.open('rb') as f:
            while chunk:=f.read(1024**2):hasher.update(chunk)
    expected=(hasher.hexdigest()+'\n').encode('ascii')
    require(len(expected)==65 and hashlib.sha256(expected).hexdigest()==item['after_sha256'],'derived output digest is not deterministic concatenation result')
    output=checked({'path':proposal['output'],'size':65,'sha256':item['after_sha256']},False)
    require(output.read_bytes()==expected,'derived output bytes must be lowercase ASCII hex plus exactly one LF')
    original=checked(frozen[CACHE_PATH]['captured'],False).read_bytes()
    require(original.decode('ascii').strip()==proposal.get('old_value') and hasher.hexdigest()==proposal.get('new_value'),'derived published digest text mismatch')
    row=rows[CACHE_PATH][0];require(row['sha256']==item['after_sha256'] and row['size']==65,'derived output differs from final filesystem readback')

def validate_composition_approval(reference,profile):
    approval=checked(reference)
    require(approval.get('build_id')=='DEV2' and approval.get('approved_for_offline_authoring') is True,'composition approval missing')
    require(approval.get('preserve_other_files_and_metadata') is True,'unchanged-file/metadata constraint missing')
    evidence=approval.get('evidence',{})
    if approval.get('schema')==1:
        require(approval.get('partition')=='vendor' and approval.get('status')=='APPROVED_OFFLINE_VENDOR_COMPOSITION','invalid vendor-only approval')
        require(set(evidence)=={'independent_policy_review','semantic_policy_review','filesystem_readback'},'vendor-only evidence set invalid')
        sources={'vendor':approval['source']};filesystems={'vendor':approval['filesystem']};readback_evidence={'vendor':evidence['filesystem_readback']}
        patches=[{'partition':'vendor',**x} for x in approval.get('patched_files',[])]
    elif approval.get('schema')==2:
        require(approval.get('status')=='APPROVED_OFFLINE_POLICY_COMPOSITION','invalid joint-policy approval')
        require(set(evidence)=={'independent_policy_review','semantic_policy_review','filesystem_readbacks'},'joint evidence set invalid')
        sources=approval.get('sources',{});filesystems=approval.get('filesystems',{});readback_evidence=evidence['filesystem_readbacks'];patches=approval.get('patched_files',[])
        require(set(sources) in ({'vendor'},{'vendor','system'}),'only vendor and optional system may be authored')
        require(set(sources)==set(filesystems)==set(readback_evidence),'source/filesystem/readback scopes differ')
    else:raise ValueError('unsupported composition approval schema')
    for name,source in sources.items():
        expected=profile['preserved_sources'][name]
        require(source.get('sha256')==expected['sha256'] and source.get('size')==expected['size'],'source does not match exact Global image: '+name)
        body=filesystems[name]
        require(type(body.get('size')) is int and 0<body['size']<=expected['size'] and body['size']%4096==0,'invalid reviewed filesystem size: '+name)
        require(isinstance(body.get('sha256'),str) and re.fullmatch('[0-9a-f]{64}',body['sha256']),'invalid reviewed filesystem SHA256: '+name)
    delta=approval.get('policy_delta',{})
    expected_delta={'kind','effective_added_permission_tuples','effective_removed_permission_tuples','existing_attribute_memberships_identical','all_original_assertions_retained_byte_identically'}
    require(set(delta)==expected_delta and delta['kind']=='exclusion_only','invalid bounded policy-delta contract')
    require(type(delta['effective_added_permission_tuples']) is int and delta['effective_added_permission_tuples']==0 and type(delta['effective_removed_permission_tuples']) is int and delta['effective_removed_permission_tuples']>0,'policy must remove permissions without adding any')
    require(delta['existing_attribute_memberships_identical'] is True and delta['all_original_assertions_retained_byte_identically'] is True,'membership/assertion preservation missing')
    independent=_evidence(evidence['independent_policy_review'],'independent_policy_review')
    require(independent.get('static_source_composition_verified') is True,'independent static source composition review has not passed')
    semantic=_evidence(evidence['semantic_policy_review'],'semantic_policy_review')
    for key in ('expected_scope_exactly_matches_effective_removals','all_other_ordinary_permissions_identical','all_extended_permissions_audit_rules_transitions_constraints_labels_capabilities_permissive_state_identical'):require(semantic.get(key) is True,'unrelated or unscoped semantic changes: '+key)
    require(semantic.get('normal_compile_returncode')==0,'normal policy compilation has not passed')
    for name,value in delta.items():
        if name!='kind':require(semantic.get(name)==value,'semantic delta not bound to receipt: '+name)
    readbacks={}
    for name,item in readback_evidence.items():
        readback=_evidence(item,'filesystem_readback:'+name);body=filesystems[name]
        require(readback.get('status')=='verified' and readback.get('all_file_bytes_sha256_verified') is True and readback.get('all_uid_gid_modes_selinux_xattrs_verified') is True,'full EROFS readback has not passed: '+name)
        for key in ('all_regular_and_symlink_bytes_verified','all_uid_gid_modes_labels_capability_xattrs_verified','hardlink_groups_preserved'):require(readback.get(key) is True,'EROFS preservation check missing or failed: '+name+':'+key)
        require(readback.get('filesystem_sha256')==body['sha256'] and readback.get('filesystem_size_bytes')==body['size'],'readback does not match final filesystem: '+name);readbacks[name]=readback
    require(isinstance(patches,list) and patches,'explicit patched-file set required')
    source_files=semantic.get('source_files',[]);changed_rows=[x for x in source_files if x['before_sha256']!=x['after_sha256']]
    changed={(x['before'],x['after']):(x['before_sha256'],x['after_sha256']) for x in changed_rows};require(len(changed)==len(changed_rows),'duplicate changed source records')
    original_files={name:source_file_inventory(name) for name in sources}
    bound=set();paths=set();touched=set()
    for patch in patches:
        partition=patch.get('partition');require(partition in sources,'patched partition is outside approval')
        name=patch['path'];prefix='/system/etc/selinux/' if partition=='system' else '/etc/selinux/'
        require(isinstance(name,str) and name.startswith(prefix) and name.endswith('.cil') and '..' not in pathlib.PurePosixPath(name).parts and str(pathlib.PurePosixPath(name))==name,'patch outside exact canonical filesystem path scope')
        require((partition,name) not in paths,'duplicate patched path');paths.add((partition,name));touched.add(partition)
        before=patch['before_sha256'];after=patch['after_sha256'];require(original_files[partition].get(name,{}).get('sha256')==before,'patched before-hash is not exact frozen source content');require(re.fullmatch('[0-9a-f]{64}',before) and re.fullmatch('[0-9a-f]{64}',after) and before!=after,'invalid patch hashes')
        pair=(patch['semantic_source_before'],patch['semantic_source_after']);suffix=name if partition=='system' else '/vendor'+name
        require(all(isinstance(x,str) and x.endswith(suffix) and str(pathlib.PurePosixPath(x))==x and '..' not in pathlib.PurePosixPath(x).parts for x in pair),'semantic source path does not match exact partition/path')
        require(pair not in bound and changed.get(pair)==(before,after),'patch not bound to reviewed semantic source hashes');bound.add(pair)
        rows=[x for x in readbacks[partition].get('files',[]) if x.get('path')==name];require(len(rows)==1 and rows[0].get('sha256')==after,'patched file does not match EROFS readback: '+partition+name)
    require(bound==set(changed),'semantic review contains unaccounted changed files')
    require(touched==set(sources),'unused or unreviewed authored partition scope')
    validate_derived_metadata(approval,patches,readbacks)
    changes={(x['partition'],x['path']):x['after_sha256'] for x in patches}
    changes.update({(x['partition'],x['path']):x['after_sha256'] for x in approval.get('derived_files',[])})
    for partition,originals in original_files.items():
        rows=readbacks[partition].get('files',[]);current={x['path']:x for x in rows}
        require(len(current)==len(rows) and set(current)==set(originals),'regular-file path set changed or duplicated: '+partition)
        for name,old in originals.items():
            expected=changes.get((partition,name),old['sha256']);require(current[name]['sha256']==expected,'unaccounted or incorrect filesystem file change: '+partition+name)
            if (partition,name) not in changes:require(current[name]['size']==old['size'],'unchanged file size differs: '+partition+name)
    return {'receipt':approval,'sources':sources,'filesystems':filesystems,'partitions':sorted(sources)}

def validate_partition_approval(reference,profile,partition):
    result=validate_composition_approval(reference,profile);require(partition in result['partitions'],'partition not included in composition approval')
    return {**result['receipt'],'source':result['sources'][partition],'filesystem':result['filesystems'][partition],'partition':partition,'reviewed_partitions':result['partitions']}

def validate_vendor_approval(reference,profile):return validate_partition_approval(reference,profile,'vendor')

def validate_authored_report(reference,profile,partition):
    report=checked(reference)
    require(report.get('schema')==2 and report.get('build_id')=='DEV2' and report.get('partition')==partition and partition in ('vendor','system'),'wrong authored-partition report schema/scope')
    require(report.get('composition_review_approved') is True and report.get('filesystem_bytes_unchanged') is True and report.get('hashtree_verified') is True,'vendor report has not passed authoring gates')
    approval=validate_partition_approval(report['approval'],profile,partition)
    require(report['source']==approval['source'],'authoring source not bound to reviewed source')
    require(report.get('source_partition_sha256')==approval['source']['sha256'],'direct source hash binding mismatch')
    require(report.get('composition_review')=={'path':report['approval']['path'],'sha256':report['approval']['sha256']},'direct composition-review binding mismatch')
    require(report['input_sha256']==approval['filesystem']['sha256'] and report['input_size']==approval['filesystem']['size'],'authored input not bound to reviewed filesystem')
    output=report['output'];require(isinstance(output.get('sha256'),str) and re.fullmatch('[0-9a-f]{64}',output['sha256']),'invalid authored output SHA256');require(output['size']==profile['preserved_sources'][partition]['size'],'authored allocation changed')
    require(report.get('fec_num_roots')==2 and report.get('verification_flags')==0,'vendor FEC or flags weakened')
    return report

def validate_vendor_report(reference,profile):return validate_authored_report(reference,profile,'vendor')

def validate_policy(spec,require_metadata=True):
    profile=checked(spec['source_profile']);entries=spec['images'];reports=spec.get('authored_partitions',{})
    if spec['build_id']=='DEV1':require(set(reports)=={'product','mi_ext'},'unexpected DEV1 authored reports')
    else:require(set(reports) in ({'product','mi_ext','vendor'},{'product','mi_ext','vendor','system'}),'unexpected DEV2 authored reports')
    records={}
    for name in ('product','mi_ext'):
        require(same_ref(reports[name],LOCK[name+'_report']),'retained authoring report changed: '+name)
        report=checked(reports[name]);require(report.get('composition_review_approved') is True,'retained partition approval missing: '+name)
        record=report['output'];locked=LOCK['retained_outputs'][name]
        require(record['sha256']==locked['sha256'] and record['size']==locked['size'],'retained DEV1 partition changed: '+name);records[name]=record
    vendor=None
    if spec['build_id']=='DEV2':
        authored={name:validate_authored_report(reports[name],profile,name) for name in set(reports)-{'product','mi_ext'}}
        vendor=authored['vendor'];approval=validate_composition_approval(vendor['approval'],profile)
        require(set(authored)==set(approval['partitions']),'map omits or adds a jointly reviewed partition')
        for name,item in authored.items():
            require(same_ref(item['approval'],vendor['approval']),'authored partitions reference different composition approvals');records[name]=item['output']
    for name,value in profile['preserved_sources'].items():
        expected=records.get(name,value);e=entries[name]
        require(e.get('expected_sha256')==expected['sha256'] and e.get('size')==expected['size'],'partition is not source/report pinned: '+name)
    require(entries['product'].get('expected_sha256')==records['product']['sha256'] and entries['product'].get('size')==records['product']['size'],'product is not retained-output pinned')
    metadata=None
    if require_metadata:
        metadata_ref=spec.get('metadata_signing_report');require(isinstance(metadata_ref,dict),'explicit metadata report is required')
        metadata=checked(metadata_ref)
        if spec['build_id']=='DEV1':
            require(same_ref(metadata_ref,LOCK['metadata_report']),'DEV1 metadata report changed');images=metadata
        else:
            require(metadata.get('schema')==2 and metadata.get('build_id')=='DEV2','wrong DEV2 metadata report')
            require(same_ref(metadata.get('authored_vendor_report',{}),reports['vendor']),'metadata not bound to authored vendor report')
            if 'system' in reports:require(same_ref(metadata.get('authored_system_report',{}),reports['system']),'metadata not bound to authored system report')
            else:require(metadata.get('authored_system_report') is None,'metadata unexpectedly declares authored system')
            require(same_ref(metadata.get('source_profile',{}),spec['source_profile']),'metadata profile binding mismatch')
            images=metadata['images']
        require(set(images)=={'vbmeta','vbmeta_system'},'wrong metadata output set')
        for name,item in images.items():
            expected=item['output'];require(entries[name].get('expected_sha256')==expected['sha256'] and entries[name].get('size')==expected['size'],'metadata image not pinned: '+name)
    return profile,vendor,metadata

def mapped_meta(entry,partition,verify_full_hash=True):
    r=G.MappedReader(entry)
    try:
        if verify_full_hash:require(r.sha256()==entry['expected_sha256'],'mapped partition hash mismatch: '+partition)
        v=G.parse_image(r);require(v[0] is not None,'mapped filesystem has no footer: '+partition)
        require(v[1].flags==0 and A.verify_vbmeta_signature(v[1],v[3]),'invalid mapped metadata: '+partition)
        require(all(G.belongs(d,partition) for d in v[2]),'foreign descriptor in '+partition)
        trees=[d for d in v[2] if isinstance(d,A.AvbHashtreeDescriptor)]
        require(len(trees)==1,'filesystem must have one hashtree: '+partition);d=trees[0]
        require(d.flags==0 and d.fec_num_roots==2 and d.fec_size>0 and d.hash_algorithm=='sha256','weak mapped verification metadata')
        require(d.image_size==v[0].original_image_size and d.fec_offset+d.fec_size<=v[0].vbmeta_offset,'invalid mapped body/FEC bounds')
        r.stable();return v
    finally:r.close()

def verify_filesystem_tree(entry,descriptor):
    r=G.MappedReader(entry);d=descriptor
    try:
        require(d.data_block_size==4096 and d.hash_block_size==4096 and d.dm_verity_version==1 and d.flags==0,'unsupported authored tree geometry')
        require(d.tree_offset>=d.image_size and d.tree_offset+d.tree_size<=r.image_size,'authored tree outside image')
        size_digest=len(hashlib.new(d.hash_algorithm).digest());padding=A.round_to_pow2(size_digest)-size_digest
        offsets,size=A.calc_hash_level_offsets(d.image_size,4096,size_digest+padding);require(size==d.tree_size,'authored tree size mismatch')
        root,tree=A.generate_hash_tree(r,d.image_size,4096,d.hash_algorithm,d.salt,padding,offsets,size)
        require(root==d.root_digest,'authored vendor root mismatch');r.seek(d.tree_offset);require(r.read(d.tree_size)==tree,'authored stored tree mismatch')
        require(d.fec_num_roots==2 and d.fec_size>0 and d.fec_offset>=d.tree_offset+d.tree_size and d.fec_offset+d.fec_size<=r.image_size,'authored FEC bounds invalid');r.stable()
    finally:r.close()

def capture_footers(map_path,out):
    spec=load_spec(map_path);validate_policy(spec);out=pathlib.Path(out);out.mkdir(exist_ok=False);records={}
    for name in ('product','mi_ext','vendor'):
        v=mapped_meta(spec['images'][name],name);p=out/(name+'.source-vbmeta.img')
        with p.open('xb') as f:f.write(v[3])
        records[name]={'image_sha256':spec['images'][name]['expected_sha256'],'image_size':spec['images'][name]['size'],'mapped_source':spec['images'][name],'captured_vbmeta':ref(p),'footer':{k:v for k,v in vars(v[0]).items() if k!='magic'},'descriptors':[G.desc_record(d) for d in v[2]]}
    result={'source_map':ref(map_path),'partitions':records,'large_image_extraction':False};write(out/'capture-report.json',result);return result

def author_partition(image,approval_ref,source_map,out_report,partition='vendor'):
    require(partition in ('vendor','system'),'unsupported authored partition')
    spec=load_spec(source_map);require(spec['build_id']=='DEV1','vendor must be based on frozen DEV1 map');profile,_,_=validate_policy(spec)
    checked(profile['avbtool'],False)
    approval=validate_partition_approval(approval_ref,profile,partition);p=pathlib.Path(image).resolve();require(p.stat().st_size==approval['filesystem']['size'] and sha(p)==approval['filesystem']['sha256'],'vendor input does not match approved filesystem')
    require(not pathlib.Path(out_report).exists(),'refusing report overwrite')
    for entry in spec['images'].values():require(not p.samefile(entry['path']),'refusing to modify a frozen DEV1 backing file')
    with p.open('rb') as f:f.seek(-64,2);require(f.read(4)!=b'AVBf','vendor already has an AVB footer')
    source=mapped_meta(spec['images'][partition],partition);tree=[d for d in source[2] if isinstance(d,A.AvbHashtreeDescriptor)][0]
    properties=[d for d in source[2] if isinstance(d,A.AvbPropertyDescriptor)]
    partition_size=profile['preserved_sources'][partition]['size'];sizing=G.command(['add_hashtree_footer','--partition_size',partition_size,'--hash_algorithm','sha256','--block_size',4096,'--fec_num_roots',2,'--calc_max_image_size'])
    require(p.stat().st_size<=int(sizing['stdout'].strip()),'reviewed vendor filesystem plus AVB/FEC will not fit')
    args=['add_hashtree_footer','--image',p,'--partition_name',partition,'--partition_size',partition_size,'--hash_algorithm','sha256','--block_size',4096,'--fec_num_roots',2,'--salt',tree.salt.hex(),'--algorithm','NONE','--flags',0]
    for d in properties:args+=['--prop',d.key+':'+d.value.decode()]
    command=G.command(args);output=ref(p);entry={'path':str(p),'size':output['size'],'expected_sha256':output['sha256']};v=mapped_meta(entry,partition)
    r=G.MappedReader(entry);h=hashlib.sha256();remaining=approval['filesystem']['size']
    try:
        while remaining:b=r.read(min(4*1024**2,remaining));h.update(b);remaining-=len(b)
        r.stable()
    finally:r.close()
    require(h.hexdigest()==approval['filesystem']['sha256'],'vendor reviewed filesystem bytes changed')
    require(v[0].original_image_size==approval['filesystem']['size'],'vendor footer body size mismatch')
    verify_filesystem_tree(entry,[d for d in v[2] if isinstance(d,A.AvbHashtreeDescriptor)][0])
    require([d.encode() for d in v[2] if isinstance(d,A.AvbPropertyDescriptor)]==[d.encode() for d in properties],'vendor lineage properties changed')
    report={'schema':2,'build_id':'DEV2','partition':partition,'composition_review_approved':True,'source':approval['source'],'source_partition_sha256':approval['source']['sha256'],'composition_review':{'path':approval_ref['path'],'sha256':approval_ref['sha256']},'source_map':ref(source_map),'approval':approval_ref,'input_sha256':approval['filesystem']['sha256'],'input_size':approval['filesystem']['size'],'output':output,'filesystem_bytes_unchanged':True,'hashtree_verified':True,'fec_num_roots':2,'verification_flags':0,'sizing':sizing,'command':command,'descriptors':[G.desc_record(d) for d in v[2]],'fec_parity_independently_verified':False}
    write(out_report,report);return report

def sign_metadata(inherited_map,vendor_image,vendor_report_ref,out,system_image=None,system_report_ref=None):
    spec=load_spec(inherited_map);require(spec['build_id']=='DEV1','signing source must be frozen DEV1');profile,_,_=validate_policy(spec)
    checked(profile['avbtool'],False)
    vendor_report=validate_vendor_report(vendor_report_ref,profile)
    approval=validate_composition_approval(vendor_report['approval'],profile)
    require(('system' in approval['partitions'])==bool(system_image and system_report_ref),'joint approval requires exactly its authored-system input')
    require(bool(system_image)==bool(system_report_ref),'system image/report must be supplied together')
    system_report=None
    if system_report_ref:
        system_report=validate_authored_report(system_report_ref,profile,'system');require(same_ref(system_report['approval'],vendor_report['approval']),'system/vendor approvals differ')
    for expected in profile['sources'].values():checked({k:expected[k] for k in ('path','size','sha256')},False)
    checked(LOCK['development_key'],False);checked(LOCK['development_public_key'],False)
    product=mapped_meta(spec['images']['product'],'product');mi_ext=mapped_meta(spec['images']['mi_ext'],'mi_ext')
    v=vendor_report['output'];vendor=mapped_meta({'path':str(vendor_image),'size':v['size'],'expected_sha256':v['sha256']},'vendor')
    top,system=G.get_descriptors(G.source_meta(),product[2])
    if system_report:
        item=system_report['output'];updated_system=mapped_meta({'path':str(system_image),'size':item['size'],'expected_sha256':item['sha256']},'system')
        system=[d for d in system if not G.belongs(d,'system')]+updated_system[2]
    top=[d for d in top if not G.belongs(d,'mi_ext') and not G.belongs(d,'vendor')]+mi_ext[2]+vendor[2]
    out=pathlib.Path(out).resolve();require(out==ROOT.parent/'final-avb-dev2','DEV2 metadata must use the explicitly assigned separate output directory');out.mkdir(exist_ok=False);reports={}
    for name,descs,rollback in [('vbmeta_system',system,1788220800),('vbmeta',top,0)]:
        capsule=out/(name+'.descriptor-capsule.img');dest=out/(name+'.img');G.unsigned_capsule(capsule,descs)
        command=G.command(['make_vbmeta_image','--output',dest,'--padding_size',4096,'--algorithm','SHA256_RSA4096','--key',G.KEY,'--rollback_index',rollback,'--rollback_index_location',0,'--flags',0,'--include_descriptors_from_image',capsule])
        parsed=G.load_meta(dest);require(hashlib.sha1(parsed[4]).hexdigest()==G.KEY_PUBLIC_SHA1,'unexpected signing key');require(dest.stat().st_size<=131072,'metadata exceeds physical capacity')
        require(sorted(d.encode() for d in parsed[2])==sorted(d.encode() for d in descs),'metadata descriptors changed')
        reports[name]={'output':ref(dest),'raw_vbmeta_size':len(parsed[3]),'rollback_index':parsed[1].rollback_index,'flags':parsed[1].flags,'signature_valid':True,'public_key_sha1':G.KEY_PUBLIC_SHA1,'command':command}
    previous=checked(spec['metadata_signing_report'])
    if not system_report:require(reports['vbmeta_system']['output']['sha256']==previous['vbmeta_system']['output']['sha256'],'unchanged product/system metadata is not reproducible')
    result={'schema':2,'build_id':'DEV2','source_profile':spec['source_profile'],'inherited_map':ref(inherited_map),'authored_vendor_report':vendor_report_ref,'authored_system_report':system_report_ref,'retained_authored_reports':spec['authored_partitions'],'images':reports,'phone_actions':False,'hardware_boot_verified':False};write(out/'metadata-signing-report.json',result);return result

def verify(map_path,report_path):
    spec=load_spec(map_path);profile,vendor,_=validate_policy(spec);entries=spec['images'];readers={};report={'build_id':spec['build_id'],'map':ref(map_path),'source_profile':spec['source_profile'],'metadata_signing_report':spec['metadata_signing_report'],'authored_partitions':spec['authored_partitions'],'images':{},'descriptors':[],'fec_parity_independently_verified':False,'hardware_boot_verified':False}
    try:
        for name,e in entries.items():
            r=G.MappedReader(e);readers[name]=r;got=r.sha256();require(got==e['expected_sha256'],'full image hash mismatch: '+name);report['images'][name]={'size':r.image_size,'sha256':got,'full_image_sha256_verified':True}
        metas={n:G.parse_image(readers[n]) for n in ('vbmeta','vbmeta_system','boot','recovery')};public=checked(LOCK['development_public_key'],False).read_bytes()
        require(metas['vbmeta'][4]==public and metas['vbmeta_system'][4]==public,'development key mismatch')
        for name,v in metas.items():
            require(v[1].rollback_index=={'vbmeta':0,'vbmeta_system':1788220800,'boot':1769904000,'recovery':1}[name],'Global rollback mismatch: '+name)
            require(v[1].flags==0 and A.verify_vbmeta_signature(v[1],v[3]),'metadata signature/flag failure: '+name)
            report['images'][name].update({'signature_valid':True,'flags':0,'rollback_index':v[1].rollback_index,'public_key_sha1':hashlib.sha1(v[4]).hexdigest()})
        chains=[d for d in metas['vbmeta'][2] if isinstance(d,A.AvbChainPartitionDescriptor)]
        require(len(chains)==3 and {d.partition_name:d.rollback_index_location for d in chains}=={'boot':3,'recovery':1,'vbmeta_system':2},'chain location mismatch')
        for d in chains:require(d.public_key==metas[d.partition_name][4] and d.flags==0,'chain key or flags changed')
        for name in ('boot','recovery'):require(hashlib.sha1(metas[name][4]).hexdigest()==G.OEM_SHA1,'OEM chain changed')
        seen=set()
        for source,v in metas.items():
            for d in v[2]:
                if not isinstance(d,(A.AvbHashDescriptor,A.AvbHashtreeDescriptor)):continue
                name=d.partition_name;require(name in AUTHENTICATED and name not in seen,'unexpected/duplicate authentication');seen.add(name);r=readers[name]
                require(d.flags==0 and 0<d.image_size<=r.image_size,'descriptor flags/size invalid')
                if isinstance(d,A.AvbHashDescriptor):
                    h=hashlib.new(d.hash_algorithm);h.update(d.salt);r.seek(0);left=d.image_size
                    while left:b=r.read(min(4*1024**2,left));h.update(b);left-=len(b)
                    require(h.digest()==d.digest,'AVB hash mismatch: '+name)
                else:
                    require(d.data_block_size==4096 and d.hash_block_size==4096 and d.dm_verity_version==1,'unsupported hashtree geometry')
                    require(d.tree_offset>=d.image_size and d.tree_offset%4096==0 and d.tree_offset+d.tree_size<=r.image_size,'hashtree bounds invalid')
                    ds=len(hashlib.new(d.hash_algorithm).digest());padding=A.round_to_pow2(ds)-ds;offsets,size=A.calc_hash_level_offsets(d.image_size,4096,ds+padding);require(size==d.tree_size,'hashtree size mismatch')
                    root,tree=A.generate_hash_tree(r,d.image_size,4096,d.hash_algorithm,d.salt,padding,offsets,size);require(root==d.root_digest,'root digest mismatch: '+name);r.seek(d.tree_offset);require(r.read(d.tree_size)==tree,'stored tree mismatch: '+name)
                    require(d.fec_num_roots==2 and d.fec_size>0 and d.fec_offset>=d.tree_offset+d.tree_size and d.fec_offset+d.fec_size<=r.image_size,'FEC bounds invalid')
                report['descriptors'].append({'partition':name,'authenticated_by':source,'type':type(d).__name__,'verified':True})
        require(seen==AUTHENTICATED,'incomplete authentication coverage')
        for r in readers.values():r.stable()
        report['full_chain_verified']=True;write(report_path,report);return report
    finally:
        for r in readers.values():r.close()

def compose_map(candidate_map,vendor_report_ref,metadata_report_ref,out,system_report_ref=None):
    raw=json.loads(pathlib.Path(candidate_map).read_text())
    require(isinstance(raw.get('super_sha256'),str) and re.fullmatch('[0-9a-f]{64}',raw['super_sha256']),'candidate super SHA256 missing')
    spec=copy.deepcopy(raw);spec.update({'schema':2,'build_id':'DEV2','source_profile':LOCK['source_profile'],'authored_partitions':{'product':LOCK['product_report'],'mi_ext':LOCK['mi_ext_report'],'vendor':vendor_report_ref},'metadata_signing_report':metadata_report_ref})
    if system_report_ref:spec['authored_partitions']['system']=system_report_ref
    require(set(spec.get('images',{}))==IMAGES,'candidate must provide all 16 images')
    validate_policy(spec);write(out,spec);return spec

def read_ref_arg(path,expected_sha):
    value=ref(path);require(value['sha256']==expected_sha,'explicit reference argument mismatch');return value

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='command',required=True)
    a=s.add_parser('capture-footers');a.add_argument('--source-map',required=True);a.add_argument('--out',required=True)
    a=s.add_parser('author-partition',aliases=['author-vendor']);a.add_argument('--partition',choices=['vendor','system'],default='vendor');a.add_argument('--image',required=True);a.add_argument('--approval',required=True);a.add_argument('--approval-sha256',required=True);a.add_argument('--source-map',required=True);a.add_argument('--report',required=True)
    a=s.add_parser('sign-metadata');a.add_argument('--source-map',required=True);a.add_argument('--vendor-image',required=True);a.add_argument('--vendor-report',required=True);a.add_argument('--vendor-report-sha256',required=True);a.add_argument('--out',required=True);a.add_argument('--system-image');a.add_argument('--system-report');a.add_argument('--system-report-sha256')
    a=s.add_parser('verify');a.add_argument('--image-map',required=True);a.add_argument('--report',required=True)
    a=s.add_parser('compose-map');a.add_argument('--candidate-map',required=True);a.add_argument('--vendor-report',required=True);a.add_argument('--vendor-report-sha256',required=True);a.add_argument('--metadata-report',required=True);a.add_argument('--metadata-report-sha256',required=True);a.add_argument('--out',required=True);a.add_argument('--system-report');a.add_argument('--system-report-sha256')
    a=p.parse_args()
    if a.command=='capture-footers':result=capture_footers(a.source_map,a.out)
    elif a.command in ('author-vendor','author-partition'):result=author_partition(a.image,read_ref_arg(a.approval,a.approval_sha256),a.source_map,a.report,a.partition)
    elif a.command=='sign-metadata':result=sign_metadata(a.source_map,a.vendor_image,read_ref_arg(a.vendor_report,a.vendor_report_sha256),a.out,a.system_image,read_ref_arg(a.system_report,a.system_report_sha256) if a.system_report else None)
    elif a.command=='compose-map':result=compose_map(a.candidate_map,read_ref_arg(a.vendor_report,a.vendor_report_sha256),read_ref_arg(a.metadata_report,a.metadata_report_sha256),a.out,read_ref_arg(a.system_report,a.system_report_sha256) if a.system_report else None)
    else:result=verify(a.image_map,a.report)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()

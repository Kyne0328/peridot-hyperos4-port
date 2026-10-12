#!/usr/bin/env python3
"""Read existing APEX evidence, validate package identities, stage unchanged copies.
Does not activate packages or invoke checkvintf. Requires reviewed source inventory.
"""
import argparse, collections, hashlib, json, pathlib, shutil, subprocess, zipfile
p = argparse.ArgumentParser()
p.add_argument('--input', required=True)
p.add_argument('--tools', required=True)
p.add_argument('--archive', required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
def digest_stream(stream):
    h=hashlib.sha256()
    while block := stream.read(1024*1024): h.update(block)
    return h.hexdigest()
def digest_file(path):
    with path.open('rb') as stream: return digest_stream(stream)
source = pathlib.Path(a.input).resolve()
archive=pathlib.Path(a.archive).resolve()
if archive.stat().st_size != 443487088 or digest_file(archive) != '0cfc97852fd56c6ef704bc625652b95beb0f8f6e5df1edaf84195d226514b6bf':
    raise SystemExit('Source archive size/hash differs from verified archive')
zip_input=zipfile.ZipFile(archive)
def archive_digest(relative_path):
    rel=str(relative_path).replace(chr(92),'/')
    matches=[n for n in zip_input.namelist() if n.replace(chr(92),'/') == rel or n.replace(chr(92),'/').endswith('/'+rel)]
    if len(matches)!=1: raise SystemExit(f'Ambiguous/missing archive path for {rel}; inspect layout')
    with zip_input.open(matches[0]) as stream: return digest_stream(stream)
tools = pathlib.Path(a.tools).resolve()
out = pathlib.Path(a.output).resolve()
if out.exists(): raise SystemExit('Output must be a fresh, nonexistent directory')
inv = source / 'package-inventory.json'
if not inv.is_file(): raise SystemExit('Source package-inventory.json is required')
inventory=json.loads(inv.read_text(encoding='utf-8-sig'))
if digest_file(inv) != archive_digest('package-inventory.json'):
    raise SystemExit('Source inventory differs from verified archive')
expected = {'system':36, 'system_ext':3, 'product':1, 'vendor':1, 'odm':0}
if inventory.get('schema_version') != 1 or inventory.get('purpose') != 'source_apex_packages_not_runtime_activation':
    raise SystemExit('Unexpected source inventory schema/purpose')
rows=inventory.get('packages')
if not isinstance(rows,list) or len(rows)!=41:
    raise SystemExit('Inventory must contain the complete 41-package set')
indexed={}
for row in rows:
    if not isinstance(row,dict): raise SystemExit('Malformed package inventory row')
    rel=row.get('path'); part=row.get('partition'); size=row.get('size_bytes'); sha=row.get('sha256')
    if not isinstance(rel,str): raise SystemExit('Missing package path')
    rel=rel.replace(chr(92),'/')
    path_parts=rel.split('/')
    if rel.startswith('/') or any(x in ('','.','..') for x in path_parts):
        raise SystemExit(f'Unsafe inventory path: {rel}')
    if part not in expected or not isinstance(size,int) or size<=0 or not isinstance(sha,str) or len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha):
        raise SystemExit(f'Malformed inventory metadata for {rel}')
    if rel in indexed: raise SystemExit(f'Duplicate inventory path: {rel}')
    indexed[rel]={'partition':part,'size_bytes':size,'sha256':sha}
if {k:sum(r['partition']==k for r in indexed.values()) for k in expected} != expected:
    raise SystemExit('Inventory partition counts differ from expected package set')
if sum(r['size_bytes'] for r in indexed.values()) != 626079252:
    raise SystemExit('Inventory total package size differs from verified extraction')
source_rows=inventory.get('sources')
if not isinstance(source_rows,list): raise SystemExit('Source image provenance list missing')
source_index={}
for row in source_rows:
    part=row.get('partition')
    if part not in expected or part in source_index: raise SystemExit('Unexpected/duplicate source partition')
    if row.get('package_count')!=expected[part]: raise SystemExit(f'Source count mismatch: {part}')
    image_hash=row.get('image_sha256')
    if not isinstance(image_hash,str) or len(image_hash)!=64 or any(c not in '0123456789abcdef' for c in image_hash):
        raise SystemExit(f'Source image hash missing/malformed: {part}')
    if row.get('logical_path') != ('/system/apex' if part=='system' else '/apex'):
        raise SystemExit(f'Unexpected logical APEX path: {part}')
    source_index[part]=row
if not all(k in source_index for k,v in expected.items() if v):
    raise SystemExit('Missing source provenance for a nonempty partition')
files = sorted(x for x in source.rglob('*') if x.suffix.lower() in ('.apex','.capex'))
actual_paths={str(x.relative_to(source)) for x in files}
if actual_paths != set(indexed):
    raise SystemExit(f'File set differs from inventory; missing={sorted(set(indexed)-actual_paths)}, extra={sorted(actual_paths-set(indexed))}')
records, names, counts = [], {}, collections.Counter()
for path in files:
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(source):
        raise SystemExit(f'Unexpected package path: {path}')
    # Discover extraction nesting. Every known extraction ultimately contains
    # <partition>/apex/<filename>; do not assume a fixed number of parent dirs.
    if path.parent.name != 'apex' or path.parent.parent.name not in expected:
        raise SystemExit(f'Cannot establish partition from path; inspect inventory: {path}')
    part = path.parent.parent.name
    row=indexed[str(path.relative_to(source))]
    if part != row['partition'] or path.stat().st_size != row['size_bytes']:
        raise SystemExit(f'Package partition/size differs from inventory: {path}')
    digest=digest_file(path)
    if digest != row['sha256']:
        raise SystemExit(f'Package hash differs from inventory: {path}')
    if digest != archive_digest(path.relative_to(source)):
        raise SystemExit(f'Package differs from verified archive: {path}')
    result = subprocess.run([str(tools/'bin/deapexer'), 'info', str(path)],
                            capture_output=True, text=True, check=True)
    info = json.loads(result.stdout)
    name = info.get('name')
    if not isinstance(name,str) or not name or name in ('.','..') or any(
            c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in name):
        raise SystemExit(f'Unsafe or missing module name in {path}')
    if name in names:
        raise SystemExit(f'Duplicate module {name}: {names[name]} and {path}; review before activation')
    names[name] = str(path)
    counts[part] += 1
    records.append({'partition':part,'source':str(path.relative_to(source)),
                    'filename':path.name,'bytes':path.stat().st_size,'sha256':digest,
                    'module':name,'manifest':info})
if {k:counts[k] for k in expected} != expected:
    raise SystemExit(f'Package counts differ from reviewed inventory: {dict(counts)}')
if sum(r['bytes'] for r in records) != 626079252:
    raise SystemExit('Total package bytes differ from parent-verified extraction')
# Parent separately verifies source-image/plan authenticity. Complete file-set,
# path, partition, size and byte hashes were validated here before any staging.
out.mkdir(parents=True)
for part in expected: (out/part/'apex').mkdir(parents=True)
for r in records:
    src = source/r['source']; dst = out/r['partition']/'apex'/r['filename']
    if dst.exists(): raise SystemExit(f'Duplicate target filename: {dst}')
    shutil.copyfile(src,dst)
    if digest_file(dst) != r['sha256']:
        raise SystemExit(f'Copy hash mismatch: {dst}')
shutil.copyfile(inv, out/'source-package-inventory.json')
(out/'preflight.json').write_text(json.dumps({'counts':expected,
    'source_inventory_sha256':digest_file(inv),
    'inventory_set_path_partition_size_hash_verified':True,
    'source_plan_authenticity_verified_by_this_helper':False,
    'source_plan_sha256':inventory.get('plan_sha256'),
    'source_extractor_sha256':inventory.get('extractor_sha256'),
    'sources':source_rows,
    'duplicate_modules':[], 'packages':records},indent=2)+'\n')
print(f'Prepared {len(records)} unchanged packages with inventory set/path/partition/size/hash verification. Review {out}/preflight.json and separately verified source-plan provenance before activation.')

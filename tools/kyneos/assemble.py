"""Replace only RI6 product span and its authenticated descriptor, preserving the root key."""
from pathlib import Path
import hashlib, json, os, shutil, struct, subprocess, sys
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005'
sys.path.insert(0, str(ROOT / 'builder'))
from peridot_builder.lp import parse_super_metadata_prefix
sys.path.insert(0, str(ROOT / 'tools/postboot'))
from assemble import footer_metadata, descriptor_name, resign
sys.path.insert(0, str(ROOT / 'tools/installer-ri3/recovery-pair'))
from pair_format import verify_avb, public_blob

def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def digest_range(path, offset, length):
    h = hashlib.sha256()
    with path.open('rb') as f:
        f.seek(offset)
        while length:
            b = f.read(min(length, 4 * 1024**2)); assert b; h.update(b); length -= len(b)
    return h.hexdigest()

def main():
    inputs = json.loads((WORK / 'INPUTS.json').read_text())
    for name in ['vbmeta.img', 'vbmeta_system.img']:
        assert sha(WORK / name) == inputs['files'][name]['sha256'], 'Pinned metadata drift: ' + name
    receipt = json.loads((WORK / 'product-repack.json').read_text())
    assert receipt['all_file_hashes_modes_uid_gid_xattrs_verified']
    fs = Path(receipt['filesystem_path']); assert sha(fs) == receipt['filesystem_sha256']
    system = (WORK / 'vbmeta_system.img').read_bytes(); parsed = verify_avb(system)
    root = verify_avb((WORK / 'vbmeta.img').read_bytes())
    product = WORK / 'product.img'; assert not product.exists(); shutil.copyfile(fs, product)
    old = next(d for d in parsed['descriptors'] if descriptor_name(d) == 'product')
    nl, sl = struct.unpack_from('>II', old, 104); salt = old[180 + nl:180 + nl + sl].hex()
    subprocess.run([sys.executable, str(ROOT / 'builder/tools/bin/avbtool.py'), 'add_hashtree_footer', '--image', str(product),
                    '--partition_name', 'product', '--partition_size', str(receipt['allocation_bytes']), '--hash_algorithm', 'sha256', '--salt', salt,
                    '--do_not_generate_fec'], check=True)
    change = next(d for d in footer_metadata(product)['descriptors'] if descriptor_name(d) == 'product')
    key = serialization.load_pem_private_key((ROOT / '.private/avb/postbootfix1/system-rsa4096.pem').read_bytes(), None)
    assert parsed['pk'] == public_blob(key)
    new_system = resign(system, [change if descriptor_name(d) == 'product' else d for d in parsed['descriptors']], key)
    verified = verify_avb(new_system)
    assert verified['pk'] == parsed['pk'] and verified['header'][16:19] == parsed['header'][16:19]
    for d in parsed['descriptors']:
        if descriptor_name(d) != 'product': assert d in verified['descriptors']
    # The parent remains byte-identical because its child key binding is unchanged.
    (WORK / 'vbmeta_system.img').write_bytes(new_system)
    assert sha(WORK / 'vbmeta.img') == inputs['files']['vbmeta.img']['sha256']
    super_source = WORK / 'super-source.img'
    assert sha(super_source) == inputs['files'][super_source.name]['sha256']
    with super_source.open('rb') as f: metadata = parse_super_metadata_prefix(f.read(1024**2))
    part = next(p for p in metadata['partitions'] if p['name'] == 'product_a'); assert len(part['extents']) == 1
    extent = part['extents'][0]; start = extent['offset_bytes']; length = extent['size_bytes']
    assert length == product.stat().st_size == receipt['allocation_bytes']
    assert digest_range(super_source, start, length) == inputs['files']['product-source.img']['sha256']
    target = WORK / 'super.img'; assert not target.exists(); shutil.copyfile(super_source, target)
    with target.open('r+b') as dst, product.open('rb') as src:
        dst.seek(start)
        for b in iter(lambda: src.read(4 * 1024**2), b''): dst.write(b)
        dst.flush(); os.fsync(dst.fileno())
    assert digest_range(target, start, length) == sha(product)
    for offset, count in [(0, start), (start + length, target.stat().st_size - start - length)]:
        assert digest_range(target, offset, count) == digest_range(super_source, offset, count)
    pins = [dict(row) for row in inputs['old_assembly']['pins']]
    for row in pins:
        if row['name'] in ['super', 'vbmeta_system']:
            path = WORK / (row['name'] + '.img'); row.update(path=str(path), sha256=sha(path), bytes=path.stat().st_size)
    value = {'build_id': inputs['build_id'], 'source_archive_sha256': inputs['source_archive_sha256'], 'pins': pins,
             'changed_image_payloads': ['super', 'vbmeta_system'], 'changed_logical_partitions': ['product'],
             'all_other_super_bytes_verified_identical': True, 'root_vbmeta_and_child_keys_unchanged': True,
             'rollback_and_avb_flags_unchanged': True, 'userdata_encryption_unchanged': True, 'product_hashtree_regenerated': True,
             'product_fec_generated': False, 'product': receipt, 'phone_partition_flash_performed': False}
    (WORK / 'ASSEMBLY.json').write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    (WORK / 'new-pins.json').write_text(json.dumps({'images': pins}, indent=2) + '\n', encoding='utf-8')
    print('Product-only assembly verified', flush=True)

if __name__ == '__main__': main()

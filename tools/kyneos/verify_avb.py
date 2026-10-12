"""Verify every authenticated AVB key relationship and actual payload/tree for RI7."""
from pathlib import Path
import hashlib, json, os, struct, subprocess, sys
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005'
sys.path.insert(0, str(ROOT / 'tools/postboot'))
from assemble import footer_metadata
sys.path.insert(0, str(ROOT / 'tools/installer-ri3/recovery-pair'))
from pair_format import verify_avb, public_blob, decode_key

def sha(path):
    with Path(path).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def main():
    assembly = json.loads((WORK / 'ASSEMBLY.json').read_text()); pins = {r['name']: r for r in assembly['pins']}
    for name in ['super', 'vbmeta', 'vbmeta_system']: assert sha(WORK / (name + '.img')) == pins[name]['sha256']
    public = WORK / 'avb-public'; public.mkdir(exist_ok=True); metadata = {}; bindings = []
    def visit(name, expected):
        path = WORK / (name + '.img')
        parsed = verify_avb(path.read_bytes()) if name.startswith('vbmeta') else verify_avb(footer_metadata(path)['data'])
        assert parsed['pk'] == expected, 'Parent key differs: ' + name
        if name in metadata: return
        metadata[name] = parsed
        (public / (name + '.avbpubkey')).write_bytes(parsed['pk'])
        (public / (name + '.pem')).write_bytes(decode_key(parsed['pk']).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        for d in parsed['descriptors']:
            if struct.unpack_from('>Q', d)[0] != 4: continue
            location, n, k = struct.unpack_from('>III', d, 16); child = d[92:92+n].decode(); child_key = d[92+n:92+n+k]
            assert child and '/' not in child and '\\' not in child
            bindings.append({'parent': name, 'child': child, 'rollback_location': location, 'public_key_sha256': hashlib.sha256(child_key).hexdigest()})
            visit(child, child_key)
    key = serialization.load_pem_private_key((ROOT / '.private/avb/postbootfix1/root-rsa4096.pem').read_bytes(), None)
    visit('vbmeta', public_blob(key))
    openssl = Path('C:/Program Files/Git/usr/bin/openssl.exe'); assert openssl.is_file()
    env = os.environ.copy(); env['PATH'] = str(openssl.parent) + os.pathsep + env['PATH']; commands = []
    for name in metadata:
        cmd = [sys.executable, str(ROOT / 'builder/tools/bin/avbtool.py'), 'verify_image', '--image', name + '.img', '--key', 'avb-public/' + name + '.pem']
        for b in bindings:
            if b['parent'] == name: cmd += ['--expected_chain_partition', b['child'] + ':' + str(b['rollback_location']) + ':avb-public/' + b['child'] + '.avbpubkey']
        p = subprocess.run(cmd, cwd=WORK, env=env, capture_output=True, text=True)
        commands.append({'partition': name, 'argv': cmd, 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
        print('AVB verified', name, p.returncode, flush=True)
        assert p.returncode == 0, p.stdout + p.stderr
    result = {'passed': len(commands) == len(metadata), 'commands': commands, 'parent_public_key_bindings': bindings,
              'super_sha256': sha(WORK / 'super.img'), 'vbmeta_system_sha256': sha(WORK / 'vbmeta_system.img'),
              'root_vbmeta_byte_identical': True, 'phone_partition_flash_performed': False}
    (WORK / 'AVB-VERIFICATION.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')

if __name__ == '__main__': main()

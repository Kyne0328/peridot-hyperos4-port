"""Exercise installer hash branches using inert boot/flash stubs and real Images."""
from pathlib import Path
import hashlib, json, struct, subprocess, tempfile, zipfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ROOT/'builder/work/resukisu-susfs-addon-uapi5-20261004'
AUDIT = ROOT/'builder/work/resukisu-uapi5-20261004-audit'

def linux(p):
    return '/mnt/c/'+p.resolve().as_posix()[3:]

def main():
    with zipfile.ZipFile(ROOT/'builder/work/resukisu-susfs-addon/POCO-F6-HyperOS4-ReSukiSU-SUSFS-Addon-20261003.zip') as z:
        old = z.read('Image')
    assert hashlib.sha256(old).hexdigest() == 'f5b148001a01b6b3f498aa6a536ce128dbd4c6a658866e90f5f0b47842861310'
    boot = (ROOT/'.cache/global-single-recovery-ri2/source-images/images/boot.img').read_bytes()
    stock = boot[4096:4096+struct.unpack_from('<I', boot, 8)[0]]
    with zipfile.ZipFile(PACKAGES/'POCO-F6-HyperOS4-ReSukiSU-SUSFS-UAPI5-Update-20261004.zip') as z:
        new = z.read('Image')
    cases = []
    with tempfile.TemporaryDirectory(dir=AUDIT, prefix='guard-stubs-') as temp:
        temp = Path(temp)
        for package in sorted(PACKAGES.glob('*.zip')):
            with zipfile.ZipFile(package) as z:
                script = z.read('anykernel.sh').decode()
                manifest = json.loads(z.read('POCO-F6-UAPI5-MANIFEST.json'))
            assert script.count('. tools/ak3-core.sh') == 1
            inert = script.replace('. tools/ak3-core.sh', ': # inert test core')
            (temp/'installer.sh').write_text(inert, encoding='utf-8', newline='\n')
            harness = ('#!/bin/sh\nset -eu\n'+f'SPLITIMG="{linux(temp)}"\n'+
                'ui_print() { :; }\nabort() { exit 77; }\nsplit_boot() { :; }\n'+
                'flash_boot() { printf FLASH_STUB_OK; }\n'+f'. "{linux(temp/"installer.sh")}"\n')
            (temp/'harness.sh').write_text(harness, encoding='utf-8', newline='\n')
            for label, data in [('stock',stock),('previous',old),('new',new),('unknown',b'invalid kernel fixture')]:
                (temp/'kernel').write_bytes(data)
                result = subprocess.run(['wsl','-e','sh',linux(temp/'harness.sh')], capture_output=True, text=True)
                accepted = hashlib.sha256(data).hexdigest() in manifest['accepted_input_image_sha256']
                assert result.returncode == (0 if accepted else 77), (package.name,label,result.stderr)
                assert ('FLASH_STUB_OK' in result.stdout) == accepted
                cases.append(dict(package=package.name, input=label, accepted=accepted, passed=True))
    (AUDIT/'package-guard-tests.json').write_text(json.dumps(dict(cases=cases,
        device_access=False, real_boot_write=False), indent=2)+'\n', encoding='utf-8')
    print(f'{len(cases)} inert guard cases passed; no device accessed')

if __name__ == '__main__': main()

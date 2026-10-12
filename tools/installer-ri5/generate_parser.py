"""Rebuild pinned private parser generators without changing the user's home."""
from pathlib import Path
import hashlib, json, os, subprocess

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/installer-ri3-native'
prefix = WORK / 'host-tools'
env = os.environ.copy()
env.update(PATH=str(prefix / 'bin') + os.pathsep + env.get('PATH', ''), MAKEINFO='true', HELP2MAN='true',
    ACLOCAL='true', AUTOCONF='true', AUTOMAKE='true', AUTOHEADER='true', LC_ALL='C', TZ='UTC')
(WORK / 'logs').mkdir(exist_ok=True)
for name in ['m4-1.4.20', 'bison-3.8.2', 'flex-2.6.4']:
    out = WORK / 'generator-builds' / name
    out.mkdir(parents=True, exist_ok=True)
    source = WORK / 'vendor' / name
    with (WORK / 'logs' / (name + '-restore.log')).open('w') as log:
        for cmd in [['bash', str(source / 'configure'), '--prefix=' + str(prefix), '--disable-nls'], ['make', '-j4'], ['make', 'install']]:
            p = subprocess.run(cmd, cwd=out, env=env, stdout=log, stderr=subprocess.STDOUT)
            assert p.returncode == 0, 'Generator build failed: ' + name
    print('Built pinned generator', name, flush=True)
generated = WORK / 'generated'
generated.mkdir(exist_ok=True)
for command in [[prefix / 'bin/bison', '--defines=parser.h', '--output=parser.cpp', WORK / 'vendor/recovery/edify/parser.yy'],
    [prefix / 'bin/flex', '--outfile=lexer.cpp', WORK / 'vendor/recovery/edify/lexer.ll']]:
    subprocess.run(list(map(str, command)), cwd=generated, env=env, check=True)
hashes = {name: hashlib.sha256((generated / name).read_bytes()).hexdigest() for name in ['parser.h', 'parser.cpp', 'lexer.cpp']}
(generated / 'generated.sha256').write_text(''.join(digest + '  ' + name + '\n' for name, digest in hashes.items()))
print(json.dumps({'generated_parser_hashes': hashes}), flush=True)

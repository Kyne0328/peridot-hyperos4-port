"""Rebuild RI5 recovery fix entirely from restored pinned sources, with a read-only preflight CLI."""
from pathlib import Path
import argparse, concurrent.futures, hashlib, importlib.util, json, os, subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'tools/installer-ri5'
CORE = ROOT / 'tools/installer-ri3/native-updater'
OLD = ROOT / 'builder/work/installer-ri3-native'
WORK = ROOT / 'builder/work/installer-ri5-recoveryfix-20261004'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', choices=['android', 'host'], required=True)
    ap.add_argument('--trust', choices=['existing', 'new'], required=True)
    ap.add_argument('--variant', default='')
    ap.add_argument('--pins-file', type=Path)
    a = ap.parse_args()
    assert not a.variant or a.variant.replace('-', '').isalnum()
    suffix = ('-' + a.variant) if a.variant else ''
    out = WORK / ('native-' + a.target + '-' + a.trust + suffix)
    out.mkdir(exist_ok=True)
    generated = WORK / ('generated' + suffix)
    generated.mkdir(exist_ok=True)
    header = ROOT / 'builder/work/installer-ri5-stream-20261004/native/image_pins.h'
    header_bytes = header.read_bytes()
    if a.pins_file:
        pin_path = a.pins_file.resolve()
        assert pin_path.is_relative_to((ROOT / 'builder/work').resolve())
        values = json.loads(pin_path.read_text())['images']
        rows = {x['name']: x for x in values}
        boot = ['boot','dtbo','init_boot','vendor_boot','recovery','vbmeta_system','vbmeta']
        order = ['super', *sorted(set(rows)-{'super',*boot}), *boot]
        assert len(order) == len(rows) == len(values) == 32
        text = '#pragma once\n#include <cstdint>\nnamespace ri4 {struct Pin{const char*name;uint64_t bytes;const char*sha;};\nconstexpr unsigned kImageCount=32;\ninline const Pin kPins[]={\n'
        for name in order:
            row=rows[name];assert row['bytes']>0 and len(row['sha256'])==64 and all(c in '0123456789abcdef' for c in row['sha256'])
            text += '{"'+name+'",'+str(row['bytes'])+'ULL,"'+row['sha256']+'"},\n'
        header_bytes=(text+'};}\n').encode()
    pins = generated / 'image_pins.h'
    if not pins.exists(): pins.write_bytes(header_bytes)
    assert pins.read_bytes() == header_bytes
    source = (ROOT / 'builder/work/installer-ri5-stream-20261004/native/main.cpp').read_text()
    source = '#ifdef __ANDROID__\n#include <sys/system_properties.h>\n#endif\n'+source
    anchor = '    if(argc==3 && strcmp(argv[1],"--verify-rom")==0) {'
    preview = r'''    if(argc==3 && strcmp(argv[1],"--preflight-readonly")==0) {
#ifdef __ANDROID__
      char mode[PROP_VALUE_MAX]{};__system_property_get("ro.bootmode",mode);
      if(!strcmp(mode,"normal")||access("/system/bin/recovery",X_OK)!=0)throw std::runtime_error("Read-only installer preflight requires an OrangeFox recovery session");
#endif
      Zip zip(argv[2]); struct stat info{};
      if(fstat(zip.HeldFd(),&info)||info.st_size<=0)throw std::runtime_error("invalid source package");
      ri3crypto::ZipVerificationReceipt signature;std::string error;
      printf("Read-only environment preflight: authenticating source ZIP...\n");fflush(stdout);
      if(!ri3crypto::VerifyZipFd(zip.HeldFd(),info.st_size,&signature,&error))throw std::runtime_error(error);
      auto result=ri3::runtime::PreviewHeldPackage(zip.HeldFd(),[](const std::string&line){printf("%s\n",line.c_str());fflush(stdout);},&signature);
      if(!result.success){fprintf(stderr,"READONLY_PREFLIGHT_FAILED: %s\n",result.error.c_str());return 9;}
      return 0;
    }
'''
    assert source.count(anchor) == 1
    source = source.replace(anchor, preview + anchor)
    main_cpp = generated / 'main.cpp'
    if not main_cpp.exists() or main_cpp.read_text()!=source: main_cpp.write_text(source)
    backend = CORE / 'backend'; vendor = OLD / 'production-vendor'; zlib = OLD / 'vendor/zlib-1.3.2'
    spec = importlib.util.spec_from_file_location('closure_helpers', backend / 'build_closure.py')
    helpers = importlib.util.module_from_spec(spec); spec.loader.exec_module(helpers)
    original = (vendor / 'core/fs_mgr/libdm/dm.cpp').read_text()
    adapted = helpers.reject_body(original, r'bool DeviceMapper::CreateDevice\(const std::string& name,\s*const DmTable& table,\s*std::string\* path,\s*const std::chrono::milliseconds& timeout_ms\)',
        '    (void)name;(void)table;(void)path;(void)timeout_ms;return false;')
    adapted = helpers.reject_body(adapted, r'bool DeviceMapper::LoadTableAndActivate\(const std::string& name,\s*const DmTable& table\)',
        '    (void)name;(void)table;return false;')
    dm_cpp = generated / 'dm-remove-only.cpp'
    if not dm_cpp.exists(): dm_cpp.write_text(adapted)
    assert dm_cpp.read_text() == adapted
    # Restore the reviewed complete old/new OrangeFox boot-control pin-set variant.
    t = (CORE / 'snapshot/hal_query.cpp').read_text()
    update = json.loads((ROOT / '09-reports/installer-ri4-orangefox-202610021801/recovery-update.json').read_text())
    assert update['source_archive_sha256'] == '3ddcf53e0fb6e7fd7a83a491a350ce51e30d818f466bd2429b3ce2ee0659c72a'
    start = t.index('constexpr Pin pins[]={'); end = t.index('\n};', start) + 3
    newer = 'constexpr Pin new_pins[]={\n' + ''.join(' {"' + n + '",' + str(size) + ',"' + digest + '"},\n' for n, size, digest in update['new_boot_control_pins']) + '};\n'
    select = '''const Pin* SelectPinnedSet(const std::vector<std::string>&hashes,const std::vector<uint64_t>&sizes){
 Need(hashes.size()==4&&sizes.size()==4,"incomplete recovery tool set");bool old_set=true,new_set=true;
 for(size_t i=0;i<4;++i){old_set=old_set&&(sizes[i]==pins[i].bytes&&hashes[i]==pins[i].hash);new_set=new_set&&(sizes[i]==new_pins[i].bytes&&hashes[i]==new_pins[i].hash);}
 Need(old_set||new_set,"unsupported or mixed recovery boot-control set");return old_set?pins:new_pins;
}
'''
    t = t[:end] + '\n' + newer + select + t[end:]
    old_loop = 'for(const auto& pin:pins){fds.push_back(OpenArtifact(pin.path));identity.push_back(Stat(fds.back().n));CheckPin(fds.back().n,pin,identity.back());}'
    new_loop = '''for(const auto&pin:pins){fds.push_back(OpenArtifact(pin.path));identity.push_back(Stat(fds.back().n));}
  std::vector<std::string>hashes;std::vector<uint64_t>sizes;
  for(size_t i=0;i<fds.size();++i){auto size=identity[i].st_size;Need(S_ISREG(identity[i].st_mode)&&size>0&&size<=512*1024,"invalid recovery artifact");hashes.push_back(Hash(fds[i].n,size));sizes.push_back(size);}
  const Pin*selected=SelectPinnedSet(hashes,sizes);for(size_t i=0;i<fds.size();++i)CheckPin(fds[i].n,selected[i],identity[i]);'''
    assert t.count(old_loop) == 1
    t = t.replace(old_loop, new_loop).replace('CheckPin(fds[i].n,pins[i],identity[i]);', 'CheckPin(fds[i].n,selected[i],identity[i]);')
    hal_cpp = generated / 'hal_query.cpp'
    if not hal_cpp.exists() or hal_cpp.read_text()!=t: hal_cpp.write_text(t)
    includes = [HERE, ROOT / 'tools/installer-ri4', CORE / 'runtime', CORE / 'extract', CORE / 'guard', CORE / 'snapshot', CORE / 'crypto', backend,
        backend / 'vendor', backend / 'vendor/base-internal', generated, OLD / 'generated', OLD / 'vendor/recovery/edify/include',
        OLD / 'vendor/recovery/edify', OLD / 'vendor/recovery/otautil/include', vendor / 'base/include', vendor / 'base',
        vendor / 'core/fs_mgr/libdm/include', vendor / 'core/fs_mgr/libdm', vendor / 'core/libsparse/include',
        vendor / 'mbedtls-3.6.7/include', vendor / 'mbedtls-3.6.7/library', zlib, zlib / 'contrib/minizip']
    cc, cxx = '/usr/bin/clang', '/usr/bin/clang++'
    flags = ['-O2', '-ffunction-sections', '-fdata-sections', '-D_FILE_OFFSET_BITS=64', '-D_LARGEFILE64_SOURCE=1', '-D_GNU_SOURCE', '-D_POSIX_C_SOURCE=200809L',
        '-DHAVE_UNISTD_H', '-DNOUNCRYPT', '-DNOCRYPT', '-DRI3_ENABLE_DEVICE_INSTALL=1', '-DMBEDTLS_CONFIG_FILE="ri3_mbedtls_config.h"',
        '-Wno-inconsistent-missing-override', '-Wno-vla-cxx-extension', '-Wno-c99-designator', *['-I' + str(p) for p in includes]]
    link = ['-Wl,--gc-sections', '-Wl,-z,noexecstack', '-Wl,-z,relro', '-Wl,-z,now']
    if a.target == 'android':
        tools = Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin'
        cc, cxx = str(tools / 'clang.exe'), str(tools / 'clang++.exe')
        flags += ['--target=aarch64-linux-android30']; link += ['--target=aarch64-linux-android30', '-static']
    if a.trust == 'new':
        key = json.loads((WORK / 'signing-public.json').read_text())
        flags += ['-DRI3_CERTIFICATE_DER_SHA256="' + key['certificate_der_sha256'] + '"',
            '-DRI3_RSA_MODULUS_HEX="' + key['rsa_modulus_hex'] + '"',
            '-DRI3_TRUSTED_CERT_HEADER="' + (WORK / 'trusted_cert_der.h').as_posix() + '"']
    sources = [zlib / (name + '.c') for name in ['adler32', 'crc32', 'deflate', 'infback', 'inffast', 'inflate', 'inftrees', 'trees', 'zutil', 'compress', 'uncompr', 'gzclose', 'gzlib', 'gzread', 'gzwrite']]
    sources += [zlib / 'contrib/minizip' / (name + '.c') for name in ['ioapi', 'unzip']]
    sources += [vendor / 'mbedtls-3.6.7/library' / (name + '.c') for name in ['bignum', 'bignum_core', 'bignum_mod', 'bignum_mod_raw', 'constant_time', 'md', 'oid', 'platform_util', 'rsa', 'rsa_alt_helpers', 'sha256']]
    sources += [CORE / 'crypto/native_zip_crypto.cpp', ROOT / 'tools/installer-ri3/zip-signing/native/zip_verify_adapter.cpp', ROOT / 'tools/installer-ri3/zip-signing/native/asn1_decoder.cpp',
        OLD / 'vendor/recovery/edify/expr.cpp', OLD / 'generated/parser.cpp', OLD / 'generated/lexer.cpp',
        CORE / 'extract/image_extract.cpp', CORE / 'guard/guard_policy.cpp', HERE / 'install_runtime.cpp', main_cpp]
    if a.target == 'android':
        sources += [backend / name for name in ['storage_backend.cpp', 'topology.cpp', 'verity_table.cpp', 'unmount.cpp', 'libdm_adapter.cpp', 'stderr_log.cpp']]
        sources += [dm_cpp, *[vendor / 'core/fs_mgr/libdm' / name for name in ['dm_table.cpp', 'dm_target.cpp', 'loop_control.cpp', 'utility.cpp']]]
        sources += [(vendor / 'base' / name if (vendor / 'base' / name).exists() else backend / 'vendor/base-internal' / name) for name in ['file.cpp', 'logging.cpp', 'threads.cpp', 'strings.cpp', 'stringprintf.cpp', 'posix_strerror_r.cpp', 'properties.cpp']]
        sources += [CORE / 'snapshot/metadata.cpp', hal_cpp]
    else:
        sources += [OLD / 'vendor/libbase' / name for name in ['strings.cpp', 'stringprintf.cpp', 'posix_strerror_r.cpp']]
    logs = []
    def compile_one(item):
        i, source = item; obj = out / (str(i) + '-' + source.stem + '.o')
        cmd = [cxx if source.suffix == '.cpp' else cc, *flags, '-std=c++17' if source.suffix == '.cpp' else '-std=c11', '-c', str(source), '-o', str(obj)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        record = {'argv': cmd, 'exit_code': p.returncode, 'stderr': p.stderr}
        assert p.returncode == 0, str(source) + '\n' + p.stderr
        return obj, record
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        compiled = list(pool.map(compile_one, enumerate(sources)))
    objects, logs = [x[0] for x in compiled], [x[1] for x in compiled]
    binary = out / 'update-binary'
    cmd = [cxx, *objects, *link, '-o', str(binary)]
    p = subprocess.run(list(map(str, cmd)), capture_output=True, text=True, timeout=120)
    logs.append({'argv': list(map(str, cmd)), 'exit_code': p.returncode, 'stderr': p.stderr})
    assert p.returncode == 0, p.stderr
    bound = sources + [HERE / 'stream_image.h', HERE / 'install_runtime.h', CORE / 'crypto/native_zip_crypto.h', CORE / 'runtime/held_package.h', CORE / 'backend/storage_backend.h', CORE / 'backend/verity_table.h', CORE / 'backend/observation_window.h', pins, Path(__file__)]
    if a.trust == 'new': bound += [WORK / 'signing-public.json', WORK / 'trusted_cert_der.h']
    if a.pins_file: bound += [a.pins_file.resolve()]
    receipt = {'target': a.target, 'trust': a.trust, 'binary': str(binary), 'binary_sha256': sha(binary),
        'sources': {str(p.relative_to(ROOT)): sha(p) for p in bound}, 'objects': {str(p.relative_to(ROOT)): sha(p) for p in objects},
        'commands': logs, 'device_execution_performed': False}
    (out / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: receipt[k] for k in ['target', 'trust', 'binary', 'binary_sha256']}, indent=2), flush=True)

if __name__ == '__main__': main()

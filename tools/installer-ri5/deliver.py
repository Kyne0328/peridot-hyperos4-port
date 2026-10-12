"""Deliver a verified RI5 package and installation notes without overwriting RI4."""
from pathlib import Path
import argparse, hashlib, json, os, shutil

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/installer-ri5-stream-20261004'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    out = a.output_dir.resolve()
    report = ROOT / '09-reports/installer-ri5-stream-20261004'
    assert not out.exists() and not report.exists(), 'Refuse delivery overwrite'
    receipt = json.loads((WORK / 'package/VALIDATION.json').read_text())
    assert receipt['host_native_readonly_verification']['passed']
    assert receipt['host_native_readonly_verification']['verifier_sha256'] == sha(WORK / 'native/verify-host')
    native = json.loads((WORK / 'native/android-build-receipt.json').read_text())
    for name, digest in native['source_sha256'].items():
        assert sha(ROOT / name) == digest, 'Delivered source differs from compiled source'
    archive = Path(receipt['archive'])
    assert archive.stat().st_size == receipt['bytes']
    out.mkdir(parents=True)
    report.mkdir()
    destination = out / archive.name
    os.link(archive, destination)  # Same-volume final immutable artifact; no extra 6+ GB allocation.
    assert os.path.samefile(archive, destination)
    receipt['sequencing_tests'] = {'passed': True, 'cases': 67}
    (WORK / 'package/VALIDATION.json').write_text(json.dumps(receipt, indent=2) + '\n')
    for source in [WORK / 'package/VALIDATION.json', WORK / 'package' / (archive.name + '.sha256'),
        WORK / 'stream-tests.json', WORK / 'host-verification.json', WORK / 'native/android-build-receipt.json', WORK / 'native/host-build-receipt.json']:
        shutil.copyfile(source, out / source.name)
        shutil.copyfile(source, report / source.name)
    previous_size = json.loads((ROOT / 'builder/work/installer-ri4-dmfix-20261004/package/VALIDATION.json').read_text())['bytes']
    reduction = (previous_size - receipt['bytes']) / previous_size * 100
    intro = f'''F6 GLOBAL HYPEROS4 DEV2 RI5 COMPRESSED DECRYPT — 4 OCTOBER 2026

ZIP: {archive.name}
Bytes: {receipt['bytes']}
SHA256: {receipt['sha256']}

This is the compressed installer rebuild requested after the RI4 flashing error.
All 32 installed raw image hashes match RI4 DMFIX. The kernel, firmware, ROM,
recovery and decrypted-storage configuration are retained exactly.

WHAT CHANGED
- ZIP_DEFLATED compression, like the inspected Mishun/Mundo packages.
- One signed-ZIP scan, followed by direct decompression/hash/write of each image.
- No separate full image CRC/hash pre-scan and no giant image staging/mmap.
- Writes coalesce into a bounded 1 MiB buffer; progress covers writes/readbacks.
- Complete image readback and sync still precede final slot-A selection.
- Retained corrected device-mapper ABI/header handling and snapshot/storage checks.

Use this RI5 ZIP from an existing WORKING OrangeFox recovery on B. A separate
recovery setup flash is not needed. The full compressed ZIP signature is still
verified before preparation/writes; USB speed and hashing can still take time.

No phone flash or boot has been performed in this build. Installation speed,
boot, hardware, recovery behavior and data formatting remain device-test gates.

Image checksums/CRC are verified as images stream to their targets. A streaming,
write or readback failure can leave partially written partitions. Save the log
and stay in recovery on failure. Shared super is replaced, so B is not an old-ROM
rollback after writes, even though B's physical firmware/boot images are preserved.

FORMAT DATA ONLY AFTER VERIFIED INSTALLATION SUCCESS AND A WORKING RECOVERY
REBOOT. This retained DECRYPT ROM requires an encrypted-to-decrypted transition;
Format Data deletes all internal files. A preflight error does not require a wipe.

The detailed retained prerequisites and recovery procedure follow.

'''
    original = (ROOT / 'tools/installer-ri4/INSTALL.txt').read_text(encoding='utf-8')
    original = original.replace('RI4', 'RI5').replace('Checking every image before any write', 'Checking the signed package and image plan')
    original = original.replace('- Included all 32 required image payloads and authenticated their hashes before\n  writes. Installed-image writes are synced and read back before reporting success.',
        '- Includes all 32 required image payloads. The complete ZIP is authenticated\n  before writes. Image CRC/hash checks run while decompressing/writing, followed\n  by sync and full readback before reporting success.')
    text = intro + original
    for directory in [out, report]:
        (directory / 'INSTALL.txt').write_text(text, encoding='utf-8')
    total_raw = sum(v['raw_bytes'] for k, v in receipt['member_sizes'].items() if k.startswith('partitions/'))
    compressed_images = sum(v['compressed_bytes'] for k, v in receipt['member_sizes'].items() if k.startswith('partitions/'))
    build_report = f'''RI5 COMPRESSED INSTALLER BUILD REPORT

Previous RI4 ZIP: {previous_size:,} bytes
RI5 ZIP: {receipt['bytes']:,} bytes
Archive reduction: {reduction:.1f}%
Raw installed image bytes: {total_raw:,}
Compressed image bytes read during streaming: {compressed_images:,}

The retained Mishun debloat/full archives are 6,525,321,381 and 7,364,910,310
bytes, and Mundo is 6,916,568,222 bytes. Their image members use DEFLATE and
their scripts extract/unsparse images to block targets. RI5 follows that
compressed streaming approach using our source-built fixed peridot installer.
It retains a full independent image readback and the existing A-only policy.
It does not copy the other ROMs' both-slot firmware writes or ROM contents.

The old RI4 range lookup also performed a standalone CRC scan before hashing
each image; the earlier roughly 19 GB preflight estimate understated its total
logical scanning work. RI5 removes both standalone image pre-scans on the phone.
Whole-ZIP signature verification still precedes writes; image CRC/length/SHA256
checks now run during streaming, followed by fsync and full target readback.
This trades pre-write image scanning for authenticated streaming and detection
during writes. It is not transactional. No on-phone duration is claimed.

VALIDATION
- All 32 raw-image hashes unchanged from the exact RI4 DMFIX image plan.
- Independent output decompression, lengths, CRCs and SHA256 pass for 37 members.
- Dedicated existing development signature passes independent verification.
- 21 streaming tests pass under AddressSanitizer/UBSan. ZIP64, stored/deflated
  payloads, invalid metadata, corrupted/truncated/trailing/oversized streams,
  wrong hashes, write/sync/readback failures, target bounds and withheld final
  slot selection are covered. Fixture writes coalesce into at most 1 MiB.
- 67 sequence cases pass. Android ARM64 and host updater compilation pass.
- The compiled native host verifier passes the complete signed compressed ZIP,
  all 32 image hashes/CRCs and the actual Edify script; host writes are disabled.
- Device-mapper ABI repair and existing topology/snapshot checks are retained.
- Earlier source archives and RI4 deliverables remain unchanged.

Sources are under tools/installer-ri5; shared ZIP metadata inspection is in
tools/installer-ri3/native-updater/runtime/held_package.h. Build and validation
receipts accompany this output. The delivered ZIP is a hard link to the final
generated archive to avoid duplicate disk allocation; neither should be edited
in place. No phone operations, automatic wipe, reboot or root injection occurred.

Device flashing, boot and real installation speed remain unverified.
'''
    for directory in [out, report]:
        (directory / 'BUILD-REPORT.txt').write_text(build_report, encoding='utf-8')
    print(json.dumps({'archive': str(destination), 'bytes': receipt['bytes'], 'reduction_percent': round(reduction, 1),
        'sha256': receipt['sha256'], 'native_verification_passed': True}, indent=2))

if __name__ == '__main__':
    main()

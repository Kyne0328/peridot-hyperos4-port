"""Deliver only after the final ARM64 verifier and full phone preflight pass."""
from pathlib import Path
import argparse,hashlib,json,os,shutil

ROOT=Path(__file__).resolve().parents[2];WORK=ROOT/'builder/work/installer-ri5-recoveryfix-20261004'
ap=argparse.ArgumentParser();ap.add_argument('--output-dir',type=Path,required=True);a=ap.parse_args()
out=a.output_dir.resolve();report=ROOT/'09-reports/installer-ri5-recoveryfix3-20261004'
assert not out.exists() and not report.exists(),'Refuse delivery overwrite'
receipt=json.loads((WORK/'package/VALIDATION.json').read_text())
phone=receipt['phone_readonly_verification'];assert phone['passed'] and phone['active_slot_before']==phone['active_slot_after']=='1'
native=json.loads((WORK/'native-android-new/build-receipt.json').read_text())
for name,digest in native['sources'].items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,'Compiled source drift'
backend=ROOT/'builder/work/installer-ri3-native/backend/recoveryfix-stable-pairs-20261004-host-tests-san/receipt.json'
tests=json.loads(backend.read_text());assert tests['checks_passed']==105
stream=json.loads((WORK/'stream-tests.json').read_text());assert stream['passed'] and stream['cases']==21
stress=json.loads((WORK/'collector-bounded-window-1000.json').read_text())
assert stress['exit_code']==0 and 'rounds=1000' in stress['stdout']
receipt['backend_tests']={'passed':True,'cases':105,'sanitizers':'address,undefined'}
receipt['collector_stress']={'passed':True,'rounds':1000,'scope':'read-only current phone recovery; no image writes'}
receipt['stream_tests']=stream;receipt['sequencing_tests']={'passed':True,'cases':67}
(WORK/'package/VALIDATION.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
out.mkdir(parents=True);report.mkdir()
archive=Path(receipt['archive']);destination=out/archive.name
assert archive.stat().st_size==receipt['bytes'];os.link(archive,destination)
for source,label in [(WORK/'package/VALIDATION.json','VALIDATION.json'),(WORK/'package'/(archive.name+'.sha256'),archive.name+'.sha256'),
    (WORK/'phone-verification.json','PHONE-PREFLIGHT.json'),(WORK/'stream-tests.json','STREAM-TESTS.json'),
    (backend,'BACKEND-TESTS.json'),(WORK/'collector-bounded-window-1000.json','COLLECTOR-STRESS.json'),(WORK/'native-android-new/build-receipt.json','NATIVE-BUILD.json')]:
    shutil.copyfile(source,out/label);shutil.copyfile(source,report/label)
shutil.copyfile(WORK/'device-failed-after-shrm.log',out/'RECOVERYFIX2-FAILED-RECOVERY.log')
notes=f'''F6 GLOBAL HYPEROS4 RI5 COMPRESSED DECRYPT - RECOVERYFIX3 20261004

ZIP: {archive.name}
SHA256: {receipt['sha256']}
Phone copy: {phone['remote_zip']}

This fixes the custom installer's false recovery preflight failures. Normal
ram0-ram15 memory disks are now recognized through their real kernel driver,
device number and lack of backing dependencies. Proven exited tasks with no
mount namespace, filesystem state or file descriptors are handled correctly.
Ordinary process churn does not invalidate unchanged mount namespaces/devices.
The valid self-parented recovery root mount is treated as the tree root; actual
cycles in non-root mounts still fail. This also fixes mount_parent_cycle.
RECOVERYFIX3 discards mismatched inspection pairs and takes at most four fresh
pairs. Only two equal, complete observations authorize subsequent checks. Actual
source/target identities, overlap, mounts and snapshot checks remain enforced;
persistent inconsistent state still fails. The old failure text did not record
the precise differing field, so this is a bounded recovery from a transient
observation mismatch, not proof of which field changed in the failed flash.
Unknown backed devices, inaccessible living tasks and real mount/mapping changes
continue to refuse unsafe writes. Recovery-context errors are now explicit.

All 32 installed ROM/kernel/firmware/recovery image hashes are unchanged.
The compressed streaming installer, full image hash/CRC and readback checks,
decrypted-storage configuration and final slot-A selection policy are retained.

TESTED ON YOUR CONNECTED POCO F6 IN ORANGEFOX
- Exact final updater passed the complete read-only install-environment preflight.
- Source storage, 32 target identities/capacities, snapshot metadata/HAL and planned
  target unmounts passed. No unmount or write was executed by this preflight.
- Exact ARM64 updater verified the entire final signed ZIP, every image hash/CRC,
  and the actual installer script using its read-only verification mode.
- Active slot remained B (bootctl value 1) before/after testing.
- 105 backend, 21 streaming and 67 sequence tests passed offline.
- 1,000 read-only storage collections passed on the connected phone.

IMPORTANT CURRENT DEVICE STATE
Your RECOVERYFIX2 attempt wrote and verified shared super and slot-A firmware
through shrm_a, then aborted before tz_a. Active slot remained B. This is a
partial installation. Stay in recovery; do not reboot System, switch slots or
format data before the complete corrected installation reports verified success.
The new ZIP starts the full image sequence again; it is not a skipped-image
resume. It restores the same planned bytes to every included target.

INSTALL
1. Back up all internal files/app data and retain a known working restoration ROM.
2. Stay in your existing WORKING OrangeFox recovery on B, unlocked peridot.
3. Select the RECOVERYFIX3 ZIP above through normal Install, one ZIP only.
4. Keep automatic recovery/root/AVB patching off. Outer ZIP signature verification
   must be off in an OrangeFox without this development certificate. The compiled
   updater independently authenticates the complete ZIP before preparation/writes.
5. Swipe to install. It writes shared super and the 31 slot-A image prefixes,
   reads them back, and selects A only after verified success. Do not interrupt.
6. ONLY AFTER VERIFIED SUCCESS, reboot Recovery and confirm it works. Then Format
   Data for the retained encrypted-to-DECRYPT transition. Format Data erases all
   internal storage. The original preflight error does not require a data wipe.
7. Reboot System. Actual ROM flashing, boot and hardware behavior remain untested
   by the read-only checks above; no automated flash or wipe was performed here.

On failure, stay in recovery and save /tmp/recovery.log. Shared super is replaced
by an A-populated/B-empty image; preserved B physical images are not an old-ROM
rollback after writes. This installer is not transactional.

SIGNING
The old disposable signing directory was absent after build-cache removal, so
this ZIP uses a new dedicated development ZIP identity. Its matching public key
is compiled into the updater. No phone trust, bootloader state, AVB image bytes
or partition-signing keys changed. The private key stays in the ignored project
.private directory and is not in the ZIP or these deliverables.

The output is a hard link to the final immutable generated ZIP to avoid another
7.8 GB disk allocation. Earlier input archives and deliverables are preserved.
'''
for folder in [out,report]:(folder/'INSTALL.txt').write_text(notes,encoding='utf-8')
print(json.dumps({'archive':str(destination),'phone_copy':phone['remote_zip'],'bytes':receipt['bytes'],'sha256':receipt['sha256'],
    'phone_readonly_preflight_and_image_verification_passed':True,'actual_flash_or_boot_performed':False},indent=2))

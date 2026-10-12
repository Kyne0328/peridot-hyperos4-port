"""Publish RI7 validation, installation instructions and persistent issue history."""
from pathlib import Path
import datetime, hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'builder/work/kyneos-ri7-20261005'
OUT = Path('D:/hyperos4-peridot-kyneos-ri7-20261005/outputs')

def main():
    validation = json.loads((OUT / 'VALIDATION.json').read_text())
    arm64 = json.loads((OUT / 'ARM64-READONLY-VERIFICATION.json').read_text())
    assert validation['all_member_crc_sha_checks_passed'] and validation['avb_verification_passed'] and arm64['passed']
    assert json.loads((WORK / 'FILESYSTEM-COMPATIBILITY.json').read_text())['passed']
    assert validation['sha256'] == arm64['archive_sha256']
    for name in ['ASSEMBLY.json', 'AVB-VERIFICATION.json', 'FILESYSTEM-COMPATIBILITY.json']:
        value = json.loads((WORK / name).read_text())
        if name == 'ASSEMBLY.json':
            value['product'] = {k: v for k, v in value['product'].items() if k != 'entries'}
        (OUT / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    apk = json.loads((WORK / 'app/VALIDATION.json').read_text())
    ui = json.loads((WORK / 'app/UI-ACCEPTANCE.json').read_text())
    assert ui['settings_tile_navigation'] and ui['back_returns_to_about_phone'] and len(ui['credits_visible']) == 5
    app_output = OUT / 'KyneOSInfo.apk'
    if app_output.exists(): assert hashlib.sha256(app_output.read_bytes()).hexdigest() == apk['sha256']
    else: shutil.copyfile(apk['apk'], app_output)
    (OUT / 'INFORMATION-APP-VALIDATION.json').write_text(json.dumps(apk, indent=2) + '\n', encoding='utf-8')
    (OUT / 'INFORMATION-APP-UI-ACCEPTANCE.json').write_text(json.dumps(ui, indent=2) + '\n', encoding='utf-8')
    scripts = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / 'tools/kyneos').rglob('*') if p.suffix in ['.py', '.java', '.xml']}
    provenance = {'build_id': 'KYNEOS-RI7.1-20261005', 'source_archive_sha256': validation['source_sha256'],
                  'output_sha256': validation['sha256'], 'source_scripts': scripts,
                  'changed_image_payloads': ['super', 'vbmeta_system'], 'changed_logical_partitions': ['product'],
                  'private_keys_included': False, 'integrated_build_device_flash_tested': False,
                  'device_preview': 'Information APK installed under /data; Settings HyperOS tile navigation and Back tested',
                  'prior_owner_confirmation': ['Bluetooth discovery/pairing', 'Lock style customize/apply/lock/unlock with Vulkan']}
    (OUT / 'PROVENANCE.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    (ROOT / '00-manifest/kyneos-ri7-delivery-20261005.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    (OUT / 'INSTALL.txt').write_text('''KyneOS RI7.1 - Global HyperOS 4 for POCO F6 / peridot
Port maintained by Kyne

Complete recovery ROM update from RI6 POSTBOOT FIX1 DECRYPT.
1. Install KyneOS-Global-HyperOS4-POCO-F6-RI7.1-20261005.zip in the supported OrangeFox recovery.
2. Wait for verified installer success. Reboot Recovery, then System.
3. On the existing RI6 DECRYPT installation, do not Format Data for this update.
4. Check Bluetooth discovery/pairing/reconnection, lock style customization/apply/lock/unlock,
   Settings > About phone > Xiaomi HyperOS tile > KyneOS, and back navigation after reboot.

Integrated properties: debug.hwui.renderer=skiavk; persist.sys.support.sar.device=peridot.
The renderer is initialized at boot for newly created HWUI processes; it affects the system's
default renderer, so check launcher/Recents, Settings and ordinary apps after installation.
The Bluetooth correction retains vendor firmware and SAR configurations; audio/BLE and
broader SAR/controller checks remain separate from the confirmed discovery/pairing test.

This is a complete 32-image recovery installer. Only product inside super and vbmeta_system
changed from RI6. Its unchanged base boot payloads are still written by the complete installer;
the separately installed ReSukiSU/SUSFS kernel addon is not merged into this ROM. Reapply a
compatible separate addon if you use it. No root module is required by the two ROM corrections.
Existing decrypted userdata configuration is preserved. The installer does not format userdata.
Shared super is not an independent slot-B rollback. Keep the previous known-working RI6 ZIP
as a recovery reinstall. Source archives remain unchanged.

Validation: complete product file/metadata/decode checks, product verity tree, all AVB signatures
and parent-key bindings, unchanged super spans, all37 decoded ZIP member hashes/CRCs,
development ZIP signature, and ARM64 read-only signed-payload/Edify verification passed.
The fixes were confirmed live before integration; the information page was previewed on the
phone. The integrated RI7 ZIP has not been flashed or reboot-tested. No phone partition flash,
reboot or data wipe was performed while building it. Development signing and RI6 AVB flags,
rollback values and key relationships are retained; product retains RI6's no-FEC parity choice.
''', encoding='utf-8')
    now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat()
    base = ROOT / '09-reports/rom-history'; path = base / 'FAILURE-REGISTER.json'; history = json.loads(path.read_text())
    issues = {x['id']: x for x in history['issues']}
    issues['UI-006']['status'] = 'RI7 ROM integration packaged and offline-verified; prior owner functional confirmation; integrated reboot regression remains OPEN'
    issues['UI-006']['change'] = 'RI7 product/etc/build.prop initializes debug.hwui.renderer=skiavk at boot; no root-startup module or AOD APK patch. Global HWUI renderer selection disclosed; prior Recents/corner/haptic fixes retained.'
    issues['UI-006']['cause_and_evidence_limits'] = 'Repeated live native crashes in com.miui.aod:keyguardeditor RenderThread: Xiaomi MiDrawGlassPath/FontSDF2 Vulkan code queried a null VkPhysicalDevice while SkiaOpenGLPipeline was active. Vulkan comparison confirmed Pipeline=Skia(Vulkan), and owner confirmed editor opening, customization, applying and lock/unlock. RI7 now packages the startup renderer property with complete offline verification. Integrated ZIP boot/reboot, alternative styles and broader app rendering remain untested.'
    issues['HW-002']['status'] = 'RI7 ROM integration packaged and offline-verified; owner discovery/pairing confirmed before integration; reboot/profile/SAR regression remains OPEN'
    issues['HW-002']['change'] = 'RI7 product/etc/build.prop initializes persist.sys.support.sar.device=peridot. No vendor firmware, SAR configuration or pairing database rewritten. Rejected tpi_supported=0 test remains rejected and restored.'
    issues['HW-002']['cause_and_evidence_limits'] = 'The stack discarded CONTROLLER_BTTPI completions when cached persist.sys.support.sar.device was empty, then hit an8-second timeout and restarted roughly every11 seconds. Native gate and missing field confirmed. Actual peridot identity stopped the loop; final live receipt showed5m7s uptime, unchanged297-crash count and one bonded device. Owner confirmed discovery and pairing. RI7 startup default is packaged; integrated reboot, audio/BLE profiles and broader SAR/controller behavior remain untested.'
    issues['HW-002']['owner_observation'] = issues['HW-002']['owner_observation'].replace('won\ufffdt', 'won\u2019t')
    issues['UI-004']['status'] = 'KyneOS Settings destination packaged in RI7; live information APK navigation/back confirmed; integrated boot test remains OPEN'
    issues['UI-004']['change'] = 'Permission-free KyneOSInfo APK supplies com.android.updater.UpdateActivity for Settings existing explicit intent. Native information page includes requested identity/maintainer, port/runtime build details and credits; no OTA operation or Settings APK rewrite.'
    issues['UI-004']['cause_and_evidence_limits'] = 'Original composition removed the factory Updater while Settings retained its explicit com.android.updater.UpdateActivity route, causing silent activity-resolution failure. The new information-only APK restores that route. Actual Settings card tap, Back to About phone and all credits entries were checked on the current phone using the data-installed preview. Integrated system APK boot behavior remains untested; no stock OTA compatibility claimed.'
    for issue_id in ['UI-006', 'HW-002', 'UI-004']:
        for reference in ['00-manifest/kyneos-ri7-delivery-20261005.json', 'tools/kyneos/repack_product.py', str(OUT / 'VALIDATION.json'), str(OUT / 'ARM64-READONLY-VERIFICATION.json')]:
            if reference not in issues[issue_id]['evidence']: issues[issue_id]['evidence'].append(reference)
    history['updated_at'] = now; path.write_text(json.dumps(history, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    update = '\nKYNEOS RI7.1 INTEGRATION | ' + now + '\nUI-006: boot-initialized Vulkan renderer. HW-002: peridot Bluetooth SAR-device gate. UI-004: KyneOS Settings information destination via existing HyperOS card intent. Native information app added to product/app/KyneOSInfo; Settings/AOD APKs unchanged. Only product super span and vbmeta_system payload changed from RI6; root keys/rollback/flags and other images retained. Complete signed recovery ZIP: ' + str(validation['archive']) + '\nSHA256 ' + validation['sha256'] + '\nOffline file/metadata/AVB/ZIP/ARM64 read-only checks passed. Prior live corrections and Settings page preview are confirmed separately; integrated ZIP flash/reboot and remaining regressions remain OPEN. No Format Data for existing RI6 DECRYPT update; no assistant flash/wipe/reboot performed.\n'
    for name in ['CHANGELOG.txt', 'ROM-AND-APP-CHANGES.txt']:
        if validation['sha256'] not in (base / name).read_text(encoding='utf-8'):
            with (base / name).open('a', encoding='utf-8') as f: f.write(update)
    (ROOT / '09-reports/KYNEOS-RI7-DELIVERY-20261005.txt').write_text(update + '\n' + (OUT / 'INSTALL.txt').read_text(), encoding='utf-8')
    link = WORK / 'outputs'
    if link.exists(): assert link.resolve() == OUT.resolve()
    else:
        subprocess.run(['powershell', '-NoProfile', '-Command',
                        "New-Item -ItemType Junction -Path '" + str(link) + "' -Target '" + str(OUT) + "' | Out-Null"], check=True)
    assert (link / Path(validation['archive']).name).stat().st_size == validation['bytes']
    print(json.dumps({k: validation[k] for k in ['archive', 'bytes', 'sha256']}, indent=2))

if __name__ == '__main__': main()

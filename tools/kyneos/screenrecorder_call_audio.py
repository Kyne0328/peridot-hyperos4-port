"""Patch RI7 framework.jar so Xiaomi Screen Recorder requests voice-call playback capture.

The signed com.miui.screenrecorder APK is intentionally left untouched. The patch is scoped in
AudioPlaybackCaptureConfiguration.Builder.build() to the recorder process, adds
USAGE_VOICE_COMMUNICATION (2), and marks its AudioMixingRule as privileged playback capture with
voice-communication capture allowed before the mixing rule is finalized.

This script is fail-closed against the current RI7 framework.jar and pinned smali tool hashes.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORK = ROOT / "builder/work/screen-recorder-call-audio-20261007"
TOOLS = ROOT / "builder/tools/bin/windows"
SOURCE_FRAMEWORK_SHA256 = "41092430f70ee0a13cc81e9b4d4c2e36199d1c73f1813499a2c9c5ef418d101f"
SOURCE_CLASSES3_SHA256 = "2d6d5c813cb2f50e33c9dfdf6edc8828d4855ba20d875c20a9d0ea8be2aa3319"
BAKSMALI_SHA256 = "37ae4a41a8886e15c20b8362fa4250f96bbdb55e1a608199ad8b5dff068b588f"
SMALI_SHA256 = "32fa0e88a6c397b3922201adf5f3e534fbaed5a663c71d0c558c3ddce0af844a"
BAKSMALI_URL = "https://github.com/baksmali/smali/releases/download/3.0.10/baksmali-3.0.10-fat.jar"
SMALI_URL = "https://github.com/baksmali/smali/releases/download/3.0.10/smali-3.0.10-fat.jar"
TARGET = Path("android/media/AudioPlaybackCaptureConfiguration$Builder.smali")
MARKER = """.method public whitelist build()Landroid/media/AudioPlaybackCaptureConfiguration;
    .registers 5

    .line 246
"""
PATCHED_MARKER = """.method public whitelist build()Landroid/media/AudioPlaybackCaptureConfiguration;
    .registers 5

    invoke-static {}, Landroid/app/ActivityThread;->currentPackageName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "com.miui.screenrecorder"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :kyneos_call_audio_done

    iget-object v2, p0, Landroid/media/AudioPlaybackCaptureConfiguration$Builder;->mAudioMixingRuleBuilder:Landroid/media/audiopolicy/AudioMixingRule$Builder;

    const/4 v3, 0x1

    invoke-virtual {v2, v3}, Landroid/media/audiopolicy/AudioMixingRule$Builder;->allowPrivilegedPlaybackCapture(Z)Landroid/media/audiopolicy/AudioMixingRule$Builder;

    invoke-virtual {v2, v3}, Landroid/media/audiopolicy/AudioMixingRule$Builder;->voiceCommunicationCaptureAllowed(Z)Landroid/media/audiopolicy/AudioMixingRule$Builder;

    const/4 v0, 0x2

    invoke-virtual {p0, v0}, Landroid/media/AudioPlaybackCaptureConfiguration$Builder;->addMatchingUsage(I)Landroid/media/AudioPlaybackCaptureConfiguration$Builder;

    :kyneos_call_audio_done
    .line 246
"""


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run([str(x) for x in argv], check=True, **kwargs)


def ensure_tool(path: Path, url: str, expected: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        partial = path.with_suffix(path.suffix + ".partial")
        if partial.exists():
            partial.unlink()
        urllib.request.urlretrieve(url, partial)
        partial.replace(path)
    actual = sha(path)
    if actual != expected:
        raise ValueError(f"Tool hash mismatch for {path}: {actual}")
    return path


def extract_framework(system_image: Path, output: Path) -> dict:
    import sys
    sys.path.insert(0, str(ROOT / "tools/postboot"))
    from image import Image

    image = Image(system_image)
    try:
        rows = image.inventory()
    finally:
        image.close()
    hits = [row for row in rows if row["path"] == "/system/framework/framework.jar"]
    if len(hits) != 1:
        raise ValueError(f"Expected one framework.jar, found {len(hits)}")
    row = hits[0]
    with output.open("wb") as dst:
        run([TOOLS / "dump.erofs.exe", "--cat", "--nid=" + str(row["nid"]), system_image], stdout=dst)
    if output.stat().st_size != row["size"]:
        raise ValueError("Extracted framework.jar size mismatch")
    if sha(output) != SOURCE_FRAMEWORK_SHA256:
        raise ValueError("framework.jar is not the pinned RI7 input")
    return row


def patch_framework(source_jar: Path, output_jar: Path, work: Path, baksmali: Path, smali: Path) -> dict:
    if sha(source_jar) != SOURCE_FRAMEWORK_SHA256:
        raise ValueError("Source framework.jar hash drift")
    dex_work = work / "framework-dex"
    if dex_work.exists():
        shutil.rmtree(dex_work)
    original_smali = dex_work / "smali-original"
    baseline_smali = dex_work / "smali-baseline"
    patched_smali = dex_work / "smali-patched"
    verify_smali = dex_work / "smali-verify"
    dex_work.mkdir(parents=True)

    with zipfile.ZipFile(source_jar) as archive:
        classes3 = archive.read("classes3.dex")
    original_dex = dex_work / "classes3.dex"
    original_dex.write_bytes(classes3)
    if hashlib.sha256(classes3).hexdigest() != SOURCE_CLASSES3_SHA256:
        raise ValueError("classes3.dex is not the pinned RI7 input")
    if classes3[:8] != b"dex\n039\x00":
        raise ValueError("Unexpected classes3.dex format")

    run(["java", "-jar", baksmali, "disassemble", "--api", "29", "-o", original_smali, original_dex])
    baseline_dex = dex_work / "classes3.baseline.dex"
    run(["java", "-jar", smali, "assemble", "--api", "29", "-o", baseline_dex, original_smali])
    if baseline_dex.read_bytes()[:8] != b"dex\n039\x00":
        raise ValueError("Baseline DEX version drift")
    run(["java", "-jar", baksmali, "disassemble", "--api", "29", "-o", baseline_smali, baseline_dex])
    shutil.copytree(original_smali, patched_smali)
    target = patched_smali / TARGET
    text = target.read_text(encoding="utf-8")
    if text.count(MARKER) != 1:
        raise ValueError("Framework build() marker drift")
    target.write_text(text.replace(MARKER, PATCHED_MARKER), encoding="utf-8", newline="\n")

    patched_dex = dex_work / "classes3.patched.dex"
    run(["java", "-jar", smali, "assemble", "--api", "29", "-o", patched_dex, patched_smali])
    if patched_dex.read_bytes()[:8] != b"dex\n039\x00":
        raise ValueError("Patched DEX version drift")

    run(["java", "-jar", baksmali, "disassemble", "--api", "29", "-o", verify_smali, patched_dex])
    baseline_files = {p.relative_to(baseline_smali) for p in baseline_smali.rglob("*.smali")}
    verify_files = {p.relative_to(verify_smali) for p in verify_smali.rglob("*.smali")}
    if baseline_files != verify_files:
        raise ValueError("Class set changed during DEX round-trip")
    for rel in sorted(baseline_files):
        if rel == TARGET:
            continue
        if (baseline_smali / rel).read_bytes() != (verify_smali / rel).read_bytes():
            raise ValueError(f"Unexpected non-target class change: {rel}")
    target_verify = (verify_smali / TARGET).read_text(encoding="utf-8")
    required = [
        "Landroid/app/ActivityThread;->currentPackageName()Ljava/lang/String;",
        '"com.miui.screenrecorder"',
        "->addMatchingUsage(I)Landroid/media/AudioPlaybackCaptureConfiguration$Builder;",
        "->allowPrivilegedPlaybackCapture(Z)Landroid/media/audiopolicy/AudioMixingRule$Builder;",
        "->voiceCommunicationCaptureAllowed(Z)Landroid/media/audiopolicy/AudioMixingRule$Builder;",
    ]
    if not all(value in target_verify for value in required):
        raise ValueError("Patched target class did not round-trip with required hook")

    if output_jar.exists():
        output_jar.unlink()
    changed = []
    with zipfile.ZipFile(source_jar) as src, zipfile.ZipFile(output_jar, "w") as dst:
        for info in src.infolist():
            data = patched_dex.read_bytes() if info.filename == "classes3.dex" else src.read(info.filename)
            dst.writestr(copy.copy(info), data, compress_type=info.compress_type)
    with zipfile.ZipFile(source_jar) as src, zipfile.ZipFile(output_jar) as dst:
        if src.namelist() != dst.namelist():
            raise ValueError("framework.jar member order changed")
        for name in src.namelist():
            before = hashlib.sha256(src.read(name)).hexdigest()
            after = hashlib.sha256(dst.read(name)).hexdigest()
            if before != after:
                changed.append(name)
    if changed != ["classes3.dex"]:
        raise ValueError(f"Unexpected framework.jar member changes: {changed}")

    receipt = {
        "source_framework_sha256": sha(source_jar),
        "patched_framework_sha256": sha(output_jar),
        "source_classes3_sha256": SOURCE_CLASSES3_SHA256,
        "patched_classes3_sha256": sha(patched_dex),
        "dex_magic": patched_dex.read_bytes()[:8].decode("ascii", errors="replace").replace("\x00", "\\0"),
        "changed_jar_members": changed,
        "target_class": "android.media.AudioPlaybackCaptureConfiguration$Builder",
        "target_method": "build",
        "scope_package": "com.miui.screenrecorder",
        "added_usage": 2,
        "added_usage_name": "USAGE_VOICE_COMMUNICATION",
        "allow_privileged_playback_capture": True,
        "voice_communication_capture_allowed": True,
        "non_target_canonical_smali_identical": True,
        "screen_recorder_apk_modified": False,
        "device_tested": False,
        "tools": {
            "baksmali_sha256": sha(baksmali),
            "smali_sha256": sha(smali),
        },
    }
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system", type=Path, default=ROOT / "builder/work/kyneos-ri7-20261005/system.img")
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK)
    parser.add_argument("--framework", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baksmali", type=Path)
    parser.add_argument("--smali", type=Path)
    args = parser.parse_args()

    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    tool_dir = work / "tools"
    baksmali = args.baksmali or tool_dir / "baksmali-3.0.10-fat.jar"
    smali = args.smali or tool_dir / "smali-3.0.10-fat.jar"
    baksmali = ensure_tool(baksmali, BAKSMALI_URL, BAKSMALI_SHA256)
    smali = ensure_tool(smali, SMALI_URL, SMALI_SHA256)

    source_jar = args.framework or work / "framework.source.jar"
    source_row = None
    if args.framework is None:
        if source_jar.exists():
            source_jar.unlink()
        source_row = extract_framework(args.system.resolve(), source_jar)
    output_jar = args.output or work / "framework.call-audio.jar"
    receipt = patch_framework(source_jar, output_jar, work, baksmali, smali)
    receipt.update(
        source_system=str(args.system.resolve()) if args.framework is None else None,
        source_system_framework_row=source_row,
        output_framework=str(output_jar.resolve()),
    )
    receipt_path = work / "screenrecorder-call-audio-framework.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()

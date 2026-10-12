"""Repack RI7 system with the scoped Screen Recorder call-audio framework patch.

Only /system/framework/framework.jar is replaced. Stale direct fs-verity/ART companions for that
boot-classpath component are omitted so ART must validate/regenerate code from the changed DEX.
All remaining file contents and metadata are verified after EROFS reconstruction.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "builder/tools/bin/windows"
DEFAULT_WORK = ROOT / "builder/work/screen-recorder-call-audio-20261007"
SOURCE_SYSTEM_SHA256 = "258ba69d7d1c93081478885980f93abce985e88d8a47037082f4552dc02dc4c6"
SOURCE_FRAMEWORK_SHA256 = "41092430f70ee0a13cc81e9b4d4c2e36199d1c73f1813499a2c9c5ef418d101f"
FRAMEWORK_PATH = "/system/framework/framework.jar"
REMOVE = {
    "/system/framework/framework.jar.fsv_meta",
    "/system/framework/boot-framework.vdex",
    "/system/framework/boot-framework.vdex.fsv_meta",
    "/system/framework/arm64/boot-framework.vdex",
    "/system/framework/arm64/boot-framework.vdex.fsv_meta",
    "/system/framework/arm64/boot-framework.oat",
    "/system/framework/arm64/boot-framework.oat.fsv_meta",
    "/system/framework/arm64/boot-framework.art",
    "/system/framework/arm64/boot-framework.art.fsv_meta",
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class Reader:
    def __init__(self, stream):
        self.stream = stream
        self.hash = hashlib.sha256()
        self.count = 0

    def read(self, count):
        if not 0 <= count <= 1024 * 1024:
            raise ValueError("Unexpected tar read size")
        data = self.stream.read(count)
        self.hash.update(data)
        self.count += len(data)
        return data


def image_hash(path: Path, nid: int, expected_size: int) -> str:
    proc = subprocess.Popen(
        [str(TOOLS / "dump.erofs.exe"), "--cat", "--nid=" + str(nid), str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    digest = hashlib.sha256()
    count = 0
    for block in iter(lambda: proc.stdout.read(1024 * 1024), b""):
        count += len(block)
        if count > expected_size:
            raise ValueError("EROFS extraction exceeded expected size")
        digest.update(block)
    errors = proc.stderr.read()
    if proc.wait() != 0:
        raise RuntimeError(errors.decode(errors="replace"))
    if count != expected_size:
        raise ValueError("EROFS extraction size mismatch")
    return digest.hexdigest()


def small(path: Path, nid: int, expected_size: int) -> bytes:
    if expected_size >= 8 * 1024 * 1024:
        raise ValueError("small() called for a large file")
    result = subprocess.run(
        [str(TOOLS / "dump.erofs.exe"), "--cat", "--nid=" + str(nid), str(path)],
        capture_output=True,
        check=True,
    )
    if len(result.stdout) != expected_size:
        raise ValueError("Small EROFS extraction size mismatch")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT / "builder/work/kyneos-ri7-20261005/system.img")
    parser.add_argument("--framework", type=Path, default=DEFAULT_WORK / "framework.call-audio.jar")
    parser.add_argument("--framework-receipt", type=Path, default=DEFAULT_WORK / "screenrecorder-call-audio-framework.json")
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tar-only", action="store_true")
    args = parser.parse_args()

    source = args.source.resolve()
    framework = args.framework.resolve()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    if sha(source) != SOURCE_SYSTEM_SHA256:
        raise ValueError("Source system image is not the pinned RI7 input")
    if not framework.is_file():
        raise ValueError("Patched framework.jar is missing")
    patch_receipt = json.loads(args.framework_receipt.read_text(encoding="utf-8"))
    if sha(framework) != patch_receipt["patched_framework_sha256"]:
        raise ValueError("Patched framework hash does not match its receipt")
    if patch_receipt["source_framework_sha256"] != SOURCE_FRAMEWORK_SHA256:
        raise ValueError("Framework patch receipt source drift")

    import sys
    sys.path.insert(0, str(ROOT / "tools/postboot"))
    from image import Image

    original = Image(source)
    rows = original.inventory()
    by_path = {row["path"]: row for row in rows}
    if set(REMOVE) - set(by_path):
        raise ValueError("Expected stale boot-framework companion is missing")
    if FRAMEWORK_PATH not in by_path:
        raise ValueError("framework.jar is missing from system")
    source_framework = by_path[FRAMEWORK_PATH]
    if image_hash(source, source_framework["nid"], source_framework["size"]) != SOURCE_FRAMEWORK_SHA256:
        raise ValueError("framework.jar inside system does not match the pinned source")

    removed_nids = {by_path[path]["nid"] for path in REMOVE}
    for row in rows:
        if row["nid"] in removed_nids and row["path"] not in REMOVE:
            raise ValueError("A removed inode has an unremoved hardlink: " + row["path"])

    tar_path = work / "system-call-audio.tar"
    if tar_path.exists():
        tar_path.unlink()
    expected = []
    seen = {}
    hashes = {}
    print("Streaming metadata-preserving system tar", flush=True)
    with tarfile.open(tar_path, "x", format=tarfile.PAX_FORMAT) as archive:
        kept = [row for row in rows if row["path"] not in REMOVE]
        for index, row in enumerate(sorted(kept, key=lambda x: (x["path"].count("/"), x["path"]))):
            path = row["path"]
            info = tarfile.TarInfo(path.lstrip("/") or ".")
            info.mode = row["mode"] & 0o7777
            info.uid = row["uid"]
            info.gid = row["gid"]
            info.mtime = 1230768000
            info.pax_headers = {
                "LIBARCHIVE.xattr." + key: base64.b64encode(bytes.fromhex(value)).decode()
                for key, value in row["xattrs"].items()
            }
            receipt = {key: row[key] for key in ["path", "mode", "uid", "gid", "xattrs"]}
            if stat.S_ISDIR(row["mode"]):
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif stat.S_ISLNK(row["mode"]):
                data = small(source, row["nid"], row["size"])
                info.type = tarfile.SYMTYPE
                info.linkname = data.decode()
                archive.addfile(info)
                receipt.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            elif stat.S_ISREG(row["mode"]):
                if path == FRAMEWORK_PATH:
                    info.size = framework.stat().st_size
                    with framework.open("rb") as stream:
                        archive.addfile(info, stream)
                    digest = sha(framework)
                elif row["nid"] in seen:
                    info.type = tarfile.LNKTYPE
                    info.linkname = seen[row["nid"]]
                    info.size = row["size"]
                    archive.addfile(info)
                    digest = hashes[row["nid"]]
                else:
                    info.size = row["size"]
                    proc = subprocess.Popen(
                        [str(TOOLS / "dump.erofs.exe"), "--cat", "--nid=" + str(row["nid"]), str(source)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    reader = Reader(proc.stdout)
                    archive.addfile(info, reader)
                    if reader.count != info.size or proc.stdout.read(1):
                        raise ValueError("Streamed EROFS file size mismatch: " + path)
                    errors = proc.stderr.read()
                    if proc.wait() != 0:
                        raise RuntimeError(errors.decode(errors="replace"))
                    digest = reader.hash.hexdigest()
                if row["nid"] not in seen:
                    seen[row["nid"]] = info.name
                    hashes[row["nid"]] = digest
                receipt.update(size=info.size, sha256=digest)
            else:
                raise ValueError("Unsupported special inode: " + path)
            expected.append(receipt)
            if index % 500 == 0:
                print("Prepared", index, "/", len(kept), flush=True)
    original.close()

    base_receipt = {
        "source_system_sha256": SOURCE_SYSTEM_SHA256,
        "patched_framework_sha256": sha(framework),
        "removed_paths": sorted(REMOVE),
        "removed_reason": "Discard stale direct framework.jar fs-verity and boot-framework ART companions; ART must validate/regenerate from the changed DEX.",
        "prepared_tar": str(tar_path),
        "prepared_tar_sha256": sha(tar_path),
        "entry_count": len(expected),
        "phone_actions_performed": False,
    }
    if args.tar_only:
        out_receipt = work / "screenrecorder-call-audio-system.json"
        out_receipt.write_text(json.dumps(base_receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(base_receipt, indent=2))
        return

    output = args.output.resolve() if args.output else work / "system-filesystem.call-audio.img"
    if output.exists():
        output.unlink()
    with source.open("rb") as stream:
        stream.seek(1072)
        ident = uuid.UUID(bytes=stream.read(16))
    temp = work / "tmp-erofs"
    temp.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update(TMPDIR=str(temp), TMP=str(temp), TEMP=str(temp))
    subprocess.run(
        [
            str(TOOLS / "mkfs.erofs.exe"),
            "-d0",
            "-T1230768000",
            "-U",
            str(ident),
            "-zlz4hc,level=12",
            "--tar=f",
            str(output),
            str(tar_path),
        ],
        env=env,
        check=True,
    )
    if output.stat().st_size >= source.stat().st_size - 8 * 1024**2:
        raise ValueError("Rebuilt system filesystem has insufficient AVB reserve")
    subprocess.run([str(TOOLS / "fsck.erofs.exe"), output], check=True)

    rebuilt = Image(output)
    actual = {row["path"]: row for row in rebuilt.inventory()}
    expected_by_path = {row["path"]: row for row in expected}
    if set(actual) != set(expected_by_path):
        raise ValueError("Rebuilt system path set mismatch")
    print("Verifying rebuilt system metadata/content", flush=True)
    for index, row in enumerate(expected):
        got = actual[row["path"]]
        for key in ["mode", "uid", "gid", "xattrs"]:
            if got[key] != row[key]:
                raise ValueError(f"Metadata differs for {row['path']} {key}")
        if "sha256" in row:
            if image_hash(output, got["nid"], row["size"]) != row["sha256"]:
                raise ValueError("Content differs for " + row["path"])
        if index % 500 == 0:
            print("Verified", index, "/", len(expected), flush=True)
    rebuilt.close()

    base_receipt.update(
        filesystem_path=str(output),
        filesystem_sha256=sha(output),
        filesystem_bytes=output.stat().st_size,
        allocation_bytes=source.stat().st_size,
        all_remaining_file_hashes_modes_uid_gid_xattrs_verified=True,
    )
    out_receipt = work / "screenrecorder-call-audio-system.json"
    out_receipt.write_text(json.dumps(base_receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(base_receipt, indent=2))


if __name__ == "__main__":
    main()

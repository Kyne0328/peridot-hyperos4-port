"""Assemble the Screen Recorder call-audio system patch into the current RI7 super image.

The RI7 base already contains the product-only KyneOS changes. This step changes only the
system_a logical-partition span and vbmeta_system's system descriptor relative to that base.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "builder/work/kyneos-ri7-20261005"
WORK = ROOT / "builder/work/screen-recorder-call-audio-20261007"

sys.path.insert(0, str(ROOT / "builder"))
from peridot_builder.lp import parse_super_metadata_prefix
sys.path.insert(0, str(ROOT / "tools/postboot"))
from assemble import descriptor_name, footer_metadata, resign
sys.path.insert(0, str(ROOT / "tools/installer-ri3/recovery-pair"))
from pair_format import verify_avb, public_blob


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def digest_range(path: Path, offset: int, length: int) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        left = length
        while left:
            block = stream.read(min(left, 4 * 1024 * 1024))
            if not block:
                raise ValueError("Unexpected EOF while hashing image range")
            h.update(block)
            left -= len(block)
    return h.hexdigest()


def wsl_path(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive
    if not drive or len(drive) < 2 or drive[1] != ":":
        raise ValueError(f"Cannot convert path to WSL form: {resolved}")
    relative = str(resolved)[2:].replace("\\", "/").lstrip("/")
    return f"/mnt/{drive[0].lower()}/{relative}"


def hashtree_geometry(descriptor: bytes) -> dict[str, int]:
    if struct.unpack_from(">Q", descriptor, 0)[0] != 1:
        raise ValueError("Expected AVB hashtree descriptor")
    return {
        "image_size": struct.unpack_from(">Q", descriptor, 20)[0],
        "tree_offset": struct.unpack_from(">Q", descriptor, 28)[0],
        "tree_size": struct.unpack_from(">Q", descriptor, 36)[0],
        "data_block_size": struct.unpack_from(">I", descriptor, 44)[0],
        "hash_block_size": struct.unpack_from(">I", descriptor, 48)[0],
        "fec_num_roots": struct.unpack_from(">I", descriptor, 52)[0],
        "fec_offset": struct.unpack_from(">Q", descriptor, 56)[0],
        "fec_size": struct.unpack_from(">Q", descriptor, 64)[0],
    }


def property_descriptor(descriptor: bytes) -> tuple[str, str] | None:
    if struct.unpack_from(">Q", descriptor, 0)[0] != 0:
        return None
    key_len = struct.unpack_from(">Q", descriptor, 16)[0]
    value_len = struct.unpack_from(">Q", descriptor, 24)[0]
    key_start = 32
    value_start = key_start + key_len + 1
    key = descriptor[key_start:key_start + key_len].decode("utf-8")
    value = descriptor[value_start:value_start + value_len].decode("utf-8")
    return key, value


def run_wsl(argv: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["wsl.exe", *argv],
        check=True,
        text=True,
        capture_output=capture,
    )


def build_fec_helper(source_system: Path, source_descriptor: bytes) -> tuple[Path, dict]:
    validation_path = WORK / "fec-helper-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    source = ROOT / "tools/kyneos/fec_helper.c"
    if validation.get("helper_source_sha256") != sha(source):
        raise ValueError("FEC helper source changed after stock-byte validation")
    if not validation.get("raw_fec_byte_identical"):
        raise ValueError("FEC helper has not passed byte-identical RI7 stock validation")
    if validation.get("source_system_sha256") != sha(source_system):
        raise ValueError("FEC helper validation is bound to a different RI7 system image")
    if validation.get("descriptor") != hashtree_geometry(source_descriptor):
        raise ValueError("FEC helper validation descriptor geometry drift")

    helper = WORK / "fec"
    if helper.exists():
        helper.unlink()
    run_wsl([
        "gcc",
        "-O3",
        "-fopenmp",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-o",
        wsl_path(helper),
        wsl_path(source),
        "-lcrypto",
    ])
    check = run_wsl([wsl_path(helper), "--self-test"], capture=True)
    if "PASS" not in check.stdout:
        raise ValueError("FEC helper self-test did not pass")
    return helper, validation


def avbtool_wsl(helper: Path, args: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    path = (
        f"{wsl_path(WORK)}:/usr/local/sbin:/usr/local/bin:"
        "/usr/sbin:/usr/bin:/sbin:/bin"
    )
    return run_wsl([
        "env",
        f"PATH={path}",
        "python3",
        wsl_path(ROOT / "builder/tools/bin/avbtool.py"),
        *args,
    ], capture=capture)


def verify_avb_image(helper: Path, image: Path) -> subprocess.CompletedProcess[str]:
    alias = WORK / "system.img"
    if alias.exists():
        alias.unlink()
    try:
        try:
            os.link(image, alias)
        except OSError:
            shutil.copyfile(image, alias)
        return avbtool_wsl(
            helper,
            ["verify_image", "--image", wsl_path(alias)],
            capture=True,
        )
    finally:
        if alias.exists():
            alias.unlink()


def verify_target_fec(helper: Path, image: Path, geometry: dict[str, int]) -> str:
    if geometry["fec_num_roots"] != 2:
        raise ValueError("Authored system did not retain two FEC roots")
    if geometry["fec_offset"] != geometry["tree_offset"] + geometry["tree_size"]:
        raise ValueError("Authored FEC does not immediately follow the hashtree")
    if geometry["fec_size"] <= 0:
        raise ValueError("Authored FEC is empty")

    regenerated = WORK / "target-system-fec-validation.bin"
    if regenerated.exists():
        regenerated.unlink()
    try:
        run_wsl([
            wsl_path(helper),
            "--encode",
            "--roots",
            "2",
            "--input-size",
            str(geometry["fec_offset"]),
            wsl_path(image),
            wsl_path(regenerated),
        ])
        raw_generated = digest_range(regenerated, 0, geometry["fec_size"])
        raw_image = digest_range(image, geometry["fec_offset"], geometry["fec_size"])
        if raw_generated != raw_image:
            raise ValueError("Authored system FEC bytes do not match independent regeneration")
        return raw_image
    finally:
        if regenerated.exists():
            regenerated.unlink()


def main() -> None:
    base_inputs = json.loads((BASE / "INPUTS.json").read_text(encoding="utf-8"))
    base_assembly = json.loads((BASE / "ASSEMBLY.json").read_text(encoding="utf-8"))
    fs_receipt = json.loads((WORK / "screenrecorder-call-audio-system.json").read_text(encoding="utf-8"))
    framework_receipt = json.loads((WORK / "screenrecorder-call-audio-framework.json").read_text(encoding="utf-8"))

    if not fs_receipt.get("all_remaining_file_hashes_modes_uid_gid_xattrs_verified"):
        raise ValueError("System filesystem verification is incomplete")
    if framework_receipt.get("screen_recorder_apk_modified"):
        raise ValueError("Signed Screen Recorder APK must remain untouched")

    source_system = BASE / "system.img"
    source_super = BASE / "super.img"
    source_vbmeta_system = BASE / "vbmeta_system.img"
    source_vbmeta = BASE / "vbmeta.img"
    if sha(source_system) != base_inputs["files"]["system.img"]["sha256"]:
        raise ValueError("RI7 base system input drift")

    pins = {row["name"]: row for row in base_assembly["pins"]}
    if sha(source_super) != pins["super"]["sha256"]:
        raise ValueError("RI7 super drift")
    if sha(source_vbmeta_system) != pins["vbmeta_system"]["sha256"]:
        raise ValueError("RI7 vbmeta_system drift")
    if sha(source_vbmeta) != pins["vbmeta"]["sha256"]:
        raise ValueError("RI7 root vbmeta drift")

    filesystem = Path(fs_receipt["filesystem_path"])
    if sha(filesystem) != fs_receipt["filesystem_sha256"]:
        raise ValueError("Repacked system filesystem drift")
    if fs_receipt["allocation_bytes"] != source_system.stat().st_size:
        raise ValueError("System allocation changed")

    parsed_system = verify_avb(source_vbmeta_system.read_bytes())
    root = verify_avb(source_vbmeta.read_bytes())
    old_descriptor = next(d for d in parsed_system["descriptors"] if descriptor_name(d) == "system")
    embedded_source = footer_metadata(source_system)
    embedded_descriptor = next(
        d for d in embedded_source["descriptors"] if descriptor_name(d) == "system"
    )
    if embedded_descriptor != old_descriptor:
        raise ValueError("Embedded RI7 system descriptor differs from vbmeta_system descriptor")

    source_geometry = hashtree_geometry(old_descriptor)
    if (
        source_geometry["data_block_size"] != 4096
        or source_geometry["hash_block_size"] != 4096
        or source_geometry["fec_num_roots"] != 2
        or source_geometry["fec_offset"] != source_geometry["tree_offset"] + source_geometry["tree_size"]
    ):
        raise ValueError("Unexpected RI7 system hashtree/FEC geometry")

    name_len, salt_len = struct.unpack_from(">II", old_descriptor, 104)
    salt = old_descriptor[180 + name_len:180 + name_len + salt_len].hex()
    properties = [
        item
        for item in (property_descriptor(d) for d in embedded_source["descriptors"])
        if item is not None
    ]

    helper, helper_validation = build_fec_helper(source_system, old_descriptor)

    target_system = WORK / "system.call-audio.img"
    if target_system.exists():
        target_system.unlink()
    shutil.copyfile(filesystem, target_system)

    avb_args = [
        "add_hashtree_footer",
        "--image",
        wsl_path(target_system),
        "--partition_name",
        "system",
        "--partition_size",
        str(fs_receipt["allocation_bytes"]),
        "--hash_algorithm",
        "sha256",
        "--block_size",
        "4096",
        "--fec_num_roots",
        "2",
        "--salt",
        salt,
        "--algorithm",
        "NONE",
        "--flags",
        "0",
    ]
    for key, value in properties:
        avb_args.extend(["--prop", f"{key}:{value}"])
    avbtool_wsl(helper, avb_args)

    if target_system.stat().st_size != fs_receipt["allocation_bytes"]:
        raise ValueError("Authored system size changed")
    verify_log = verify_avb_image(helper, target_system)

    target_footer = footer_metadata(target_system)
    new_descriptor = next(
        d for d in target_footer["descriptors"] if descriptor_name(d) == "system"
    )
    new_geometry = hashtree_geometry(new_descriptor)
    if new_geometry["image_size"] != fs_receipt["filesystem_bytes"]:
        raise ValueError("Authored descriptor does not bind the rebuilt filesystem body")
    target_fec_sha256 = verify_target_fec(helper, target_system, new_geometry)

    key_path = ROOT / ".private/avb/postbootfix1/system-rsa4096.pem"
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    if parsed_system["pk"] != public_blob(key):
        raise ValueError("Configured system AVB key does not match RI7 vbmeta_system")

    new_vbmeta_system_bytes = resign(
        source_vbmeta_system.read_bytes(),
        [new_descriptor if descriptor_name(d) == "system" else d for d in parsed_system["descriptors"]],
        key,
    )
    new_vbmeta_system = WORK / "vbmeta_system.call-audio.img"
    new_vbmeta_system.write_bytes(new_vbmeta_system_bytes)
    checked = verify_avb(new_vbmeta_system_bytes)
    if checked["pk"] != parsed_system["pk"]:
        raise ValueError("vbmeta_system public key changed")
    if checked["header"][16:19] != parsed_system["header"][16:19]:
        raise ValueError("vbmeta_system rollback/flags changed")
    for descriptor in parsed_system["descriptors"]:
        if descriptor_name(descriptor) != "system" and descriptor not in checked["descriptors"]:
            raise ValueError("Unrelated vbmeta_system descriptor changed")
    checked_system_descriptor = next(
        d for d in checked["descriptors"] if descriptor_name(d) == "system"
    )
    if checked_system_descriptor != new_descriptor:
        raise ValueError("vbmeta_system did not receive the exact authored system descriptor")
    if sha(source_vbmeta) != base_inputs["files"]["vbmeta.img"]["sha256"]:
        raise ValueError("Root vbmeta must remain byte-identical")

    with source_super.open("rb") as stream:
        metadata = parse_super_metadata_prefix(stream.read(1024 * 1024))
    partition = next(p for p in metadata["partitions"] if p["name"] == "system_a")
    if len(partition["extents"]) != 1:
        raise ValueError("system_a no longer has one fixed extent")
    extent = partition["extents"][0]
    start = extent["offset_bytes"]
    length = extent["size_bytes"]
    if length != target_system.stat().st_size:
        raise ValueError("system_a extent/allocation mismatch")
    if digest_range(source_super, start, length) != sha(source_system):
        raise ValueError("RI7 super system_a span does not match pinned system.img")

    target_super = WORK / "super.call-audio.img"
    if target_super.exists():
        target_super.unlink()
    shutil.copyfile(source_super, target_super)
    with target_super.open("r+b") as dst, target_system.open("rb") as src:
        dst.seek(start)
        for block in iter(lambda: src.read(4 * 1024 * 1024), b""):
            dst.write(block)
        dst.flush()
        os.fsync(dst.fileno())

    if digest_range(target_super, start, length) != sha(target_system):
        raise ValueError("system_a replacement readback failed")
    for offset, count in [
        (0, start),
        (start + length, target_super.stat().st_size - start - length),
    ]:
        if digest_range(target_super, offset, count) != digest_range(source_super, offset, count):
            raise ValueError("Bytes outside system_a changed")

    result = {
        "base_build_id": base_inputs["build_id"],
        "source_super_sha256": sha(source_super),
        "output_super": str(target_super),
        "output_super_sha256": sha(target_super),
        "source_system_sha256": sha(source_system),
        "output_system": str(target_system),
        "output_system_sha256": sha(target_system),
        "source_vbmeta_system_sha256": sha(source_vbmeta_system),
        "output_vbmeta_system": str(new_vbmeta_system),
        "output_vbmeta_system_sha256": sha(new_vbmeta_system),
        "root_vbmeta_sha256": sha(source_vbmeta),
        "root_vbmeta_unchanged": True,
        "changed_logical_partitions": ["system"],
        "changed_flash_payloads": ["super", "vbmeta_system"],
        "all_super_bytes_outside_system_a_verified_identical": True,
        "source_system_a_span_verified_against_source_system_image": True,
        "target_system_a_span_verified_against_target_system_image": True,
        "embedded_source_descriptor_matched_vbmeta_system": True,
        "vbmeta_system_unrelated_descriptors_unchanged": True,
        "vbmeta_system_public_key_unchanged": True,
        "vbmeta_system_system_descriptor_exactly_replaced": True,
        "rollback_and_flags_unchanged": True,
        "avb_verify_image_passed": True,
        "avb_verify_image_stdout": verify_log.stdout.strip(),
        "fec_generated": True,
        "fec_num_roots": new_geometry["fec_num_roots"],
        "fec_offset": new_geometry["fec_offset"],
        "fec_size": new_geometry["fec_size"],
        "fec_sha256": target_fec_sha256,
        "fec_parity_independently_regenerated_and_verified": True,
        "fec_helper_source_sha256": sha(ROOT / "tools/kyneos/fec_helper.c"),
        "fec_helper_stock_ri7_byte_validation": helper_validation["raw_fec_byte_identical"],
        "screen_recorder_apk_modified": False,
        "phone_partition_flash_performed": False,
        "device_boot_tested": False,
    }
    (WORK / "screenrecorder-call-audio-assembly.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

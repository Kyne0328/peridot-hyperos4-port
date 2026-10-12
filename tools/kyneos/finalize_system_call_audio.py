"""Resume/finalize validation for an already-authored Screen Recorder call-audio image set.

This exists so an expensive 9 GiB super copy does not need to be repeated when the interactive
runner reaches its execution ceiling during final integrity hashing.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json

from cryptography.hazmat.primitives import serialization

from assemble_system_call_audio import (
    BASE,
    ROOT,
    WORK,
    build_fec_helper,
    descriptor_name,
    footer_metadata,
    hashtree_geometry,
    sha,
    verify_avb,
    verify_avb_image,
    verify_target_fec,
    public_blob,
    parse_super_metadata_prefix,
)


def validate_super_pair(
    source: Path,
    target: Path,
    span_start: int,
    span_length: int,
) -> dict[str, str | bool]:
    if source.stat().st_size != target.stat().st_size:
        raise ValueError("Source and target super sizes differ")
    span_end = span_start + span_length
    source_full = hashlib.sha256()
    target_full = hashlib.sha256()
    source_span = hashlib.sha256()
    target_span = hashlib.sha256()
    outside_identical = True

    position = 0
    with source.open("rb") as src, target.open("rb") as dst:
        while True:
            a = src.read(8 * 1024 * 1024)
            b = dst.read(8 * 1024 * 1024)
            if not a and not b:
                break
            if len(a) != len(b):
                raise ValueError("Source/target super read lengths diverged")
            source_full.update(a)
            target_full.update(b)

            block_start = position
            block_end = position + len(a)
            overlap_start = max(block_start, span_start)
            overlap_end = min(block_end, span_end)
            if overlap_start < overlap_end:
                lo = overlap_start - block_start
                hi = overlap_end - block_start
                source_span.update(a[lo:hi])
                target_span.update(b[lo:hi])

            if block_start < span_start:
                hi = min(len(a), span_start - block_start)
                if a[:hi] != b[:hi]:
                    outside_identical = False
            if block_end > span_end:
                lo = max(0, span_end - block_start)
                if a[lo:] != b[lo:]:
                    outside_identical = False

            position = block_end

    if position != source.stat().st_size:
        raise ValueError("Did not consume the full super image")
    return {
        "source_super_sha256": source_full.hexdigest(),
        "target_super_sha256": target_full.hexdigest(),
        "source_span_sha256": source_span.hexdigest(),
        "target_span_sha256": target_span.hexdigest(),
        "outside_span_identical": outside_identical,
    }


def main() -> None:
    base_inputs = json.loads((BASE / "INPUTS.json").read_text(encoding="utf-8"))
    base_assembly = json.loads((BASE / "ASSEMBLY.json").read_text(encoding="utf-8"))
    fs_receipt = json.loads((WORK / "screenrecorder-call-audio-system.json").read_text(encoding="utf-8"))
    framework_receipt = json.loads((WORK / "screenrecorder-call-audio-framework.json").read_text(encoding="utf-8"))

    source_system = BASE / "system.img"
    source_super = BASE / "super.img"
    source_vbmeta_system = BASE / "vbmeta_system.img"
    source_vbmeta = BASE / "vbmeta.img"
    target_system = WORK / "system.call-audio.img"
    target_super = WORK / "super.call-audio.img"
    target_vbmeta_system = WORK / "vbmeta_system.call-audio.img"

    for path in (target_system, target_super, target_vbmeta_system):
        if not path.is_file():
            raise ValueError(f"Missing authored output: {path}")

    pins = {row["name"]: row for row in base_assembly["pins"]}
    if sha(source_system) != base_inputs["files"]["system.img"]["sha256"]:
        raise ValueError("RI7 source system drift")
    if sha(source_vbmeta_system) != pins["vbmeta_system"]["sha256"]:
        raise ValueError("RI7 source vbmeta_system drift")
    if sha(source_vbmeta) != pins["vbmeta"]["sha256"]:
        raise ValueError("RI7 source root vbmeta drift")

    parsed_system = verify_avb(source_vbmeta_system.read_bytes())
    root = verify_avb(source_vbmeta.read_bytes())
    old_descriptor = next(d for d in parsed_system["descriptors"] if descriptor_name(d) == "system")
    embedded_source_descriptor = next(
        d for d in footer_metadata(source_system)["descriptors"] if descriptor_name(d) == "system"
    )
    if embedded_source_descriptor != old_descriptor:
        raise ValueError("RI7 embedded/vbmeta_system system descriptor mismatch")

    helper, helper_validation = build_fec_helper(source_system, old_descriptor)
    verify_log = verify_avb_image(helper, target_system)
    target_footer = footer_metadata(target_system)
    new_descriptor = next(
        d for d in target_footer["descriptors"] if descriptor_name(d) == "system"
    )
    new_geometry = hashtree_geometry(new_descriptor)
    if new_geometry["image_size"] != fs_receipt["filesystem_bytes"]:
        raise ValueError("Target AVB descriptor filesystem size mismatch")
    target_fec_sha256 = verify_target_fec(helper, target_system, new_geometry)

    checked = verify_avb(target_vbmeta_system.read_bytes())
    key_path = ROOT / ".private/avb/postbootfix1/system-rsa4096.pem"
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    if checked["pk"] != parsed_system["pk"] or checked["pk"] != public_blob(key):
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
        raise ValueError("vbmeta_system system descriptor differs from target system image")

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

    super_validation = validate_super_pair(source_super, target_super, start, length)
    if super_validation["source_super_sha256"] != pins["super"]["sha256"]:
        raise ValueError("RI7 source super hash drift")
    if super_validation["source_span_sha256"] != sha(source_system):
        raise ValueError("RI7 source system_a span does not equal source system.img")
    target_system_sha256 = sha(target_system)
    if super_validation["target_span_sha256"] != target_system_sha256:
        raise ValueError("Target super system_a span does not equal target system image")
    if not super_validation["outside_span_identical"]:
        raise ValueError("Bytes outside system_a differ in target super")

    result = {
        "base_build_id": base_inputs["build_id"],
        "source_super_sha256": super_validation["source_super_sha256"],
        "output_super": str(target_super),
        "output_super_sha256": super_validation["target_super_sha256"],
        "source_system_sha256": sha(source_system),
        "output_system": str(target_system),
        "output_system_sha256": target_system_sha256,
        "source_vbmeta_system_sha256": sha(source_vbmeta_system),
        "output_vbmeta_system": str(target_vbmeta_system),
        "output_vbmeta_system_sha256": sha(target_vbmeta_system),
        "root_vbmeta_sha256": sha(source_vbmeta),
        "root_vbmeta_unchanged": True,
        "changed_logical_partitions": ["system"],
        "changed_flash_payloads": ["super", "vbmeta_system"],
        "system_a_offset_bytes": start,
        "system_a_size_bytes": length,
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
        "screen_recorder_apk_modified": framework_receipt["screen_recorder_apk_modified"],
        "phone_partition_flash_performed": False,
        "device_boot_tested": False,
    }
    (WORK / "screenrecorder-call-audio-assembly.json").write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

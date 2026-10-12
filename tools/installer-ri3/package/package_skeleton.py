#!/usr/bin/env python3
"""Deterministic RI3 ZIP skeleton. Production ZIP emission is intentionally disabled."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path, PurePosixPath
import re
import struct
import zipfile
from sparse_super import (IO_BYTES, LARGE_GATE, DEFAULT_RESERVE, SparseError, check,
                          regular, sha_pin, analyze_file, emit_stream, validate_stream)

REQUIRED = {
    "updater": "META-INF/com/google/android/update-binary",
    "edify": "META-INF/com/google/android/updater-script",
}
ROLES = {"updater", "edify", "super", "recovery", "vbmeta", "image", "notice"}

def confined(root, relative):
    check(isinstance(relative, str) and relative and "\\" not in relative and ":" not in relative,
          "source paths must be nonempty workspace-relative POSIX paths")
    value = PurePosixPath(relative)
    check(not value.is_absolute() and all(p not in ("", ".", "..") for p in relative.split("/")),
          "source path escapes workspace")
    root = Path(root).resolve()
    p = root.joinpath(*value.parts)
    check(p.resolve().is_relative_to(root), "source path escapes workspace")
    regular(p)
    return p

def member_name(name):
    check(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_./+-]+", name) is not None,
          "invalid ZIP member name")
    check(not name.startswith("/") and
          all(p not in ("", ".", "..") for p in name.split("/")), "unsafe ZIP member path")
    return name

def hash_file(path):
    h = hashlib.sha256()
    with regular(path).open("rb") as src:
        for data in iter(lambda: src.read(IO_BYTES), b""):
            h.update(data)
    return h.hexdigest()

def plan_contract(contract, root, *, verify_hashes=True):
    check(contract.get("schema_version") == 1, "unsupported package contract version")
    members = contract.get("members")
    check(isinstance(members, list) and 4 <= len(members) <= 128, "invalid package member list")
    names, case_names, roles, result = set(), set(), {}, []
    for item in members:
        check(isinstance(item, dict), "invalid member record")
        role = item.get("role")
        check(role in ROLES, "invalid member role")
        name = member_name(item.get("zip_path"))
        check(name not in names and name.lower() not in case_names, "duplicate ZIP member")
        names.add(name)
        case_names.add(name.lower())
        roles.setdefault(role, []).append(name)
        if role in REQUIRED:
            check(name == REQUIRED[role], "conventional updater entry name mismatch")
        sha_pin(item.get("sha256"))
        size = item.get("size")
        check(isinstance(size, int) and size > 0, "missing or invalid file size pin")
        source = confined(root, item.get("source_path"))
        check(source.stat().st_size == size, "file size changed from contract")
        if verify_hashes:
            check(hash_file(source) == item["sha256"], "file hash changed from contract")
        result.append({"role": role, "zip_path": name, "source_path": item["source_path"],
                       "size": size, "sha256": item["sha256"], "method": "ZIP_STORED",
                       "unix_mode": "0755" if role == "updater" else "0644"})
    for role in ("updater", "edify", "super", "recovery", "vbmeta"):
        check(len(roles.get(role, [])) == 1, "exactly one " + role + " member is required")
    check(not any(re.search(r"(^|/)super(?:[_-](?:part|chunk|sparse))", x, re.I) for x in names),
          "split sparse super naming is forbidden")
    super_member = next(x for x in result if x["role"] == "super")
    raw = contract.get("original_super")
    check(isinstance(raw, dict), "original super pin missing")
    sha_pin(raw.get("sha256"))
    check(isinstance(raw.get("size"), int) and raw["size"] > 0 and raw["size"] % 4096 == 0,
          "original super size must be block aligned")
    return {"schema_version": 1, "kind": "ri3-files-only-package-plan",
            "production_emission_enabled": False,
            "contract_status": contract.get("contract_status", "draft"),
            "original_super": raw,
            "members": sorted(result, key=lambda x: x["zip_path"]),
            "member_bytes": sum(x["size"] for x in result),
            "super_member_zip64_required": super_member["size"] > 0xFFFFFFFF,
            "archive_zip64_allowed": True, "compression": "ZIP_STORED",
            "checks": {"source_sizes": True, "source_sha256": verify_hashes,
                       "complete_sparse_super": "separate sparse validator required",
                       "source_built_arm64_updater": "separate updater attestation required",
                       "real_edify_semantics": "separate installer review required",
                       "matching_recovery_vbmeta": "separate recovery-pair attestation required"},
            "release_ready": False}

def build_fixture_zip(contract, root, output):
    """Test only; cannot produce a full ROM ZIP, regardless of contract_status."""
    plan = plan_contract(contract, root)
    check(plan["member_bytes"] <= LARGE_GATE, "fixture-only ZIP writer refuses more than 64 MiB")
    output = Path(output)
    check(not output.exists() and not output.is_symlink(), "ZIP output exists")
    with output.open("xb") as outer:
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED,
                             allowZip64=True, strict_timestamps=True) as archive:
            for item in plan["members"]:
                info = zipfile.ZipInfo(item["zip_path"], date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (0o100000 | int(item["unix_mode"], 8)) << 16
                info.file_size = item["size"]
                h = hashlib.sha256()
                copied = 0
                with confined(root, item["source_path"]).open("rb") as src:
                    with archive.open(info, "w", force_zip64=True) as dst:
                        for data in iter(lambda: src.read(IO_BYTES), b""):
                            dst.write(data)
                            h.update(data)
                            copied += len(data)
                check(copied == item["size"] and h.hexdigest() == item["sha256"],
                      "input changed during ZIP write")
    verify_fixture_zip(output, plan)
    return {"zip_bytes": output.stat().st_size, "zip_sha256": hash_file(output),
            "members": len(plan["members"]), "fixture_only": True, "release_ready": False}

def verify_fixture_zip(path, plan):
    with zipfile.ZipFile(regular(path), "r", allowZip64=True) as archive:
        expected = {x["zip_path"]: x for x in plan["members"]}
        check(archive.namelist() == sorted(expected), "ZIP entry list or order mismatch")
        with Path(path).open("rb") as raw_zip:
            for info in archive.infolist():
                item = expected[info.filename]
                check(info.compress_type == zipfile.ZIP_STORED, "compressed member rejected")
                check(info.file_size == item["size"] and info.compress_size == item["size"],
                      "ZIP size mismatch")
                check(info.flag_bits & (1 | 8) == 0, "encrypted or data-descriptor member rejected")
                raw_zip.seek(info.header_offset)
                header = raw_zip.read(30)
                check(len(header) == 30 and header[:4] == b"PK\x03\x04", "bad local ZIP header")
                fields = struct.unpack("<I5H3I2H", header)
                check(fields[7:9] == (0xFFFFFFFF, 0xFFFFFFFF), "ZIP64 local sizes not emitted")
                raw_zip.seek(fields[9], 1)
                extra = raw_zip.read(fields[10])
                check(len(extra) >= 20 and struct.unpack_from("<HH", extra) == (1, 16),
                      "ZIP64 local extra missing")
                check(struct.unpack_from("<QQ", extra, 4) == (item["size"], item["size"]),
                      "ZIP64 local extra sizes mismatch")
                h = hashlib.sha256()
                with archive.open(info, "r") as src:
                    for data in iter(lambda: src.read(IO_BYTES), b""):
                        h.update(data)
                check(h.hexdigest() == item["sha256"], "ZIP member pin mismatch")
    return True



def derive_image_manifest(original, *, source_manifest_path, source_manifest_sha256, replacements):
    """Create distinct candidate metadata; never rewrite or relabel the original source manifest."""
    sha_pin(source_manifest_sha256)
    allowed = {"images/recovery.img", "images/vbmeta.img"}
    check(set(replacements) == allowed, "only the matching recovery/vbmeta pair may be replaced")
    images = original.get("images")
    check(isinstance(images, list) and len(images) == 32, "expected 32 original source images")
    index = {}
    for entry in images:
        check(isinstance(entry, dict), "invalid original image record")
        path = member_name(entry.get("path"))
        check(path not in index, "duplicate original image path")
        sha_pin(entry.get("sha256"))
        check(isinstance(entry.get("size"), int) and entry["size"] > 0, "invalid original image size")
        index[path] = entry
    check(allowed <= set(index) and "images/super.img" in index, "required original image missing")
    derived, changes = [], []
    for path in sorted(index):
        source = index[path]
        item = {"path": path, "size": source["size"], "sha256": source["sha256"],
                "origin": "unchanged-original-source"}
        if path in allowed:
            replacement = replacements[path]
            sha_pin(replacement.get("sha256"))
            check(isinstance(replacement.get("size"), int) and replacement["size"] > 0,
                  "invalid paired replacement size")
            check((replacement["size"], replacement["sha256"]) != (source["size"], source["sha256"]),
                  "replacement must have distinct bytes from original source")
            member_name(replacement.get("source_path"))
            evidence = replacement.get("avb_provenance")
            check(isinstance(evidence, dict) and isinstance(evidence.get("report_path"), str)
                  and evidence["report_path"], "paired replacement AVB evidence is required")
            sha_pin(evidence.get("report_sha256"))
            item = {"path": path, "size": replacement["size"], "sha256": replacement["sha256"],
                    "source_path": replacement["source_path"], "origin": "new-matching-pair",
                    "avb_provenance": dict(evidence)}
            changes.append({"path": path,
                            "original": {"size": source["size"], "sha256": source["sha256"]},
                            "replacement": dict(item)})
        derived.append(item)
    return {"schema_version": 1, "kind": "derived-ri3-image-manifest",
            "source_evidence": {"path": source_manifest_path, "sha256": source_manifest_sha256},
            "images": derived, "image_count": 32, "unchanged_image_count": 30,
            "replacement_count": 2, "changes": changes,
            "original_source_manifest_preserved": True, "release_ready": False,
            "verification_scope": "metadata derivation only; input bytes and AVB reports require independent verification"}

def stream_sparse_fixture_zip(raw_path, output, *, expected_bytes, expected_sha256,
                              capacity_bytes, super_member="images/super.img",
                              reserve_bytes=DEFAULT_RESERVE):
    """Prove direct non-seekable ZIP entry emission without creating an intermediate sparse file."""
    check(expected_bytes <= LARGE_GATE, "fixture-only streaming ZIP refuses raw input over 64 MiB")
    name = member_name(super_member)
    check(len(name) <= 255, "fixture member name too long")
    check(reserve_bytes >= 0, "negative free-space reserve")
    output = Path(output)
    check(not output.exists() and not output.is_symlink(), "ZIP output exists")
    pins = dict(expected_bytes=expected_bytes, expected_sha256=expected_sha256,
                capacity_bytes=capacity_bytes)
    plan = analyze_file(raw_path, **pins)
    check(shutil.disk_usage(output.parent).free >= plan["sparse_bytes"] + 1024**2 + reserve_bytes,
          "insufficient disk headroom for ZIP plus reserve")
    with output.open("xb") as outer:
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            info.file_size = plan["sparse_bytes"]
            with archive.open(info, "w", force_zip64=True) as sink:
                emitted = emit_stream(raw_path, sink, plan, **pins)
        outer.flush()
        os.fsync(outer.fileno())
    with zipfile.ZipFile(output, "r", allowZip64=True) as archive:
        check(archive.namelist() == [name], "unexpected ZIP members")
        info = archive.getinfo(name)
        check(info.compress_type == zipfile.ZIP_STORED and info.file_size == plan["sparse_bytes"],
              "stored sparse entry metadata mismatch")
        with archive.open(info, "r") as source:
            validated = validate_stream(source, **pins)
        h = hashlib.sha256()
        with archive.open(info, "r") as source:
            for buf in iter(lambda: source.read(IO_BYTES), b""):
                h.update(buf)
        check(h.hexdigest() == emitted["sparse_sha256"], "ZIP sparse bytes differ from emission")
    return {"fixture_only": True, "release_ready": False,
            "no_intermediate_sparse_created": True,
            "zip_sha256": hash_file(output), "zip_bytes": output.stat().st_size,
            "sparse_sha256": emitted["sparse_sha256"], "expanded_validation": validated,
            "source_identity_verified_between_passes": True}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("contract", type=Path)
    p.add_argument("--workspace", type=Path, default=Path.cwd())
    p.add_argument("--plan", type=Path, required=True)
    args = p.parse_args()
    contract = json.loads(args.contract.read_text(encoding="utf-8-sig"))
    result = plan_contract(contract, args.workspace)
    with args.plan.open("x", encoding="utf-8", newline="\n") as dst:
        json.dump(result, dst, sort_keys=True, indent=2)
        dst.write("\n")
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()

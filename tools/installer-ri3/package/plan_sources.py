#!/usr/bin/env python3
"""Read-only RI3 source verification and sparse/ZIP size planning; never creates an archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

import sparse_super as sparse
from package_skeleton import derive_image_manifest

SOURCE_MANIFEST = ".cache/global-single-recovery-ri2/source-images/MANIFEST.json"
SOURCE_MANIFEST_SHA = "bc5f9e4f415e2910667aae20935e3130a1bfa99acb46c1131c170b31a325c38b"
FROZEN_CONTRACT = "09-reports/installer-ri3/recovery-pair/FROZEN-CONTRACT.json"
FROZEN_CONTRACT_SHA = "76b6b839b320fd4796808fe9fa7ab4c03cc4e81bbd275a7617f26a80930515c0"
RAW_SUPER_SHA = "04842fd6988f96e6e9784adab37d71ec1602ffe35a966f7043658fb84feefd9b"
RAW_SUPER_BYTES = 9126805504
RESERVE = 12 * 1024**3
REPLACEMENTS = {
    "images/recovery.img": {"size": 104857600, "sha256": "8ba7e1e077f31e1a345397fca9842ed1bdf39e69d1003b7bbbcde0830b65e52a"},
    "images/vbmeta.img": {"size": 12288, "sha256": "2c3ad5c1ebdf271a6c2363d5367791e52bf119683091100254143f476587777c"},
}
PUBLIC_CERT = "builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem"
PUBLIC_CERT_SHA = "099a2c2261110568ef1e48b4929a8d3f4e76ffd71b49ee9bf7fe5074987f31d8"

def checked_json(path, expected_sha):
    raw = sparse.regular(path).read_bytes()
    sparse.check(hashlib.sha256(raw).hexdigest() == expected_sha, "manifest/contract pin changed")
    return json.loads(raw)

def checked_hash(path, size, sha):
    path = sparse.regular(path)
    sparse.check(path.stat().st_size == size, "source size mismatch: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as src:
        identity = sparse.fingerprint(os.fstat(src.fileno()))
        for block in iter(lambda: src.read(sparse.IO_BYTES), b""):
            digest.update(block)
        sparse.check(identity == sparse.fingerprint(os.fstat(src.fileno())),
                     "source identity changed during hashing")
    sparse.check(digest.hexdigest() == sha, "source SHA mismatch: " + str(path))
    return list(identity)

def plan(root):
    started = time.monotonic()
    free_before = shutil.disk_usage(root).free
    sparse.check(free_before >= RESERVE, "less than 12 GiB physical free space; planning paused")
    print(json.dumps({"phase": "planning_started", "free_bytes": free_before,
                      "reserve_bytes": RESERVE, "archive_creation": False}), flush=True)
    original = checked_json(root / SOURCE_MANIFEST, SOURCE_MANIFEST_SHA)
    contract = checked_json(root / FROZEN_CONTRACT, FROZEN_CONTRACT_SHA)
    sparse.check(contract["contract"] == "RI3_PAIRED_RECOVERY_DECLARED_GUI_V1",
                 "unexpected frozen recovery contract")
    source_base = root / ".cache/global-single-recovery-ri2/source-images"
    replacements = {}
    for path, pin in REPLACEMENTS.items():
        paired = contract["files"][Path(path).name]
        sparse.check((paired["size"], paired["sha256"]) == (pin["size"], pin["sha256"]),
                     "paired image pin mismatch in frozen contract")
        replacements[path] = dict(pin, source_path=paired["path"],
            avb_provenance={"report_path": FROZEN_CONTRACT, "report_sha256": FROZEN_CONTRACT_SHA})
    derived = derive_image_manifest(original, source_manifest_path=SOURCE_MANIFEST,
                                    source_manifest_sha256=SOURCE_MANIFEST_SHA,
                                    replacements=replacements)
    super_source = next(x for x in original["images"] if x["path"] == "images/super.img")
    sparse.check((super_source["size"], super_source["sha256"]) == (RAW_SUPER_BYTES, RAW_SUPER_SHA),
                 "original raw super pin mismatch")
    super_plan = sparse.analyze_file(source_base / "images/super.img",
                   expected_bytes=RAW_SUPER_BYTES, expected_sha256=RAW_SUPER_SHA,
                   capacity_bytes=RAW_SUPER_BYTES)
    print(json.dumps({"phase": "super_plan_verified", "raw_size": RAW_SUPER_BYTES,
                      "encoded_size": super_plan["sparse_bytes"],
                      "raw_sha256": super_plan["raw_sha256"],
                      "raw_chunks": super_plan["raw_chunks"],
                      "fill_chunks": super_plan["fill_chunks"]}), flush=True)
    members = []
    for entry in derived["images"]:
        name = entry["path"]
        source_path = entry.get("source_path",
                              ".cache/global-single-recovery-ri2/source-images/" + name)
        if name == "images/super.img":
            identity = super_plan["source_identity"]
            encoded_size = super_plan["sparse_bytes"]
            encoded_sha = None
            encoding = "android_sparse_v1_raw_zero_fill_crc"
        else:
            sparse.check(shutil.disk_usage(root).free >= RESERVE,
                         "physical free space fell below 12 GiB during planning")
            identity = checked_hash(root / source_path, entry["size"], entry["sha256"])
            encoded_size, encoded_sha, encoding = entry["size"], entry["sha256"], "raw"
        members.append({"zip_path": name, "source_path": source_path,
                        "raw_size": entry["size"], "raw_sha256": entry["sha256"],
                        "encoded_size": encoded_size, "encoded_sha256": encoded_sha,
                        "encoding": encoding, "zip_method": "ZIP_STORED",
                        "source_identity": identity, "origin": entry["origin"]})
    cert = sparse.regular(root / PUBLIC_CERT)
    cert_identity = checked_hash(cert, cert.stat().st_size, PUBLIC_CERT_SHA)
    members.append({"zip_path": "META-INF/com/android/otacert", "source_path": PUBLIC_CERT,
                    "raw_size": cert.stat().st_size, "raw_sha256": PUBLIC_CERT_SHA,
                    "encoded_size": cert.stat().st_size, "encoded_sha256": PUBLIC_CERT_SHA,
                    "encoding": "raw", "zip_method": "ZIP_STORED",
                    "source_identity": cert_identity, "origin": "frozen-public-zip-certificate"})
    free_after = shutil.disk_usage(root).free
    sparse.check(free_after >= RESERVE, "physical free space fell below 12 GiB before plan receipt")
    return {"schema_version": 1, "phase": "verified_sources_and_exact_sparse_plan",
            "archive_created": False, "installable": False, "release_ready": False,
            "source_manifest": {"path": SOURCE_MANIFEST, "sha256": SOURCE_MANIFEST_SHA},
            "frozen_contract": {"path": FROZEN_CONTRACT, "sha256": FROZEN_CONTRACT_SHA},
            "derived_images": derived, "super_plan": super_plan,
            "members": sorted(members, key=lambda x: x["zip_path"]),
            "payload_encoded_bytes": sum(x["encoded_size"] for x in members),
            "raw_size_is_not_zip_member_size": True,
            "super_encoded_sha256_pending_emission": True,
            "pending": ["Final updater and Edify pins", "Final metadata member layout",
                        "Parent clearance after signer disk reconciliation",
                        "Reproducible payload archive/finalization design review",
                        "Independent ZIP-member readback and whole-file signing"],
            "reserve_bytes": RESERVE, "free_bytes_before": free_before,
            "free_bytes_after": free_after, "elapsed_seconds": time.monotonic()-started}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    sparse.check(output.is_relative_to(root / "09-reports/installer-ri3/package"),
                 "planning receipt must remain in owned report directory")
    sparse.check(not output.exists(), "planning receipt already exists")
    result = plan(root)
    with output.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2, sort_keys=True); f.write("\n")
    print(json.dumps({"phase": result["phase"], "report": str(output),
                      "raw_size": result["super_plan"]["raw_bytes"],
                      "encoded_size": result["super_plan"]["sparse_bytes"],
                      "payload_encoded_bytes": result["payload_encoded_bytes"],
                      "free_bytes_after": result["free_bytes_after"],
                      "elapsed_seconds": result["elapsed_seconds"]}), flush=True)

if __name__ == "__main__":
    main()

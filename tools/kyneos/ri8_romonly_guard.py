"""RI8 vendor-only recovery guard contract; pure preflight and testable write scope.

This module NEVER flashes, remounts, or runs fastboot/adb. It is deliberately
separate from a privileged installer. A source-pinned recovery updater must
evaluate this policy on fresh, complete device observations before any writes.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json

VENDOR_BYTES=430030848
VENDOR_OFFSET=8496611328
SUPER_BYTES=9126805504
SOURCE_VENDOR_SHA256="42b6e24e3ee5a665535621920d77a88ffd6d99ec2359522bc8a8e82cc6a5a9a7"
SOURCE_VBMETA_SHA256="225a9dca237c0c46e1e74d44447eb56f9d3d8882ac2b6000bc8e6795aec4cd2d"
TARGET_VENDOR_SHA256="e7a82d8718b08dfda2cc07bde19433fdf74ee06b236a5f4925da3fd3fe44333f"
TARGET_VBMETA_SHA256="172a1b8ba1bb19a7a1e7155859d845fa5d3afba8b8431dec48ab41864290fbe0"
ARCHIVE_SHA256="6a91acc421cb43121ca0f82f1a2ac690ea0cb6ec489cbe7e95eaca3c1c7b7ae3"
ALLOWED_TARGETS=("vendor_a","vbmeta_a")
BOOT_PROTECTED=("boot_a","boot_b","init_boot_a","init_boot_b","vendor_boot_a","vendor_boot_b",
                "dtbo_a","dtbo_b","recovery_a","recovery_b")

class PreflightError(ValueError):
    pass

def need(ok:bool,message:str)->None:
    if not ok:
        raise PreflightError(message)

def is_digest(s)->bool:
    return isinstance(s,str) and len(s)==64 and all(c in "0123456789abcdef" for c in s)

def preflight(observation:dict)->dict:
    """Validate a complete REPRODUCIBLE read-only recovery receipt.

    Input must originate from current recovery kernel state, not Android apps
    and not inferred defaults. This does not validate freshness on its own.
    Re-sample all dynamic state during a real privileged write operation.
    """
    need(isinstance(observation,dict),"observation must be object")
    need(observation.get("device")=="peridot","wrong device")
    need(observation.get("active_slot")=="a","unsupported active slot")
    need(observation.get("bootloader_unlocked") is True,"bootloader unlock unverified")
    need(observation.get("recovery_running") is True,"not in recovery")
    need(observation.get("recovery_identity_verified") is True,"unverified recovery binary")
    need(observation.get("snapshot_state")=="none" and observation.get("snapshot_state_complete") is True,"unsafe OTA snapshot state")
    need(observation.get("topology_complete") is True,"incomplete block/dm topology")
    need(observation.get("mappings_unmounted") is True,"active logical mapping overlaps vendor write")
    need(observation.get("package_signature_verified") is True,"package signature not verified")
    need(observation.get("package_sha256")==ARCHIVE_SHA256,"signed package drift")
    need(observation.get("package_source_does_not_overlap_target") is True,"source archive stored on target backing")
    need(observation.get("source_package_held_read_only") is True,"source package identity not pinned")
    need(observation.get("single_authorized_writer") is True,"write authority not exclusive")
    need(observation.get("evidence_read_before_write") is True,"pre-write evidence not obtained")
    need(observation.get("target_set")==list(ALLOWED_TARGETS),"unexpected installation targets")
    need(not set(observation["target_set"])&set(BOOT_PROTECTED),"boot partition in allowed write set")
    need(observation.get("super_bytes")==SUPER_BYTES,"unexpected shared super capacity")
    geom=observation.get("vendor_a_extent")
    need(isinstance(geom,dict) and geom.get("backing")=="super","vendor_a is not a verified super extent")
    need(geom.get("offset_bytes")==VENDOR_OFFSET and geom.get("size_bytes")==VENDOR_BYTES,"vendor_a physical offset/capacity changed")
    need(geom.get("extent_count")==1,"unsupported fragmented vendor mapping")
    need(VENDOR_OFFSET>0 and VENDOR_OFFSET+VENDOR_BYTES<=SUPER_BYTES,"vendor extent exceeds super")
    need(observation.get("vendor_a_sha256")==SOURCE_VENDOR_SHA256,"source vendor_a does not match installed RI7.1")
    need(observation.get("vbmeta_a_sha256")==SOURCE_VBMETA_SHA256,
         "current vbmeta does not match original: separate ReSukiSU boot may require different AVB metadata")
    need(observation.get("root_vbmeta_other_descriptors_preserved") is True,
         "cannot prove boot chain descriptor preservation")
    need(observation.get("other_logical_partition_extents_disjoint") is True,
         "logical extent collision")
    need(observation.get("root_vbmeta_key_and_rollback_unchanged") is True,
         "incompatible key or rollback index")
    preserved=observation.get("protected_partition_hashes")
    need(isinstance(preserved,dict) and set(BOOT_PROTECTED)<=set(preserved),
         "missing boot stack source hashes")
    need(all(is_digest(preserved[n]) for n in BOOT_PROTECTED),
         "invalid protected boot partition hashes")
    return {
      "preflight_passed":True,
      "permitted_operations":[{"target":"super","offset_bytes":VENDOR_OFFSET,"bytes":VENDOR_BYTES,
                               "expected_target_sha256":TARGET_VENDOR_SHA256},
                              {"target":"vbmeta_a","offset_bytes":0,"bytes":12288,
                               "expected_target_sha256":TARGET_VBMETA_SHA256}],
      "permitted_logical_targets":list(ALLOWED_TARGETS),
      "explicitly_forbidden_targets":list(BOOT_PROTECTED)+["userdata","metadata","init_boot","vendor_boot","dtbo","recovery","super_full_rewrite"],
      "must_readback_written_bytes":True,
      "must_rehash_protected_partitions_after":True,
      "requires_fresh_state_rechecks_during_write":True,
      "requires_recovery_fixture_tests":True,
      "requires_device_readonly_preflight":True,
      "authorized_to_flash_by_this_planner":False,
    }

def offline_review(source_image:Path,target_image:Path,old_vbmeta:Path,new_vbmeta:Path)->dict:
    """Check source/target artifacts; no target writes."""
    def hash_path(p):
        with p.open("rb") as stream:
            return hashlib.file_digest(stream,"sha256").hexdigest()
    for p in (source_image,target_image,old_vbmeta,new_vbmeta):
        need(p.is_file(),"missing image "+str(p))
    need(source_image.stat().st_size==VENDOR_BYTES and target_image.stat().st_size==VENDOR_BYTES,"vendor length drift")
    need(hash_path(source_image)==SOURCE_VENDOR_SHA256,"old vendor SHA mismatch")
    need(hash_path(target_image)==TARGET_VENDOR_SHA256,"new vendor SHA mismatch")
    need(hash_path(old_vbmeta)==SOURCE_VBMETA_SHA256,"old vbmeta SHA mismatch")
    need(hash_path(new_vbmeta)==TARGET_VBMETA_SHA256,"new vbmeta SHA mismatch")
    return {"verified":True,"source_vendor_sha256":SOURCE_VENDOR_SHA256,
            "target_vendor_sha256":TARGET_VENDOR_SHA256,"source_root_vbmeta_sha256":SOURCE_VBMETA_SHA256,
            "target_root_vbmeta_sha256":TARGET_VBMETA_SHA256,"planned_targets":list(ALLOWED_TARGETS),
            "phone_boot_compatibility":"OPEN","installer_authorized":False}

if __name__=="__main__":
    root=Path(__file__).resolve().parents[2]
    stage=Path("D:/hyperos4-peridot-kyneos-ri8-20261014/work")
    validation=offline_review(root/"builder/work/kyneos-ri7-20261005/vendor.img",stage/"vendor.ri8.img",
                              root/"builder/work/kyneos-ri7-20261005/vbmeta.img",stage/"vbmeta.ri8.img")
    print(json.dumps(validation,indent=2))

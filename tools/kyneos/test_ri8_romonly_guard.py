"""Fail-closed RI8 ROM-only recovery plan fixture tests. Zero device commands."""
from __future__ import annotations
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import unittest

MODULE=Path(__file__).with_name("ri8_romonly_guard.py")
spec=importlib.util.spec_from_file_location("ri8_romonly_guard",MODULE)
import sys
guard=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=guard
spec.loader.exec_module(guard)

def fixture():
    return {
      "device":"peridot",
      "active_slot":"a",
      "bootloader_unlocked":True,
      "recovery_running":True,
      "recovery_identity_verified":True,
      "snapshot_state":"none",
      "snapshot_state_complete":True,
      "topology_complete":True,
      "mappings_unmounted":True,
      "package_signature_verified":True,
      "package_sha256":guard.ARCHIVE_SHA256,
      "package_source_does_not_overlap_target":True,
      "source_package_held_read_only":True,
      "single_authorized_writer":True,
      "evidence_read_before_write":True,
      "target_set":["vendor_a","vbmeta_a"],
      "super_bytes":guard.SUPER_BYTES,
      "vendor_a_extent":{"backing":"super","offset_bytes":guard.VENDOR_OFFSET,
                         "size_bytes":guard.VENDOR_BYTES,"extent_count":1},
      "vendor_a_sha256":guard.SOURCE_VENDOR_SHA256,
      "vbmeta_a_sha256":guard.SOURCE_VBMETA_SHA256,
      "root_vbmeta_other_descriptors_preserved":True,
      "other_logical_partition_extents_disjoint":True,
      "root_vbmeta_key_and_rollback_unchanged":True,
      "protected_partition_hashes":{n:"1"*64 for n in guard.BOOT_PROTECTED}
    }

class GuardTests(unittest.TestCase):
    def test_positive_fixture_is_still_not_flash_permission(self):
        o=guard.preflight(fixture())
        self.assertTrue(o["preflight_passed"])
        self.assertFalse(o["authorized_to_flash_by_this_planner"])
        self.assertEqual(o["permitted_logical_targets"],["vendor_a","vbmeta_a"])
        self.assertEqual(o["permitted_operations"][0]["offset_bytes"],8496611328)
        self.assertTrue(set(guard.BOOT_PROTECTED).isdisjoint(o["permitted_logical_targets"]))

    def reject(self,changes:dict,message:str|None=None):
        o=fixture()
        for path,value in changes.items():
            if "." in path:
                key,field=path.split(".",1)
                o[key][field]=value
            else:
                o[path]=value
        with self.assertRaises(guard.PreflightError) as result:
            guard.preflight(o)
        if message:
            self.assertIn(message,str(result.exception))

    def test_wrong_device(self): self.reject({"device":"whyred"})
    def test_unknown_device(self): self.reject({"device":None})
    def test_wrong_slot(self): self.reject({"active_slot":"b"})
    def test_locked_bootloader(self): self.reject({"bootloader_unlocked":False})
    def test_not_in_recovery(self): self.reject({"recovery_running":False})
    def test_spoofed_recovery(self): self.reject({"recovery_identity_verified":False})
    def test_merging_snapshot(self): self.reject({"snapshot_state":"merging"})
    def test_unknown_snapshot(self): self.reject({"snapshot_state_complete":False})
    def test_incomplete_topology(self): self.reject({"topology_complete":False})
    def test_mounted_target(self): self.reject({"mappings_unmounted":False})
    def test_no_zip_signature(self): self.reject({"package_signature_verified":False})
    def test_altered_package(self): self.reject({"package_sha256":"f"*64})
    def test_source_overlaps(self): self.reject({"package_source_does_not_overlap_target":False})
    def test_source_unpinned(self): self.reject({"source_package_held_read_only":False})
    def test_two_writers(self): self.reject({"single_authorized_writer":False})
    def test_old_observation(self): self.reject({"evidence_read_before_write":False})
    def test_super_reflash_in_plan(self): self.reject({"target_set":["super","vbmeta_a"]})
    def test_kernel_target_in_plan(self): self.reject({"target_set":["vendor_a","boot_a"]})
    def test_missing_avb_write(self): self.reject({"target_set":["vendor_a"]})
    def test_wrong_super_size(self): self.reject({"super_bytes":guard.SUPER_BYTES+4096})
    def test_vendor_at_wrong_offset(self): self.reject({"vendor_a_extent.offset_bytes":0})
    def test_vendor_size_mismatch(self): self.reject({"vendor_a_extent.size_bytes":guard.VENDOR_BYTES-4096})
    def test_vendor_fragmented(self): self.reject({"vendor_a_extent.extent_count":2})
    def test_vendor_other_backing(self): self.reject({"vendor_a_extent.backing":"userdata"})
    def test_replaced_vendor(self): self.reject({"vendor_a_sha256":"f"*64})
    def test_custom_resukisu_vbmeta(self):
        self.reject({"vbmeta_a_sha256":"f"*64},"separate ReSukiSU boot")
    def test_missing_original_vbmeta(self): self.reject({"vbmeta_a_sha256":None})
    def test_root_boot_descriptor_mismatch(self): self.reject({"root_vbmeta_other_descriptors_preserved":False})
    def test_misaligned_layout(self): self.reject({"other_logical_partition_extents_disjoint":False})
    def test_avb_key_changed(self): self.reject({"root_vbmeta_key_and_rollback_unchanged":False})
    def test_missing_protection_hashes(self): self.reject({"protected_partition_hashes":{}})
    def test_bad_protection_hash(self):
        x=fixture()["protected_partition_hashes"]
        x["boot_a"]="not-a-digest"
        self.reject({"protected_partition_hashes":x})
    def test_missing_snapshot(self):
        x=fixture()
        x.pop("snapshot_state")
        with self.assertRaises(guard.PreflightError): guard.preflight(x)
    def test_empty_input(self):
        with self.assertRaises(guard.PreflightError): guard.preflight({})
    def test_nonstr_input(self):
        with self.assertRaises(guard.PreflightError): guard.preflight(None)

if __name__=="__main__":
    unittest.main(verbosity=2)

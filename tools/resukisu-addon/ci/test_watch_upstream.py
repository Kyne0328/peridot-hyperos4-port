"""Offline tests for BakaSU watcher: no GitHub API or device access required."""
from __future__ import annotations
import base64
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("watch_upstream.py")
spec = importlib.util.spec_from_file_location("watch_upstream", SCRIPT)
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)

A = "a" * 40
B = "b" * 40
IMAGE1 = "1" * 64
IMAGE2 = "2" * 64


def artifact(revision, image, when, *, expired=False, size=100):
    return {"name": f"bakasu-peridot-{revision}-{image}",
            "created_at": when, "expired": expired, "size_in_bytes": size}


class WatchTests(unittest.TestCase):
    def test_first_upstream_build(self):
        d = watch.choose(A, [])
        self.assertTrue(d["changed"])
        self.assertFalse(d["already_built"])
        self.assertEqual(d["previous_image_sha"], "")

    def test_already_built_skipped(self):
        d = watch.choose(A, [artifact(A, IMAGE1, "2026-10-14T00:00:00Z")])
        self.assertFalse(d["changed"])
        self.assertTrue(d["already_built"])

    def test_new_revision_retains_last_verified_image_guard(self):
        d = watch.choose(B, [artifact(A, IMAGE1, "2026-10-14T00:00:00Z")])
        self.assertTrue(d["changed"])
        self.assertEqual(d["previous_image_sha"], IMAGE1)

    def test_force_rebuild_existing_revision(self):
        d = watch.choose(A, [artifact(A, IMAGE1, "2026-10-14T00:00:00Z")], force=True)
        self.assertTrue(d["changed"])
        self.assertTrue(d["already_built"])

    def test_newer_history_takes_precedence(self):
        rows = [artifact(A, IMAGE1, "2026-10-10T00:00:00Z"),
                artifact(B, IMAGE2, "2026-10-13T00:00:00Z")]
        d = watch.choose("c"*40, rows)
        self.assertEqual(d["previous_image_sha"], IMAGE2)

    def test_expired_artifacts_do_not_block_build(self):
        d = watch.choose(A, [artifact(A, IMAGE1, "2026-10-14T00:00:00Z", expired=True)])
        self.assertTrue(d["changed"])

    def test_empty_artifact_does_not_block(self):
        d = watch.choose(A, [artifact(A, IMAGE1, "2026-10-14T00:00:00Z", size=0)])
        self.assertTrue(d["changed"])

    def test_malformed_artifact_does_not_affect_guard(self):
        d = watch.choose(B, [{"name": "bakasu-peridot-foo", "size_in_bytes": 50}])
        self.assertTrue(d["changed"])
        self.assertEqual(d["previous_image_sha"], "")

    def test_upstream_sha_strict(self):
        for value in ("B"*40, "xyz", "", "../BakaSU", "a"*39):
            with self.subTest(value=value), self.assertRaises(ValueError):
                watch.choose(value, [])

    def test_other_revisions_do_not_satisfy_current(self):
        d = watch.choose(B, [artifact(A, IMAGE1, "2026-10-14T00:00:00Z")])
        self.assertFalse(d["already_built"])

    def test_upstream_intentional_susfs_stop_is_honored(self):
        text = (
            "# old susfs is incompatible\n"
            "$(info -- BakaSU: Please wait simonpunk update)\n"
            "$(error Please wait susfs update.)\n"
        )
        supported, reason = watch.susfs_inline_gate(text)
        self.assertFalse(supported)
        self.assertEqual(reason, "upstream_susfs_inline_build_suspended")

    def test_pre_suspension_susfs_contract_is_not_blocked(self):
        text = (
            "# susfs selinux_hide feature\n"
            "ifeq ($(shell echo ok),0)\n"
            "ccflags-y += -DKSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE\n"
            "endif\n"
        )
        self.assertTrue(watch.susfs_inline_gate(text)[0])

    def test_unknown_contract_is_fail_closed(self):
        self.assertFalse(watch.susfs_inline_gate("")[0])
        self.assertFalse(watch.susfs_inline_gate("CONFIG=maybe")[0])
        self.assertFalse(watch.susfs_inline_gate("$(error SUSFS compatibility unknown)")[0])

    def test_manual_force_does_not_override_upstream_hard_stop(self):
        compat = "$(info -- susfs compatibility)\n$(error Please wait susfs update.)\n"
        calls = []
        def api(url, token):
            calls.append(url)
            if "/git/ref/heads/main" in url:
                return {"object": {"sha": A}}
            if "/actions/artifacts" in url:
                return {"artifacts": []}
            if "/contents/kernel/tools/susfs_compat.mk" in url:
                return {"encoding": "base64", "content": base64.b64encode(compat.encode()).decode()}
            raise AssertionError("Unexpected API endpoint: " + url)
        with patch.object(watch, "api_json", side_effect=api):
            result = watch.inspect_remote("Kyne0328/peridot-bakasu-kernel", "", True)
        self.assertTrue(result["changed"])
        self.assertTrue(result["force"])
        self.assertFalse(result["build_required"])
        self.assertFalse(result["susfs_inline_supported"])
        self.assertEqual(result["susfs_status"], "upstream_susfs_inline_build_suspended")
        self.assertTrue(any("?ref=" + A in u for u in calls))

    def test_new_upstream_without_stop_may_build(self):
        compat = "# susfs inline compatibility\nccflags-y += -DSUSFS\n"
        def api(url, token):
            if "/git/ref/heads/main" in url:
                return {"object": {"sha": B}}
            if "/actions/artifacts" in url:
                return {"artifacts": []}
            if "/contents/kernel/tools/susfs_compat.mk" in url:
                return {"encoding": "base64", "content": base64.b64encode(compat.encode()).decode()}
            raise AssertionError("Unexpected API URL")
        with patch.object(watch, "api_json", side_effect=api):
            result = watch.inspect_remote("Kyne0328/peridot-bakasu-kernel", "", False)
        self.assertTrue(result["build_required"])
        self.assertTrue(result["susfs_inline_supported"])

    def test_unexpected_upstream_contract_format_is_rejected(self):
        with patch.object(watch, "api_json", return_value={"encoding":"utf-8", "content":"wrong"}):
            with self.assertRaises(ValueError):
                watch.read_susfs_contract(A)


if __name__ == "__main__":
    unittest.main(verbosity=2)

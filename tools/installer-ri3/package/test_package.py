#!/usr/bin/env python3
"""Small regular-file fixtures only. Preserves every generated fixture."""
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
import zlib

import sparse_super as sparse
import package_skeleton as package

ROOT = Path.cwd()
REPORTS = ROOT / "09-reports/installer-ri3/package"
REPORTS.mkdir(parents=True, exist_ok=True)
RUN = REPORTS / "fixtures" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + str(os.getpid()))
RUN.mkdir(parents=True, exist_ok=False)
BLOCK = 4096
ZERO = bytes(BLOCK)
DATA = bytes(range(256)) * 16

class CodecTests(unittest.TestCase):
    def setUp(self):
        self.folder = RUN / self.id().split(".")[-1]
        self.folder.mkdir()
        self.counter = 0

    def file(self, content, suffix=".bin"):
        self.counter += 1
        p = self.folder / (str(self.counter) + suffix)
        p.write_bytes(content)
        return p

    def pins(self, raw):
        return dict(expected_bytes=len(raw), expected_sha256=hashlib.sha256(raw).hexdigest(),
                    capacity_bytes=len(raw))

    def encoded(self, raw, max_raw_bytes=2*BLOCK):
        src = self.file(raw, ".raw")
        dst = self.folder / (str(self.counter) + ".sparse")
        report = sparse.encode_file(src, dst, reserve_bytes=0, max_raw_bytes=max_raw_bytes,
                                     **self.pins(raw))
        return dst, report

    def validate(self, content, raw):
        return sparse.validate_file(self.file(content, ".sparse"), **self.pins(raw))

    def rejects(self, content, raw):
        with self.assertRaises(sparse.SparseError):
            self.validate(content, raw)

    def header(self, data, index, value):
        h = list(sparse.HEADER.unpack(data[:28]))
        h[index] = value
        return sparse.HEADER.pack(*h) + data[28:]

    def chunks(self, data):
        out, at = [], 28
        while at < len(data):
            h = sparse.CHUNK.unpack(data[at:at+12])
            out.append((at, h))
            at += h[3]
        self.assertEqual(at, len(data))
        return out

    def test_mixed_roundtrip_zero_preservation(self):
        raw = DATA + ZERO + DATA * 3 + ZERO * 2 + DATA + ZERO
        path, result = self.encoded(raw)
        self.assertEqual(result["raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["raw_bytes"], len(raw))
        self.assertEqual(result["fill_chunks"], 3)
        self.assertEqual(result["raw_chunks"], 4)
        self.assertEqual(result["dont_care_chunks"], 0)
        # Independent tiny fixture decoder writes an ordinary file for byte equality.
        encoded = path.read_bytes()
        reconstructed = bytearray()
        for at, (kind, _, blocks, total) in self.chunks(encoded):
            if kind == sparse.RAW:
                reconstructed.extend(encoded[at+12:at+total])
            elif kind == sparse.FILL:
                reconstructed.extend(encoded[at+12:at+16] * (blocks*BLOCK//4))
        restored = self.file(reconstructed, ".reconstructed.raw")
        self.assertEqual(restored.read_bytes(), raw)

    def test_deterministic_bytes(self):
        raw = DATA * 3 + ZERO * 3 + DATA
        a, ar = self.encoded(raw)
        b, br = self.encoded(raw)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(ar["sparse_sha256"], br["sparse_sha256"])

    def test_all_zero_fill_and_crc(self):
        raw = ZERO * 7
        p, report = self.encoded(raw)
        self.assertEqual(report["sparse_bytes"], 60)
        self.assertEqual(report["raw_chunks"], 0)
        self.assertEqual(report["fill_chunks"], 1)
        self.assertEqual(report["total_chunks"], 2)

    def test_raw_chunk_boundary(self):
        raw = DATA * 5
        p, report = self.encoded(raw)
        counts = [h[2] for _, h in self.chunks(p.read_bytes()) if h[0] == sparse.RAW]
        self.assertEqual(counts, [2, 2, 1])

    def test_header_rejections(self):
        raw = DATA + ZERO
        p, _ = self.encoded(raw)
        data = p.read_bytes()
        changes = [(0, 0), (1, 2), (2, 1), (3, 27), (3, 32), (4, 11),
                   (4, 16), (5, 0), (5, 3), (5, 4095), (5, 2**31),
                   (6, 0), (6, 1), (6, 3), (6, 0xffffffff),
                   (7, 0), (7, 1), (7, 100), (8, 0x12345678)]
        for index, value in changes:
            with self.subTest(index=index, value=value):
                self.rejects(self.header(data, index, value), raw)

    def test_truncation_and_trailing_data(self):
        raw = DATA + ZERO + DATA
        p, _ = self.encoded(raw)
        data = p.read_bytes()
        cuts = {0, 1, 4, 27, 28, 29, len(data)-1}
        for at, h in self.chunks(data):
            cuts.update([at, at+1, at+11, at+12, at+h[3]-1])
        for cut in sorted(cuts):
            if cut < len(data):
                with self.subTest(cut=cut):
                    self.rejects(data[:cut], raw)
        self.rejects(data + b"junk", raw)

    def test_chunk_rejections(self):
        raw = DATA + ZERO + DATA
        p, _ = self.encoded(raw)
        data = p.read_bytes()
        chunks = self.chunks(data)
        for at, original in chunks:
            variants = []
            h = list(original); h[0] = 0xCAFF; variants.append(h)
            h = list(original); h[1] = 1; variants.append(h)
            h = list(original); h[3] = 11; variants.append(h)
            h = list(original); h[3] += 4; variants.append(h)
            h = list(original); h[2] = 0xffffffff; variants.append(h)
            if original[0] != sparse.CRC32:
                h = list(original); h[2] = 0; variants.append(h)
            else:
                h = list(original); h[2] = 1; variants.append(h)
            for h in variants:
                with self.subTest(offset=at, header=h):
                    self.rejects(data[:at]+sparse.CHUNK.pack(*h)+data[at+12:], raw)

    def test_dont_care_rejected(self):
        raw = DATA + ZERO + DATA
        p, _ = self.encoded(raw)
        data = p.read_bytes()
        at, h = next(x for x in self.chunks(data) if x[1][0] == sparse.FILL)
        bad = data[:at] + sparse.CHUNK.pack(sparse.DONT_CARE, 0, h[2], 12) + data[at+16:]
        self.rejects(bad, raw)

    def test_nonzero_fill_rejected(self):
        raw = ZERO
        p, _ = self.encoded(raw)
        data = p.read_bytes()
        self.rejects(data[:40] + b"abcd" + data[44:], raw)

    def test_missing_and_early_crc_rejected(self):
        raw = DATA + ZERO
        p, _ = self.encoded(raw)
        data = p.read_bytes()
        chunks = self.chunks(data)
        terminal_at, _ = chunks[-1]
        self.rejects(data[:terminal_at], raw)
        bad = data[:28] + data[terminal_at:] + data[28:terminal_at]
        self.rejects(bad, raw)

    def test_crc_corruption_and_original_pin(self):
        raw = DATA + ZERO
        p, _ = self.encoded(raw)
        data = p.read_bytes()
        self.rejects(data[:-1] + bytes([data[-1] ^ 1]), raw)
        bad = bytearray(data); bad[40] ^= 1
        self.rejects(bytes(bad), raw)
        with self.assertRaises(sparse.SparseError):
            sparse.validate_file(p, **dict(self.pins(raw), expected_sha256="0"*64))

    def test_optional_zero_header_crc(self):
        raw = DATA + ZERO
        p, _ = self.encoded(raw)
        self.assertEqual(self.validate(self.header(p.read_bytes(), 8, 0), raw)["raw_bytes"], len(raw))

    def test_capacity_and_alignment(self):
        raw = DATA + ZERO
        p, _ = self.encoded(raw)
        for capacity in (len(raw)-BLOCK, len(raw)+1):
            with self.subTest(capacity=capacity), self.assertRaises(sparse.SparseError):
                sparse.validate_file(p, **dict(self.pins(raw), capacity_bytes=capacity))
        for size, block, cap in [(0, BLOCK, BLOCK), (BLOCK-1, BLOCK, BLOCK),
                                (BLOCK, 3, BLOCK), (BLOCK, 0, BLOCK),
                                (BLOCK, BLOCK, BLOCK-1), ((2**32)*BLOCK, BLOCK, (2**32)*BLOCK)]:
            with self.assertRaises(sparse.SparseError):
                sparse.geometry(size, block, cap)

    def test_raw_input_pin_no_overwrite_and_large_gate(self):
        raw = DATA
        src = self.file(raw)
        existing = self.file(b"KEEP")
        with self.assertRaises(sparse.SparseError):
            sparse.encode_file(src, existing, reserve_bytes=0, **self.pins(raw))
        self.assertEqual(existing.read_bytes(), b"KEEP")
        bad = self.folder / "bad.sparse"
        with self.assertRaises(sparse.SparseError):
            sparse.encode_file(src, bad, reserve_bytes=0,
                               **dict(self.pins(raw), expected_sha256="0"*64))
        self.assertFalse(bad.exists())
        with self.assertRaises(sparse.SparseError):
            sparse.encode_file(src, self.folder/"huge.sparse", reserve_bytes=0,
                               expected_bytes=128*1024**2, expected_sha256="0"*64,
                               capacity_bytes=128*1024**2)
        self.assertFalse((self.folder/"huge.sparse").exists())

    def test_disk_reserve_guard(self):
        raw = DATA
        src = self.file(raw)
        out = self.folder/"space.sparse"
        with patch("sparse_super.shutil.disk_usage") as disk:
            disk.return_value.free = 1
            with self.assertRaises(sparse.SparseError):
                sparse.encode_file(src, out, reserve_bytes=0, **self.pins(raw))
        self.assertFalse(out.exists())

    def test_regular_files_only(self):
        with self.assertRaises(sparse.SparseError):
            sparse.regular(self.folder)

    def test_ieee_crc_known_vector(self):
        self.assertEqual(zlib.crc32(b"123456789"), 0xCBF43926)


    def test_planned_stream_matches_regular_file(self):
        raw = DATA * 3 + ZERO * 2 + DATA
        src = self.file(raw, ".raw")
        plan = sparse.analyze_file(src, max_raw_bytes=2*BLOCK, **self.pins(raw))
        class NonSeekable(io.BytesIO):
            def seek(self, *args):
                raise AssertionError("stream encoder must never seek")
        sink = NonSeekable()
        emitted = sparse.emit_stream(src, sink, plan, **self.pins(raw))
        direct, direct_report = self.encoded(raw)
        self.assertEqual(sink.getvalue(), direct.read_bytes())
        self.assertEqual(plan["sparse_bytes"], len(sink.getvalue()))
        self.assertEqual(emitted["sparse_sha256"], direct_report["sparse_sha256"])

    def test_stream_identity_change_before_emission(self):
        raw = DATA + ZERO
        src = self.file(raw)
        plan = sparse.analyze_file(src, **self.pins(raw))
        st = src.stat()
        os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns + 1000000000))
        sink = io.BytesIO()
        with self.assertRaises(sparse.SparseError):
            sparse.emit_stream(src, sink, plan, **self.pins(raw))
        self.assertEqual(sink.getvalue(), b"")

    def test_stream_content_change_even_with_preserved_metadata(self):
        raw = DATA + ZERO
        src = self.file(raw)
        plan = sparse.analyze_file(src, **self.pins(raw))
        st = src.stat()
        changed = bytearray(raw); changed[7] ^= 1
        src.write_bytes(changed)
        os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
        sink = io.BytesIO()
        with self.assertRaises(sparse.SparseError):
            sparse.emit_stream(src, sink, plan, **self.pins(raw))
        self.rejects(sink.getvalue(), raw)

    def test_stream_short_write_rejected(self):
        raw = DATA + ZERO
        src = self.file(raw)
        plan = sparse.analyze_file(src, **self.pins(raw))
        class ShortSink:
            def write(self, data):
                return max(0, len(data)-1)
        with self.assertRaises(sparse.SparseError):
            sparse.emit_stream(src, ShortSink(), plan, **self.pins(raw))

    def test_stream_plan_count_change_rejected(self):
        raw = DATA + ZERO
        src = self.file(raw)
        plan = sparse.analyze_file(src, **self.pins(raw))
        plan["total_chunks"] += 1
        sink = io.BytesIO()
        with self.assertRaises(sparse.SparseError):
            sparse.emit_stream(src, sink, plan, **self.pins(raw))
        self.rejects(sink.getvalue(), raw)

class PackageTests(CodecTests):
    # Do not inherit the codec tests a second time in the runner.
    def contract(self):
        raw = DATA + ZERO
        sparse_path, report = self.encoded(raw)
        specs = [
            ("updater", package.REQUIRED["updater"], self.file(b"fixture executable only")),
            ("edify", package.REQUIRED["edify"], self.file(b'assert("fixture");\n')),
            ("super", "images/super.img", sparse_path),
            ("recovery", "images/recovery.img", self.file(b"fixture recovery")),
            ("vbmeta", "images/vbmeta.img", self.file(b"fixture vbmeta")),
        ]
        return {"schema_version": 1, "contract_status": "draft",
                "original_super": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                "members": [{"role": role, "zip_path": name,
                             "source_path": str(path.relative_to(ROOT)).replace("\\", "/"),
                             "size": path.stat().st_size, "sha256": package.hash_file(path)}
                            for role, name, path in specs]}

    def test_package_plan_and_zip_determinism(self):
        contract = self.contract()
        plan = package.plan_contract(contract, ROOT)
        self.assertFalse(plan["release_ready"])
        self.assertFalse(plan["production_emission_enabled"])
        a, b = self.folder/"a.zip", self.folder/"b.zip"
        ar = package.build_fixture_zip(contract, ROOT, a)
        br = package.build_fixture_zip(contract, ROOT, b)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(ar["zip_sha256"], br["zip_sha256"])
        self.assertTrue(package.verify_fixture_zip(a, plan))

    def test_package_bad_names_pins_and_roles(self):
        contract = self.contract()
        mutations = [
            ("zip_path", "../escape"), ("zip_path", "/absolute"), ("zip_path", "a\\b"),
            ("zip_path", "images//super.img"), ("zip_path", "images/./super.img"),
            ("sha256", "0"*64), ("sha256", None), ("size", 1), ("role", "unknown"),
            ("source_path", "../elsewhere"), ("source_path", "C:/Windows/file"),
        ]
        for key, val in mutations:
            bad = copy.deepcopy(contract); bad["members"][2][key] = val
            with self.subTest(key=key, value=val), self.assertRaises(sparse.SparseError):
                package.plan_contract(bad, ROOT)
        for member_index in range(5):
            bad = copy.deepcopy(contract); del bad["members"][member_index]
            with self.assertRaises(sparse.SparseError):
                package.plan_contract(bad, ROOT)
        bad = copy.deepcopy(contract); bad["members"].append(copy.deepcopy(bad["members"][2]))
        with self.assertRaises(sparse.SparseError):
            package.plan_contract(bad, ROOT)

    def test_package_large_emission_gate(self):
        contract = self.contract()
        plan = package.plan_contract(contract, ROOT)
        plan["member_bytes"] = sparse.LARGE_GATE + 1
        output = self.folder/"forbidden.zip"
        with patch("package_skeleton.plan_contract", return_value=plan):
            with self.assertRaises(sparse.SparseError):
                package.build_fixture_zip(contract, ROOT, output)
        self.assertFalse(output.exists())


    def test_streaming_zip_without_sparse_intermediate(self):
        raw = DATA*4 + ZERO*3 + DATA
        src = self.file(raw, ".raw")
        before = set(self.folder.iterdir())
        a, b = self.folder/"stream-a.zip", self.folder/"stream-b.zip"
        ar = package.stream_sparse_fixture_zip(src, a, reserve_bytes=0, **self.pins(raw))
        br = package.stream_sparse_fixture_zip(src, b, reserve_bytes=0, **self.pins(raw))
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(ar["zip_sha256"], br["zip_sha256"])
        self.assertTrue(ar["no_intermediate_sparse_created"])
        self.assertEqual(ar["expanded_validation"]["raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(set(self.folder.iterdir()) - before, {a, b})


    def test_derived_manifest_preserves_30_and_replaces_only_pair(self):
        names = ["images/super.img", "images/recovery.img", "images/vbmeta.img"]
        names += ["images/fixture%02d.img" % n for n in range(29)]
        original = {"images": [{"path": n, "size": BLOCK, "sha256": "1"*64} for n in names]}
        before = copy.deepcopy(original)
        replacements = {n: {"source_path": "new-pair/" + n.split("/")[-1],
                            "size": 2*BLOCK, "sha256": "2"*64,
                            "avb_provenance": {"report_path": "evidence/pair.json",
                                               "report_sha256": "3"*64}}
                        for n in ("images/recovery.img", "images/vbmeta.img")}
        derived = package.derive_image_manifest(original, source_manifest_path="original/MANIFEST.json",
                   source_manifest_sha256="4"*64, replacements=replacements)
        self.assertEqual(original, before)
        self.assertEqual(derived["unchanged_image_count"], 30)
        self.assertEqual(derived["replacement_count"], 2)
        self.assertEqual(sum(x["origin"] == "unchanged-original-source" for x in derived["images"]), 30)
        super_image = next(x for x in derived["images"] if x["path"] == "images/super.img")
        self.assertEqual(super_image["sha256"], "1"*64)
        self.assertFalse(derived["release_ready"])
        bad = copy.deepcopy(replacements)
        bad["images/super.img"] = copy.deepcopy(next(iter(bad.values())))
        with self.assertRaises(sparse.SparseError):
            package.derive_image_manifest(original, source_manifest_path="original/MANIFEST.json",
                source_manifest_sha256="4"*64, replacements=bad)
        bad = copy.deepcopy(replacements)
        del bad["images/recovery.img"]["avb_provenance"]
        with self.assertRaises(sparse.SparseError):
            package.derive_image_manifest(original, source_manifest_path="original/MANIFEST.json",
                source_manifest_sha256="4"*64, replacements=bad)

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(CodecTests)
    suite.addTests(PackageTests(name) for name in (
        "test_package_plan_and_zip_determinism", "test_package_bad_names_pins_and_roles",
        "test_package_large_emission_gate", "test_streaming_zip_without_sparse_intermediate",
        "test_derived_manifest_preserves_30_and_replaces_only_pair"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"run_directory": str(RUN), "tests_run": result.testsRun,
              "failures": [(str(test), trace) for test, trace in result.failures],
              "errors": [(str(test), trace) for test, trace in result.errors],
              "passed": result.wasSuccessful(), "fixture_files_preserved": True,
              "production_sparse_created": False, "production_zip_created": False}
    (RUN/"test-results.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    sys.exit(not result.wasSuccessful())

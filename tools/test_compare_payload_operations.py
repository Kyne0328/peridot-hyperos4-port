import bz2
import contextlib
import hashlib
import io
import json
import lzma
import pathlib
import struct
import tempfile
import unittest
import zipfile
import compare_payload_operations as c
import verify_payload_partition as v
from test_verify_payload_partition import field, var, info


def uint(n, value):
    return var(n * 8) + var(value)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.ota, self.image, self.identity, self.report = [self.root / x for x in ('ota.zip', 'odm.img', 'identity.json', 'compare.json')]

    def make(self, mismatch=False, gap=False, bad_blob=False, unsupported=False):
        blocks = [b'A' * 4096, b'B' * 4096, b'C' * 4096]
        ops, blobs = b'', b''
        for i, (kind, block) in enumerate(zip((0, 1, 8), blocks)):
            blob = block if kind == 0 else bz2.compress(block) if kind == 1 else lzma.compress(block)
            extent = uint(1, i + (1 if gap and i == 2 else 0)) + uint(2, 1)
            digest = hashlib.sha256(blob).digest() if not bad_blob else b'x' * 32
            op = uint(1, 6 if unsupported else kind) + uint(2, len(blobs)) + uint(3, len(blob)) + field(6, extent) + field(8, digest)
            ops += field(8, op)
            blobs += blob
        raw = b''.join(blocks)
        manifest = uint(3, 4096) + field(13, field(1, b'odm') + field(7, info(raw)) + ops)
        with zipfile.ZipFile(self.ota, 'w') as z:
            z.writestr('payload.bin', struct.pack('>4sQQI', b'CrAU', 2, len(manifest), 0) + manifest + blobs)
        image = bytearray(raw)
        if mismatch:
            image[5] = 1
            image[9000] = 1
        self.image.write_bytes(image)
        self.checksum = hashlib.sha256(self.ota.read_bytes()).hexdigest()
        with contextlib.redirect_stdout(io.StringIO()):
            v.main(['--ota', str(self.ota), '--ota-sha256', self.checksum, '--partition', 'odm', '--image', str(self.image), '--report', str(self.identity)])

    def run_compare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = c.main(['--ota', str(self.ota), '--ota-sha256', self.checksum, '--partition', 'odm', '--image', str(self.image), '--identity-report', str(self.identity), '--report', str(self.report)])
        return code, json.loads(self.report.read_text())

    def test_three_codecs_match(self):
        self.make()
        code, report = self.run_compare()
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'matched')
        self.assertTrue(report['decoded_image_matches_manifest'])
        self.assertEqual(report['operation_types'], {'0': 1, '1': 1, '8': 1})

    def test_mismatch_offsets(self):
        self.make(mismatch=True)
        code, report = self.run_compare()
        self.assertEqual(code, 1)
        self.assertEqual(report['status'], 'different')
        self.assertEqual(report['mismatch_operation_count'], 2)
        self.assertEqual(report['mismatch_byte_count'], 2)
        self.assertEqual(report['first_differing_offsets'], [5, 9000])
        self.assertTrue(report['decoded_image_matches_manifest'])

    def test_gap_rejected(self):
        self.make(gap=True)
        code, report = self.run_compare()
        self.assertEqual(code, 1)
        self.assertEqual(report['status'], 'error')
        self.assertIn('gap/overlap', report['error'])

    def test_bad_blob_rejected(self):
        self.make(bad_blob=True)
        _, report = self.run_compare()
        self.assertIn('blob SHA-256 mismatch', report['error'])

    def test_unsupported_rejected(self):
        self.make(unsupported=True)
        _, report = self.run_compare()
        self.assertIn('supported replacement', report['error'])

    def test_changed_zip_rejected(self):
        self.make()
        with self.ota.open('ab') as f:
            f.write(b'x')
        _, report = self.run_compare()
        self.assertIn('ZIP checksum mismatch', report['error'])

    def test_changed_image_rejected(self):
        self.make()
        self.image.write_bytes(b'x' * self.image.stat().st_size)
        _, report = self.run_compare()
        self.assertIn('image differs from prior', report['error'])

    def test_codec_bounds_and_trailing(self):
        for kind, codec in ((1, bz2.compress), (8, lzma.compress)):
            for blob, size in ((codec(b'A' * 4096), 10), (codec(b'ABC') + b'extra', 3), (codec(b'ABC')[:-1], 3)):
                with self.assertRaises(v.Invalid):
                    c.decode(kind, blob, size)


if __name__ == '__main__':
    unittest.main()

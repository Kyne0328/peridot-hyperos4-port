import contextlib
import hashlib
import io
import json
import pathlib
import struct
import tempfile
import unittest
import zipfile

import verify_payload_partition as v


def var(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    return bytes(out + bytes([n]))


def field(n, value):
    return var(n * 8 + 2) + var(len(value)) + value


def info(image):
    return var(8) + var(len(image)) + field(2, hashlib.sha256(image).digest())


def part(image, name=b'vendor', extra=b''):
    return field(13, field(1, name) + field(7, info(image)) + extra)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.image = self.root / 'vendor.img'
        self.data = b'raw partition\x00' * 100
        self.image.write_bytes(self.data)
        self.ota = self.root / 'ota.zip'
        self.report = self.root / 'report.json'

    def make(self, manifest=None, header=None, duplicate=False, compression=zipfile.ZIP_STORED):
        if manifest is None:
            manifest = part(self.data)
        if header is None:
            header = struct.pack('>4sQQI', b'CrAU', 2, len(manifest), 0)
        with zipfile.ZipFile(self.ota, 'w', compression=compression) as z:
            z.writestr('payload.bin', header + manifest)
            if duplicate:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    z.writestr('payload.bin', header + manifest)
        return hashlib.sha256(self.ota.read_bytes()).hexdigest()

    def run_cli(self, checksum):
        with contextlib.redirect_stdout(io.StringIO()):
            result = v.main(['--ota', str(self.ota), '--ota-sha256', checksum,
                             '--partition', 'vendor', '--image', str(self.image),
                             '--report', str(self.report)])
        return result, json.loads(self.report.read_text())

    def test_valid_stored(self):
        code, report = self.run_cli(self.make())
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'verified')
        self.assertTrue(report['image_sha256_matches'])

    def test_valid_deflated(self):
        code, _ = self.run_cli(self.make(compression=zipfile.ZIP_DEFLATED))
        self.assertEqual(code, 0)

    def test_checksum_first(self):
        self.ota.write_bytes(b'not even a zip')
        self.image.unlink()
        code, report = self.run_cli('0' * 64)
        self.assertEqual(code, 1)
        self.assertIn('OTA SHA-256 mismatch', report['error'])
        self.assertNotIn('manifest_size', report)

    def test_image_hash_mismatch(self):
        checksum = self.make()
        self.image.write_bytes(b'x' * len(self.data))
        code, report = self.run_cli(checksum)
        self.assertEqual(code, 1)
        self.assertTrue(report['image_size_matches'])
        self.assertFalse(report['image_sha256_matches'])

    def test_image_size_mismatch(self):
        checksum = self.make()
        self.image.write_bytes(self.data + b'x')
        code, report = self.run_cli(checksum)
        self.assertEqual(code, 1)
        self.assertFalse(report['image_size_matches'])

    def test_truncated_manifest(self):
        code, report = self.run_cli(self.make(b'\x6a\x7f\x00'))
        self.assertEqual(code, 1)
        self.assertIn('truncated', report['error'])

    def test_payload_truncated_header(self):
        code, report = self.run_cli(self.make(b'', b'CrAU'))
        self.assertEqual(code, 1)
        self.assertIn('truncated', report['error'])

    def test_header_length_and_signature_bounds(self):
        for length, signature in [(v.MAX_MANIFEST + 1, 0), (10000, 0), (2, 10000), (0, 0)]:
            with self.subTest(length=length, signature=signature):
                self.report.unlink(missing_ok=True)
                code, _ = self.run_cli(self.make(header=struct.pack('>4sQQI', b'CrAU', 2, length, signature)))
                self.assertEqual(code, 1)

    def test_wrong_version(self):
        code, _ = self.run_cli(self.make(header=struct.pack('>4sQQI', b'CrAU', 3, len(part(self.data)), 0)))
        self.assertEqual(code, 1)

    def test_duplicate_payload(self):
        code, report = self.run_cli(self.make(duplicate=True))
        self.assertEqual(code, 1)
        self.assertIn('exactly one', report['error'])

    def test_duplicate_partition(self):
        with self.assertRaisesRegex(v.Invalid, 'duplicate partition'):
            v.partition_info(part(self.data) * 2, 'vendor')

    def test_duplicate_required(self):
        for extra in [field(1, b'vendor'), field(7, info(self.data))]:
            with self.assertRaisesRegex(v.Invalid, 'duplicate required'):
                v.partition_info(part(self.data, extra=extra), 'vendor')
        for extra in [b'\x08\x01', field(2, b'x' * 32)]:
            with self.assertRaisesRegex(v.Invalid, 'duplicate required'):
                v.partition_info(field(13, field(1, b'vendor') + field(7, info(self.data) + extra)), 'vendor')

    def test_malformed_fields(self):
        for malformed in [b'\x00', b'\x6b', b'\x6e', b'\x6f', b'\x80', b'\xff' * 10,
                          b'\x80\x00', b'\x09\x00', b'\x0d\x00', b'\x68\x01']:
            with self.subTest(malformed=malformed), self.assertRaises(v.Invalid):
                v.partition_info(malformed, 'vendor')

    def test_missing_partition_or_fields(self):
        for manifest in [part(self.data, b'boot'), field(13, field(1, b'vendor')),
                         field(13, field(1, b'vendor') + field(7, b'\x08\x01'))]:
            with self.assertRaises(v.Invalid):
                v.partition_info(manifest, 'vendor')

    def test_opaque_unknown_fields(self):
        self.assertEqual(v.partition_info(b'\x19' + b'\x00' * 8 + part(self.data) + b'\x1d' + b'\x00' * 4, 'vendor')[0], len(self.data))

    def test_existing_report_untouched(self):
        checksum = self.make()
        self.report.write_text('existing')
        with contextlib.redirect_stderr(io.StringIO()):
            code = v.main(['--ota', str(self.ota), '--ota-sha256', checksum, '--partition', 'vendor', '--image', str(self.image), '--report', str(self.report)])
        self.assertEqual(code, 2)
        self.assertEqual(self.report.read_text(), 'existing')


if __name__ == '__main__':
    unittest.main()

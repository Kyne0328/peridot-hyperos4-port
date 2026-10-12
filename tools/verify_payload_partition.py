#!/usr/bin/env python3
"""Read-only comparison of a raw image with a checksum-pinned OTA manifest.

No extraction, payload application, signature validation, or device access.
Only the JSON report is written; it must not already exist. Python 3.9+.
Schema source (PartitionInfo 1/2, PartitionUpdate 1/7, manifest 13):
https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto
Header/endian source (24-byte major-version-2 header):
https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/payload_consumer/payload_metadata.cc
This is a bounded protobuf projection, not a complete OTA validity checker:
unknown length-delimited fields are opaque and are never executed.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import stat
import struct
import sys
import zipfile

MAX_MANIFEST = 64 * 1024 * 1024
CHUNK = 1024 * 1024


class Invalid(ValueError):
    pass


def varint(buf, pos):
    value = 0
    for i in range(10):
        if pos >= len(buf):
            raise Invalid('truncated varint')
        b = buf[pos]
        pos += 1
        if i == 9 and b > 1:
            raise Invalid('varint exceeds uint64')
        value |= (b & 127) << (7 * i)
        if not b & 128:
            if i and b == 0:
                raise Invalid('noncanonical varint')
            return value, pos
    raise Invalid('unterminated varint')


def fields(buf):
    buf = memoryview(buf)
    pos = 0
    while pos < len(buf):
        key, pos = varint(buf, pos)
        number, wire = key >> 3, key & 7
        if not 1 <= number <= 536870911:
            raise Invalid('invalid protobuf field number')
        if wire == 0:
            value, pos = varint(buf, pos)
        elif wire in (1, 2, 5):
            if wire == 2:
                size, pos = varint(buf, pos)
            else:
                size = 8 if wire == 1 else 4
            if size > len(buf) - pos:
                raise Invalid('truncated protobuf field')
            value = buf[pos:pos + size]
            pos += size
        else:
            raise Invalid('unsupported protobuf wire type: %d' % wire)
        yield number, wire, value


def unique_fields(buf, required):
    result = {}
    for number, wire, value in fields(buf):
        if number in required:
            if number in result:
                raise Invalid('duplicate required field: %d' % number)
            if wire != required[number]:
                raise Invalid('wrong wire type for field: %d' % number)
            result[number] = value
    if result.keys() != required.keys():
        raise Invalid('missing required field')
    return result


def partition_info(manifest, requested):
    seen = set()
    selected = None
    for number, wire, value in fields(manifest):
        if number != 13:
            continue
        if wire != 2:
            raise Invalid('wrong partitions wire type')
        p = unique_fields(value, {1: 2, 7: 2})
        try:
            name = bytes(p[1]).decode('utf-8', errors='strict')
        except UnicodeDecodeError as exc:
            raise Invalid('invalid partition name encoding') from exc
        if not name or '\x00' in name:
            raise Invalid('invalid partition name')
        if name in seen:
            raise Invalid('duplicate partition name')
        seen.add(name)
        info = unique_fields(p[7], {1: 0, 2: 2})
        digest = bytes(info[2])
        if len(digest) != 32:
            raise Invalid('partition hash must contain 32 SHA-256 bytes')
        if name == requested:
            selected = (info[1], digest.hex())
    if selected is None:
        raise Invalid('requested partition absent')
    return selected


def fingerprint(file):
    s = os.fstat(file.fileno())
    if not stat.S_ISREG(s.st_mode):
        raise Invalid('input must be a regular file')
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def hash_stream(file):
    h = hashlib.sha256()
    size = 0
    while True:
        block = file.read(CHUNK)
        if not block:
            return size, h.hexdigest()
        size += len(block)
        h.update(block)


def read_exact(file, size):
    data = file.read(size)
    if len(data) != size:
        raise Invalid('truncated payload metadata')
    return data


def verify(ota, expected, partition, image, report):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', expected):
        raise Invalid('expected OTA SHA-256 must be exactly 64 hexadecimal characters')
    expected = expected.lower()
    report.update(ota_sha256_expected=expected, partition=partition,
                  ota_path=os.path.abspath(ota), image_path=os.path.abspath(image))
    with open(ota, 'rb') as source:
        before = fingerprint(source)
        size, actual = hash_stream(source)
        report.update(ota_size=size, ota_sha256_actual=actual,
                      ota_checksum_matches=(actual == expected))
        if actual != expected:
            raise Invalid('OTA SHA-256 mismatch; manifest and image were not read')
        if fingerprint(source) != before:
            raise Invalid('OTA changed while hashing')
        source.seek(0)
        with zipfile.ZipFile(source, 'r') as archive:
            matches = [x for x in archive.infolist() if x.filename == 'payload.bin']
            if len(matches) != 1:
                raise Invalid('ZIP must contain exactly one root payload.bin')
            entry = matches[0]
            if entry.flag_bits & 1:
                raise Invalid('encrypted payload unsupported')
            if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise Invalid('unsupported payload ZIP compression')
            with archive.open(entry, 'r') as payload:
                magic, version, length, signature_size = struct.unpack('>4sQQI', read_exact(payload, 24))
                if magic != b'CrAU' or version != 2:
                    raise Invalid('requires CrAU major version 2 payload')
                if not 0 < length <= MAX_MANIFEST:
                    raise Invalid('manifest length outside 1..64 MiB bound')
                if 24 + length + signature_size > entry.file_size:
                    raise Invalid('metadata exceeds payload entry size')
                manifest = read_exact(payload, length)
                expected_size, expected_hash = partition_info(manifest, partition)
            report.update(payload_major_version=version, manifest_size=length,
                          manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                          image_size_expected=expected_size, image_sha256_expected=expected_hash)
        if fingerprint(source) != before:
            raise Invalid('OTA changed while reading metadata')
    with open(image, 'rb') as source:
        before = fingerprint(source)
        actual_size, actual_hash = hash_stream(source)
        if fingerprint(source) != before:
            raise Invalid('image changed while hashing')
    report.update(image_size_actual=actual_size, image_sha256_actual=actual_hash,
                  image_size_matches=(actual_size == expected_size),
                  image_sha256_matches=(actual_hash == expected_hash))
    if actual_size != expected_size or actual_hash != expected_hash:
        raise Invalid('raw image does not match manifest size and SHA-256')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ota', required=True, help='Existing OTA ZIP')
    parser.add_argument('--ota-sha256', required=True, help='Trusted expected ZIP SHA-256; mandatory')
    parser.add_argument('--partition', required=True, help='Exact manifest partition name')
    parser.add_argument('--image', required=True, help='Existing raw (not Android sparse) image')
    parser.add_argument('--report', required=True, help='New JSON file; refuses overwrite')
    args = parser.parse_args(argv)
    report = {'schema_version': 1, 'status': 'error',
              'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'Byte identity against checksum-pinned manifest; not OEM signature or compatibility verification'}
    # Exclusive creation avoids clobbering inputs, existing reports, or symlink targets.
    try:
        output = open(args.report, 'x', encoding='utf-8')
    except OSError as exc:
        print('Cannot create fresh report: %s' % exc, file=sys.stderr)
        return 2
    code = 1
    with output:
        try:
            verify(args.ota, args.ota_sha256, args.partition, args.image, report)
            report['status'] = 'verified'
            code = 0
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError) as exc:
            report['error'] = str(exc)
        report['finished_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        json.dump(report, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'status': report['status'], 'report': os.path.abspath(args.report)}))
    return code


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Read-only, contiguous full-partition operation comparison; Python stdlib only.
Uses verify_payload_partition.py's bounded protobuf reader. No image output.
Schema: https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto
REPLACE=0, REPLACE_BZ=1, REPLACE_XZ=8. Operation fields: type=1,
data_offset=2, data_length=3, dst_extents=6, data_sha256_hash=8.
"""
import argparse
import bz2
import datetime
import hashlib
import json
import lzma
import os
import re
import struct
import sys
import zipfile
import zlib
import verify_payload_partition as v

MAX_OP = 64 * 1024 * 1024


def parse_fields(buf, specifications, repeated=()):
    result = {}
    for number, wire, value in v.fields(buf):
        if number not in specifications:
            continue
        if wire != specifications[number]:
            raise v.Invalid('wrong wire type for field %d' % number)
        if number in repeated:
            result.setdefault(number, []).append(value)
        elif number in result:
            raise v.Invalid('duplicate field %d' % number)
        else:
            result[number] = value
    return result


def operations(manifest, partition):
    # This also verifies unique partition names and mandatory partition size/hash.
    size, digest = v.partition_info(manifest, partition)
    m = parse_fields(manifest, {3: 0, 12: 0, 13: 2}, (13,))
    block = m.get(3, 4096)
    if block <= 0 or block > MAX_OP or m.get(12, 0) != 0:
        raise v.Invalid('requires full payload minor 0 and bounded positive block size')
    chosen = None
    for encoded in m.get(13, []):
        p = parse_fields(encoded, {1: 2, 8: 2, **{n: 2 for n in range(10, 16)}, 16: 0}, (8,))
        if bytes(p[1]).decode('utf-8') == partition:
            chosen = p
    if chosen is None or any(n in chosen for n in range(10, 17)):
        raise v.Invalid('missing partition or generated verity metadata unsupported')
    result = []
    next_byte = 0
    for encoded in chosen.get(8, []):
        op = parse_fields(encoded, {1: 0, 2: 0, 3: 0, 6: 2, 7: 0, 8: 2}, (6,))
        if not all(n in op for n in (1, 2, 3, 6, 8)):
            raise v.Invalid('operation missing required comparison metadata')
        if op[1] not in (0, 1, 8) or len(op[6]) != 1:
            raise v.Invalid('requires supported replacement and exactly one destination extent')
        extent = v.unique_fields(op[6][0], {1: 0, 2: 0})
        offset, length = extent[1] * block, extent[2] * block
        if offset != next_byte or not 0 < length <= MAX_OP or offset + length > size:
            raise v.Invalid('destination gap/overlap/out-of-bounds or operation exceeds 64 MiB')
        if not 0 < op[3] <= MAX_OP or len(op[8]) != 32:
            raise v.Invalid('invalid blob length/hash or blob exceeds 64 MiB')
        if 7 in op and op[7] != length:
            raise v.Invalid('destination length disagrees with extent')
        next_byte += length
        result.append((op[1], op[2], op[3], bytes(op[8]), offset, length))
    if not result or next_byte != size:
        raise v.Invalid('operations do not cover the entire partition contiguously')
    return result, size, digest


def decode(kind, blob, expected_size):
    if kind == 0:
        output = blob
    else:
        # max_length prevents expansion beyond a validated destination plus one byte.
        decoder = bz2.BZ2Decompressor() if kind == 1 else lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_OP * 2)
        output = decoder.decompress(blob, max_length=expected_size + 1)
        if not decoder.eof or decoder.unused_data:
            raise v.Invalid('truncated, concatenated, trailing, or oversized compressed blob')
    if len(output) != expected_size:
        raise v.Invalid('decoded output length differs from destination extent')
    return output


def compare(args, report):
    if not re.fullmatch('[0-9a-fA-F]{64}', args.ota_sha256):
        raise v.Invalid('expected ZIP SHA-256 must be 64 hexadecimal characters')
    expected_zip = args.ota_sha256.lower()
    with open(args.identity_report, 'rb') as identity_file:
        raw_identity = identity_file.read(1024 * 1024 + 1)
    if len(raw_identity) > 1024 * 1024:
        raise v.Invalid('identity report exceeds 1 MiB')
    identity = json.loads(raw_identity)
    if (identity.get('ota_sha256_expected') != expected_zip or
        identity.get('ota_sha256_actual') != expected_zip or
        identity.get('ota_checksum_matches') is not True or
        identity.get('partition') != args.partition):
        raise v.Invalid('identity report does not match checksum/partition')
    report.update(partition=args.partition, ota_sha256_expected=expected_zip,
                  identity_report_sha256=hashlib.sha256(raw_identity).hexdigest())
    with open(args.ota, 'rb') as source, open(args.image, 'rb') as image:
        source_before, image_before = v.fingerprint(source), v.fingerprint(image)
        _, actual_zip = v.hash_stream(source)
        report['ota_sha256_actual'] = actual_zip
        if actual_zip != expected_zip or v.fingerprint(source) != source_before:
            raise v.Invalid('ZIP checksum mismatch or archive changed; payload not read')
        source.seek(0)
        with zipfile.ZipFile(source, 'r') as archive:
            matches = [e for e in archive.infolist() if e.filename == 'payload.bin']
            if len(matches) != 1:
                raise v.Invalid('requires exactly one root payload.bin')
            entry = matches[0]
            if entry.flag_bits & 1 or entry.compress_type not in (0, 8):
                raise v.Invalid('unsupported ZIP payload encoding')
            with archive.open(entry, 'r') as payload:
                magic, version, length, signature = struct.unpack('>4sQQI', v.read_exact(payload, 24))
                base = 24 + length + signature
                if magic != b'CrAU' or version != 2 or not 0 < length <= v.MAX_MANIFEST or base > entry.file_size:
                    raise v.Invalid('invalid/bounded payload header')
                manifest = v.read_exact(payload, length)
                manifest_hash = hashlib.sha256(manifest).hexdigest()
                if manifest_hash != identity.get('manifest_sha256'):
                    raise v.Invalid('manifest differs from identity report')
                ops, size, expected_hash = operations(manifest, args.partition)
                if (size != image_before[2] or size != identity.get('image_size_actual') or
                    size != identity.get('image_size_expected') or expected_hash != identity.get('image_sha256_expected')):
                    raise v.Invalid('image size or manifest identity disagreement')
                report.update(manifest_sha256=manifest_hash, image_size=size, operation_count=len(ops),
                              manifest_image_sha256=expected_hash, mismatch_operation_count=0,
                              mismatch_byte_count=0, mismatch_ranges=[], first_differing_offsets=[])
                expected_hasher, actual_hasher = hashlib.sha256(), hashlib.sha256()
                types = {}
                for index, (kind, blob_offset, blob_length, blob_hash, dst, out_length) in enumerate(ops):
                    if blob_offset + blob_length > entry.file_size - base:
                        raise v.Invalid('operation blob outside payload')
                    payload.seek(base + blob_offset)
                    blob = v.read_exact(payload, blob_length)
                    if hashlib.sha256(blob).digest() != blob_hash:
                        raise v.Invalid('operation %d blob SHA-256 mismatch' % index)
                    output = decode(kind, blob, out_length)
                    actual = v.read_exact(image, out_length)
                    expected_hasher.update(output)
                    actual_hasher.update(actual)
                    types[str(kind)] = types.get(str(kind), 0) + 1
                    if output != actual:
                        report['mismatch_operation_count'] += 1
                        # Each range is the containing operation extent, not a claim
                        # that every byte inside it differs. Exact byte count follows.
                        report['mismatch_ranges'].append({'operation_index': index, 'start': dst,
                                                         'end_exclusive': dst + out_length})
                        different = 0
                        first = report['first_differing_offsets']
                        for relative, (a, b) in enumerate(zip(output, actual)):
                            if a != b:
                                different += 1
                                if len(first) < 64:
                                    first.append(dst + relative)
                        report['mismatch_byte_count'] += different
                report.update(operation_types=types, decoded_image_sha256=expected_hasher.hexdigest(),
                              actual_image_sha256=actual_hasher.hexdigest(),
                              all_operation_blob_hashes_verified=True)
        if v.fingerprint(source) != source_before or v.fingerprint(image) != image_before:
            raise v.Invalid('input changed during comparison')
        if report['actual_image_sha256'] != identity.get('image_sha256_actual'):
            raise v.Invalid('image differs from prior identity report')
        report['decoded_image_matches_manifest'] = report['decoded_image_sha256'] == expected_hash
        report['image_matches_decoded_operations'] = report['mismatch_operation_count'] == 0
        if not report['decoded_image_matches_manifest']:
            raise v.Invalid('decoded full-image hash does not match manifest; provenance unresolved')
        report['status'] = 'matched' if report['image_matches_decoded_operations'] else 'different'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ota', 'ota-sha256', 'partition', 'image', 'identity-report', 'report'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    report = {'status': 'error', 'schema_version': 1,
              'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'range_semantics': 'Mismatch ranges are containing operation extents, not exact differing runs'}
    try:
        output = open(args.report, 'x', encoding='utf-8')
    except OSError as exc:
        print('Cannot create fresh report: %s' % exc, file=sys.stderr)
        return 2
    with output:
        try:
            compare(args, report)
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError, EOFError, zlib.error, lzma.LZMAError) as exc:
            report['error'] = str(exc)
        report['finished_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        json.dump(report, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'status': report['status'], 'report': os.path.abspath(args.report)}))
    return 0 if report['status'] == 'matched' else 1


if __name__ == '__main__':
    sys.exit(main())

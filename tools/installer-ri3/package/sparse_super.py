#!/usr/bin/env python3
"""RI3 files-only sparse codec. Canonical RAW/zero-FILL/terminal-CRC profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import zlib

MAGIC = 0xED26FF3A
RAW, FILL, DONT_CARE, CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4
HEADER = struct.Struct("<I4H4I")
CHUNK = struct.Struct("<2H2I")
U32 = (1 << 32) - 1
IO_BYTES = 1024 * 1024
DEFAULT_RAW_CHUNK = 16 * 1024 * 1024
DEFAULT_RESERVE = 11 * 1024**3
LARGE_GATE = 64 * 1024**2

class SparseError(ValueError):
    pass

def check(condition, message):
    if not condition:
        raise SparseError(message)

def regular(path):
    p = Path(path)
    check(stat.S_ISREG(p.lstat().st_mode), "input must be a regular non-symlink file")
    return p

def fingerprint(st):
    return st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino

def geometry(raw_bytes, block_size, capacity):
    check(isinstance(block_size, int) and 4 <= block_size <= IO_BYTES and
          block_size % 4 == 0, "block size must be a multiple of 4, at most 1 MiB")
    check(isinstance(raw_bytes, int) and raw_bytes > 0 and
          raw_bytes % block_size == 0, "raw length must be positive and block aligned")
    check(raw_bytes // block_size <= U32, "block count exceeds sparse uint32 field")
    check(isinstance(capacity, int) and capacity >= raw_bytes, "target capacity is too small")
    check(capacity % block_size == 0, "target capacity must be block aligned")

def sha_pin(pin):
    check(isinstance(pin, str) and len(pin) == 64 and
          all(c in "0123456789abcdef" for c in pin), "SHA-256 must be 64 lowercase hex digits")

def exact(src, size):
    data = src.read(size)
    check(data is not None and len(data) == size, "truncated sparse stream")
    return data

def validate_stream(src, *, expected_bytes, expected_sha256, capacity_bytes,
                    ):
    """Validate only complete canonical images; never writes reconstructed bytes."""
    sha_pin(expected_sha256)
    h = HEADER.unpack(exact(src, HEADER.size))
    magic, major, minor, fh, ch, block, blocks, chunks, header_crc = h
    check(magic == MAGIC, "bad sparse magic")
    check((major, minor, fh, ch) == (1, 0, HEADER.size, CHUNK.size),
          "unsupported noncanonical sparse header")
    geometry(blocks * block, block, capacity_bytes)
    check(blocks * block == expected_bytes, "expanded length does not match pin")
    check(chunks >= 2 and chunks <= blocks + 1, "invalid chunk count")
    digest, crc, covered, compressed = hashlib.sha256(), 0, 0, HEADER.size
    raw_chunks = fill_chunks = 0
    terminal_crc = None
    for index in range(chunks):
        kind, reserved, count, total = CHUNK.unpack(exact(src, CHUNK.size))
        compressed += CHUNK.size
        check(reserved == 0, "reserved chunk field must be zero")
        check(total >= CHUNK.size, "chunk size smaller than header")
        payload = total - CHUNK.size
        if kind == CRC32:
            check(index == chunks - 1 and count == 0 and payload == 4,
                  "CRC must be terminal, have zero blocks and four payload bytes")
            terminal_crc = struct.unpack("<I", exact(src, 4))[0]
            compressed += 4
            check(terminal_crc == crc, "terminal CRC mismatch")
            continue
        check(index < chunks - 1, "missing terminal CRC")
        check(count > 0 and covered + count <= blocks, "invalid chunk coverage")
        length = count * block
        if kind == RAW:
            check(payload == length, "RAW payload length does not match blocks")
            raw_chunks += 1
            remaining = length
            while remaining:
                buf = exact(src, min(IO_BYTES, remaining))
                digest.update(buf)
                crc = zlib.crc32(buf, crc)
                remaining -= len(buf)
            compressed += length
        elif kind == FILL:
            check(payload == 4, "FILL payload must be four bytes")
            word = exact(src, 4)
            compressed += 4
            check(word == b"\0" * 4,
                  "nonzero FILL not permitted by RI3 profile")
            fill_chunks += 1
            buffer_size = min(IO_BYTES, length)
            buf = word * (buffer_size // 4)
            remaining = length
            while remaining:
                data = buf[:min(len(buf), remaining)]
                digest.update(data)
                crc = zlib.crc32(data, crc)
                remaining -= len(data)
        elif kind == DONT_CARE:
            raise SparseError("DONT_CARE forbidden: full image must explicitly cover zero bytes")
        else:
            raise SparseError("unknown sparse chunk type")
        covered += count
    check(covered == blocks, "incomplete expanded-image block coverage")
    check(terminal_crc is not None, "missing terminal CRC")
    check(header_crc == 0 or header_crc == crc, "header CRC mismatch")
    check(src.read(1) == b"", "trailing data after declared chunks")
    actual = digest.hexdigest()
    check(actual == expected_sha256, "expanded SHA-256 does not match original raw pin")
    return {"profile": "ri3-raw-zero-fill-terminal-crc-v1", "raw_bytes": expected_bytes,
            "raw_sha256": actual, "raw_crc32": f"{crc:08x}",
            "sparse_bytes": compressed, "block_size": block, "total_blocks": blocks,
            "total_chunks": chunks, "raw_chunks": raw_chunks, "fill_chunks": fill_chunks,
            "dont_care_chunks": 0, "terminal_crc_chunks": 1, "complete_coverage": True}

def validate_file(path, **kwargs):
    p = regular(path)
    with p.open("rb") as src:
        initial = fingerprint(os.fstat(src.fileno()))
        result = validate_stream(src, **kwargs)
        check(initial == fingerprint(os.fstat(src.fileno())), "sparse source changed during validation")
    check(result["sparse_bytes"] == initial[0], "sparse file length mismatch")
    return result

def worst_case_bytes(raw_bytes, block_size):
    # At most one chunk per input block, plus one CRC chunk.
    return HEADER.size + raw_bytes + (raw_bytes // block_size) * CHUNK.size + CHUNK.size + 4


def _walk_runs(src, *, block_size, max_raw_bytes, keep_data, emit):
    """Scan in slabs; retain at most one capped RAW run when a streaming sink needs it."""
    digest, crc, consumed = hashlib.sha256(), 0, 0
    kind, blocks, data = None, 0, bytearray()
    stats = {"raw_chunks": 0, "fill_chunks": 0, "total_chunks": 1, "sparse_bytes": 44}
    zero = bytes(block_size)
    def finish():
        nonlocal kind, blocks, data
        if kind is None:
            return
        size = blocks * block_size if kind == RAW else 4
        stats["raw_chunks" if kind == RAW else "fill_chunks"] += 1
        stats["total_chunks"] += 1
        stats["sparse_bytes"] += CHUNK.size + size
        emit(kind, blocks, data if kind == RAW else b"\0" * 4)
        kind, blocks, data = None, 0, bytearray()
    read_size = max(block_size, IO_BYTES // block_size * block_size)
    while True:
        slab = src.read(read_size)
        if not slab:
            break
        check(len(slab) % block_size == 0, "raw file became unaligned")
        consumed += len(slab)
        digest.update(slab)
        crc = zlib.crc32(slab, crc)
        view = memoryview(slab)
        for at in range(0, len(slab), block_size):
            block = view[at:at+block_size]
            next_kind = FILL if block == zero else RAW
            limit = max_raw_bytes // block_size if next_kind == RAW else U32
            if next_kind != kind or blocks == limit:
                finish()
                kind = next_kind
            if next_kind == RAW and keep_data:
                data.extend(block)
            blocks += 1
    finish()
    stats.update(raw_bytes=consumed, raw_sha256=digest.hexdigest(), raw_crc32=f"{crc:08x}")
    return stats

def _encoder_inputs(raw_path, expected_bytes, expected_sha256, capacity_bytes,
                    block_size, max_raw_bytes):
    sha_pin(expected_sha256)
    geometry(expected_bytes, block_size, capacity_bytes)
    check(max_raw_bytes >= block_size and max_raw_bytes % block_size == 0 and
          max_raw_bytes + CHUNK.size <= U32 and max_raw_bytes <= 64*1024**2,
          "RAW chunk limit must be aligned and no more than 64 MiB")
    p = regular(raw_path)
    check(p.stat().st_size == expected_bytes, "raw file size does not match pin")
    return p

def analyze_file(raw_path, *, expected_bytes, expected_sha256, capacity_bytes,
                 block_size=4096, max_raw_bytes=DEFAULT_RAW_CHUNK):
    """Read-only first pass: exact deterministic output size, counts, hash, CRC and identity."""
    p = _encoder_inputs(raw_path, expected_bytes, expected_sha256, capacity_bytes,
                        block_size, max_raw_bytes)
    with p.open("rb") as src:
        initial = fingerprint(os.fstat(src.fileno()))
        stats = _walk_runs(src, block_size=block_size, max_raw_bytes=max_raw_bytes,
                           keep_data=False, emit=lambda *unused: None)
        check(initial == fingerprint(os.fstat(src.fileno())), "raw source changed during planning")
    check(stats["raw_bytes"] == expected_bytes, "raw length changed during planning")
    check(stats["raw_sha256"] == expected_sha256, "original raw SHA-256 pin mismatch")
    check(stats["total_chunks"] <= U32, "chunk count overflows uint32")
    return dict(stats, block_size=block_size, deterministic_raw_chunk_limit=max_raw_bytes,
                source_raw_path=str(p.resolve()), source_identity=list(initial),
                profile="ri3-raw-zero-fill-terminal-crc-v1", complete_coverage=True,
                dont_care_chunks=0, terminal_crc_chunks=1, total_blocks=expected_bytes//block_size)

def emit_stream(raw_path, sink, plan, *, expected_bytes, expected_sha256, capacity_bytes,
                allow_large_output=False):
    """Second pass into a non-seekable file-like sink; caller must independently validate output."""
    block_size, limit = plan["block_size"], plan["deterministic_raw_chunk_limit"]
    p = _encoder_inputs(raw_path, expected_bytes, expected_sha256, capacity_bytes,
                        block_size, limit)
    check(expected_bytes <= LARGE_GATE or allow_large_output,
          "large output requires explicit --allow-large-output after contract approval")
    check(plan["raw_bytes"] == expected_bytes and plan["raw_sha256"] == expected_sha256,
          "planning pass does not match original pins")
    check(str(p.resolve()) == plan["source_raw_path"], "source path differs from planning pass")
    encoded_hash, encoded_count = hashlib.sha256(), 0
    def write(buf):
        nonlocal encoded_count
        check(sink.write(buf) == len(buf), "short output write")
        encoded_hash.update(buf)
        encoded_count += len(buf)
    with p.open("rb") as src:
        identity = fingerprint(os.fstat(src.fileno()))
        check(list(identity) == plan["source_identity"], "source identity changed between passes")
        write(HEADER.pack(MAGIC, 1, 0, HEADER.size, CHUNK.size, block_size,
                          expected_bytes//block_size, plan["total_chunks"], int(plan["raw_crc32"], 16)))
        def emit(kind, blocks, payload):
            write(CHUNK.pack(kind, 0, blocks, CHUNK.size+len(payload)))
            write(payload)
        stats = _walk_runs(src, block_size=block_size, max_raw_bytes=limit, keep_data=True, emit=emit)
        check(identity == fingerprint(os.fstat(src.fileno())), "raw source changed during emission")
        check(stats["raw_bytes"] == expected_bytes and stats["raw_sha256"] == expected_sha256,
              "raw source content changed between passes")
        for key in ("raw_bytes", "raw_sha256", "raw_crc32", "raw_chunks", "fill_chunks",
                    "total_chunks", "sparse_bytes"):
            check(stats[key] == plan[key], "emission differs from planning pass: " + key)
        # Missing final CRC makes interrupted/failed streams invalid in the RI3 profile.
        write(CHUNK.pack(CRC32, 0, 0, CHUNK.size+4))
        write(struct.pack("<I", int(stats["raw_crc32"], 16)))
    check(encoded_count == plan["sparse_bytes"], "emitted sparse byte count differs from plan")
    return dict(plan, sparse_sha256=encoded_hash.hexdigest(),
                streaming_second_pass_verified=True, output_validation_required=True)

def encode_file(raw_path, output_path, *, expected_bytes, expected_sha256, capacity_bytes,
                block_size=4096, max_raw_bytes=DEFAULT_RAW_CHUNK,
                reserve_bytes=DEFAULT_RESERVE, allow_large_output=False):
    """Exclusive-create a sparse file using plan/stream/independent-validate passes."""
    check(expected_bytes <= LARGE_GATE or allow_large_output,
          "large output requires explicit --allow-large-output after contract approval")
    check(reserve_bytes >= 0, "negative free-space reserve")
    out = Path(output_path)
    check(not out.exists() and not out.is_symlink(), "output exists; refusing overwrite")
    check(out.parent.is_dir(), "output parent must already exist")
    pins = dict(expected_bytes=expected_bytes, expected_sha256=expected_sha256,
                capacity_bytes=capacity_bytes)
    plan = analyze_file(raw_path, block_size=block_size, max_raw_bytes=max_raw_bytes, **pins)
    check(shutil.disk_usage(out.parent).free >= plan["sparse_bytes"] + reserve_bytes,
          "insufficient disk headroom for exact sparse output plus reserve")
    with out.open("xb") as dst:
        emitted = emit_stream(raw_path, dst, plan, allow_large_output=allow_large_output, **pins)
        dst.flush()
        os.fsync(dst.fileno())
    result = validate_file(out, **pins)
    # Match physical sparse bytes independently too; expanded-image validation alone is insufficient.
    h = hashlib.sha256()
    with out.open("rb") as src:
        for buf in iter(lambda: src.read(IO_BYTES), b""):
            h.update(buf)
    check(h.hexdigest() == emitted["sparse_sha256"], "stored sparse bytes differ from emission")
    result.update(sparse_sha256=h.hexdigest(), deterministic_raw_chunk_limit=max_raw_bytes,
                  source_raw_path=str(Path(raw_path).resolve()), output_sparse_path=str(out),
                  free_bytes_after=shutil.disk_usage(out.parent).free)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["analyze", "encode", "validate"])
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-bytes", type=int, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--capacity-bytes", type=int, required=True)
    parser.add_argument("--block-size", type=int, default=4096)
    parser.add_argument("--max-raw-bytes", type=int, default=DEFAULT_RAW_CHUNK)
    parser.add_argument("--reserve-bytes", type=int, default=DEFAULT_RESERVE)
    parser.add_argument("--allow-large-output", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    pins = dict(expected_bytes=args.expected_bytes, expected_sha256=args.expected_sha256,
                capacity_bytes=args.capacity_bytes)
    if args.action == "encode":
        parser.error("--output is required for encode") if args.output is None else None
        result = encode_file(args.input, args.output, block_size=args.block_size,
                             max_raw_bytes=args.max_raw_bytes, reserve_bytes=args.reserve_bytes,
                             allow_large_output=args.allow_large_output, **pins)
    elif args.action == "analyze":
        result = analyze_file(args.input, block_size=args.block_size,
                              max_raw_bytes=args.max_raw_bytes, **pins)
    else:
        result = validate_file(args.input, **pins)
    data = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.report:
        with args.report.open("x", encoding="utf-8", newline="\n") as dst:
            dst.write(data)
    print(data, end="")

if __name__ == "__main__":
    main()

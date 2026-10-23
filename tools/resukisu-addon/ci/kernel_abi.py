"""Standalone, read-only POCO F6 kernel ABI inspection helpers.

Derived from the existing project's inspect_recovery.py and
check_module_crcs.py. No ROM builder, signing, or shell imports.
"""
from __future__ import annotations

import struct


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def imports(module: bytes) -> list[tuple[str, int]]:
    require(module[:6] == b"\x7fELF\x02\x01", "Expected ELF64 little-endian module")
    require(len(module) >= 64, "Truncated module header")
    offset = struct.unpack_from("<Q", module, 40)[0]
    size, count, string_index = struct.unpack_from("<HHH", module, 58)
    require(size == 64 and offset + count * size <= len(module) and string_index < count,
            "ELF section table out of bounds")
    sections = [struct.unpack_from("<IIQQQQIIQQ", module, offset + i * size) for i in range(count)]
    section_names = sections[string_index]
    require(section_names[4] + section_names[5] <= len(module), "Section string table out of bounds")
    names = module[section_names[4]:section_names[4] + section_names[5]]
    entries = []
    for section in sections:
        require(section[4] + section[5] <= len(module), "Module section out of bounds")
        if names[section[0]:].split(b"\0", 1)[0] == b"__versions":
            data = module[section[4]:section[4] + section[5]]
            require(len(data) % 64 == 0, "Invalid __versions bounds")
            for i in range(0, len(data), 64):
                crc = struct.unpack_from("<Q", data, i)[0]
                name = data[i+8:i+64].split(b"\0", 1)[0].decode()
                entries.append((name, crc))
    require(entries, "Missing module __versions entries")
    return entries


def _lz4_block(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    def length(base: int) -> int:
        nonlocal pos
        if base == 15:
            while True:
                require(pos < len(data), "Truncated LZ4 length")
                value = data[pos]
                pos += 1
                base += value
                if value != 255:
                    break
        return base
    while pos < len(data):
        token = data[pos]
        pos += 1
        literal = length(token >> 4)
        require(pos + literal <= len(data), "Truncated LZ4 literal")
        out += data[pos:pos+literal]
        pos += literal
        if pos == len(data):
            break
        require(pos + 2 <= len(data), "Truncated LZ4 offset")
        offset = data[pos] | data[pos+1] << 8
        pos += 2
        require(0 < offset <= len(out), "Invalid LZ4 offset")
        count = length(token & 15) + 4
        chunk = bytes(out[-offset:])
        out += (chunk * ((count+offset-1)//offset))[:count]
        require(len(out) <= 8 * 1024 * 1024, "Oversized LZ4 block")
    return bytes(out)


def ramdisk(image: bytes) -> tuple[dict, dict[str, bytes]]:
    require(image[:8] == b"ANDROID!", "Not an Android boot image")
    require(len(image) >= 4096, "Truncated Android boot header")
    version = struct.unpack_from("<I", image, 40)[0]
    require(version in (3, 4), "Unsupported boot header")
    kernel_size, size = struct.unpack_from("<II", image, 8)
    offset = 4096 + ((kernel_size + 4095) // 4096) * 4096
    data = image[offset:offset + size]
    require(len(data) == size and data[:4] == b"\x02\x21\x4c\x18",
            "Expected legacy LZ4 ramdisk")
    pos = 4
    blocks = []
    while pos < len(data):
        require(pos + 4 <= len(data), "Truncated LZ4 block size")
        count = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        require(0 < count <= len(data) - pos, "Invalid LZ4 block bounds")
        blocks.append(_lz4_block(data[pos:pos+count]))
        pos += count
    raw = b"".join(blocks)
    entries = {}
    pos = 0
    while pos + 110 <= len(raw) and raw[pos:pos+6] in (b"070701", b"070702"):
        fields = [int(raw[pos+6+j*8:pos+14+j*8], 16) for j in range(13)]
        size, name_size = fields[6], fields[11]
        require(name_size > 0 and pos + 110 + name_size <= len(raw), "CPIO name out of bounds")
        name = raw[pos+110:pos+110+name_size-1].decode()
        pos = (pos + 110 + name_size + 3) & ~3
        require(pos + size <= len(raw), "CPIO file out of bounds")
        payload = raw[pos:pos+size]
        pos = (pos + size + 3) & ~3
        if name == "TRAILER!!!":
            break
        require(name not in entries, "Duplicate CPIO path")
        entries[name] = payload
    return {"header_version": version, "kernel_size": kernel_size,
            "ramdisk_bytes": len(raw)}, entries
